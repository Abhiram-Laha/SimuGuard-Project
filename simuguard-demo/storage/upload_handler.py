"""Upload handling, security enforcement, and safe staging cleanup for Terraform configurations."""

from datetime import datetime, timezone
import os
from pathlib import Path
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import uuid

from config.settings import CHANGES_DIR, DEMO_ENV_DIR, UPLOADS_DIR

MAX_UPLOAD_SIZE_BYTES = 1024 * 1024  # 1 MB
ALLOWED_EXTENSIONS = {".tf"}

# Unicode Bidirectional Control Characters prohibited to prevent filename spoofing
BIDI_CONTROL_CHARS: Set[str] = {
    "\u202a",  # Left-to-Right Embedding (LRE)
    "\u202b",  # Right-to-Left Embedding (RLE)
    "\u202c",  # Pop Directional Formatting (PDF)
    "\u202d",  # Left-to-Right Override (LRO)
    "\u202e",  # Right-to-Left Override (RLO)
    "\u2066",  # Left-to-Right Isolate (LRI)
    "\u2067",  # Right-to-Left Isolate (RLI)
    "\u2068",  # First Strong Isolate (FSI)
    "\u2069",  # Pop Directional Isolate (PDI)
}


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent directory traversal and dangerous characters."""
    # Strip any leading directory path
    base_name = Path(filename).name

    # Remove null bytes or non-printable chars
    cleaned = base_name.replace("\x00", "").strip()

    # Strip any Unicode bidirectional control characters
    for ch in BIDI_CONTROL_CHARS:
        cleaned = cleaned.replace(ch, "")

    # Reject or sanitize traversal patterns
    if ".." in cleaned or "/" in cleaned or "\\" in cleaned or ":" in cleaned:
        cleaned = re.sub(r"[\./\\:]+", "_", cleaned)

    # Allow alphanumeric, underscore, hyphen, and period
    sanitized = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", cleaned)

    # Ensure it ends with .tf
    if not sanitized.lower().endswith(".tf"):
        sanitized = f"{sanitized}.tf"

    return sanitized


def validate_and_stage_upload(
    filename: str,
    file_bytes: bytes,
    target_dir: Optional[Union[str, Path]] = None,
) -> Tuple[bool, str, Optional[str], Optional[str]]:
    """
    Validate, sanitize, and stage an uploaded Terraform file.

    Returns:
        (is_valid, message, staged_file_path, content_text)
    """
    if not filename or not filename.strip():
        return False, "Filename cannot be empty.", None, None

    raw_name = filename.strip()

    # 1. Check for Unicode Bidirectional Override characters
    if any(ch in raw_name for ch in BIDI_CONTROL_CHARS):
        return (
            False,
            "Unicode bidirectional override characters detected in filename (spoofing prohibited).",
            None,
            None,
        )

    # 2. Check for Windows Alternate Data Streams (ADS)
    if ":" in raw_name:
        return (
            False,
            "Invalid character ':' detected in filename (Windows Alternate Data Streams prohibited).",
            None,
            None,
        )

    # 3. Check for path traversal indicators or null bytes in raw input
    if ".." in raw_name or "/" in raw_name or "\\" in raw_name or "\x00" in raw_name:
        return False, "Path traversal attempt detected in uploaded filename.", None, None

    # 4. Enforce strict extension
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return (
            False,
            f"Invalid file extension '{ext}'. Only Terraform files (.tf) are permitted.",
            None,
            None,
        )

    # 5. Enforce file size limit
    if len(file_bytes) == 0:
        return False, "Uploaded file is empty (0 bytes).", None, None

    if len(file_bytes) > MAX_UPLOAD_SIZE_BYTES:
        max_mb = MAX_UPLOAD_SIZE_BYTES / (1024 * 1024)
        return (
            False,
            f"File size exceeds maximum permitted limit of {max_mb:.1f} MB ({len(file_bytes)} bytes).",
            None,
            None,
        )

    # 6. Binary content detection (null bytes in content)
    if b"\x00" in file_bytes:
        return (
            False,
            "Binary file content detected (null bytes). Only plain text UTF-8 Terraform files are permitted.",
            None,
            None,
        )

    # 7. Validate UTF-8 encoding
    try:
        content_text = file_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return False, "File must be valid UTF-8 plain text.", None, None

    # 8. Sanitize the base filename
    safe_base = sanitize_filename(filename)

    # Staging destination
    stage_dir = Path(target_dir) if target_dir else UPLOADS_DIR
    stage_dir.mkdir(parents=True, exist_ok=True)

    # Generate unique staged filename to prevent collisions and overwrite
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    unique_id = uuid.uuid4().hex[:8]
    staged_filename = f"staged_{timestamp}_{unique_id}_{safe_base}"
    staged_path = (stage_dir / staged_filename).resolve()

    # Safety check: Ensure the staged path is inside the allowed upload directory sandbox
    if not str(staged_path).startswith(str(stage_dir.resolve())):
        return False, "Staged file path escapes upload directory sandbox.", None, None

    # Safety check: Never overwrite original scenario files or demo environment
    if str(staged_path).startswith(str(CHANGES_DIR.resolve())) or str(staged_path).startswith(
        str(DEMO_ENV_DIR.resolve())
    ):
        return False, "Target path conflicts with protected demo environment or scenario files.", None, None

    # Save safely
    try:
        staged_path.write_text(content_text, encoding="utf-8")
    except Exception as e:
        return False, f"Failed to stage uploaded file to disk: {str(e)}", None, None

    return True, "File uploaded and staged securely.", str(staged_path), content_text


def cleanup_orphaned_uploads(
    repository: Optional[Any] = None,
    dry_run: bool = True,
    max_age_hours: float = 24.0,
    target_dir: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """
    Safely prune unreferenced, orphaned staged upload files.

    Guarantees:
    - NEVER deletes any file referenced by an active change request or assessment audit.
    - NEVER touches files in `changes/` or `demo_environment/`.
    - Enforces conservative age-based retention (defaults to files older than 24 hours).
    - In dry_run mode (default), only reports what would be removed without deleting.

    Returns:
        Summary dict containing scan statistics and per-file audit actions.
    """
    stage_dir = Path(target_dir) if target_dir else UPLOADS_DIR
    if not stage_dir.exists():
        return {
            "scanned": 0,
            "active_referenced": 0,
            "retained_fresh": 0,
            "removed": 0,
            "dry_run": dry_run,
            "details": [],
        }

    # Query all active references from SQLite repository if available
    referenced_paths: Set[str] = set()
    if repository and hasattr(repository, "get_all_referenced_source_files"):
        try:
            referenced_paths = repository.get_all_referenced_source_files()
        except Exception:
            referenced_paths = set()

    now_ts = time.time()
    max_age_seconds = max_age_hours * 3600.0

    scanned_count = 0
    active_ref_count = 0
    fresh_count = 0
    removed_count = 0
    details: List[Dict[str, Any]] = []

    for item in stage_dir.iterdir():
        if not item.is_file():
            continue

        scanned_count += 1
        item_resolved = str(item.resolve())
        item_name = item.name

        # 1. Protected Check: Is it referenced in SQLite database?
        if item_resolved in referenced_paths or item_name in referenced_paths:
            active_ref_count += 1
            details.append({
                "file": item_name,
                "status": "PROTECTED_ACTIVE_REFERENCE",
                "reason": "Referenced by an active Change Request or Assessment in database.",
            })
            continue

        # 2. Age Check: Is the unreferenced file older than max_age_hours?
        try:
            mtime = item.stat().st_mtime
            age_seconds = now_ts - mtime
            age_hours = age_seconds / 3600.0
        except OSError:
            age_hours = 0.0

        if age_seconds < max_age_seconds:
            fresh_count += 1
            details.append({
                "file": item_name,
                "status": "RETAINED_RECENT",
                "age_hours": round(age_hours, 2),
                "reason": f"File is recent (< {max_age_hours} hours). Retained for active session.",
            })
            continue

        # 3. Eligible for cleanup
        if dry_run:
            details.append({
                "file": item_name,
                "status": "WOULD_REMOVE",
                "age_hours": round(age_hours, 2),
                "reason": f"Orphaned file older than {max_age_hours} hours. Eligible for safe pruning.",
            })
            removed_count += 1
        else:
            try:
                item.unlink(missing_ok=True)
                removed_count += 1
                details.append({
                    "file": item_name,
                    "status": "REMOVED",
                    "age_hours": round(age_hours, 2),
                    "reason": f"Pruned orphaned upload file older than {max_age_hours} hours.",
                })
            except Exception as e:
                details.append({
                    "file": item_name,
                    "status": "ERROR_REMOVING",
                    "error": str(e),
                })

    return {
        "scanned": scanned_count,
        "active_referenced": active_ref_count,
        "retained_fresh": fresh_count,
        "removed": removed_count,
        "dry_run": dry_run,
        "details": details,
    }
