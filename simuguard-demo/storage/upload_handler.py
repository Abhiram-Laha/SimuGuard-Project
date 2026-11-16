"""Upload handling and security enforcement for Terraform configurations."""

from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Optional, Tuple, Union
import uuid

from config.settings import CHANGES_DIR, DEMO_ENV_DIR, UPLOADS_DIR

MAX_UPLOAD_SIZE_BYTES = 1024 * 1024  # 1 MB
ALLOWED_EXTENSIONS = {".tf"}


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent directory traversal and dangerous characters."""
    # Strip any leading directory path
    base_name = Path(filename).name

    # Remove null bytes or non-printable chars
    cleaned = base_name.replace("\x00", "").strip()

    # Reject or sanitize traversal patterns
    if ".." in cleaned or "/" in cleaned or "\\" in cleaned:
        cleaned = re.sub(r"[\./\\]+", "_", cleaned)

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

    # Check for path traversal indicators in raw input
    raw_name = filename.strip()
    if ".." in raw_name or "/" in raw_name or "\\" in raw_name or "\x00" in raw_name:
        return False, "Path traversal attempt detected in uploaded filename.", None, None

    # Enforce extension
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return (
            False,
            f"Invalid file extension '{ext}'. Only Terraform files (.tf) are permitted.",
            None,
            None,
        )

    # Enforce file size limit
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

    # Validate UTF-8 encoding
    try:
        content_text = file_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return False, "File must be valid UTF-8 plain text.", None, None

    # Sanitize the base filename
    safe_base = sanitize_filename(filename)

    # Staging destination
    stage_dir = Path(target_dir) if target_dir else UPLOADS_DIR
    stage_dir.mkdir(parents=True, exist_ok=True)

    # Generate unique staged filename to prevent collisions and overwrite
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    unique_id = uuid.uuid4().hex[:8]
    staged_filename = f"staged_{timestamp}_{unique_id}_{safe_base}"
    staged_path = (stage_dir / staged_filename).resolve()

    # Safety check: Ensure the staged path is inside the allowed upload directory
    if not str(staged_path).startswith(str(stage_dir.resolve())):
        return False, "Staged file path escapes upload directory sandbox.", None, None

    # Safety check: Never overwrite original scenario files
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
