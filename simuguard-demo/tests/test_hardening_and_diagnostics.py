"""Focused regression and hardening test suite for Milestone F (Stage 2 & Stage 3)."""

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import pytest

from storage.database import init_db
from storage.models import (
    AssessmentRecord,
    ChangeDomain,
    ChangePriority,
    ChangeRequestRecord,
    ChangeType,
    SailPointChangeDetails,
    WorkflowState,
)
from storage.repository import ChangeRepository
from storage.upload_handler import (
    ALLOWED_EXTENSIONS,
    BIDI_CONTROL_CHARS,
    MAX_UPLOAD_SIZE_BYTES,
    cleanup_orphaned_uploads,
    sanitize_filename,
    validate_and_stage_upload,
)
from ui.pages.diagnostics import _run_system_health_checks


@pytest.fixture
def temp_repo(tmp_path: Path) -> ChangeRepository:
    """Fixture providing an isolated ChangeRepository backed by a temporary SQLite file."""
    db_file = tmp_path / "test_hardening.db"
    init_db(db_file)
    return ChangeRepository(db_path=str(db_file))


# =============================================================================
# 1. Request Number Generation & Concurrency Hardening
# =============================================================================

def test_request_number_monotonic_generation(temp_repo: ChangeRepository):
    """Verify monotonic sequence generation with clean and custom record numbering."""
    # Empty DB
    assert temp_repo.generate_next_request_number() == "SIM-CHG-000001"

    # Insert record SIM-CHG-000001
    r1 = ChangeRequestRecord(
        request_number="SIM-CHG-000001",
        title="Initial Change",
    )
    temp_repo.create_change_request(r1)
    assert temp_repo.generate_next_request_number() == "SIM-CHG-000002"

    # Insert custom out-of-band request numbers (e.g. from tests or ITSM sync)
    r_custom = ChangeRequestRecord(
        request_number="SIM-2026-TEST-999",
        title="Custom Format Change",
    )
    temp_repo.create_change_request(r_custom)

    # Next sequential number should still correctly be SIM-CHG-000002
    assert temp_repo.generate_next_request_number() == "SIM-CHG-000002"

    # Insert SIM-CHG-000005 directly
    r5 = ChangeRequestRecord(
        request_number="SIM-CHG-000005",
        title="Fifth Change",
    )
    temp_repo.create_change_request(r5)

    # Next sequential number should be SIM-CHG-000006
    assert temp_repo.generate_next_request_number() == "SIM-CHG-000006"


def test_create_change_request_concurrent_conflict_retry(temp_repo: ChangeRepository):
    """Verify that create_change_request safely retries on collision for SIM-CHG- identifiers."""
    # Insert SIM-CHG-000001
    r1 = ChangeRequestRecord(
        request_number="SIM-CHG-000001",
        title="First Request",
    )
    temp_repo.create_change_request(r1)

    # Attempt to insert another request that was generated as SIM-CHG-000001 concurrently
    r2 = ChangeRequestRecord(
        request_number="SIM-CHG-000001",
        title="Concurrent Second Request",
    )
    # The retry logic inside create_change_request should detect IntegrityError and increment
    saved_r2 = temp_repo.create_change_request(r2)
    assert saved_r2.request_number == "SIM-CHG-000002"
    assert temp_repo.get_change_request("SIM-CHG-000001") is not None
    assert temp_repo.get_change_request("SIM-CHG-000002") is not None


def test_create_change_request_non_sequential_collision_raises(temp_repo: ChangeRepository):
    """Verify that custom non-sequential collisions still raise IntegrityError."""
    r_cust1 = ChangeRequestRecord(
        request_number="CUSTOM-COLLISION-ID",
        title="Custom 1",
    )
    temp_repo.create_change_request(r_cust1)

    r_cust2 = ChangeRequestRecord(
        request_number="CUSTOM-COLLISION-ID",
        title="Custom 2",
    )
    with pytest.raises(sqlite3.IntegrityError):
        temp_repo.create_change_request(r_cust2)


# =============================================================================
# 2. Upload Handler Hardening & Attack Vectors
# =============================================================================

def test_upload_rejection_path_traversal(tmp_path: Path):
    """Verify path traversal patterns are strictly blocked."""
    traversal_filenames = [
        "../../etc/passwd.tf",
        "..\\..\\windows\\system32\\cmd.tf",
        "/absolute/path/escape.tf",
        "nested/sub/folder/file.tf",
    ]
    for bad_name in traversal_filenames:
        ok, msg, path, content = validate_and_stage_upload(
            filename=bad_name,
            file_bytes=b'resource "null_resource" "test" {}',
            target_dir=tmp_path,
        )
        assert not ok, f"Expected rejection for traversal name: {bad_name}"
        assert "traversal" in msg.lower() or "escapes" in msg.lower() or "invalid" in msg.lower()


def test_upload_rejection_bidi_unicode_override(tmp_path: Path):
    """Verify Unicode bidirectional override characters (spoofing) are rejected."""
    # E.g. using Right-to-Left Override (\u202e)
    bidi_name = "test_\u202etxt.tf"
    ok, msg, path, content = validate_and_stage_upload(
        filename=bidi_name,
        file_bytes=b'resource "null_resource" "test" {}',
        target_dir=tmp_path,
    )
    assert not ok
    assert "bidirectional" in msg.lower() or "spoofing" in msg.lower()


def test_upload_rejection_windows_alternate_data_stream(tmp_path: Path):
    """Verify Windows Alternate Data Stream ':' separator is rejected."""
    ads_name = "legit.tf:hidden_payload.exe"
    ok, msg, path, content = validate_and_stage_upload(
        filename=ads_name,
        file_bytes=b'resource "null_resource" "test" {}',
        target_dir=tmp_path,
    )
    assert not ok
    assert "alternate data stream" in msg.lower() or ":" in msg


def test_upload_rejection_binary_content(tmp_path: Path):
    """Verify binary files containing null bytes are rejected."""
    binary_bytes = b'resource "aws_security_group" "test" {\x00\x01\x02}'
    ok, msg, path, content = validate_and_stage_upload(
        filename="binary_payload.tf",
        file_bytes=binary_bytes,
        target_dir=tmp_path,
    )
    assert not ok
    assert "binary" in msg.lower() or "null bytes" in msg.lower()


def test_upload_rejection_empty_and_oversized_files(tmp_path: Path):
    """Verify zero-byte and oversized files are blocked."""
    # Empty
    ok_empty, msg_empty, _, _ = validate_and_stage_upload(
        filename="empty.tf",
        file_bytes=b"",
        target_dir=tmp_path,
    )
    assert not ok_empty
    assert "empty" in msg_empty.lower()

    # Oversized (>1MB)
    huge_bytes = b"A" * (MAX_UPLOAD_SIZE_BYTES + 1024)
    ok_huge, msg_huge, _, _ = validate_and_stage_upload(
        filename="huge.tf",
        file_bytes=huge_bytes,
        target_dir=tmp_path,
    )
    assert not ok_huge
    assert "exceeds" in msg_huge.lower()


def test_upload_successful_valid_terraform(tmp_path: Path):
    """Verify valid UTF-8 plain text Terraform file passes and stages safely."""
    valid_tf = (
        'resource "aws_security_group_rule" "allow_https" {\n'
        '  type = "egress"\n'
        '  from_port = 443\n'
        '  to_port = 443\n'
        '  protocol = "tcp"\n'
        '}\n'
    ).encode("utf-8")

    ok, msg, staged_path, content = validate_and_stage_upload(
        filename="valid_policy.tf",
        file_bytes=valid_tf,
        target_dir=tmp_path,
    )
    assert ok
    assert staged_path is not None
    assert Path(staged_path).exists()
    assert "valid_policy" in Path(staged_path).name
    assert "resource" in content


# =============================================================================
# 3. Safe Upload Staging Cleanup
# =============================================================================

def test_cleanup_orphaned_uploads_protection(tmp_path: Path, temp_repo: ChangeRepository):
    """Verify cleanup protects active referenced files and prunes unreferenced old files."""
    upload_sandbox = tmp_path / "uploads_sandbox"
    upload_sandbox.mkdir(parents=True, exist_ok=True)

    # 1. Create an active referenced file in DB
    ref_file = upload_sandbox / "staged_20261101_000000_12345678_active.tf"
    ref_file.write_text('resource "panos_security_rule" "active" {}', encoding="utf-8")

    # Backdate mtime to 48 hours ago
    old_time = time.time() - (48 * 3600)
    import os
    os.utime(ref_file, (old_time, old_time))

    req = ChangeRequestRecord(
        request_number="SIM-CHG-REF-001",
        title="Active Reference Ticket",
        source_file_path=str(ref_file.resolve()),
    )
    temp_repo.create_change_request(req)

    # 2. Create an orphaned old file (48h old, unreferenced)
    orphaned_file = upload_sandbox / "staged_20261101_000000_87654321_orphaned.tf"
    orphaned_file.write_text('resource "panos_security_rule" "orphan" {}', encoding="utf-8")
    os.utime(orphaned_file, (old_time, old_time))

    # 3. Create a recent unreferenced file (1h old)
    recent_file = upload_sandbox / "staged_20261116_120000_11112222_recent.tf"
    recent_file.write_text('resource "panos_security_rule" "recent" {}', encoding="utf-8")

    # Run cleanup in dry-run mode
    dry_report = cleanup_orphaned_uploads(
        repository=temp_repo,
        dry_run=True,
        max_age_hours=24.0,
        target_dir=upload_sandbox,
    )
    assert dry_report["scanned"] == 3
    assert dry_report["active_referenced"] == 1
    assert dry_report["retained_fresh"] == 1
    assert dry_report["removed"] == 1  # 1 would be removed

    # Files must still exist on disk after dry run
    assert ref_file.exists()
    assert orphaned_file.exists()
    assert recent_file.exists()

    # Run cleanup with dry_run=False
    live_report = cleanup_orphaned_uploads(
        repository=temp_repo,
        dry_run=False,
        max_age_hours=24.0,
        target_dir=upload_sandbox,
    )
    assert live_report["removed"] == 1

    # Active referenced file MUST be preserved
    assert ref_file.exists(), "Active referenced file must NEVER be deleted"
    # Recent file MUST be preserved
    assert recent_file.exists(), "Recent file must be preserved"
    # Orphaned old file MUST be deleted
    assert not orphaned_file.exists(), "Orphaned old file should be deleted"


# =============================================================================
# 4. SailPoint Form Validation Decoupling
# =============================================================================

def test_sailpoint_change_details_validation():
    """Verify SailPoint change details validation logic independently of Terraform upload."""
    sp_details = SailPointChangeDetails(
        identity_id="sp-ident-sarah-chen",
        identity_name="Sarah Chen (sp-ident-sarah-chen - Senior Treasury Analyst)",
        requested_role="Finance & Treasury Analyst",
        entitlement="AWS Production S3 CUI Vault Read",
        approval_status="PENDING",
        provisioning_status="UNPROVISIONED",
    )

    # Valid identity and role
    assert sp_details.identity_name != ""
    assert sp_details.requested_role != ""
    assert sp_details.approval_status == "PENDING"
    assert sp_details.provisioning_status == "UNPROVISIONED"

    # Verify model serialization
    sp_json = sp_details.model_dump_json()
    assert "Sarah Chen" in sp_json
    assert "Treasury Analyst" in sp_json


# =============================================================================
# 5. System Diagnostics Subsystem Integrity
# =============================================================================

def test_system_health_checks_live(temp_repo: ChangeRepository):
    """Verify all live runtime health checks return PASS on verified deployment."""
    checks = _run_system_health_checks(temp_repo)
    assert len(checks) >= 8

    # All checks should PASS in standard verified environment
    failures = [c for c in checks if c["status"] == "FAIL"]
    assert len(failures) == 0, f"Diagnostic health checks failed: {failures}"

    check_names = {c["name"] for c in checks}
    assert "Python Runtime Version" in check_names
    assert "Core Platform Dependencies" in check_names
    assert "SQLite Database & Schema Integrity" in check_names
    assert "Digital Twin Topology & Estate Model" in check_names
    assert "Deterministic Pre-Flight Analysis Engine" in check_names
    assert "Executive PDF & JSON Compliance Exporters" in check_names
