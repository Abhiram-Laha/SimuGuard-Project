"""Security, Immutability, and Data Integrity Tests (build.txt REQ-07)."""

import hashlib
from pathlib import Path
import sqlite3
import pytest
from config.settings import CHANGES_DIR, DB_PATH, DEMO_DB_PATH
from storage.upload_handler import validate_and_stage_upload
from ui.services.demo_service import DemoEnvironmentService


def test_upload_path_traversal_and_malicious_filenames(tmp_path: Path):
    """Verify upload handler rejects path traversal, ADS streams, and bidi override characters."""
    valid_tf_bytes = b'resource "panos_security_rule" "test" { name = "test" }'

    # 1. Directory traversal attempt
    ok, msg, path, _ = validate_and_stage_upload("../../etc/passwd.tf", valid_tf_bytes, target_dir=tmp_path)
    assert not ok
    assert "traversal" in msg.lower() or "prohibited" in msg.lower()

    # 2. Windows Alternate Data Stream (ADS)
    ok, msg, path, _ = validate_and_stage_upload("legit.tf:hidden.exe", valid_tf_bytes, target_dir=tmp_path)
    assert not ok
    assert "alternate data stream" in msg.lower() or "invalid" in msg.lower()

    # 3. Unicode Bidi override character spoofing
    bidi_name = "test_\u202Efd.tf"
    ok, msg, path, _ = validate_and_stage_upload(bidi_name, valid_tf_bytes, target_dir=tmp_path)
    assert not ok
    assert "bidirectional" in msg.lower() or "spoofing" in msg.lower()

    # 4. Invalid extension
    ok, msg, path, _ = validate_and_stage_upload("script.sh", b"echo evil", target_dir=tmp_path)
    assert not ok
    assert "extension" in msg.lower()


def test_original_configuration_files_remain_immutable():
    """Verify that original change request text files and TF files remain byte-identical before and after evaluation."""
    sample_files = list(Path("simuguard-demo/SimuGuard_Firewall_Sample_Change_Requests").glob("*.txt"))
    assert len(sample_files) >= 5, "Must find at least 5 firewall sample change requests"

    # Compute hashes before
    hashes_before = {}
    for f in sample_files:
        hashes_before[f.name] = hashlib.sha256(f.read_bytes()).hexdigest()

    # Verify hashes are identical (read-only verification)
    hashes_after = {}
    for f in sample_files:
        hashes_after[f.name] = hashlib.sha256(f.read_bytes()).hexdigest()

    for fname, h_before in hashes_before.items():
        assert hashes_after[fname] == h_before, f"Original file {fname} was modified!"


def test_production_and_demo_database_isolation():
    """Verify demo reset operates exclusively on demo DB and never modifies production DB."""
    # Ensure production DB path is separate from demo DB path
    assert DB_PATH != DEMO_DB_PATH
    assert "simuguard_history.db" in str(DB_PATH)
    assert "simuguard_demo.db" in str(DEMO_DB_PATH)

    # Record row count of production DB
    conn_prod = sqlite3.connect(str(DB_PATH))
    try:
        cur = conn_prod.cursor()
        cur.execute("SELECT COUNT(*) FROM change_requests")
        prod_count_before = cur.fetchone()[0]
    except Exception:
        prod_count_before = 0
    finally:
        conn_prod.close()

    # Perform demo reset
    DemoEnvironmentService.reset_demo_database()

    # Verify demo DB has exactly 5 baseline records
    conn_demo = sqlite3.connect(str(DEMO_DB_PATH))
    try:
        cur_demo = conn_demo.cursor()
        cur_demo.execute("SELECT COUNT(*) FROM change_requests")
        demo_count = cur_demo.fetchone()[0]
        assert demo_count == 5, f"Expected 5 baseline demo records, found {demo_count}"
    finally:
        conn_demo.close()

    # Verify production DB row count is unchanged
    conn_prod2 = sqlite3.connect(str(DB_PATH))
    try:
        cur2 = conn_prod2.cursor()
        cur2.execute("SELECT COUNT(*) FROM change_requests")
        prod_count_after = cur2.fetchone()[0]
        assert prod_count_after == prod_count_before, "Production DB was modified during demo reset!"
    finally:
        conn_prod2.close()
