"""SQLite database management and schema definitions for SimuGuard AI."""

import sqlite3
from pathlib import Path
from typing import Optional, Union
from config.settings import DB_PATH


SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS change_requests (
    request_number TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    submitted_by TEXT,
    submitter_role TEXT,
    change_type TEXT,
    domain TEXT,
    priority TEXT,
    status TEXT,
    created_at TEXT,
    updated_at TEXT,
    assigned_engineer TEXT,
    target_environment TEXT,
    source_file_path TEXT,
    raw_content TEXT
);

CREATE TABLE IF NOT EXISTS assessment_records (
    assessment_id TEXT PRIMARY KEY,
    request_number TEXT NOT NULL,
    timestamp TEXT,
    verdict TEXT NOT NULL,
    composite_risk_score REAL,
    max_risk_score REAL,
    security_gaps_count INTEGER,
    critical_count INTEGER,
    high_count INTEGER,
    medium_count INTEGER,
    low_count INTEGER,
    blast_radius_nodes_count INTEGER,
    assessment_type TEXT,
    raw_json TEXT,
    FOREIGN KEY (request_number) REFERENCES change_requests (request_number) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS remediation_records (
    remediation_id TEXT PRIMARY KEY,
    request_number TEXT NOT NULL,
    assessment_id TEXT NOT NULL,
    created_at TEXT,
    synthesized_hcl TEXT,
    plan_json TEXT,
    comparison_json TEXT,
    status TEXT,
    FOREIGN KEY (request_number) REFERENCES change_requests (request_number) ON DELETE CASCADE,
    FOREIGN KEY (assessment_id) REFERENCES assessment_records (assessment_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_number TEXT NOT NULL,
    timestamp TEXT,
    actor TEXT,
    action TEXT,
    details TEXT,
    FOREIGN KEY (request_number) REFERENCES change_requests (request_number) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_assessment_request ON assessment_records (request_number);
CREATE INDEX IF NOT EXISTS idx_remediation_request ON remediation_records (request_number);
CREATE INDEX IF NOT EXISTS idx_activity_request ON activity_logs (request_number);
"""


def get_db_connection(db_path: Optional[Union[str, Path]] = None) -> sqlite3.Connection:
    """Obtain a SQLite database connection with row factory enabled."""
    target_path = Path(db_path) if db_path else DB_PATH
    target_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Optional[Union[str, Path]] = None) -> None:
    """Initialize database schema, tables, and indices."""
    target_path = Path(db_path) if db_path else DB_PATH
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with get_db_connection(target_path) as conn:
        conn.executescript(SCHEMA_SQL)
        conn.commit()
