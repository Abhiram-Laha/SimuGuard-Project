"""Data Access Repository for SimuGuard AI SQLite Storage."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import sqlite3

from storage.database import get_db_connection
from storage.models import (
    ActivityLogRecord,
    AssessmentRecord,
    ChangeRequestRecord,
    KPISummary,
    RemediationRecord,
)


class ChangeRepository:
    """Repository managing CRUD operations for change requests and assessments."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path

    def _get_conn(self, conn: Optional[sqlite3.Connection] = None) -> sqlite3.Connection:
        if conn is not None:
            return conn
        return get_db_connection(self.db_path)

    def generate_next_request_number(self, conn: Optional[sqlite3.Connection] = None) -> str:
        """Generate a sequential enterprise change request identifier (e.g. SIM-CHG-000001)."""
        close_after = conn is None
        c = self._get_conn(conn)
        try:
            cursor = c.cursor()
            cursor.execute("SELECT request_number FROM change_requests ORDER BY rowid DESC LIMIT 1")
            row = cursor.fetchone()
            if not row:
                return "SIM-CHG-000001"
            last_num_str = row["request_number"]
            # Extract digits after SIM-CHG-
            try:
                parts = last_num_str.split("-")
                num = int(parts[-1])
                return f"SIM-CHG-{num + 1:06d}"
            except (ValueError, IndexError):
                cursor.execute("SELECT COUNT(*) as count FROM change_requests")
                count = cursor.fetchone()["count"]
                return f"SIM-CHG-{count + 1:06d}"
        finally:
            if close_after:
                c.close()

    def create_change_request(
        self, record: ChangeRequestRecord, conn: Optional[sqlite3.Connection] = None
    ) -> ChangeRequestRecord:
        """Insert a new change request into the database."""
        close_after = conn is None
        c = self._get_conn(conn)
        try:
            now = datetime.now(timezone.utc).isoformat()
            if not record.created_at:
                record.created_at = now
            record.updated_at = now

            c.execute(
                """
                INSERT INTO change_requests (
                    request_number, title, description, submitted_by, submitter_role,
                    change_type, domain, priority, status, created_at, updated_at,
                    assigned_engineer, target_environment, source_file_path, raw_content
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.request_number,
                    record.title,
                    record.description,
                    record.submitted_by,
                    record.submitter_role,
                    record.change_type,
                    record.domain,
                    record.priority,
                    record.status,
                    record.created_at,
                    record.updated_at,
                    record.assigned_engineer,
                    record.target_environment,
                    record.source_file_path,
                    record.raw_content,
                ),
            )
            c.commit()

            # Record initial activity log
            self.log_activity(
                request_number=record.request_number,
                action="REQUEST_CREATED",
                actor=record.submitted_by,
                details=f"Created change request '{record.title}' with priority {record.priority}",
                conn=c,
            )
            return record
        finally:
            if close_after:
                c.close()

    def get_change_request(
        self, request_number: str, conn: Optional[sqlite3.Connection] = None
    ) -> Optional[ChangeRequestRecord]:
        """Retrieve a change request by its request number."""
        close_after = conn is None
        c = self._get_conn(conn)
        try:
            cursor = c.cursor()
            cursor.execute(
                "SELECT * FROM change_requests WHERE request_number = ?", (request_number,)
            )
            row = cursor.fetchone()
            if not row:
                return None
            return ChangeRequestRecord(**dict(row))
        finally:
            if close_after:
                c.close()

    def list_change_requests(
        self, limit: int = 50, conn: Optional[sqlite3.Connection] = None
    ) -> List[ChangeRequestRecord]:
        """List change requests sorted by newest first."""
        close_after = conn is None
        c = self._get_conn(conn)
        try:
            cursor = c.cursor()
            cursor.execute(
                "SELECT * FROM change_requests ORDER BY created_at DESC LIMIT ?", (limit,)
            )
            rows = cursor.fetchall()
            return [ChangeRequestRecord(**dict(row)) for row in rows]
        finally:
            if close_after:
                c.close()

    def update_change_request_status(
        self, request_number: str, status: str, conn: Optional[sqlite3.Connection] = None
    ) -> None:
        """Update workflow status of a change request."""
        close_after = conn is None
        c = self._get_conn(conn)
        try:
            now = datetime.now(timezone.utc).isoformat()
            c.execute(
                "UPDATE change_requests SET status = ?, updated_at = ? WHERE request_number = ?",
                (status, now, request_number),
            )
            c.commit()
            self.log_activity(
                request_number=request_number,
                action="STATUS_UPDATED",
                actor="System",
                details=f"Workflow status transitioned to {status}",
                conn=c,
            )
        finally:
            if close_after:
                c.close()

    def save_assessment_record(
        self, record: AssessmentRecord, conn: Optional[sqlite3.Connection] = None
    ) -> AssessmentRecord:
        """Persist a simulation assessment record."""
        close_after = conn is None
        c = self._get_conn(conn)
        try:
            c.execute(
                """
                INSERT OR REPLACE INTO assessment_records (
                    assessment_id, request_number, timestamp, verdict,
                    composite_risk_score, max_risk_score, security_gaps_count,
                    critical_count, high_count, medium_count, low_count,
                    blast_radius_nodes_count, assessment_type, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.assessment_id,
                    record.request_number,
                    record.timestamp,
                    record.verdict,
                    record.composite_risk_score,
                    record.max_risk_score,
                    record.security_gaps_count,
                    record.critical_count,
                    record.high_count,
                    record.medium_count,
                    record.low_count,
                    record.blast_radius_nodes_count,
                    record.assessment_type,
                    record.raw_json,
                ),
            )
            c.commit()
            self.log_activity(
                request_number=record.request_number,
                action="ASSESSMENT_COMPLETED",
                actor="SimuGuard AI Engine",
                details=f"Simulation assessed verdict {record.verdict} with risk score {record.composite_risk_score:.1f}",
                conn=c,
            )
            return record
        finally:
            if close_after:
                c.close()

    def get_latest_assessment(
        self,
        request_number: str,
        assessment_type: Optional[str] = None,
        conn: Optional[sqlite3.Connection] = None,
    ) -> Optional[AssessmentRecord]:
        """Fetch the most recent assessment for a change request."""
        close_after = conn is None
        c = self._get_conn(conn)
        try:
            cursor = c.cursor()
            if assessment_type:
                cursor.execute(
                    """
                    SELECT * FROM assessment_records
                    WHERE request_number = ? AND assessment_type = ?
                    ORDER BY timestamp DESC LIMIT 1
                    """,
                    (request_number, assessment_type),
                )
            else:
                cursor.execute(
                    """
                    SELECT * FROM assessment_records
                    WHERE request_number = ?
                    ORDER BY timestamp DESC LIMIT 1
                    """,
                    (request_number,),
                )
            row = cursor.fetchone()
            if not row:
                return None
            return AssessmentRecord(**dict(row))
        finally:
            if close_after:
                c.close()

    def list_assessments_for_request(
        self, request_number: str, conn: Optional[sqlite3.Connection] = None
    ) -> List[AssessmentRecord]:
        """List all assessments associated with a change request."""
        close_after = conn is None
        c = self._get_conn(conn)
        try:
            cursor = c.cursor()
            cursor.execute(
                "SELECT * FROM assessment_records WHERE request_number = ? ORDER BY timestamp ASC",
                (request_number,),
            )
            rows = cursor.fetchall()
            return [AssessmentRecord(**dict(row)) for row in rows]
        finally:
            if close_after:
                c.close()

    def save_remediation_record(
        self, record: RemediationRecord, conn: Optional[sqlite3.Connection] = None
    ) -> RemediationRecord:
        """Persist a remediation record."""
        close_after = conn is None
        c = self._get_conn(conn)
        try:
            c.execute(
                """
                INSERT OR REPLACE INTO remediation_records (
                    remediation_id, request_number, assessment_id,
                    created_at, synthesized_hcl, plan_json, comparison_json, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.remediation_id,
                    record.request_number,
                    record.assessment_id,
                    record.created_at,
                    record.synthesized_hcl,
                    record.plan_json,
                    record.comparison_json,
                    record.status,
                ),
            )
            c.commit()
            self.log_activity(
                request_number=record.request_number,
                action="REMEDIATION_GENERATED",
                actor="SimuGuard AI Engine",
                details=f"Remediation plan generated with status {record.status}",
                conn=c,
            )
            return record
        finally:
            if close_after:
                c.close()

    def get_remediation_record(
        self, request_number: str, conn: Optional[sqlite3.Connection] = None
    ) -> Optional[RemediationRecord]:
        """Get the latest remediation record for a change request."""
        close_after = conn is None
        c = self._get_conn(conn)
        try:
            cursor = c.cursor()
            cursor.execute(
                "SELECT * FROM remediation_records WHERE request_number = ? ORDER BY created_at DESC LIMIT 1",
                (request_number,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return RemediationRecord(**dict(row))
        finally:
            if close_after:
                c.close()

    def log_activity(
        self,
        request_number: str,
        action: str,
        actor: str = "System",
        details: Optional[str] = None,
        conn: Optional[sqlite3.Connection] = None,
    ) -> None:
        """Append an audit trail entry."""
        close_after = conn is None
        c = self._get_conn(conn)
        try:
            now = datetime.now(timezone.utc).isoformat()
            c.execute(
                """
                INSERT INTO activity_logs (request_number, timestamp, actor, action, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (request_number, now, actor, action, details),
            )
            c.commit()
        finally:
            if close_after:
                c.close()

    def get_activity_logs(
        self, request_number: str, conn: Optional[sqlite3.Connection] = None
    ) -> List[ActivityLogRecord]:
        """Retrieve audit trail logs for a change request."""
        close_after = conn is None
        c = self._get_conn(conn)
        try:
            cursor = c.cursor()
            cursor.execute(
                "SELECT * FROM activity_logs WHERE request_number = ? ORDER BY timestamp ASC",
                (request_number,),
            )
            rows = cursor.fetchall()
            return [ActivityLogRecord(**dict(row)) for row in rows]
        finally:
            if close_after:
                c.close()

    def get_kpi_summary(self, conn: Optional[sqlite3.Connection] = None) -> KPISummary:
        """Compute aggregated KPI statistics across all change requests."""
        close_after = conn is None
        c = self._get_conn(conn)
        try:
            cursor = c.cursor()
            cursor.execute("SELECT COUNT(*) as cnt FROM change_requests")
            total = cursor.fetchone()["cnt"]

            if total == 0:
                return KPISummary()

            # Latest assessment per request
            cursor.execute(
                """
                SELECT a.verdict, a.composite_risk_score
                FROM assessment_records a
                INNER JOIN (
                    SELECT request_number, MAX(timestamp) as max_ts
                    FROM assessment_records
                    GROUP BY request_number
                ) latest ON a.request_number = latest.request_number AND a.timestamp = latest.max_ts
                """
            )
            assessment_rows = cursor.fetchall()

            allowed = sum(1 for r in assessment_rows if r["verdict"] == "ALLOW")
            warn = sum(1 for r in assessment_rows if r["verdict"] == "WARN_MANUAL_REVIEW")
            blocked = sum(1 for r in assessment_rows if r["verdict"] == "BLOCK_DEPLOYMENT")
            avg_score = (
                sum(r["composite_risk_score"] for r in assessment_rows) / len(assessment_rows)
                if assessment_rows
                else 0.0
            )

            # Count remediations
            cursor.execute("SELECT COUNT(DISTINCT request_number) as rem_cnt FROM remediation_records")
            remediated_count = cursor.fetchone()["rem_cnt"]

            return KPISummary(
                total_requests=total,
                allowed_count=allowed,
                warn_count=warn,
                blocked_count=blocked,
                remediated_count=remediated_count,
                avg_risk_score=round(avg_score, 1),
            )
        finally:
            if close_after:
                c.close()

    def get_recent_assessments(
        self, limit: int = 10, conn: Optional[sqlite3.Connection] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve recent change requests merged with their latest assessment info."""
        close_after = conn is None
        c = self._get_conn(conn)
        try:
            cursor = c.cursor()
            cursor.execute(
                """
                SELECT
                    cr.request_number,
                    cr.title,
                    cr.priority,
                    cr.status,
                    cr.created_at,
                    a.verdict,
                    a.composite_risk_score,
                    a.security_gaps_count,
                    a.blast_radius_nodes_count
                FROM change_requests cr
                LEFT JOIN (
                    SELECT a1.*
                    FROM assessment_records a1
                    INNER JOIN (
                        SELECT request_number, MAX(timestamp) as max_ts
                        FROM assessment_records
                        GROUP BY request_number
                    ) a2 ON a1.request_number = a2.request_number AND a1.timestamp = a2.max_ts
                ) a ON cr.request_number = a.request_number
                ORDER BY cr.created_at DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        finally:
            if close_after:
                c.close()
