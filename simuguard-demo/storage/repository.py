"""Data Access Repository for SimuGuard AI SQLite Storage."""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional, Tuple
import sqlite3

from storage.database import get_db_connection
from storage.models import (
    ActivityLogRecord,
    AssessmentRecord,
    ChangeRequestRecord,
    KPISummary,
    RemediationRecord,
    WorkflowState,
)

ALL_CHANGE_REQUEST_COLUMNS = [
    "request_number",
    "title",
    "description",
    "justification",
    "submitted_by",
    "submitter_role",
    "change_type",
    "domain",
    "priority",
    "status",
    "created_at",
    "updated_at",
    "category",
    "subcategory",
    "assignment_group",
    "assigned_engineer",
    "business_service",
    "configuration_item",
    "affected_application",
    "infrastructure_platform",
    "target_environment",
    "scenario_name",
    "source_file_path",
    "raw_content",
    "implementation_plan",
    "technical_approach",
    "backout_plan",
    "validation_plan",
    "business_impact",
    "operational_impact",
    "dependencies",
    "additional_notes",
    "planned_start",
    "planned_end",
    "maintenance_window",
    "scheduling_notes",
    "expected_business_impact",
    "expected_technical_impact",
    "expected_service_disruption",
    "risk_context",
    "firewall_details_json",
    "sailpoint_details_json",
]


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

            # Fetch existing columns in change_requests
            cursor = c.cursor()
            cursor.execute("PRAGMA table_info(change_requests);")
            valid_cols = {row["name"] for row in cursor.fetchall()}

            record_dict = record.model_dump()
            cols_to_insert = [col for col in ALL_CHANGE_REQUEST_COLUMNS if col in valid_cols]
            placeholders = ", ".join(["?"] * len(cols_to_insert))
            col_names = ", ".join(cols_to_insert)
            values = [record_dict.get(col) for col in cols_to_insert]

            query = f"INSERT INTO change_requests ({col_names}) VALUES ({placeholders})"
            c.execute(query, values)
            c.commit()

            # Record initial activity log
            action_name = "DRAFT_SAVED" if record.status == WorkflowState.DRAFT.value else "REQUEST_CREATED"
            self.log_activity(
                request_number=record.request_number,
                action=action_name,
                actor=record.submitted_by,
                details=f"Change request created with status '{record.status}' and priority '{record.priority}'",
                conn=c,
            )
            return record
        finally:
            if close_after:
                c.close()

    def update_change_request(
        self, record: ChangeRequestRecord, conn: Optional[sqlite3.Connection] = None
    ) -> ChangeRequestRecord:
        """Update all fields of an existing change request."""
        close_after = conn is None
        c = self._get_conn(conn)
        try:
            now = datetime.now(timezone.utc).isoformat()
            record.updated_at = now

            cursor = c.cursor()
            cursor.execute("PRAGMA table_info(change_requests);")
            valid_cols = {row["name"] for row in cursor.fetchall()}

            record_dict = record.model_dump()
            cols_to_update = [
                col for col in ALL_CHANGE_REQUEST_COLUMNS if col in valid_cols and col != "request_number"
            ]
            set_clause = ", ".join([f"{col} = ?" for col in cols_to_update])
            values = [record_dict.get(col) for col in cols_to_update]
            values.append(record.request_number)

            query = f"UPDATE change_requests SET {set_clause} WHERE request_number = ?"
            c.execute(query, values)
            c.commit()
            return record
        finally:
            if close_after:
                c.close()

    def save_draft(
        self, record: ChangeRequestRecord, conn: Optional[sqlite3.Connection] = None
    ) -> ChangeRequestRecord:
        """Save change request in DRAFT status without creating any assessment."""
        record.status = WorkflowState.DRAFT.value
        existing = self.get_change_request(record.request_number, conn=conn)
        if existing:
            saved = self.update_change_request(record, conn=conn)
            self.log_activity(
                request_number=record.request_number,
                action="DRAFT_SAVED",
                actor=record.submitted_by,
                details=f"Draft updated with title '{record.title}'",
                conn=conn,
            )
            return saved
        else:
            return self.create_change_request(record, conn=conn)

    def submit_change_request(
        self, record: ChangeRequestRecord, conn: Optional[sqlite3.Connection] = None
    ) -> ChangeRequestRecord:
        """Submit change request for assessment (sets status to SUBMITTED)."""
        record.status = WorkflowState.SUBMITTED.value
        existing = self.get_change_request(record.request_number, conn=conn)
        if existing:
            saved = self.update_change_request(record, conn=conn)
            self.log_activity(
                request_number=record.request_number,
                action="REQUEST_SUBMITTED",
                actor=record.submitted_by,
                details=f"Change request submitted for simulation assessment. Priority: {record.priority}",
                conn=conn,
            )
            return saved
        else:
            saved = self.create_change_request(record, conn=conn)
            self.log_activity(
                request_number=record.request_number,
                action="REQUEST_SUBMITTED",
                actor=record.submitted_by,
                details=f"Change request submitted for simulation assessment. Priority: {record.priority}",
                conn=conn,
            )
            return saved

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

    def filter_change_requests(
        self,
        search_query: Optional[str] = None,
        domain: Optional[str] = None,
        priority: Optional[str] = None,
        status: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        sort_field: str = "created_at",
        sort_order: str = "DESC",
        limit: int = 20,
        offset: int = 0,
        conn: Optional[sqlite3.Connection] = None,
    ) -> List[Dict[str, Any]]:
        """Query change requests with comprehensive search, filtering, sorting and pagination."""
        close_after = conn is None
        c = self._get_conn(conn)
        try:
            where_clauses = []
            params: List[Any] = []

            if search_query and search_query.strip():
                sq = f"%{search_query.strip()}%"
                where_clauses.append(
                    "(cr.request_number LIKE ? OR cr.title LIKE ? OR cr.description LIKE ?)"
                )
                params.extend([sq, sq, sq])

            if domain and domain.strip() and domain.upper() != "ALL":
                where_clauses.append("cr.domain = ?")
                params.append(domain.strip())

            if priority and priority.strip() and priority.upper() != "ALL":
                where_clauses.append("cr.priority = ?")
                params.append(priority.strip())

            if status and status.strip() and status.upper() != "ALL":
                where_clauses.append("cr.status = ?")
                params.append(status.strip())

            if start_date and start_date.strip():
                where_clauses.append("cr.created_at >= ?")
                params.append(start_date.strip())

            if end_date and end_date.strip():
                where_clauses.append("cr.created_at <= ?")
                params.append(end_date.strip())

            where_str = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

            # Validate sort field & direction to prevent SQL injection
            allowed_sort_fields = {"created_at", "request_number", "priority", "status", "domain", "title"}
            safe_sort_field = sort_field if sort_field in allowed_sort_fields else "created_at"
            safe_sort_order = "ASC" if sort_order.upper() == "ASC" else "DESC"

            query = f"""
            SELECT
                cr.*,
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
            {where_str}
            ORDER BY cr.{safe_sort_field} {safe_sort_order}
            LIMIT ? OFFSET ?
            """
            params.extend([limit, offset])

            cursor = c.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        finally:
            if close_after:
                c.close()

    def count_filtered_change_requests(
        self,
        search_query: Optional[str] = None,
        domain: Optional[str] = None,
        priority: Optional[str] = None,
        status: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        conn: Optional[sqlite3.Connection] = None,
    ) -> int:
        """Count total matching records for pagination calculation."""
        close_after = conn is None
        c = self._get_conn(conn)
        try:
            where_clauses = []
            params: List[Any] = []

            if search_query and search_query.strip():
                sq = f"%{search_query.strip()}%"
                where_clauses.append(
                    "(request_number LIKE ? OR title LIKE ? OR description LIKE ?)"
                )
                params.extend([sq, sq, sq])

            if domain and domain.strip() and domain.upper() != "ALL":
                where_clauses.append("domain = ?")
                params.append(domain.strip())

            if priority and priority.strip() and priority.upper() != "ALL":
                where_clauses.append("priority = ?")
                params.append(priority.strip())

            if status and status.strip() and status.upper() != "ALL":
                where_clauses.append("status = ?")
                params.append(status.strip())

            if start_date and start_date.strip():
                where_clauses.append("created_at >= ?")
                params.append(start_date.strip())

            if end_date and end_date.strip():
                where_clauses.append("created_at <= ?")
                params.append(end_date.strip())

            where_str = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
            query = f"SELECT COUNT(*) as total FROM change_requests {where_str}"

            cursor = c.cursor()
            cursor.execute(query, params)
            return cursor.fetchone()["total"]
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
