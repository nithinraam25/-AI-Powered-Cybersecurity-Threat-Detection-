"""SQLite repository implementation for persistent threat alert management.

Provides schema creation, deduplication-aware alert persistence, query filtering,
and lifecycle state machine management for threat detection findings.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Dict, Generator, List, Optional, Set, Union
import uuid

from threat_detection.config import config
from threat_detection.detection.engine import DetectionFinding
from threat_detection.detection.rules import RuleMatch
from threat_detection.storage.models import (
    SEVERITY_ORDER,
    VALID_DISPOSITIONS,
    VALID_PREDICTED_LABELS,
    VALID_SEVERITIES,
    VALID_STATUSES,
    AlertNotFoundError,
    AlertRecord,
    AlertStatus,
    AlertStorageError,
    InvalidFindingError,
    InvalidLifecycleTransitionError,
)

FINGERPRINT_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")


class AlertRepository:
    """Thread-safe SQLite repository for storing and managing security alerts.

    Features:
    - Atomicity & Isolation: Explicit transaction boundaries with automatic rollbacks.
    - Partial Unique Index: Guarantees at most one active (NEW or ACKNOWLEDGED) alert
      per record_fingerprint, while allowing historically resolved alerts to remain immutable.
    - Idempotent Lifecycle: Validated NEW -> ACKNOWLEDGED -> RESOLVED transitions.
    - In-Memory & File-Backed: Supports both isolated :memory: tests and disk-backed files.
    """

    def __init__(
        self,
        db_path: Optional[Union[str, Path]] = None,
        timeout: float = 30.0,
    ) -> None:
        """Initialize repository.

        Args:
            db_path: Path to SQLite database file or ':memory:'. Defaults to config.DATABASE_PATH.
            timeout: SQLite busy timeout in seconds (default: 30.0).
        """
        if db_path is None:
            self.db_path: Union[str, Path] = config.DATABASE_PATH
        else:
            self.db_path = db_path

        self.timeout = timeout
        self.is_memory = str(self.db_path) == ":memory:"

        # For in-memory databases, maintain a persistent connection so tables persist
        # across multiple repository calls on the same instance.
        self._mem_conn: Optional[sqlite3.Connection] = None
        if self.is_memory:
            self._mem_conn = sqlite3.connect(
                ":memory:",
                timeout=self.timeout,
                check_same_thread=False,
            )
            self._mem_conn.row_factory = sqlite3.Row
        else:
            target_path = Path(self.db_path)
            target_path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Yield an SQLite connection with active transaction control."""
        if self.is_memory:
            assert self._mem_conn is not None
            try:
                yield self._mem_conn
            except Exception:
                self._mem_conn.rollback()
                raise
        else:
            conn = sqlite3.connect(
                str(self.db_path),
                timeout=self.timeout,
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            try:
                yield conn
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def initialize_schema(self) -> None:
        """Idempotently initialize the alerts table and supporting indexes."""
        ddl = """
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            record_fingerprint TEXT NOT NULL CHECK (length(record_fingerprint) == 64),
            detection_timestamp TEXT NOT NULL,
            threat_detected INTEGER NOT NULL CHECK (threat_detected IN (0, 1)),
            disposition TEXT NOT NULL CHECK (disposition IN ('BENIGN', 'MODEL_DETECTED', 'RULE_DETECTED', 'CORROBORATED')),
            overall_severity TEXT NOT NULL CHECK (overall_severity IN ('INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
            predicted_label TEXT NOT NULL CHECK (predicted_label IN ('normal', 'attack')),
            attack_probability REAL NOT NULL CHECK (attack_probability >= 0.0 AND attack_probability <= 1.0),
            confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
            rule_ids_json TEXT NOT NULL DEFAULT '[]',
            rule_matches_json TEXT NOT NULL DEFAULT '[]',
            explanation TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'NEW' CHECK (status IN ('NEW', 'ACKNOWLEDGED', 'RESOLVED')),
            occurrence_count INTEGER NOT NULL DEFAULT 1 CHECK (occurrence_count >= 1),
            first_seen_timestamp TEXT NOT NULL,
            last_seen_timestamp TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            acknowledged_at TEXT NULL,
            resolved_at TEXT NULL,
            analyst_notes TEXT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint ON alerts (record_fingerprint);
        CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);
        CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (overall_severity);
        CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (detection_timestamp DESC);

        -- Partial unique index: prevents duplicate active (NEW or ACKNOWLEDGED) alerts for the same fingerprint
        CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_active_fingerprint ON alerts (record_fingerprint)
        WHERE status IN ('NEW', 'ACKNOWLEDGED');
        """
        with self._get_connection() as conn:
            conn.executescript(ddl)
            conn.commit()

    def _validate_finding(self, finding: DetectionFinding) -> None:
        """Validate input finding fields prior to opening database transactions."""
        if (
            not isinstance(finding.record_fingerprint, str)
            or not FINGERPRINT_REGEX.fullmatch(finding.record_fingerprint)
        ):
            raise InvalidFindingError(
                f"Invalid record_fingerprint '{finding.record_fingerprint}'. "
                "Must be a 64-character hexadecimal SHA-256 digest."
            )

        if finding.disposition not in VALID_DISPOSITIONS:
            raise InvalidFindingError(
                f"Invalid disposition '{finding.disposition}'. Allowed: {VALID_DISPOSITIONS}"
            )

        if finding.overall_severity not in VALID_SEVERITIES:
            raise InvalidFindingError(
                f"Invalid overall_severity '{finding.overall_severity}'. Allowed: {VALID_SEVERITIES}"
            )

        if finding.model_decision.predicted_label not in VALID_PREDICTED_LABELS:
            raise InvalidFindingError(
                f"Invalid predicted_label '{finding.model_decision.predicted_label}'."
            )

        prob = finding.model_decision.attack_probability
        if not (0.0 <= prob <= 1.0):
            raise InvalidFindingError(f"attack_probability {prob} outside [0.0, 1.0].")

        conf = finding.model_decision.confidence
        if not (0.0 <= conf <= 1.0):
            raise InvalidFindingError(f"confidence {conf} outside [0.0, 1.0].")

    def _derive_merged_severity(
        self,
        current_severity: str,
        finding_severity: str,
        model_is_attack: bool,
        has_rules: bool,
    ) -> str:
        """Derive updated overall severity when merging findings without downgrading.

        Rules:
        - Recomputes candidate severity based on combined model and rule evidence:
          HIGH if model_is_attack and has_rules; MEDIUM if either; INFORMATIONAL if neither.
        - Takes max rank among current_severity, finding_severity, and candidate severity.
        - Guarantees severity is never accidentally downgraded.
        """
        if model_is_attack and has_rules:
            candidate = "HIGH"
        elif model_is_attack or has_rules:
            candidate = "MEDIUM"
        else:
            candidate = "INFORMATIONAL"

        severities = [current_severity, finding_severity, candidate]
        return max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0))

    def _save_finding_tx(
        self,
        conn: sqlite3.Connection,
        finding: DetectionFinding,
        deduplicate: bool = True,
    ) -> AlertRecord:
        """Internal worker persisting or merging a finding within an open transaction."""
        self._validate_finding(finding)
        now_utc = datetime.now(timezone.utc).isoformat()

        if deduplicate:
            # Query for active alert with matching fingerprint
            cursor = conn.execute(
                """
                SELECT * FROM alerts
                WHERE record_fingerprint = ? AND status IN ('NEW', 'ACKNOWLEDGED')
                LIMIT 1
                """,
                (finding.record_fingerprint,),
            )
            row = cursor.fetchone()

            if row is not None:
                current = AlertRecord.from_row(row)

                # Merge rule evidence by rule_id without duplicates
                existing_rules_by_id = {r.rule_id: r for r in current.rule_matches}
                for r in finding.rule_matches:
                    if r.rule_id not in existing_rules_by_id:
                        existing_rules_by_id[r.rule_id] = r

                merged_rule_matches = list(existing_rules_by_id.values())
                merged_rule_ids = sorted(list(existing_rules_by_id.keys()))

                # Derive merged severity
                model_is_attack = finding.model_decision.predicted_label == "attack"
                has_rules = len(merged_rule_matches) > 0
                merged_severity = self._derive_merged_severity(
                    current_severity=current.overall_severity,
                    finding_severity=finding.overall_severity,
                    model_is_attack=model_is_attack,
                    has_rules=has_rules,
                )

                # Update latest observation telemetry
                new_occurrence_count = current.occurrence_count + 1
                detection_ts = finding.timestamp
                last_seen_ts = max(current.last_seen_timestamp, finding.timestamp)

                rule_ids_json = json.dumps(merged_rule_ids)
                rule_matches_json = json.dumps([r.to_dict() for r in merged_rule_matches])

                conn.execute(
                    """
                    UPDATE alerts SET
                        occurrence_count = ?,
                        last_seen_timestamp = ?,
                        detection_timestamp = ?,
                        updated_at = ?,
                        threat_detected = ?,
                        disposition = ?,
                        overall_severity = ?,
                        predicted_label = ?,
                        attack_probability = ?,
                        confidence = ?,
                        rule_ids_json = ?,
                        rule_matches_json = ?,
                        explanation = ?
                    WHERE alert_id = ?
                    """,
                    (
                        new_occurrence_count,
                        last_seen_ts,
                        detection_ts,
                        now_utc,
                        int(finding.threat_detected or current.threat_detected),
                        finding.disposition,
                        merged_severity,
                        finding.model_decision.predicted_label,
                        finding.model_decision.attack_probability,
                        finding.model_decision.confidence,
                        rule_ids_json,
                        rule_matches_json,
                        finding.explanation,
                        current.alert_id,
                    ),
                )

                return AlertRecord(
                    alert_id=current.alert_id,
                    record_fingerprint=current.record_fingerprint,
                    detection_timestamp=detection_ts,
                    threat_detected=bool(finding.threat_detected or current.threat_detected),
                    disposition=finding.disposition,
                    overall_severity=merged_severity,
                    predicted_label=finding.model_decision.predicted_label,
                    attack_probability=finding.model_decision.attack_probability,
                    confidence=finding.model_decision.confidence,
                    rule_ids=merged_rule_ids,
                    rule_matches=merged_rule_matches,
                    explanation=finding.explanation,
                    status=current.status,
                    occurrence_count=new_occurrence_count,
                    first_seen_timestamp=current.first_seen_timestamp,
                    last_seen_timestamp=last_seen_ts,
                    created_at=current.created_at,
                    updated_at=now_utc,
                    acknowledged_at=current.acknowledged_at,
                    resolved_at=current.resolved_at,
                    analyst_notes=current.analyst_notes,
                )

        # Insert new alert (either deduplicate=False or no active duplicate found)
        new_alert_id = str(uuid.uuid4())
        rule_ids = sorted(list({r.rule_id for r in finding.rule_matches}))
        rule_ids_json = json.dumps(rule_ids)
        rule_matches_json = json.dumps([r.to_dict() for r in finding.rule_matches])

        conn.execute(
            """
            INSERT INTO alerts (
                alert_id,
                record_fingerprint,
                detection_timestamp,
                threat_detected,
                disposition,
                overall_severity,
                predicted_label,
                attack_probability,
                confidence,
                rule_ids_json,
                rule_matches_json,
                explanation,
                status,
                occurrence_count,
                first_seen_timestamp,
                last_seen_timestamp,
                created_at,
                updated_at,
                acknowledged_at,
                resolved_at,
                analyst_notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)
            """,
            (
                new_alert_id,
                finding.record_fingerprint,
                finding.timestamp,
                int(finding.threat_detected),
                finding.disposition,
                finding.overall_severity,
                finding.model_decision.predicted_label,
                finding.model_decision.attack_probability,
                finding.model_decision.confidence,
                rule_ids_json,
                rule_matches_json,
                finding.explanation,
                AlertStatus.NEW.value,
                1,
                finding.timestamp,
                finding.timestamp,
                now_utc,
                now_utc,
            ),
        )

        return AlertRecord(
            alert_id=new_alert_id,
            record_fingerprint=finding.record_fingerprint,
            detection_timestamp=finding.timestamp,
            threat_detected=finding.threat_detected,
            disposition=finding.disposition,
            overall_severity=finding.overall_severity,
            predicted_label=finding.model_decision.predicted_label,
            attack_probability=finding.model_decision.attack_probability,
            confidence=finding.model_decision.confidence,
            rule_ids=rule_ids,
            rule_matches=list(finding.rule_matches),
            explanation=finding.explanation,
            status=AlertStatus.NEW.value,
            occurrence_count=1,
            first_seen_timestamp=finding.timestamp,
            last_seen_timestamp=finding.timestamp,
            created_at=now_utc,
            updated_at=now_utc,
            acknowledged_at=None,
            resolved_at=None,
            analyst_notes=None,
        )

    def save_finding(
        self,
        finding: DetectionFinding,
        deduplicate: bool = True,
    ) -> AlertRecord:
        """Persist a single detection finding with optional active deduplication.

        Args:
            finding: Validated DetectionFinding instance.
            deduplicate: If True (default), merges into an existing active alert
                with the same fingerprint.

        Returns:
            Saved or merged AlertRecord instance.

        Raises:
            InvalidFindingError: If finding fails validation.
        """
        with self._get_connection() as conn:
            with conn:
                record = self._save_finding_tx(conn, finding, deduplicate=deduplicate)
            return record

    def save_findings_batch(
        self,
        findings: List[DetectionFinding],
        deduplicate: bool = True,
    ) -> List[AlertRecord]:
        """Atomically persist a batch of detection findings in a single transaction.

        Args:
            findings: List of DetectionFinding instances.
            deduplicate: Whether to merge active duplicates.

        Returns:
            List of AlertRecord instances corresponding to the batch.

        Raises:
            InvalidFindingError: If any finding is invalid (rolls back entire batch).
        """
        results: List[AlertRecord] = []
        with self._get_connection() as conn:
            with conn:
                for f in findings:
                    record = self._save_finding_tx(conn, f, deduplicate=deduplicate)
                    results.append(record)
        return results

    def get_alert_by_id(self, alert_id: str) -> Optional[AlertRecord]:
        """Retrieve an alert by its primary key UUID.

        Args:
            alert_id: Alert UUID string.

        Returns:
            AlertRecord if found, None otherwise.
        """
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (str(alert_id),))
            row = cursor.fetchone()
            if row is None:
                return None
            return AlertRecord.from_row(row)

    def get_active_alert_by_fingerprint(self, fingerprint: str) -> Optional[AlertRecord]:
        """Retrieve active (NEW or ACKNOWLEDGED) alert by fingerprint.

        Args:
            fingerprint: 64-char hexadecimal SHA-256 fingerprint.

        Returns:
            AlertRecord if active alert exists, None otherwise.

        Raises:
            ValueError: If fingerprint is malformed or not a 64-char hex string.
        """
        if (
            not isinstance(fingerprint, str)
            or not FINGERPRINT_REGEX.fullmatch(fingerprint)
        ):
            raise ValueError(
                f"Invalid record_fingerprint '{fingerprint}'. "
                "Must be a 64-character hexadecimal SHA-256 digest."
            )

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM alerts
                WHERE record_fingerprint = ? AND status IN ('NEW', 'ACKNOWLEDGED')
                LIMIT 1
                """,
                (fingerprint,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return AlertRecord.from_row(row)

    def list_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        disposition: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AlertRecord]:
        """Query and paginate alerts with multi-column filtering.

        Args:
            status: Optional status filter ('NEW', 'ACKNOWLEDGED', 'RESOLVED').
            severity: Optional overall severity filter.
            disposition: Optional disposition filter.
            limit: Maximum records to return (must be >= 0).
            offset: Record offset for pagination (must be >= 0).

        Returns:
            List of matching AlertRecord objects ordered by detection_timestamp DESC.
        """
        if limit < 0 or offset < 0:
            raise ValueError(f"Limit ({limit}) and offset ({offset}) must be non-negative integers.")

        query_parts = ["SELECT * FROM alerts WHERE 1=1"]
        params: List[Any] = []

        if status is not None:
            if status not in VALID_STATUSES:
                raise ValueError(f"Invalid status filter '{status}'. Allowed: {VALID_STATUSES}")
            query_parts.append("AND status = ?")
            params.append(status)

        if severity is not None:
            if severity not in VALID_SEVERITIES:
                raise ValueError(f"Invalid severity filter '{severity}'. Allowed: {VALID_SEVERITIES}")
            query_parts.append("AND overall_severity = ?")
            params.append(severity)

        if disposition is not None:
            if disposition not in VALID_DISPOSITIONS:
                raise ValueError(f"Invalid disposition filter '{disposition}'. Allowed: {VALID_DISPOSITIONS}")
            query_parts.append("AND disposition = ?")
            params.append(disposition)

        query_parts.append("ORDER BY detection_timestamp DESC, created_at DESC")
        query_parts.append("LIMIT ? OFFSET ?")
        params.extend([limit, offset])

        query = " ".join(query_parts)
        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()
            return [AlertRecord.from_row(r) for r in rows]

    def acknowledge_alert(
        self,
        alert_id: str,
        analyst_notes: Optional[str] = None,
    ) -> AlertRecord:
        """Transition an alert from NEW to ACKNOWLEDGED (idempotent on ACKNOWLEDGED).

        Args:
            alert_id: Target alert UUID.
            analyst_notes: Optional notes to attach or update.

        Returns:
            Updated AlertRecord.

        Raises:
            AlertNotFoundError: If alert does not exist.
            InvalidLifecycleTransitionError: If alert is currently RESOLVED.
        """
        with self._get_connection() as conn:
            with conn:
                cursor = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (str(alert_id),))
                row = cursor.fetchone()
                if row is None:
                    raise AlertNotFoundError(f"Alert with ID '{alert_id}' not found.")

                current = AlertRecord.from_row(row)
                now_utc = datetime.now(timezone.utc).isoformat()

                if current.status == AlertStatus.RESOLVED.value:
                    raise InvalidLifecycleTransitionError(
                        f"Cannot acknowledge alert '{alert_id}' because it is already in 'RESOLVED' status."
                    )

                if current.status == AlertStatus.ACKNOWLEDGED.value:
                    # Idempotent: preserve original acknowledged_at
                    notes = analyst_notes if analyst_notes is not None else current.analyst_notes
                    conn.execute(
                        "UPDATE alerts SET updated_at = ?, analyst_notes = ? WHERE alert_id = ?",
                        (now_utc, notes, alert_id),
                    )
                    return AlertRecord(
                        alert_id=current.alert_id,
                        record_fingerprint=current.record_fingerprint,
                        detection_timestamp=current.detection_timestamp,
                        threat_detected=current.threat_detected,
                        disposition=current.disposition,
                        overall_severity=current.overall_severity,
                        predicted_label=current.predicted_label,
                        attack_probability=current.attack_probability,
                        confidence=current.confidence,
                        rule_ids=current.rule_ids,
                        rule_matches=current.rule_matches,
                        explanation=current.explanation,
                        status=current.status,
                        occurrence_count=current.occurrence_count,
                        first_seen_timestamp=current.first_seen_timestamp,
                        last_seen_timestamp=current.last_seen_timestamp,
                        created_at=current.created_at,
                        updated_at=now_utc,
                        acknowledged_at=current.acknowledged_at,
                        resolved_at=current.resolved_at,
                        analyst_notes=notes,
                    )

                # Transition from NEW -> ACKNOWLEDGED
                notes = analyst_notes if analyst_notes is not None else current.analyst_notes
                conn.execute(
                    """
                    UPDATE alerts SET
                        status = ?,
                        acknowledged_at = ?,
                        updated_at = ?,
                        analyst_notes = ?
                    WHERE alert_id = ?
                    """,
                    (AlertStatus.ACKNOWLEDGED.value, now_utc, now_utc, notes, alert_id),
                )

                return AlertRecord(
                    alert_id=current.alert_id,
                    record_fingerprint=current.record_fingerprint,
                    detection_timestamp=current.detection_timestamp,
                    threat_detected=current.threat_detected,
                    disposition=current.disposition,
                    overall_severity=current.overall_severity,
                    predicted_label=current.predicted_label,
                    attack_probability=current.attack_probability,
                    confidence=current.confidence,
                    rule_ids=current.rule_ids,
                    rule_matches=current.rule_matches,
                    explanation=current.explanation,
                    status=AlertStatus.ACKNOWLEDGED.value,
                    occurrence_count=current.occurrence_count,
                    first_seen_timestamp=current.first_seen_timestamp,
                    last_seen_timestamp=current.last_seen_timestamp,
                    created_at=current.created_at,
                    updated_at=now_utc,
                    acknowledged_at=now_utc,
                    resolved_at=None,
                    analyst_notes=notes,
                )

    def resolve_alert(
        self,
        alert_id: str,
        analyst_notes: Optional[str] = None,
    ) -> AlertRecord:
        """Transition an alert from ACKNOWLEDGED to RESOLVED (idempotent on RESOLVED).

        Args:
            alert_id: Target alert UUID.
            analyst_notes: Optional notes to attach.

        Returns:
            Updated AlertRecord.

        Raises:
            AlertNotFoundError: If alert does not exist.
            InvalidLifecycleTransitionError: If alert is currently in NEW status (must be acknowledged first).
        """
        with self._get_connection() as conn:
            with conn:
                cursor = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (str(alert_id),))
                row = cursor.fetchone()
                if row is None:
                    raise AlertNotFoundError(f"Alert with ID '{alert_id}' not found.")

                current = AlertRecord.from_row(row)
                now_utc = datetime.now(timezone.utc).isoformat()

                if current.status == AlertStatus.NEW.value:
                    raise InvalidLifecycleTransitionError(
                        f"Cannot resolve alert '{alert_id}' directly from 'NEW' status. "
                        "Alert must be in 'ACKNOWLEDGED' status before resolution."
                    )

                if current.status == AlertStatus.RESOLVED.value:
                    # Idempotent: preserve original resolved_at
                    notes = analyst_notes if analyst_notes is not None else current.analyst_notes
                    conn.execute(
                        "UPDATE alerts SET updated_at = ?, analyst_notes = ? WHERE alert_id = ?",
                        (now_utc, notes, alert_id),
                    )
                    return AlertRecord(
                        alert_id=current.alert_id,
                        record_fingerprint=current.record_fingerprint,
                        detection_timestamp=current.detection_timestamp,
                        threat_detected=current.threat_detected,
                        disposition=current.disposition,
                        overall_severity=current.overall_severity,
                        predicted_label=current.predicted_label,
                        attack_probability=current.attack_probability,
                        confidence=current.confidence,
                        rule_ids=current.rule_ids,
                        rule_matches=current.rule_matches,
                        explanation=current.explanation,
                        status=current.status,
                        occurrence_count=current.occurrence_count,
                        first_seen_timestamp=current.first_seen_timestamp,
                        last_seen_timestamp=current.last_seen_timestamp,
                        created_at=current.created_at,
                        updated_at=now_utc,
                        acknowledged_at=current.acknowledged_at,
                        resolved_at=current.resolved_at,
                        analyst_notes=notes,
                    )

                # Transition from ACKNOWLEDGED -> RESOLVED
                notes = analyst_notes if analyst_notes is not None else current.analyst_notes
                conn.execute(
                    """
                    UPDATE alerts SET
                        status = ?,
                        resolved_at = ?,
                        updated_at = ?,
                        analyst_notes = ?
                    WHERE alert_id = ?
                    """,
                    (AlertStatus.RESOLVED.value, now_utc, now_utc, notes, alert_id),
                )

                return AlertRecord(
                    alert_id=current.alert_id,
                    record_fingerprint=current.record_fingerprint,
                    detection_timestamp=current.detection_timestamp,
                    threat_detected=current.threat_detected,
                    disposition=current.disposition,
                    overall_severity=current.overall_severity,
                    predicted_label=current.predicted_label,
                    attack_probability=current.attack_probability,
                    confidence=current.confidence,
                    rule_ids=current.rule_ids,
                    rule_matches=current.rule_matches,
                    explanation=current.explanation,
                    status=AlertStatus.RESOLVED.value,
                    occurrence_count=current.occurrence_count,
                    first_seen_timestamp=current.first_seen_timestamp,
                    last_seen_timestamp=current.last_seen_timestamp,
                    created_at=current.created_at,
                    updated_at=now_utc,
                    acknowledged_at=current.acknowledged_at,
                    resolved_at=now_utc,
                    analyst_notes=notes,
                )

    def get_summary_counts(self) -> Dict[str, Dict[str, int]]:
        """Return aggregated alert counts grouped by status and by overall severity."""
        with self._get_connection() as conn:
            # Counts by status
            status_counts = {s.value: 0 for s in AlertStatus}
            cursor_status = conn.execute(
                "SELECT status, COUNT(*) as cnt FROM alerts GROUP BY status"
            )
            for row in cursor_status.fetchall():
                status_counts[row["status"]] = row["cnt"]

            # Counts by severity
            severity_counts = {sev: 0 for sev in SEVERITY_ORDER.keys()}
            cursor_sev = conn.execute(
                "SELECT overall_severity, COUNT(*) as cnt FROM alerts GROUP BY overall_severity"
            )
            for row in cursor_sev.fetchall():
                severity_counts[row["overall_severity"]] = row["cnt"]

            return {
                "by_status": status_counts,
                "by_severity": severity_counts,
            }
