"""Data models and typed structures for persisted alert storage.

Provides dataclasses, status definitions, severity orderings, and serialization
utilities for security alerts.
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
import json
import sqlite3
from typing import Any, Dict, List, Optional, Union

from threat_detection.detection.rules import RuleMatch


class AlertStatus(str, Enum):
    """Lifecycle statuses for security alerts."""

    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


VALID_STATUSES = {s.value for s in AlertStatus}

SEVERITY_ORDER: Dict[str, int] = {
    "INFORMATIONAL": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

VALID_SEVERITIES = set(SEVERITY_ORDER.keys())
VALID_DISPOSITIONS = {"BENIGN", "MODEL_DETECTED", "RULE_DETECTED", "CORROBORATED"}
VALID_PREDICTED_LABELS = {"normal", "attack"}


class AlertStorageError(Exception):
    """Base exception for alert storage operations."""
    pass


class AlertNotFoundError(AlertStorageError):
    """Raised when an alert lookup by ID fails."""
    pass


class InvalidLifecycleTransitionError(AlertStorageError):
    """Raised when an unsupported alert lifecycle transition is attempted."""
    pass


class InvalidFindingError(AlertStorageError):
    """Raised when a detection finding is malformed or invalid."""
    pass


@dataclass
class AlertRecord:
    """Strongly typed representation of a persisted security alert."""

    alert_id: str
    record_fingerprint: str
    detection_timestamp: str
    threat_detected: bool
    disposition: str
    overall_severity: str
    predicted_label: str
    attack_probability: float
    confidence: float
    rule_ids: List[str]
    rule_matches: List[RuleMatch]
    explanation: str
    status: str
    occurrence_count: int
    first_seen_timestamp: str
    last_seen_timestamp: str
    created_at: str
    updated_at: str
    acknowledged_at: Optional[str] = None
    resolved_at: Optional[str] = None
    analyst_notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert record to a serializable dictionary."""
        return {
            "alert_id": self.alert_id,
            "record_fingerprint": self.record_fingerprint,
            "detection_timestamp": self.detection_timestamp,
            "threat_detected": self.threat_detected,
            "disposition": self.disposition,
            "overall_severity": self.overall_severity,
            "predicted_label": self.predicted_label,
            "attack_probability": self.attack_probability,
            "confidence": self.confidence,
            "rule_ids": list(self.rule_ids),
            "rule_matches": [r.to_dict() for r in self.rule_matches],
            "explanation": self.explanation,
            "status": self.status,
            "occurrence_count": self.occurrence_count,
            "first_seen_timestamp": self.first_seen_timestamp,
            "last_seen_timestamp": self.last_seen_timestamp,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "acknowledged_at": self.acknowledged_at,
            "resolved_at": self.resolved_at,
            "analyst_notes": self.analyst_notes,
        }

    @classmethod
    def from_row(cls, row: Union[sqlite3.Row, Dict[str, Any]]) -> "AlertRecord":
        """Reconstruct an AlertRecord from an SQLite row or dictionary."""
        d = dict(row)

        # Deserialize rule_ids JSON array
        rule_ids_raw = d.get("rule_ids_json") or "[]"
        if isinstance(rule_ids_raw, str):
            rule_ids = json.loads(rule_ids_raw)
        else:
            rule_ids = list(rule_ids_raw)

        # Deserialize rule_matches JSON array
        rule_matches_raw = d.get("rule_matches_json") or "[]"
        if isinstance(rule_matches_raw, str):
            matches_data = json.loads(rule_matches_raw)
        else:
            matches_data = list(rule_matches_raw)

        rule_matches = [
            RuleMatch(
                rule_id=m["rule_id"],
                rule_name=m["rule_name"],
                severity=m["severity"],
                description=m["description"],
                matched_fields=dict(m.get("matched_fields", {})),
            )
            for m in matches_data
        ]

        return cls(
            alert_id=str(d["alert_id"]),
            record_fingerprint=str(d["record_fingerprint"]),
            detection_timestamp=str(d["detection_timestamp"]),
            threat_detected=bool(d["threat_detected"]),
            disposition=str(d["disposition"]),
            overall_severity=str(d["overall_severity"]),
            predicted_label=str(d["predicted_label"]),
            attack_probability=float(d["attack_probability"]),
            confidence=float(d["confidence"]),
            rule_ids=[str(rid) for rid in rule_ids],
            rule_matches=rule_matches,
            explanation=str(d["explanation"]),
            status=str(d["status"]),
            occurrence_count=int(d["occurrence_count"]),
            first_seen_timestamp=str(d["first_seen_timestamp"]),
            last_seen_timestamp=str(d["last_seen_timestamp"]),
            created_at=str(d["created_at"]),
            updated_at=str(d["updated_at"]),
            acknowledged_at=str(d["acknowledged_at"]) if d.get("acknowledged_at") else None,
            resolved_at=str(d["resolved_at"]) if d.get("resolved_at") else None,
            analyst_notes=str(d["analyst_notes"]) if d.get("analyst_notes") else None,
        )
