"""Automated test suite for SQLite alert storage repository and lifecycle management.

All tests utilize isolated in-memory or temporary SQLite databases.
Zero production databases or external network resources are touched.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
import pytest

from threat_detection.detection.engine import (
    DetectionFinding,
    ModelDecision,
)
from threat_detection.detection.rules import RuleMatch
from threat_detection.storage import (
    AlertNotFoundError,
    AlertRecord,
    AlertRepository,
    AlertStatus,
    InvalidFindingError,
    InvalidLifecycleTransitionError,
)


def _make_dummy_finding(
    fingerprint: str = "a" * 64,
    threat_detected: bool = True,
    disposition: str = "MODEL_DETECTED",
    overall_severity: str = "MEDIUM",
    pred_label: str = "attack",
    attack_prob: float = 0.85,
    confidence: float = 0.85,
    rule_matches: Optional[List[RuleMatch]] = None,
    explanation: str = "Test finding explanation.",
    timestamp: Optional[str] = None,
    record_index: Optional[int] = 0,
) -> DetectionFinding:
    """Construct a valid synthetic DetectionFinding for storage testing."""
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    return DetectionFinding(
        record_index=record_index,
        timestamp=ts,
        record_fingerprint=fingerprint,
        threat_detected=threat_detected,
        disposition=disposition,
        overall_severity=overall_severity,
        model_decision=ModelDecision(
            predicted_label=pred_label,
            attack_probability=attack_prob,
            confidence=confidence,
        ),
        rule_matches=rule_matches or [],
        explanation=explanation,
    )


@pytest.fixture
def memory_repo() -> AlertRepository:
    """Fixture providing an initialized in-memory AlertRepository."""
    repo = AlertRepository(db_path=":memory:")
    repo.initialize_schema()
    return repo


@pytest.fixture
def file_repo(tmp_path: Path) -> AlertRepository:
    """Fixture providing an initialized file-backed AlertRepository in tmp_path."""
    db_file = tmp_path / "test_alerts.db"
    repo = AlertRepository(db_path=db_file)
    repo.initialize_schema()
    return repo


# -------------------------------------------------------------------------
# Schema Initialization & Idempotency
# -------------------------------------------------------------------------

def test_initialize_schema_idempotency(file_repo):
    """Verify initialize_schema is idempotent and does not drop existing data."""
    finding = _make_dummy_finding()
    saved = file_repo.save_finding(finding)

    # Call initialize_schema again
    file_repo.initialize_schema()

    # Alert should still exist intact
    retrieved = file_repo.get_alert_by_id(saved.alert_id)
    assert retrieved is not None
    assert retrieved.alert_id == saved.alert_id


# -------------------------------------------------------------------------
# CRUD Round-Trip & JSON Serialization
# -------------------------------------------------------------------------

def test_save_and_retrieve_finding(memory_repo):
    """Verify persisting a finding and retrieving it by alert_id matches all fields."""
    rule_match = RuleMatch(
        rule_id="RULE-DOS-SYN-001",
        rule_name="SYN Flood",
        severity="MEDIUM",
        description="SYN burst detected",
        matched_fields={"count": 120, "serror_rate": 0.85, "flag": "S0"},
    )
    finding = _make_dummy_finding(
        fingerprint="b" * 64,
        threat_detected=True,
        disposition="CORROBORATED",
        overall_severity="HIGH",
        rule_matches=[rule_match],
        explanation="Corroborated SYN flood attack.",
    )

    saved = memory_repo.save_finding(finding)
    assert isinstance(saved, AlertRecord)
    assert saved.status == AlertStatus.NEW.value
    assert saved.occurrence_count == 1
    assert saved.overall_severity == "HIGH"
    assert saved.rule_ids == ["RULE-DOS-SYN-001"]

    retrieved = memory_repo.get_alert_by_id(saved.alert_id)
    assert retrieved is not None
    assert retrieved.alert_id == saved.alert_id
    assert retrieved.record_fingerprint == "b" * 64
    assert retrieved.threat_detected is True
    assert retrieved.disposition == "CORROBORATED"
    assert retrieved.overall_severity == "HIGH"
    assert retrieved.attack_probability == pytest.approx(0.85)
    assert retrieved.confidence == pytest.approx(0.85)
    assert retrieved.rule_ids == ["RULE-DOS-SYN-001"]
    assert retrieved.explanation == "Corroborated SYN flood attack."


def test_json_roundtrip_rule_matches_and_matched_fields(memory_repo):
    """Verify complex nested RuleMatch objects and matched_fields roundtrip cleanly."""
    rule1 = RuleMatch(
        rule_id="RULE-LAND-001",
        rule_name="LAND Attack",
        severity="HIGH",
        description="Land anomaly",
        matched_fields={"land": 1},
    )
    rule2 = RuleMatch(
        rule_id="RULE-DOS-REJ-001",
        rule_name="Rejection Burst",
        severity="MEDIUM",
        description="Rejection rate burst",
        matched_fields={"count": 75, "rerror_rate": 0.92, "flag": "REJ"},
    )

    finding = _make_dummy_finding(rule_matches=[rule1, rule2])
    saved = memory_repo.save_finding(finding)
    retrieved = memory_repo.get_alert_by_id(saved.alert_id)

    assert retrieved is not None
    assert len(retrieved.rule_matches) == 2
    r_map = {r.rule_id: r for r in retrieved.rule_matches}
    assert "RULE-LAND-001" in r_map
    assert "RULE-DOS-REJ-001" in r_map
    assert r_map["RULE-LAND-001"].matched_fields == {"land": 1}
    assert r_map["RULE-DOS-REJ-001"].matched_fields == {
        "count": 75,
        "rerror_rate": 0.92,
        "flag": "REJ",
    }


# -------------------------------------------------------------------------
# Query Filtering, Pagination, and Summary Counts
# -------------------------------------------------------------------------

def test_list_alerts_filters_and_pagination(memory_repo):
    """Verify filtering by status, severity, disposition, limit, and offset."""
    f1 = _make_dummy_finding(fingerprint="1" * 64, overall_severity="HIGH", disposition="CORROBORATED")
    f2 = _make_dummy_finding(fingerprint="2" * 64, overall_severity="MEDIUM", disposition="MODEL_DETECTED")
    f3 = _make_dummy_finding(fingerprint="3" * 64, overall_severity="LOW", disposition="BENIGN")

    a1 = memory_repo.save_finding(f1)
    a2 = memory_repo.save_finding(f2)
    a3 = memory_repo.save_finding(f3)

    # Acknowledge a1
    memory_repo.acknowledge_alert(a1.alert_id)

    # Filter by status
    new_alerts = memory_repo.list_alerts(status="NEW")
    assert len(new_alerts) == 2
    assert {a.alert_id for a in new_alerts} == {a2.alert_id, a3.alert_id}

    ack_alerts = memory_repo.list_alerts(status="ACKNOWLEDGED")
    assert len(ack_alerts) == 1
    assert ack_alerts[0].alert_id == a1.alert_id

    # Filter by severity
    high_alerts = memory_repo.list_alerts(severity="HIGH")
    assert len(high_alerts) == 1
    assert high_alerts[0].alert_id == a1.alert_id

    # Filter by disposition
    model_alerts = memory_repo.list_alerts(disposition="MODEL_DETECTED")
    assert len(model_alerts) == 1
    assert model_alerts[0].alert_id == a2.alert_id

    # Limit and offset pagination
    all_p1 = memory_repo.list_alerts(limit=2, offset=0)
    all_p2 = memory_repo.list_alerts(limit=2, offset=2)
    assert len(all_p1) == 2
    assert len(all_p2) == 1
    assert all_p1[0].alert_id != all_p2[0].alert_id


def test_get_summary_counts(memory_repo):
    """Verify aggregated summary counts by status and overall severity."""
    f1 = _make_dummy_finding(fingerprint="1" * 64, overall_severity="HIGH")
    f2 = _make_dummy_finding(fingerprint="2" * 64, overall_severity="MEDIUM")
    f3 = _make_dummy_finding(fingerprint="3" * 64, overall_severity="HIGH")

    a1 = memory_repo.save_finding(f1)
    a2 = memory_repo.save_finding(f2)
    a3 = memory_repo.save_finding(f3)

    memory_repo.acknowledge_alert(a1.alert_id)
    memory_repo.acknowledge_alert(a2.alert_id)
    memory_repo.resolve_alert(a2.alert_id)

    counts = memory_repo.get_summary_counts()
    assert counts["by_status"]["NEW"] == 1
    assert counts["by_status"]["ACKNOWLEDGED"] == 1
    assert counts["by_status"]["RESOLVED"] == 1
    assert counts["by_severity"]["HIGH"] == 2
    assert counts["by_severity"]["MEDIUM"] == 1
    assert counts["by_severity"]["LOW"] == 0


# -------------------------------------------------------------------------
# Lifecycle State Transitions
# -------------------------------------------------------------------------

def test_lifecycle_transitions_and_timestamps(memory_repo):
    """Verify NEW -> ACKNOWLEDGED -> RESOLVED transitions set timestamps appropriately."""
    finding = _make_dummy_finding()
    alert = memory_repo.save_finding(finding)

    assert alert.status == AlertStatus.NEW.value
    assert alert.acknowledged_at is None
    assert alert.resolved_at is None
    assert alert.analyst_notes is None

    # 1. Acknowledge
    ack = memory_repo.acknowledge_alert(alert.alert_id, analyst_notes="Investigating traffic burst.")
    assert ack.status == AlertStatus.ACKNOWLEDGED.value
    assert ack.acknowledged_at is not None
    assert ack.resolved_at is None
    assert ack.analyst_notes == "Investigating traffic burst."

    # 2. Resolve
    res = memory_repo.resolve_alert(alert.alert_id, analyst_notes="False alarm; verified benign load testing.")
    assert res.status == AlertStatus.RESOLVED.value
    assert res.acknowledged_at == ack.acknowledged_at
    assert res.resolved_at is not None
    assert res.analyst_notes == "False alarm; verified benign load testing."


def test_idempotent_repeated_transitions_and_note_preservation(memory_repo):
    """Verify repeated transitions are idempotent, preserve timestamps, and preserve prior notes."""
    finding = _make_dummy_finding()
    alert = memory_repo.save_finding(finding)

    # Initial acknowledge
    ack1 = memory_repo.acknowledge_alert(alert.alert_id, analyst_notes="Initial note.")
    orig_ack_time = ack1.acknowledged_at

    # Repeated acknowledge without notes should preserve original timestamp and notes
    ack2 = memory_repo.acknowledge_alert(alert.alert_id)
    assert ack2.status == AlertStatus.ACKNOWLEDGED.value
    assert ack2.acknowledged_at == orig_ack_time
    assert ack2.analyst_notes == "Initial note."

    # Resolve
    res1 = memory_repo.resolve_alert(alert.alert_id)
    orig_res_time = res1.resolved_at
    assert res1.analyst_notes == "Initial note."  # Preserved from ack

    # Repeated resolve
    res2 = memory_repo.resolve_alert(alert.alert_id)
    assert res2.status == AlertStatus.RESOLVED.value
    assert res2.resolved_at == orig_res_time


def test_invalid_lifecycle_transitions(memory_repo):
    """Verify invalid transitions raise InvalidLifecycleTransitionError."""
    finding = _make_dummy_finding()
    alert = memory_repo.save_finding(finding)

    # Attempt direct resolve from NEW (must be ACKNOWLEDGED first)
    with pytest.raises(InvalidLifecycleTransitionError, match="must be in 'ACKNOWLEDGED' status"):
        memory_repo.resolve_alert(alert.alert_id)

    # Acknowledge, then resolve
    memory_repo.acknowledge_alert(alert.alert_id)
    memory_repo.resolve_alert(alert.alert_id)

    # Attempt to acknowledge a RESOLVED alert
    with pytest.raises(InvalidLifecycleTransitionError, match="already in 'RESOLVED' status"):
        memory_repo.acknowledge_alert(alert.alert_id)


def test_missing_alert_raises_alert_not_found(memory_repo):
    """Verify lookups/operations on nonexistent alerts raise AlertNotFoundError."""
    assert memory_repo.get_alert_by_id("nonexistent-id") is None

    with pytest.raises(AlertNotFoundError, match="not found"):
        memory_repo.acknowledge_alert("nonexistent-id")

    with pytest.raises(AlertNotFoundError, match="not found"):
        memory_repo.resolve_alert("nonexistent-id")


# -------------------------------------------------------------------------
# Deduplication & Evidence Merging
# -------------------------------------------------------------------------

def test_active_duplicate_merging_and_occurrence_count(memory_repo):
    """Verify findings with identical fingerprints merge into active alert, incrementing count."""
    fp = "c" * 64
    f1 = _make_dummy_finding(fingerprint=fp, timestamp="2026-10-13T10:00:00+00:00")
    a1 = memory_repo.save_finding(f1)
    assert a1.occurrence_count == 1
    assert a1.first_seen_timestamp == "2026-10-13T10:00:00+00:00"
    assert a1.last_seen_timestamp == "2026-10-13T10:00:00+00:00"

    # Save duplicate finding with later timestamp
    f2 = _make_dummy_finding(fingerprint=fp, timestamp="2026-10-13T10:05:00+00:00")
    a2 = memory_repo.save_finding(f2)

    # Preserves alert_id, increments occurrence_count, updates last_seen
    assert a2.alert_id == a1.alert_id
    assert a2.occurrence_count == 2
    assert a2.first_seen_timestamp == "2026-10-13T10:00:00+00:00"
    assert a2.last_seen_timestamp == "2026-10-13T10:05:00+00:00"

    # Only 1 alert row exists in database
    all_alerts = memory_repo.list_alerts()
    assert len(all_alerts) == 1


def test_evidence_merging_by_rule_id_without_duplicates(memory_repo):
    """Verify merging findings accumulates distinct RuleMatches without duplicate rule IDs."""
    fp = "d" * 64
    rule1 = RuleMatch("RULE-DOS-SYN-001", "SYN", "MEDIUM", "desc", {})
    f1 = _make_dummy_finding(fingerprint=fp, rule_matches=[rule1])
    a1 = memory_repo.save_finding(f1)
    assert a1.rule_ids == ["RULE-DOS-SYN-001"]

    # Subsequent finding introduces a second rule
    rule2 = RuleMatch("RULE-LAND-001", "LAND", "HIGH", "desc", {})
    f2 = _make_dummy_finding(fingerprint=fp, rule_matches=[rule1, rule2])
    a2 = memory_repo.save_finding(f2)

    # Accumulates both rules without duplicates
    assert a2.alert_id == a1.alert_id
    assert sorted(a2.rule_ids) == ["RULE-DOS-SYN-001", "RULE-LAND-001"]
    assert len(a2.rule_matches) == 2


def test_severity_preservation_for_less_severe_subsequent_finding(memory_repo):
    """Verify overall_severity is never downgraded when a subsequent duplicate finding is less severe."""
    fp = "e" * 64
    # Finding 1 has HIGH severity
    f1 = _make_dummy_finding(fingerprint=fp, overall_severity="HIGH", pred_label="attack")
    a1 = memory_repo.save_finding(f1)
    assert a1.overall_severity == "HIGH"

    # Finding 2 arrives with less severe classification (LOW / normal)
    f2 = _make_dummy_finding(fingerprint=fp, overall_severity="LOW", pred_label="normal", attack_prob=0.1)
    a2 = memory_repo.save_finding(f2)

    # Severity remains HIGH (not downgraded)
    assert a2.alert_id == a1.alert_id
    assert a2.overall_severity == "HIGH"


def test_new_alert_id_created_on_recurrence_after_resolution(memory_repo):
    """Verify an alert with the same fingerprint creates a new alert if prior is RESOLVED."""
    fp = "f" * 64
    f1 = _make_dummy_finding(fingerprint=fp)
    a1 = memory_repo.save_finding(f1)

    # Triage and resolve alert 1
    memory_repo.acknowledge_alert(a1.alert_id)
    resolved_a1 = memory_repo.resolve_alert(a1.alert_id, analyst_notes="Resolved initial event.")
    assert resolved_a1.status == AlertStatus.RESOLVED.value

    # New finding arrives with same fingerprint
    f2 = _make_dummy_finding(fingerprint=fp)
    a2 = memory_repo.save_finding(f2)

    # Must create a fresh alert with a new ID and status NEW
    assert a2.alert_id != a1.alert_id
    assert a2.status == AlertStatus.NEW.value
    assert a2.occurrence_count == 1

    # Database now contains both the historically resolved alert and the active new alert
    all_alerts = memory_repo.list_alerts()
    assert len(all_alerts) == 2


# -------------------------------------------------------------------------
# Transactions, Rollbacks, and Safety
# -------------------------------------------------------------------------

def test_batch_atomicity_and_rollback_on_injected_error(memory_repo):
    """Verify save_findings_batch rolls back all inserts if any finding fails validation."""
    valid_finding1 = _make_dummy_finding(fingerprint="1" * 64)
    valid_finding2 = _make_dummy_finding(fingerprint="2" * 64)
    # Malformed finding with invalid fingerprint length
    invalid_finding = _make_dummy_finding(fingerprint="too_short")

    with pytest.raises(InvalidFindingError):
        memory_repo.save_findings_batch([valid_finding1, invalid_finding, valid_finding2])

    # Zero records should be saved due to transaction rollback
    all_alerts = memory_repo.list_alerts()
    assert len(all_alerts) == 0


def test_sql_parameterization_safety_with_unusual_characters(memory_repo):
    """Verify parameterization safely handles quotes, semicolons, and injection patterns."""
    adversarial_explanation = "Normal traffic; DROP TABLE alerts; -- ' OR '1'='1"
    adversarial_notes = "Analyst notes with quotes \" and semicolons; SELECT * FROM alerts;"

    finding = _make_dummy_finding(explanation=adversarial_explanation)
    saved = memory_repo.save_finding(finding)

    memory_repo.acknowledge_alert(saved.alert_id, analyst_notes=adversarial_notes)
    retrieved = memory_repo.get_alert_by_id(saved.alert_id)

    assert retrieved is not None
    assert retrieved.explanation == adversarial_explanation
    assert retrieved.analyst_notes == adversarial_notes


def test_persistence_across_separate_repository_instances(tmp_path: Path):
    """Verify alerts persist across independent repository instances connecting to same file."""
    db_file = tmp_path / "shared_alerts.db"

    repo1 = AlertRepository(db_path=db_file)
    repo1.initialize_schema()
    saved = repo1.save_finding(_make_dummy_finding(fingerprint="9" * 64))

    # Second instance
    repo2 = AlertRepository(db_path=db_file)
    retrieved = repo2.get_alert_by_id(saved.alert_id)

    assert retrieved is not None
    assert retrieved.alert_id == saved.alert_id
    assert retrieved.record_fingerprint == "9" * 64


def test_invalid_finding_validation_rejections(memory_repo):
    """Verify validation rejects invalid probabilities, dispositions, and severities."""
    # Invalid attack probability > 1.0
    bad_prob = _make_dummy_finding()
    bad_prob.model_decision.attack_probability = 1.5
    with pytest.raises(InvalidFindingError, match="outside"):
        memory_repo.save_finding(bad_prob)

    # Invalid disposition
    bad_disp = _make_dummy_finding(disposition="INVALID_DISPOSITION")
    with pytest.raises(InvalidFindingError, match="disposition"):
        memory_repo.save_finding(bad_disp)

    # Invalid severity
    bad_sev = _make_dummy_finding(overall_severity="SUPER_CRITICAL")
    with pytest.raises(InvalidFindingError, match="overall_severity"):
        memory_repo.save_finding(bad_sev)


# -------------------------------------------------------------------------
# Targeted Verification Tests (Fingerprint, Evidence/Severity, Recurrence)
# -------------------------------------------------------------------------

def test_fingerprint_strict_validation(memory_repo):
    """Verify strict validation of 64-char hex SHA-256 fingerprint at input boundary."""
    # 1. Empty string
    with pytest.raises(InvalidFindingError, match="record_fingerprint"):
        memory_repo.save_finding(_make_dummy_finding(fingerprint=""))

    # 2. Too short
    with pytest.raises(InvalidFindingError, match="record_fingerprint"):
        memory_repo.save_finding(_make_dummy_finding(fingerprint="a" * 63))

    # 3. Too long
    with pytest.raises(InvalidFindingError, match="record_fingerprint"):
        memory_repo.save_finding(_make_dummy_finding(fingerprint="a" * 65))

    # 4. Exactly 64 chars but non-hex characters
    with pytest.raises(InvalidFindingError, match="record_fingerprint"):
        memory_repo.save_finding(_make_dummy_finding(fingerprint="g" * 64))

    with pytest.raises(InvalidFindingError, match="record_fingerprint"):
        memory_repo.save_finding(_make_dummy_finding(fingerprint="z" * 64))

    with pytest.raises(InvalidFindingError, match="record_fingerprint"):
        memory_repo.save_finding(_make_dummy_finding(fingerprint="0" * 60 + "xyz!"))

    # 5. Non-string types
    bad_type_finding = _make_dummy_finding()
    bad_type_finding.record_fingerprint = 123456789  # type: ignore
    with pytest.raises(InvalidFindingError, match="record_fingerprint"):
        memory_repo.save_finding(bad_type_finding)

    # 6. Valid 64-char lowercase hex
    valid_lower = "0123456789abcdef" * 4
    saved1 = memory_repo.save_finding(_make_dummy_finding(fingerprint=valid_lower))
    assert saved1.record_fingerprint == valid_lower

    # 7. Valid 64-char uppercase hex
    valid_upper = "ABCDEF0123456789" * 4
    saved2 = memory_repo.save_finding(_make_dummy_finding(fingerprint=valid_upper))
    assert saved2.record_fingerprint == valid_upper

    # 8. Valid 64-char mixed-case hex
    valid_mixed = "aAbBcC0123456789" * 4
    saved3 = memory_repo.save_finding(_make_dummy_finding(fingerprint=valid_mixed))
    assert saved3.record_fingerprint == valid_mixed


def test_get_active_alert_by_fingerprint_behavior(memory_repo):
    """Verify get_active_alert_by_fingerprint input validation, lookup, and status filtering."""
    # Invalid inputs must raise ValueError
    with pytest.raises(ValueError, match="record_fingerprint"):
        memory_repo.get_active_alert_by_fingerprint("")

    with pytest.raises(ValueError, match="record_fingerprint"):
        memory_repo.get_active_alert_by_fingerprint("too_short")

    with pytest.raises(ValueError, match="record_fingerprint"):
        memory_repo.get_active_alert_by_fingerprint("g" * 64)

    # Valid fingerprint with no existing record -> returns None
    missing_fp = "0" * 64
    assert memory_repo.get_active_alert_by_fingerprint(missing_fp) is None

    # Save active alert in NEW status -> found
    fp1 = "1" * 64
    saved1 = memory_repo.save_finding(_make_dummy_finding(fingerprint=fp1))
    found1 = memory_repo.get_active_alert_by_fingerprint(fp1)
    assert found1 is not None
    assert found1.alert_id == saved1.alert_id
    assert found1.status == AlertStatus.NEW.value

    # Acknowledge alert -> still active, found
    memory_repo.acknowledge_alert(saved1.alert_id)
    found_ack = memory_repo.get_active_alert_by_fingerprint(fp1)
    assert found_ack is not None
    assert found_ack.alert_id == saved1.alert_id
    assert found_ack.status == AlertStatus.ACKNOWLEDGED.value

    # Resolve alert -> no longer active, returns None
    memory_repo.resolve_alert(saved1.alert_id)
    assert memory_repo.get_active_alert_by_fingerprint(fp1) is None


def test_duplicate_evidence_accumulation_and_severity_preservation(memory_repo):
    """Verify evidence merging, severity non-downgrade, and latest-observation field updates.

    Steps:
    1. Initial finding: 1 rule match (RULE-DOS-SYN-001), severity MEDIUM, RULE_DETECTED.
    2. Active duplicate: adds RULE-LAND-001, model detects attack, severity HIGH, CORROBORATED.
       -> rule_ids accumulated without duplicates.
       -> occurrence_count increments.
       -> severity becomes HIGH.
       -> latest observation fields reflect finding 2.
    3. Subsequent finding: 0 rule matches, model normal, severity INFORMATIONAL, BENIGN.
       -> existing rule evidence is NOT erased.
       -> severity is NOT downgraded from HIGH.
       -> latest observation fields reflect finding 3.
    """
    fp = "e" * 64
    rule_syn = RuleMatch("RULE-DOS-SYN-001", "SYN Flood", "MEDIUM", "SYN burst", {"count": 100})
    rule_land = RuleMatch("RULE-LAND-001", "LAND Attack", "HIGH", "Land packet", {"land": 1})

    # Finding 1
    f1 = _make_dummy_finding(
        fingerprint=fp,
        disposition="RULE_DETECTED",
        overall_severity="MEDIUM",
        pred_label="normal",
        attack_prob=0.15,
        confidence=0.85,
        rule_matches=[rule_syn],
        explanation="Initial rule match for SYN flood.",
        timestamp="2026-10-13T12:00:00+00:00",
    )
    a1 = memory_repo.save_finding(f1)
    assert a1.occurrence_count == 1
    assert a1.overall_severity == "MEDIUM"
    assert a1.rule_ids == ["RULE-DOS-SYN-001"]
    assert len(a1.rule_matches) == 1
    assert a1.disposition == "RULE_DETECTED"
    assert a1.explanation == "Initial rule match for SYN flood."

    # Finding 2: brings rule_syn again plus rule_land, model is attack
    f2 = _make_dummy_finding(
        fingerprint=fp,
        disposition="CORROBORATED",
        overall_severity="HIGH",
        pred_label="attack",
        attack_prob=0.94,
        confidence=0.94,
        rule_matches=[rule_syn, rule_land],
        explanation="Corroborated finding with model attack and two rules.",
        timestamp="2026-10-13T12:05:00+00:00",
    )
    a2 = memory_repo.save_finding(f2)
    assert a2.alert_id == a1.alert_id
    assert a2.occurrence_count == 2
    # Accumulated rules without duplicate IDs
    assert sorted(a2.rule_ids) == ["RULE-DOS-SYN-001", "RULE-LAND-001"]
    assert len(a2.rule_matches) == 2
    # Severity upgraded to HIGH
    assert a2.overall_severity == "HIGH"
    # Latest observation fields reflect finding 2
    assert a2.predicted_label == "attack"
    assert a2.attack_probability == pytest.approx(0.94)
    assert a2.confidence == pytest.approx(0.94)
    assert a2.disposition == "CORROBORATED"
    assert a2.detection_timestamp == "2026-10-13T12:05:00+00:00"
    assert a2.last_seen_timestamp == "2026-10-13T12:05:00+00:00"
    assert a2.first_seen_timestamp == "2026-10-13T12:00:00+00:00"
    assert a2.explanation == "Corroborated finding with model attack and two rules."

    # Finding 3: 0 rule matches, model normal, low severity
    f3 = _make_dummy_finding(
        fingerprint=fp,
        disposition="BENIGN",
        overall_severity="INFORMATIONAL",
        pred_label="normal",
        attack_prob=0.03,
        confidence=0.97,
        rule_matches=[],  # Fewer rule matches
        explanation="Latest flow observation is benign.",
        timestamp="2026-10-13T12:10:00+00:00",
    )
    a3 = memory_repo.save_finding(f3)
    assert a3.alert_id == a1.alert_id
    assert a3.occurrence_count == 3
    # Existing accumulated evidence is NOT erased
    assert sorted(a3.rule_ids) == ["RULE-DOS-SYN-001", "RULE-LAND-001"]
    assert len(a3.rule_matches) == 2
    # Severity is NOT downgraded; remains HIGH
    assert a3.overall_severity == "HIGH"
    # Latest observation fields reflect finding 3
    assert a3.predicted_label == "normal"
    assert a3.attack_probability == pytest.approx(0.03)
    assert a3.confidence == pytest.approx(0.97)
    assert a3.disposition == "BENIGN"
    assert a3.detection_timestamp == "2026-10-13T12:10:00+00:00"
    assert a3.last_seen_timestamp == "2026-10-13T12:10:00+00:00"
    assert a3.first_seen_timestamp == "2026-10-13T12:00:00+00:00"
    assert a3.explanation == "Latest flow observation is benign."


def test_recurrence_after_resolution_leaves_prior_resolved_record_unchanged(memory_repo):
    """Verify recurrence creates fresh alert and leaves historical resolved alert immutable."""
    fp = "f" * 64
    f1 = _make_dummy_finding(fingerprint=fp, timestamp="2026-10-13T09:00:00+00:00")
    a1 = memory_repo.save_finding(f1)

    memory_repo.acknowledge_alert(a1.alert_id, analyst_notes="Acknowledged incident.")
    resolved_a1 = memory_repo.resolve_alert(
        a1.alert_id, analyst_notes="Resolved incident: mitigated by firewall rule."
    )

    # Snapshot of resolved alert
    snap_id = resolved_a1.alert_id
    snap_status = resolved_a1.status
    snap_count = resolved_a1.occurrence_count
    snap_ack_at = resolved_a1.acknowledged_at
    snap_res_at = resolved_a1.resolved_at
    snap_notes = resolved_a1.analyst_notes

    # Subsequent finding arrives with same fingerprint
    f2 = _make_dummy_finding(
        fingerprint=fp,
        timestamp="2026-10-13T11:00:00+00:00",
        explanation="New recurrent incident.",
    )
    a2 = memory_repo.save_finding(f2)

    # A new alert must be created with fresh ID and status NEW
    assert a2.alert_id != snap_id
    assert a2.status == AlertStatus.NEW.value
    assert a2.occurrence_count == 1
    assert a2.acknowledged_at is None
    assert a2.resolved_at is None

    # Fetch prior resolved alert from DB: must remain completely unmodified
    prior = memory_repo.get_alert_by_id(snap_id)
    assert prior is not None
    assert prior.alert_id == snap_id
    assert prior.status == snap_status == "RESOLVED"
    assert prior.occurrence_count == snap_count == 1
    assert prior.acknowledged_at == snap_ack_at
    assert prior.resolved_at == snap_res_at
    assert prior.analyst_notes == snap_notes


def test_file_repo_batch_rollback_on_injected_error(tmp_path: Path):
    """Verify file-backed database transaction rolls back all rows when batch fails mid-stream."""
    db_file = tmp_path / "rollback_test.db"
    repo = AlertRepository(db_path=db_file)
    repo.initialize_schema()

    valid1 = _make_dummy_finding(fingerprint="1" * 64)
    valid2 = _make_dummy_finding(fingerprint="2" * 64)
    invalid = _make_dummy_finding(fingerprint="invalid_non_hex_fingerprint_length_mismatch")
    valid3 = _make_dummy_finding(fingerprint="3" * 64)

    with pytest.raises(InvalidFindingError):
        repo.save_findings_batch([valid1, valid2, invalid, valid3])

    # No alerts must exist in database file
    assert len(repo.list_alerts()) == 0
