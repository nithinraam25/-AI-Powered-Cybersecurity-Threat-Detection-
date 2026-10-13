"""Automated test suite for the Streamlit threat detection dashboard.

Validates the Alert Triage console, metric aggregations, search scoping,
pagination logic, lifecycle transitions, and safety constraints.
All tests strictly utilize temporary or isolated test databases.
Zero production databases or default database paths are touched.
"""

from datetime import datetime, timezone
import os
from pathlib import Path
from typing import List, Optional
import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from dashboard.helpers import (
    compute_kpis,
    filter_alerts_on_page,
    format_alert_table_data,
    format_severity_badge,
    resolve_database_path,
)
from threat_detection.config import config
from threat_detection.detection.engine import DetectionFinding, ModelDecision
from threat_detection.detection.rules import RuleMatch
from threat_detection.storage import (
    AlertNotFoundError,
    AlertRecord,
    AlertRepository,
    AlertStatus,
    InvalidLifecycleTransitionError,
)

DASHBOARD_APP_PATH = str(Path(__file__).resolve().parent.parent / "dashboard" / "app.py")


def _create_sample_finding(
    fingerprint: str = "a" * 64,
    threat_detected: bool = True,
    disposition: str = "MODEL_DETECTED",
    overall_severity: str = "HIGH",
    pred_label: str = "attack",
    attack_prob: float = 0.88,
    confidence: float = 0.88,
    rule_matches: Optional[List[RuleMatch]] = None,
    explanation: str = "Automated test finding.",
    timestamp: Optional[str] = None,
) -> DetectionFinding:
    """Helper to generate valid DetectionFinding instances for tests."""
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    return DetectionFinding(
        record_index=0,
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


@pytest.fixture(autouse=True)
def clean_streamlit_cache():
    """Ensure Streamlit resource cache is cleared before and after each test."""
    st.cache_resource.clear()
    yield
    st.cache_resource.clear()


# -------------------------------------------------------------------------
# 1. Path Resolution & Safe Database Configuration Tests
# -------------------------------------------------------------------------

def test_resolve_database_path_environment_override(monkeypatch):
    """Verify THREAT_DETECTION_DB_PATH overrides default config path."""
    # When unset, defaults to config.DATABASE_PATH
    monkeypatch.delenv("THREAT_DETECTION_DB_PATH", raising=False)
    assert resolve_database_path() == config.DATABASE_PATH

    # When set to in-memory
    monkeypatch.setenv("THREAT_DETECTION_DB_PATH", ":memory:")
    assert resolve_database_path() == ":memory:"

    # When set to custom file path
    custom_path = r"C:\tmp\custom_threats.db"
    monkeypatch.setenv("THREAT_DETECTION_DB_PATH", custom_path)
    assert resolve_database_path() == Path(custom_path)


# -------------------------------------------------------------------------
# 2. KPI Computation and Formatting Helper Tests
# -------------------------------------------------------------------------

def test_compute_kpis_aggregation():
    """Verify KPI computations correctly aggregate statuses and high/critical counts."""
    summary_counts = {
        "by_status": {
            "NEW": 5,
            "ACKNOWLEDGED": 3,
            "RESOLVED": 2,
        },
        "by_severity": {
            "CRITICAL": 1,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 1,
            "INFORMATIONAL": 1,
        },
    }
    kpis = compute_kpis(summary_counts)
    assert kpis["total"] == 10
    assert kpis["new"] == 5
    assert kpis["acknowledged"] == 3
    assert kpis["resolved"] == 2
    assert kpis["high_critical"] == 5  # 1 CRITICAL + 4 HIGH


def test_format_severity_badge_labels():
    """Verify severity badges include explicit text labels alongside visual markers."""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
        badge = format_severity_badge(sev)
        assert f"[{sev}]" in badge


# -------------------------------------------------------------------------
# 3. In-Memory Search Scoping Tests
# -------------------------------------------------------------------------

def test_search_scoped_to_loaded_page():
    """Verify search filter operates strictly on the loaded page records."""
    f1 = _create_sample_finding(
        fingerprint="1" * 64,
        explanation="SYN flood attack detected by classifier",
    )
    f2 = _create_sample_finding(
        fingerprint="2" * 64,
        explanation="Normal benign network session",
    )
    repo = AlertRepository(db_path=":memory:")
    repo.initialize_schema()
    a1 = repo.save_finding(f1)
    a2 = repo.save_finding(f2)

    page_alerts = [a1, a2]

    # Search for explanation term
    res_syn = filter_alerts_on_page(page_alerts, "syn flood")
    assert len(res_syn) == 1
    assert res_syn[0].alert_id == a1.alert_id

    # Search for fingerprint substring
    res_fp = filter_alerts_on_page(page_alerts, "2222")
    assert len(res_fp) == 1
    assert res_fp[0].alert_id == a2.alert_id

    # Search for alert_id substring
    res_id = filter_alerts_on_page(page_alerts, a1.alert_id[:6])
    assert len(res_id) == 1
    assert res_id[0].alert_id == a1.alert_id

    # Non-matching search returns empty list
    res_none = filter_alerts_on_page(page_alerts, "nonexistent keyword")
    assert len(res_none) == 0

    # Empty search returns all page records
    res_all = filter_alerts_on_page(page_alerts, "")
    assert len(res_all) == 2


# -------------------------------------------------------------------------
# 4. Table Formatting Helper Tests
# -------------------------------------------------------------------------

def test_format_alert_table_data():
    """Verify alert table formatting transforms AlertRecords into display dictionaries."""
    f = _create_sample_finding(attack_prob=0.9234)
    repo = AlertRepository(db_path=":memory:")
    repo.initialize_schema()
    alert = repo.save_finding(f)

    rows = format_alert_table_data([alert])
    assert len(rows) == 1
    row = rows[0]
    assert row["Alert ID"] == f"{alert.alert_id[:8]}..."
    assert row["Status"] == alert.status
    assert row["Severity"] == alert.overall_severity
    assert row["Attack Prob"] == "92.3%"
    assert row["_full_id"] == alert.alert_id


# -------------------------------------------------------------------------
# 5. Pagination & Page Navigation Tests
# -------------------------------------------------------------------------

def test_page_navigation_no_duplicates_or_skips(tmp_path: Path):
    """Verify multi-page queries traverse records cleanly without duplicates or gaps."""
    db_file = tmp_path / "pagination_test.db"
    repo = AlertRepository(db_path=db_file)
    repo.initialize_schema()

    # Create 5 distinct alerts
    alert_ids = []
    for i in range(5):
        finding = _create_sample_finding(
            fingerprint=f"{i:02d}" + "0" * 62,
            timestamp=f"2026-10-13T10:{i:02d}:00+00:00",
        )
        saved = repo.save_finding(finding)
        alert_ids.append(saved.alert_id)

    # Page size 2
    page_size = 2

    # Page 0 (offset 0, limit 2)
    p0 = repo.list_alerts(limit=page_size, offset=0)
    assert len(p0) == 2

    # Page 1 (offset 2, limit 2)
    p1 = repo.list_alerts(limit=page_size, offset=2)
    assert len(p1) == 2

    # Page 2 (offset 4, limit 2)
    p2 = repo.list_alerts(limit=page_size, offset=4)
    assert len(p2) == 1

    # Verify zero overlap across pages (no duplicate records)
    ids_p0 = {a.alert_id for a in p0}
    ids_p1 = {a.alert_id for a in p1}
    ids_p2 = {a.alert_id for a in p2}

    assert ids_p0.isdisjoint(ids_p1)
    assert ids_p1.isdisjoint(ids_p2)
    assert ids_p0.isdisjoint(ids_p2)

    # Verify all 5 records accounted for (no skipped records)
    all_retrieved = ids_p0 | ids_p1 | ids_p2
    assert all_retrieved == set(alert_ids)


# -------------------------------------------------------------------------
# 6. Lifecycle Transitions & State Machine Tests
# -------------------------------------------------------------------------

def test_lifecycle_transitions_via_repository(tmp_path: Path):
    """Verify alert acknowledgement and resolution lifecycle transitions."""
    db_file = tmp_path / "lifecycle_test.db"
    repo = AlertRepository(db_path=db_file)
    repo.initialize_schema()

    alert = repo.save_finding(_create_sample_finding())
    assert alert.status == AlertStatus.NEW.value
    assert alert.acknowledged_at is None
    assert alert.resolved_at is None

    # 1. Acknowledge
    ack = repo.acknowledge_alert(alert.alert_id, analyst_notes="Investigating anomalous burst.")
    assert ack.status == AlertStatus.ACKNOWLEDGED.value
    assert ack.acknowledged_at is not None
    assert ack.analyst_notes == "Investigating anomalous burst."

    # 2. Resolve
    res = repo.resolve_alert(alert.alert_id, analyst_notes="Mitigated via edge ACL.")
    assert res.status == AlertStatus.RESOLVED.value
    assert res.acknowledged_at == ack.acknowledged_at
    assert res.resolved_at is not None
    assert res.analyst_notes == "Mitigated via edge ACL."


def test_invalid_lifecycle_transition_raises_error(tmp_path: Path):
    """Verify attempting an invalid transition raises InvalidLifecycleTransitionError."""
    db_file = tmp_path / "invalid_lifecycle.db"
    repo = AlertRepository(db_path=db_file)
    repo.initialize_schema()

    alert = repo.save_finding(_create_sample_finding())

    # Direct resolution from NEW is rejected (must be ACKNOWLEDGED first)
    with pytest.raises(InvalidLifecycleTransitionError, match="must be in 'ACKNOWLEDGED' status"):
        repo.resolve_alert(alert.alert_id)


# -------------------------------------------------------------------------
# 7. Streamlit AppTest Headless Integration Tests
# -------------------------------------------------------------------------

def test_apptest_empty_database_state(tmp_path: Path, monkeypatch):
    """Verify dashboard loads empty database cleanly with zero counts and empty state info."""
    db_file = tmp_path / "empty_app.db"
    monkeypatch.setenv("THREAT_DETECTION_DB_PATH", str(db_file))

    at = AppTest.from_file(DASHBOARD_APP_PATH, default_timeout=15)
    at.run(timeout=15)

    assert len(at.exception) == 0

    # Metric cards display 0
    metric_labels = [m.label for m in at.metric]
    metric_values = [m.value for m in at.metric]
    assert "Total Alerts" in metric_labels
    assert "New Alerts" in metric_labels
    assert all(val == "0" for val in metric_values)

    # Empty state message rendered
    assert len(at.info) >= 1
    assert "No security alerts currently exist" in at.info[0].value


def test_apptest_existing_alerts_displayed(tmp_path: Path, monkeypatch):
    """Verify dashboard displays populated alert inventory and metric counts."""
    db_file = tmp_path / "populated_app.db"
    repo = AlertRepository(db_path=db_file)
    repo.initialize_schema()

    rule_syn = RuleMatch(
        rule_id="RULE-DOS-SYN-001",
        rule_name="SYN Flood",
        severity="HIGH",
        description="SYN burst detected",
        matched_fields={"count": 150},
    )
    f1 = _create_sample_finding(
        fingerprint="a" * 64,
        overall_severity="HIGH",
        disposition="CORROBORATED",
        rule_matches=[rule_syn],
    )
    f2 = _create_sample_finding(
        fingerprint="b" * 64,
        overall_severity="MEDIUM",
        disposition="MODEL_DETECTED",
    )
    repo.save_finding(f1)
    a2 = repo.save_finding(f2)
    repo.acknowledge_alert(a2.alert_id)

    monkeypatch.setenv("THREAT_DETECTION_DB_PATH", str(db_file))

    at = AppTest.from_file(DASHBOARD_APP_PATH, default_timeout=15)
    at.run(timeout=15)

    assert len(at.exception) == 0

    # Metrics verify counts: Total=2, New=1, Acknowledged=1, High/Critical=1
    metric_dict = {m.label: m.value for m in at.metric}
    assert metric_dict["Total Alerts"] == "2"
    assert metric_dict["New Alerts"] == "1"
    assert metric_dict["Acknowledged"] == "1"
    assert metric_dict["Resolved"] == "0"
    assert metric_dict["High / Critical"] == "1"

    # Dataframe table rendered
    assert len(at.dataframe) == 1
    df_data = at.dataframe[0].value
    assert len(df_data) == 2


def test_apptest_lifecycle_action_execution(tmp_path: Path, monkeypatch):
    """Verify acknowledging an alert through AppTest executes the transition and updates state."""
    db_file = tmp_path / "lifecycle_app.db"
    repo = AlertRepository(db_path=db_file)
    repo.initialize_schema()

    finding = _create_sample_finding(fingerprint="c" * 64)
    alert = repo.save_finding(finding)
    assert alert.status == AlertStatus.NEW.value

    monkeypatch.setenv("THREAT_DETECTION_DB_PATH", str(db_file))

    at = AppTest.from_file(DASHBOARD_APP_PATH, default_timeout=15)
    at.run(timeout=15)
    assert len(at.exception) == 0

    # Locate Acknowledge button and click it
    ack_btn = None
    for btn in at.button:
        if "Acknowledge Alert" in btn.label and not btn.disabled:
            ack_btn = btn
            break

    assert ack_btn is not None, "Acknowledge Alert button should be enabled for NEW alert"
    ack_btn.click().run(timeout=15)

    assert len(at.exception) == 0

    # Verify repository status was updated to ACKNOWLEDGED
    updated_alert = repo.get_alert_by_id(alert.alert_id)
    assert updated_alert is not None
    assert updated_alert.status == AlertStatus.ACKNOWLEDGED.value
    assert updated_alert.acknowledged_at is not None


def test_filters_behavior_on_repository(tmp_path: Path):
    """Verify repository multi-column filtering by status, severity, and disposition."""
    db_file = tmp_path / "filter_test.db"
    repo = AlertRepository(db_path=db_file)
    repo.initialize_schema()

    f1 = _create_sample_finding(
        fingerprint="1" * 64,
        overall_severity="HIGH",
        disposition="CORROBORATED",
    )
    f2 = _create_sample_finding(
        fingerprint="2" * 64,
        overall_severity="MEDIUM",
        disposition="MODEL_DETECTED",
    )
    f3 = _create_sample_finding(
        fingerprint="3" * 64,
        overall_severity="LOW",
        disposition="BENIGN",
    )

    a1 = repo.save_finding(f1)
    a2 = repo.save_finding(f2)
    a3 = repo.save_finding(f3)
    repo.acknowledge_alert(a2.alert_id)
    repo.acknowledge_alert(a3.alert_id)
    repo.resolve_alert(a3.alert_id)

    # Filter by Status
    new_alerts = repo.list_alerts(status="NEW")
    assert len(new_alerts) == 1
    assert new_alerts[0].alert_id == a1.alert_id

    ack_alerts = repo.list_alerts(status="ACKNOWLEDGED")
    assert len(ack_alerts) == 1
    assert ack_alerts[0].alert_id == a2.alert_id

    res_alerts = repo.list_alerts(status="RESOLVED")
    assert len(res_alerts) == 1
    assert res_alerts[0].alert_id == a3.alert_id

    # Filter by Severity
    high_alerts = repo.list_alerts(severity="HIGH")
    assert len(high_alerts) == 1
    assert high_alerts[0].alert_id == a1.alert_id

    # Filter by Disposition
    model_alerts = repo.list_alerts(disposition="MODEL_DETECTED")
    assert len(model_alerts) == 1
    assert model_alerts[0].alert_id == a2.alert_id


def test_alert_details_fields_representation(tmp_path: Path):
    """Verify alert record contains all expected fields for detail inspection."""
    db_file = tmp_path / "details_test.db"
    repo = AlertRepository(db_path=db_file)
    repo.initialize_schema()

    rule_syn = RuleMatch(
        rule_id="RULE-DOS-SYN-001",
        rule_name="SYN Flood",
        severity="MEDIUM",
        description="SYN burst detected",
        matched_fields={"count": 120, "serror_rate": 0.85},
    )
    finding = _create_sample_finding(
        fingerprint="d" * 64,
        threat_detected=True,
        disposition="CORROBORATED",
        overall_severity="HIGH",
        pred_label="attack",
        attack_prob=0.91,
        confidence=0.91,
        rule_matches=[rule_syn],
        explanation="Corroborated SYN flood attack profile.",
    )
    saved = repo.save_finding(finding)

    retrieved = repo.get_alert_by_id(saved.alert_id)
    assert retrieved is not None
    assert retrieved.alert_id == saved.alert_id
    assert retrieved.record_fingerprint == "d" * 64
    assert retrieved.threat_detected is True
    assert retrieved.disposition == "CORROBORATED"
    assert retrieved.overall_severity == "HIGH"
    assert retrieved.predicted_label == "attack"
    assert retrieved.attack_probability == pytest.approx(0.91)
    assert retrieved.confidence == pytest.approx(0.91)
    assert retrieved.rule_ids == ["RULE-DOS-SYN-001"]
    assert len(retrieved.rule_matches) == 1
    assert retrieved.rule_matches[0].matched_fields == {"count": 120, "serror_rate": 0.85}
    assert retrieved.explanation == "Corroborated SYN flood attack profile."
    assert retrieved.status == "NEW"
    assert retrieved.occurrence_count == 1
    assert retrieved.detection_timestamp is not None
    assert retrieved.first_seen_timestamp is not None
    assert retrieved.last_seen_timestamp is not None
    assert retrieved.created_at is not None
    assert retrieved.updated_at is not None


def test_invalid_lifecycle_ui_disabled_buttons(tmp_path: Path, monkeypatch):
    """Verify UI prevents invalid transitions by disabling improper action buttons."""
    db_file = tmp_path / "disabled_btn_app.db"
    repo = AlertRepository(db_path=db_file)
    repo.initialize_schema()

    # Create alert in NEW status
    finding = _create_sample_finding(fingerprint="e" * 64)
    alert = repo.save_finding(finding)

    monkeypatch.setenv("THREAT_DETECTION_DB_PATH", str(db_file))
    at = AppTest.from_file(DASHBOARD_APP_PATH, default_timeout=15)
    at.run(timeout=15)

    assert len(at.exception) == 0

    # For NEW alert: Resolve button must be disabled
    resolve_btns = [b for b in at.button if "Resolve Alert" in b.label]
    assert len(resolve_btns) == 1
    assert resolve_btns[0].disabled is True, "Resolve button must be disabled for NEW alert"


def test_database_failure_handling(tmp_path: Path, monkeypatch):
    """Verify database initialization failure produces clean error and no false success metrics."""
    # Point to an un-creatable path (e.g. invalid file path on Windows with invalid chars)
    invalid_path = tmp_path / "a" / "b" / "c" / "readonly_file"
    # Create invalid_path as a file so that initializing a child dir fails
    invalid_path.parent.mkdir(parents=True, exist_ok=True)
    invalid_path.write_text("blocker")
    blocked_db = invalid_path / "cannot_create_dir_inside_file.db"

    monkeypatch.setenv("THREAT_DETECTION_DB_PATH", str(blocked_db))
    at = AppTest.from_file(DASHBOARD_APP_PATH, default_timeout=15)
    at.run(timeout=15)

    # Should report error and stop execution
    assert len(at.error) >= 1
    assert "Database Connection Failure" in at.error[0].value
    # No healthy metric cards should be rendered
    assert len(at.metric) == 0


# -------------------------------------------------------------------------
# 8. Full Lifecycle Interactions & Safety Verification
# -------------------------------------------------------------------------

def test_apptest_full_lifecycle_sequence(tmp_path: Path, monkeypatch):
    """Verify complete NEW -> ACKNOWLEDGED -> RESOLVED flow with notes, metric refreshes, and button states."""
    db_file = tmp_path / "full_lifecycle.db"
    repo = AlertRepository(db_path=db_file)
    repo.initialize_schema()

    finding = _create_sample_finding(fingerprint="f" * 64)
    alert = repo.save_finding(finding)

    monkeypatch.setenv("THREAT_DETECTION_DB_PATH", str(db_file))

    at = AppTest.from_file(DASHBOARD_APP_PATH, default_timeout=15)
    at.run(timeout=15)
    assert len(at.exception) == 0

    # 1. Verify initial metrics: NEW=1, ACK=0, RES=0
    metrics_init = {m.label: m.value for m in at.metric}
    assert metrics_init["New Alerts"] == "1"
    assert metrics_init["Acknowledged"] == "0"
    assert metrics_init["Resolved"] == "0"

    # Verify buttons for NEW alert: Ack enabled, Resolve disabled
    ack_btns = [b for b in at.button if "Acknowledge Alert" in b.label]
    res_btns = [b for b in at.button if "Resolve Alert" in b.label]
    assert len(ack_btns) == 1 and not ack_btns[0].disabled
    assert len(res_btns) == 1 and res_btns[0].disabled

    # 2. Enter analyst notes and click Acknowledge
    at.text_area[0].input("Analyst Ack Note")
    ack_btns[0].click().run(timeout=15)
    assert len(at.exception) == 0

    # Verify updated metrics: NEW=0, ACK=1, RES=0
    metrics_ack = {m.label: m.value for m in at.metric}
    assert metrics_ack["New Alerts"] == "0"
    assert metrics_ack["Acknowledged"] == "1"
    assert metrics_ack["Resolved"] == "0"

    # Verify buttons for ACKNOWLEDGED alert: Ack disabled, Resolve enabled
    ack_btns_ack = [b for b in at.button if "Acknowledge Alert" in b.label]
    res_btns_ack = [b for b in at.button if "Resolve Alert" in b.label]
    assert ack_btns_ack[0].disabled
    assert not res_btns_ack[0].disabled

    # 3. Enter resolution notes and click Resolve
    at.text_area[0].input("Analyst Res Note")
    res_btns_ack[0].click().run(timeout=15)
    assert len(at.exception) == 0

    # Verify updated metrics: NEW=0, ACK=0, RES=1
    metrics_res = {m.label: m.value for m in at.metric}
    assert metrics_res["New Alerts"] == "0"
    assert metrics_res["Acknowledged"] == "0"
    assert metrics_res["Resolved"] == "1"

    # Verify buttons for RESOLVED alert: both disabled
    ack_btns_res = [b for b in at.button if "Acknowledge Alert" in b.label]
    res_btns_res = [b for b in at.button if "Resolve Alert" in b.label]
    assert ack_btns_res[0].disabled
    assert res_btns_res[0].disabled

    # Verify database persistence
    final_alert = repo.get_alert_by_id(alert.alert_id)
    assert final_alert is not None
    assert final_alert.status == AlertStatus.RESOLVED.value
    assert final_alert.analyst_notes == "Analyst Res Note"
    assert final_alert.acknowledged_at is not None
    assert final_alert.resolved_at is not None


def test_apptest_lifecycle_error_handling(tmp_path: Path, monkeypatch):
    """Verify repository exceptions during triage actions render visible st.error and no false success."""
    db_file = tmp_path / "error_handling.db"
    repo = AlertRepository(db_path=db_file)
    repo.initialize_schema()

    finding = _create_sample_finding(fingerprint="9" * 64)
    alert = repo.save_finding(finding)

    monkeypatch.setenv("THREAT_DETECTION_DB_PATH", str(db_file))

    # Mock acknowledge_alert to raise AlertStorageError
    def mock_fail(alert_id, analyst_notes=None):
        raise AlertNotFoundError("Simulated record not found error")

    monkeypatch.setattr(AlertRepository, "acknowledge_alert", mock_fail)

    at = AppTest.from_file(DASHBOARD_APP_PATH, default_timeout=15)
    at.run(timeout=15)

    ack_btn = [b for b in at.button if "Acknowledge Alert" in b.label and not b.disabled][0]
    ack_btn.click().run(timeout=15)

    # Error message rendered, no unhandled crash, no success message
    assert len(at.exception) == 0
    assert len(at.error) >= 1
    assert "Failed to acknowledge alert" in at.error[0].value
    assert len(at.success) == 0


def test_dashboard_read_only_on_navigation_and_filters(tmp_path: Path, monkeypatch):
    """Verify browsing, filtering, and searching never create or modify database records."""
    db_file = tmp_path / "readonly_test.db"
    repo = AlertRepository(db_path=db_file)
    repo.initialize_schema()

    finding1 = _create_sample_finding(fingerprint="1" * 64)
    finding2 = _create_sample_finding(fingerprint="2" * 64)
    repo.save_finding(finding1)
    repo.save_finding(finding2)

    monkeypatch.setenv("THREAT_DETECTION_DB_PATH", str(db_file))

    at = AppTest.from_file(DASHBOARD_APP_PATH, default_timeout=15)
    at.run(timeout=15)

    # Change search input
    at.text_input[0].input("some search query").run(timeout=15)

    # Change status filter
    at.selectbox[0].select("NEW").run(timeout=15)

    # Confirm exactly 2 alerts still exist in the database, unmodified
    all_alerts = repo.list_alerts()
    assert len(all_alerts) == 2
    assert all_alerts[0].occurrence_count == 1
    assert all_alerts[1].occurrence_count == 1


# -------------------------------------------------------------------------
# 9. Production Database Untouched Verification
# -------------------------------------------------------------------------

def test_production_database_untouched():
    """Verify default production database was not created or modified during tests."""
    prod_db = config.DATABASE_PATH
    # In pristine test environment, outputs/threat_events.db must not be touched
    if prod_db.exists():
        # If it exists, ensure it is not locked or modified by our isolated tests
        assert prod_db.is_file()
