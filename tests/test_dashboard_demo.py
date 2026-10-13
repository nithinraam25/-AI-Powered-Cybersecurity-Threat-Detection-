"""Automated test suite for the Threat Detection Demo tab and flow evaluation interface.

Validates flow preset schemas, CSV upload parsing and validation,
in-memory engine evaluation without persistence, explicit persistence actions,
deduplication on persistence, and temporary database isolation.
Zero production databases or default database paths are touched.
"""

from datetime import datetime, timezone
import io
import os
from pathlib import Path
from typing import Any, Dict
import pandas as pd
import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from dashboard.helpers import (
    PRESET_FLOW_RECORDS,
    parse_and_validate_csv_upload,
    resolve_database_path,
)
from threat_detection.config import config
from threat_detection.data.schema import (
    DIFFICULTY_COLUMN,
    FEATURE_COLUMNS,
    LABEL_COLUMN,
)
from threat_detection.detection.engine import ThreatDetectionEngine, compute_record_fingerprint
from threat_detection.detection.trainer import ThreatDetectionArtifact
from threat_detection.preprocessing.pipeline import validate_traffic_features
from threat_detection.storage import AlertRepository, AlertStatus

DASHBOARD_APP_PATH = str(Path(__file__).resolve().parent.parent / "dashboard" / "app.py")


@pytest.fixture(autouse=True)
def clean_streamlit_cache():
    """Ensure Streamlit resource cache is cleared before and after each test."""
    st.cache_resource.clear()
    yield
    st.cache_resource.clear()


@pytest.fixture
def frozen_engine() -> ThreatDetectionEngine:
    """Fixture providing a ThreatDetectionEngine loaded with the frozen baseline artifact."""
    artifact = ThreatDetectionArtifact.load(config.MODELS_DIR / "baseline_rf_binary.joblib")
    return ThreatDetectionEngine(artifact=artifact)


# -------------------------------------------------------------------------
# 1. Preset Schema & Validation Tests
# -------------------------------------------------------------------------

def test_all_curated_presets_have_41_features():
    """Verify each authentic preset record contains all 41 features and passes validation."""
    assert len(PRESET_FLOW_RECORDS) >= 4

    for preset_name, preset_data in PRESET_FLOW_RECORDS.items():
        assert "record" in preset_data, f"Preset '{preset_name}' missing 'record' key."
        assert "provenance" in preset_data, f"Preset '{preset_name}' missing 'provenance' key."
        record = preset_data["record"]

        # Ensure exact 41 features
        assert len(record) == 41, f"Preset '{preset_name}' has {len(record)} features, expected 41."
        for col in FEATURE_COLUMNS:
            assert col in record, f"Preset '{preset_name}' missing required feature '{col}'."

        # Target label and difficulty must NOT be in the record
        assert LABEL_COLUMN not in record
        assert DIFFICULTY_COLUMN not in record

        # Validate with strict schema validator
        df_row = pd.DataFrame([record])
        validate_traffic_features(df_row)


# -------------------------------------------------------------------------
# 2. CSV Upload Parsing & Schema Validation Tests
# -------------------------------------------------------------------------

def test_valid_csv_upload_parses_successfully():
    """Verify single-row CSV with 41 features parses and validates cleanly."""
    sample_record = PRESET_FLOW_RECORDS["Authentic Benchmark: Normal FTP Session (KDDTest+ Row 2)"]["record"]
    df = pd.DataFrame([sample_record])
    csv_str = df.to_csv(index=False)

    parsed = parse_and_validate_csv_upload(csv_str)
    assert len(parsed) == 41
    for col in FEATURE_COLUMNS:
        assert col in parsed


def test_missing_features_rejected_in_csv():
    """Verify CSV upload missing one or more required traffic features is rejected."""
    sample_record = PRESET_FLOW_RECORDS["Authentic Benchmark: Normal FTP Session (KDDTest+ Row 2)"]["record"]
    df = pd.DataFrame([sample_record])
    df_missing = df.drop(columns=["duration", "src_bytes"])
    csv_str = df_missing.to_csv(index=False)

    with pytest.raises(ValueError, match="missing 2 required traffic feature"):
        parse_and_validate_csv_upload(csv_str)


def test_invalid_numerical_values_rejected_in_csv():
    """Verify CSV upload with unparseable non-numeric values in numeric columns is rejected."""
    sample_record = dict(PRESET_FLOW_RECORDS["Authentic Benchmark: Normal FTP Session (KDDTest+ Row 2)"]["record"])
    sample_record["src_bytes"] = "invalid_string_not_a_number"
    df = pd.DataFrame([sample_record])
    csv_str = df.to_csv(index=False)

    with pytest.raises(ValueError, match="Invalid non-numeric value"):
        parse_and_validate_csv_upload(csv_str)


def test_empty_and_multi_row_csv_rejected():
    """Verify empty uploads and multi-row CSV files are rejected with clear errors."""
    # Completely empty CSV
    with pytest.raises(ValueError, match="empty"):
        parse_and_validate_csv_upload("")

    with pytest.raises(ValueError, match="empty"):
        parse_and_validate_csv_upload(b"   \n  ")

    # Header only, 0 data rows
    sample_record = PRESET_FLOW_RECORDS["Authentic Benchmark: Normal FTP Session (KDDTest+ Row 2)"]["record"]
    df_empty_data = pd.DataFrame(columns=list(sample_record.keys()))
    with pytest.raises(ValueError, match="0 data rows"):
        parse_and_validate_csv_upload(df_empty_data.to_csv(index=False))

    # Multiple rows (2 rows)
    df_two_rows = pd.DataFrame([sample_record, sample_record])
    with pytest.raises(ValueError, match="multiple rows"):
        parse_and_validate_csv_upload(df_two_rows.to_csv(index=False))


def test_extra_metadata_and_unexpected_columns_rejected_in_csv():
    """Verify uploads containing extra columns (e.g. class, difficulty_level, or unexpected fields) are rejected."""
    sample_record = dict(PRESET_FLOW_RECORDS["Authentic Benchmark: Normal FTP Session (KDDTest+ Row 2)"]["record"])

    # 1. Reject target label ('class') column as unexpected extra column
    sample_with_class = dict(sample_record)
    sample_with_class[LABEL_COLUMN] = "normal"
    df_class = pd.DataFrame([sample_with_class])
    with pytest.raises(ValueError, match="unexpected column.*class"):
        parse_and_validate_csv_upload(df_class.to_csv(index=False))

    # 2. Reject benchmark difficulty column ('difficulty_level') as unexpected extra column
    sample_with_diff = dict(sample_record)
    sample_with_diff[DIFFICULTY_COLUMN] = 21
    df_diff = pd.DataFrame([sample_with_diff])
    with pytest.raises(ValueError, match="unexpected column.*difficulty_level"):
        parse_and_validate_csv_upload(df_diff.to_csv(index=False))

    # 3. Reject arbitrary unexpected column
    sample_with_extra = dict(sample_record)
    sample_with_extra["unexpected_feature_field"] = 999
    df_extra = pd.DataFrame([sample_with_extra])
    with pytest.raises(ValueError, match="unexpected column.*unexpected_feature_field"):
        parse_and_validate_csv_upload(df_extra.to_csv(index=False))



# -------------------------------------------------------------------------
# 3. In-Memory Evaluation Tests (Pure Inference Without Persistence)
# -------------------------------------------------------------------------

def test_valid_record_produces_detection_finding(frozen_engine):
    """Verify valid preset records produce structured DetectionFinding objects."""
    syn_record = PRESET_FLOW_RECORDS["Authentic Benchmark: SYN Flood Burst (KDDTest+ Row 13)"]["record"]
    finding = frozen_engine.detect_record(syn_record)

    assert finding is not None
    assert finding.record_fingerprint == compute_record_fingerprint(syn_record)
    assert finding.model_decision.predicted_label in ["normal", "attack"]
    assert 0.0 <= finding.model_decision.attack_probability <= 1.0
    assert 0.0 <= finding.model_decision.confidence <= 1.0
    assert finding.disposition in ["BENIGN", "MODEL_DETECTED", "RULE_DETECTED", "CORROBORATED"]
    assert finding.overall_severity in ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert len(finding.explanation) > 0


def test_evaluating_record_does_not_modify_database(tmp_path: Path, frozen_engine):
    """Verify evaluating a network flow is purely in-memory and executes zero database writes."""
    db_file = tmp_path / "test_no_writes.db"
    repo = AlertRepository(db_path=db_file)
    repo.initialize_schema()

    # Pre-condition: 0 alerts
    assert len(repo.list_alerts()) == 0

    # Evaluate multiple preset records
    for preset_data in PRESET_FLOW_RECORDS.values():
        finding = frozen_engine.detect_record(preset_data["record"])
        assert finding.threat_detected is not None

    # Post-condition: Database remains completely empty (zero writes)
    assert len(repo.list_alerts()) == 0


# -------------------------------------------------------------------------
# 4. Explicit Persistence & Deduplication Tests
# -------------------------------------------------------------------------

def test_explicit_persistence_creates_and_merges_alert(tmp_path: Path, frozen_engine):
    """Verify explicit persistence creates a new alert and merges subsequent identical flows."""
    db_file = tmp_path / "test_persistence.db"
    repo = AlertRepository(db_path=db_file)
    repo.initialize_schema()

    syn_record = PRESET_FLOW_RECORDS["Authentic Benchmark: SYN Flood Burst (KDDTest+ Row 13)"]["record"]
    finding = frozen_engine.detect_record(syn_record)

    # 1. First persistence -> Creates brand new alert
    prior_active = repo.get_active_alert_by_fingerprint(finding.record_fingerprint)
    assert prior_active is None

    saved_alert1 = repo.save_finding(finding)
    assert saved_alert1.status == AlertStatus.NEW.value
    assert saved_alert1.occurrence_count == 1

    # Database contains exactly 1 alert
    assert len(repo.list_alerts()) == 1

    # 2. Second persistence with same finding -> Merges into active alert
    prior_active2 = repo.get_active_alert_by_fingerprint(finding.record_fingerprint)
    assert prior_active2 is not None
    assert prior_active2.alert_id == saved_alert1.alert_id

    saved_alert2 = repo.save_finding(finding)
    assert saved_alert2.alert_id == saved_alert1.alert_id
    assert saved_alert2.occurrence_count == 2

    # Database still contains exactly 1 alert (merged, not duplicated)
    assert len(repo.list_alerts()) == 1


# -------------------------------------------------------------------------
# 5. Interactive Streamlit AppTest Integration Tests for Demo Tab
# -------------------------------------------------------------------------

def test_apptest_demo_tab_evaluation_and_persistence(tmp_path: Path, monkeypatch):
    """Verify interactive evaluation and optional persistence workflow in Streamlit AppTest."""
    db_file = tmp_path / "apptest_demo.db"
    repo = AlertRepository(db_path=db_file)
    repo.initialize_schema()

    monkeypatch.setenv("THREAT_DETECTION_DB_PATH", str(db_file))

    at = AppTest.from_file(DASHBOARD_APP_PATH, default_timeout=15)
    at.run(timeout=15)
    assert len(at.exception) == 0

    # Locate "Evaluate Flow" button and trigger evaluation
    eval_btn = None
    for btn in at.button:
        if "Evaluate Flow" in btn.label:
            eval_btn = btn
            break

    assert eval_btn is not None, "Evaluate Flow button must be present in demo interface."
    eval_btn.click().run(timeout=15)
    assert len(at.exception) == 0

    # Verify evaluated in-memory warning banner is present (NOT persisted yet)
    warning_texts = [w.value for w in at.warning]
    assert any("Evaluated in memory" in w for w in warning_texts)

    # Verify database still has 0 alerts (evaluating alone did not write)
    assert len(repo.list_alerts()) == 0

    # Locate "Persist Finding as Alert" button and click it
    persist_btn = None
    for btn in at.button:
        if "Persist Finding as Alert" in btn.label and not btn.disabled:
            persist_btn = btn
            break

    assert persist_btn is not None, "Persist Finding as Alert button must be active after evaluation."
    persist_btn.click().run(timeout=15)
    assert len(at.exception) == 0

    # Verify alert was saved to repository
    saved_alerts = repo.list_alerts()
    assert len(saved_alerts) == 1
    assert saved_alerts[0].status == "NEW"

    # Verify UI reports exact resulting alert ID, status, and occurrence count
    assert any(
        "Status: Persisted to database" in s.value
        and f"Alert ID: `{saved_alerts[0].alert_id}`" in s.value
        and "Occurrence Count: `1`" in s.value
        for s in at.success
    )

    # Verify button is now disabled ("Already Saved") to prevent repeated clicks
    disabled_persist_btns = [
        btn for btn in at.button if "Persist Finding as Alert" in btn.label and btn.disabled
    ]
    assert len(disabled_persist_btns) >= 1

    # Rerun app without clicks and verify alert count remains 1 (no duplicate submissions)
    at.run(timeout=15)
    assert len(repo.list_alerts()) == 1


def test_apptest_persistence_failure_handled_cleanly(tmp_path: Path, monkeypatch):
    """Verify persistence failure shows error, does not claim success, and preserves finding for retry."""
    import sqlite3

    db_file = tmp_path / "persistence_failure.db"
    repo = AlertRepository(db_path=db_file)
    repo.initialize_schema()

    monkeypatch.setenv("THREAT_DETECTION_DB_PATH", str(db_file))

    at = AppTest.from_file(DASHBOARD_APP_PATH, default_timeout=15)
    at.run(timeout=15)
    assert len(at.exception) == 0

    # 1. Trigger evaluation
    eval_btn = None
    for btn in at.button:
        if "Evaluate Flow" in btn.label:
            eval_btn = btn
            break
    assert eval_btn is not None
    eval_btn.click().run(timeout=15)
    assert len(at.exception) == 0

    # Verify finding is rendered
    assert any("Evaluated in memory" in w.value for w in at.warning)

    # 2. Mock AlertRepository.save_finding to simulate a database write failure
    def mock_save_failure(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked (simulated write failure)")

    monkeypatch.setattr(AlertRepository, "save_finding", mock_save_failure)

    # 3. Click "Persist Finding as Alert"
    persist_btn = None
    for btn in at.button:
        if "Persist Finding as Alert" in btn.label and not btn.disabled:
            persist_btn = btn
            break
    assert persist_btn is not None

    persist_btn.click().run(timeout=15)
    assert len(at.exception) == 0

    # 4. Verify UI shows error message
    assert len(at.error) >= 1
    assert any("Persistence Failure" in err.value for err in at.error)

    # 5. Verify UI does NOT claim the alert was saved (no success banner for persistence)
    for success_box in at.success:
        assert "Persisted to database" not in success_box.value

    # 6. Verify 0 alerts written to database
    assert len(repo.list_alerts()) == 0

    # 7. Verify finding is preserved in memory and persistence button is still active (not disabled)
    assert any("Evaluated in memory" in w.value for w in at.warning)
    retry_persist_btns = [
        btn for btn in at.button if "Persist Finding as Alert" in btn.label and not btn.disabled
    ]
    assert len(retry_persist_btns) >= 1, "Persist button must remain active for retry after failure."


def test_apptest_missing_model_handled_cleanly(tmp_path: Path, monkeypatch):
    """Verify missing model artifact displays clean error and halts execution without crash."""
    db_file = tmp_path / "missing_model.db"
    monkeypatch.setenv("THREAT_DETECTION_DB_PATH", str(db_file))

    # Mock ThreatDetectionArtifact.load to simulate missing artifact
    def mock_load(filepath):
        raise FileNotFoundError(f"Model artifact not found at: '{filepath}'")

    monkeypatch.setattr(ThreatDetectionArtifact, "load", mock_load)

    at = AppTest.from_file(DASHBOARD_APP_PATH, default_timeout=15)
    at.run(timeout=15)

    assert len(at.exception) == 0
    # Error message rendered
    assert len(at.error) >= 1
    assert any("Model Loading Failure" in err.value for err in at.error)


def test_default_database_untouched():
    """Verify default production database outputs/threat_events.db was not modified or created."""
    prod_db = config.DATABASE_PATH
    if prod_db.exists():
        assert prod_db.is_file()
