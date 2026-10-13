"""End-to-end integration test suite for the AI-Powered Cybersecurity Threat Detection System.

Validates cross-component interactions across data ingestion, preprocessing,
frozen model inference, deterministic heuristic rules, fingerprinting, alert persistence,
lifecycle state transitions, and dashboard helpers.

Scope: Defensive educational cybersecurity portfolio testing using NSL-KDD benchmark data.
Zero live monitoring or production protection is claimed.
All tests isolate database operations using tmp_path and preserve frozen artifacts.
"""

import hashlib
import io
import os
from pathlib import Path
from typing import Any, Dict
import pandas as pd
import pytest

from dashboard.helpers import (
    compute_kpis,
    filter_alerts_on_page,
    load_evaluation_metrics,
    parse_and_validate_csv_upload,
    resolve_database_path,
)
from threat_detection.config import config
from threat_detection.data.loader import load_nsl_kdd
from threat_detection.data.schema import FEATURE_COLUMNS
from threat_detection.detection.engine import (
    DetectionFinding,
    ThreatDetectionEngine,
    compute_record_fingerprint,
)
from threat_detection.detection.trainer import ThreatDetectionArtifact
from threat_detection.preprocessing.pipeline import (
    split_features_and_target,
    validate_traffic_features,
)
from threat_detection.storage import (
    AlertRecord,
    AlertRepository,
    AlertStatus,
    InvalidLifecycleTransitionError,
)

CANONICAL_MODEL_HASH = "0E364EA84FA5F35BA1CE2FF025235ED70B0BEE9423611C354CE520F69E60F6C5"
CANONICAL_TRAIN_HASH = "1B86D2F957B33082081BBA410FE129B475EFEBCC13C9014C3F447C8271AADF95"
CANONICAL_TEST_HASH = "FA46B0935342616AA83B7C2578DB355B6A7AAABBC492248172C7A1E8B7AB8F84"


def _hash_file(filepath: Path) -> str:
    """Calculate the uppercase hexadecimal SHA-256 digest of a file."""
    h = hashlib.sha256()
    with filepath.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().upper()


@pytest.fixture(scope="module")
def frozen_artifact() -> ThreatDetectionArtifact:
    """Load the frozen RandomForest binary model artifact."""
    model_path = config.MODELS_DIR / "baseline_rf_binary.joblib"
    assert model_path.exists(), f"Model artifact missing at {model_path}"
    return ThreatDetectionArtifact.load(model_path)


@pytest.fixture(scope="module")
def frozen_engine(frozen_artifact: ThreatDetectionArtifact) -> ThreatDetectionEngine:
    """Instantiate the ThreatDetectionEngine with frozen model and default rules."""
    return ThreatDetectionEngine(artifact=frozen_artifact)


@pytest.fixture(scope="module")
def kdd_test_data() -> tuple[pd.DataFrame, pd.Series]:
    """Load and separate features and labels for the NSL-KDD test benchmark once."""
    test_path = config.RAW_DATA_DIR / "KDDTest+.txt"
    assert test_path.exists(), f"Test benchmark missing at {test_path}"
    df = load_nsl_kdd(test_path)
    X, y = split_features_and_target(df)
    return X, y


# =========================================================================
# Scenario 1: Normal Benchmark Record End-to-End Execution
# =========================================================================

def test_normal_benchmark_record_pipeline(
    frozen_engine: ThreatDetectionEngine,
    kdd_test_data: tuple[pd.DataFrame, pd.Series],
) -> None:
    """Verify authentic normal benchmark record produces expected benign finding."""
    X, y = kdd_test_data
    # Row 2 in KDDTest+ is a verified normal FTP session
    assert y.iloc[2] == "normal"
    normal_record = X.iloc[2].to_dict()

    finding = frozen_engine.detect_record(normal_record, record_index=2)

    assert isinstance(finding, DetectionFinding)
    assert finding.record_index == 2
    assert finding.threat_detected is False
    assert finding.model_decision.predicted_label == "normal"
    assert finding.model_decision.attack_probability <= 0.05
    assert finding.disposition == "BENIGN"
    assert finding.overall_severity == "INFORMATIONAL"
    assert len(finding.rule_matches) == 0
    assert len(finding.record_fingerprint) == 64
    assert all(c in "0123456789abcdef" for c in finding.record_fingerprint)
    assert "classified as normal" in finding.explanation


# =========================================================================
# Scenario 2: Attack Benchmark Record End-to-End Corroboration
# =========================================================================

def test_attack_benchmark_record_corroboration(
    frozen_engine: ThreatDetectionEngine,
    kdd_test_data: tuple[pd.DataFrame, pd.Series],
) -> None:
    """Verify authentic attack benchmark record produces corroborated threat finding."""
    X, y = kdd_test_data
    # Row 13 in KDDTest+ is a verified neptune SYN flood burst
    assert y.iloc[13] == "neptune"
    attack_record = X.iloc[13].to_dict()

    finding = frozen_engine.detect_record(attack_record, record_index=13)

    assert isinstance(finding, DetectionFinding)
    assert finding.threat_detected is True
    assert finding.model_decision.predicted_label == "attack"
    assert finding.model_decision.attack_probability >= 0.80
    assert finding.disposition == "CORROBORATED"
    assert finding.overall_severity == "HIGH"

    matched_ids = [r.rule_id for r in finding.rule_matches]
    assert "RULE-DOS-SYN-001" in matched_ids
    assert "Corroborated threat finding" in finding.explanation


# =========================================================================
# Scenario 3: Input Validation and Boundary Rejection
# =========================================================================

def test_input_validation_and_boundary_rejection(
    frozen_engine: ThreatDetectionEngine,
    kdd_test_data: tuple[pd.DataFrame, pd.Series],
) -> None:
    """Verify strict rejection of malformed inputs, data leakage, and upload violations."""
    X, _ = kdd_test_data
    base_record = X.iloc[0].to_dict()

    # 3a: Missing required feature
    missing_record = dict(base_record)
    del missing_record["dst_bytes"]
    with pytest.raises(ValueError, match="missing.*required traffic feature"):
        frozen_engine.detect_record(missing_record)

    # 3b: Invalid non-numeric value in numerical feature
    bad_num_record = dict(base_record)
    bad_num_record["src_bytes"] = "invalid_string_val"
    with pytest.raises(ValueError, match="Invalid non-numeric value"):
        frozen_engine.detect_record(bad_num_record)

    # 3c: Target label leakage protection in DataFrame
    leakage_df = pd.DataFrame([base_record])
    leakage_df["class"] = "normal"
    with pytest.raises(ValueError, match="Target label column 'class' must not be present"):
        validate_traffic_features(leakage_df)

    # 3d: Programmatic contract permits auxiliary extra columns (sliced safely)
    df_with_extra = pd.DataFrame([base_record])
    df_with_extra["auxiliary_flow_id"] = "flow-998811"
    validate_traffic_features(df_with_extra)  # Succeeds without raising
    prog_finding = frozen_engine.detect_record(df_with_extra.iloc[0].to_dict())
    assert isinstance(prog_finding, DetectionFinding)

    # 3e: Strict CSV upload schema rejection (rejects ANY unexpected column)
    valid_csv_df = pd.DataFrame([base_record])
    csv_buffer = io.StringIO()
    valid_csv_df.to_csv(csv_buffer, index=False)
    valid_csv_text = csv_buffer.getvalue()

    # Valid CSV parses cleanly
    parsed = parse_and_validate_csv_upload(valid_csv_text)
    assert set(parsed.keys()) == set(FEATURE_COLUMNS)

    # Unexpected extra column in CSV upload is strictly rejected
    invalid_csv_df = valid_csv_df.copy()
    invalid_csv_df["auxiliary_flow_id"] = "flow-998811"
    invalid_csv_buf = io.StringIO()
    invalid_csv_df.to_csv(invalid_csv_buf, index=False)
    with pytest.raises(ValueError, match="Uploaded CSV contains unexpected column"):
        parse_and_validate_csv_upload(invalid_csv_buf.getvalue())


# =========================================================================
# Scenario 4: Finding Persistence and Retrieval in Isolated DB
# =========================================================================

def test_persistence_and_retrieval_isolated_db(
    frozen_engine: ThreatDetectionEngine,
    kdd_test_data: tuple[pd.DataFrame, pd.Series],
    tmp_path: Path,
) -> None:
    """Verify persisting a detection finding and retrieving it via separate repo instance."""
    X, _ = kdd_test_data
    isolated_db = tmp_path / "test_roundtrip.db"

    # Instance 1: Initialize schema and save finding
    repo_writer = AlertRepository(db_path=isolated_db)
    repo_writer.initialize_schema()

    finding = frozen_engine.detect_record(X.iloc[13].to_dict(), record_index=13)
    saved = repo_writer.save_finding(finding)

    assert isinstance(saved, AlertRecord)
    assert saved.status == AlertStatus.NEW.value
    assert saved.occurrence_count == 1
    assert saved.overall_severity == "HIGH"

    # Instance 2: Separate connection instance retrieving from the isolated file
    repo_reader = AlertRepository(db_path=isolated_db)
    retrieved = repo_reader.get_alert_by_id(saved.alert_id)

    assert retrieved is not None
    assert retrieved.alert_id == saved.alert_id
    assert retrieved.record_fingerprint == finding.record_fingerprint
    assert retrieved.disposition == finding.disposition
    assert retrieved.overall_severity == finding.overall_severity
    assert retrieved.predicted_label == finding.model_decision.predicted_label
    assert abs(retrieved.attack_probability - finding.model_decision.attack_probability) < 1e-5
    assert retrieved.status == AlertStatus.NEW.value
    assert "RULE-DOS-SYN-001" in retrieved.rule_ids


# =========================================================================
# Scenario 5: Duplicate Finding Deduplication and Occurrence Counts
# =========================================================================

def test_deduplication_behavior_and_occurrence_count(
    frozen_engine: ThreatDetectionEngine,
    kdd_test_data: tuple[pd.DataFrame, pd.Series],
    tmp_path: Path,
) -> None:
    """Verify active duplicates merge into existing alert with incremented count."""
    X, _ = kdd_test_data
    isolated_db = tmp_path / "test_dedup.db"
    repo = AlertRepository(db_path=isolated_db)
    repo.initialize_schema()

    finding_1 = frozen_engine.detect_record(X.iloc[13].to_dict())
    alert_1 = repo.save_finding(finding_1)

    # Re-evaluate identical telemetry record (same fingerprint)
    finding_2 = frozen_engine.detect_record(X.iloc[13].to_dict())
    alert_2 = repo.save_finding(finding_2)

    assert alert_2.alert_id == alert_1.alert_id
    assert alert_2.record_fingerprint == alert_1.record_fingerprint
    assert alert_2.occurrence_count == 2
    assert alert_2.status == AlertStatus.NEW.value

    # Verify database contains exactly 1 row
    all_alerts = repo.list_alerts(limit=10)
    assert len(all_alerts) == 1
    assert all_alerts[0].occurrence_count == 2


# =========================================================================
# Scenario 6: Alert Lifecycle Transitions and State Machine Enforcement
# =========================================================================

def test_alert_lifecycle_state_machine(
    frozen_engine: ThreatDetectionEngine,
    kdd_test_data: tuple[pd.DataFrame, pd.Series],
    tmp_path: Path,
) -> None:
    """Verify strict NEW -> ACKNOWLEDGED -> RESOLVED lifecycle state machine."""
    X, _ = kdd_test_data
    isolated_db = tmp_path / "test_lifecycle.db"
    repo = AlertRepository(db_path=isolated_db)
    repo.initialize_schema()

    finding = frozen_engine.detect_record(X.iloc[13].to_dict())
    saved = repo.save_finding(finding)
    assert saved.status == AlertStatus.NEW.value

    # 1. Illegal transition: direct NEW -> RESOLVED must be rejected
    with pytest.raises(InvalidLifecycleTransitionError, match="Cannot resolve alert.*directly from 'NEW'"):
        repo.resolve_alert(saved.alert_id)

    # Verify state remains NEW
    current = repo.get_alert_by_id(saved.alert_id)
    assert current is not None
    assert current.status == AlertStatus.NEW.value

    # 2. Valid transition: NEW -> ACKNOWLEDGED
    ack = repo.acknowledge_alert(saved.alert_id, analyst_notes="Investigating SYN flood")
    assert ack.status == AlertStatus.ACKNOWLEDGED.value
    assert ack.acknowledged_at is not None
    assert ack.analyst_notes == "Investigating SYN flood"

    # 3. Idempotent acknowledgement updates notes without breaking state
    ack_again = repo.acknowledge_alert(saved.alert_id, analyst_notes="Updated notes: confirmed attack")
    assert ack_again.status == AlertStatus.ACKNOWLEDGED.value
    assert ack_again.acknowledged_at == ack.acknowledged_at
    assert ack_again.analyst_notes == "Updated notes: confirmed attack"

    # 4. Valid transition: ACKNOWLEDGED -> RESOLVED
    res = repo.resolve_alert(saved.alert_id, analyst_notes="Mitigated upstream")
    assert res.status == AlertStatus.RESOLVED.value
    assert res.resolved_at is not None
    assert res.analyst_notes == "Mitigated upstream"

    # 5. Illegal transition: cannot acknowledge an already RESOLVED alert
    with pytest.raises(InvalidLifecycleTransitionError, match="already in 'RESOLVED' status"):
        repo.acknowledge_alert(saved.alert_id)


# =========================================================================
# Scenario 7: Dashboard Helpers Interaction with Stored Alerts
# =========================================================================

def test_dashboard_helpers_with_stored_alerts(
    frozen_engine: ThreatDetectionEngine,
    kdd_test_data: tuple[pd.DataFrame, pd.Series],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify dashboard helpers accurately query and aggregate alerts from isolated DB."""
    X, _ = kdd_test_data
    isolated_db = tmp_path / "test_dashboard.db"

    # Set environment override and assert resolve_database_path picks it up
    monkeypatch.setenv("THREAT_DETECTION_DB_PATH", str(isolated_db))
    assert resolve_database_path() == isolated_db

    repo = AlertRepository(db_path=isolated_db)
    repo.initialize_schema()

    # Populate 3 distinct alerts:
    # Alert 1: Corroborated attack (Row 13) -> NEW
    f1 = frozen_engine.detect_record(X.iloc[13].to_dict())
    a1 = repo.save_finding(f1)

    # Alert 2: Benign normal (Row 2) -> ACKNOWLEDGED
    f2 = frozen_engine.detect_record(X.iloc[2].to_dict())
    a2 = repo.save_finding(f2)
    repo.acknowledge_alert(a2.alert_id, analyst_notes="Reviewed benign flow")

    # Alert 3: LAND anomaly (Row 4892) -> RESOLVED
    f3 = frozen_engine.detect_record(X.iloc[4892].to_dict())
    a3 = repo.save_finding(f3)
    repo.acknowledge_alert(a3.alert_id)
    repo.resolve_alert(a3.alert_id, analyst_notes="Closed LAND incident")

    # Verify KPI calculations
    summary = repo.get_summary_counts()
    kpis = compute_kpis(summary)
    assert kpis["total"] == 3
    assert kpis["new"] == 1
    assert kpis["acknowledged"] == 1
    assert kpis["resolved"] == 1
    assert kpis["high_critical"] == 2  # a1 and a3 are HIGH severity

    # Verify status filtering
    new_alerts = repo.list_alerts(status=AlertStatus.NEW.value)
    assert len(new_alerts) == 1
    assert new_alerts[0].alert_id == a1.alert_id

    # Verify page-level text search
    matched_page = filter_alerts_on_page(new_alerts, "RULE-DOS-SYN-001")
    assert len(matched_page) == 1
    assert matched_page[0].alert_id == a1.alert_id

    unmatched_page = filter_alerts_on_page(new_alerts, "nonexistent_query_xyz")
    assert len(unmatched_page) == 0


# =========================================================================
# Scenario 8: Truthful Error Reporting and Failure Handling
# =========================================================================

def test_truthful_error_reporting_and_failure_handling(tmp_path: Path) -> None:
    """Verify truthful, explicit error reporting across core failure modes."""
    # 8a: Missing model artifact raises FileNotFoundError
    nonexistent_model = tmp_path / "nonexistent_model.joblib"
    with pytest.raises(FileNotFoundError, match="Model artifact not found"):
        ThreatDetectionArtifact.load(nonexistent_model)

    # 8b: Missing metrics file returns documented missing status dict
    nonexistent_metrics = tmp_path / "missing_metrics.json"
    metrics_result = load_evaluation_metrics(metrics_path=nonexistent_metrics)
    assert metrics_result["status"] == "missing"
    assert metrics_result["data"] is None
    assert "not found" in metrics_result["error"]

    # 8c: Missing alert lookup returns None gracefully
    repo = AlertRepository(db_path=tmp_path / "empty.db")
    repo.initialize_schema()
    assert repo.get_alert_by_id("00000000-0000-0000-0000-000000000000") is None

    # 8d: Malformed fingerprint rejected with ValueError
    with pytest.raises(ValueError, match="Invalid record_fingerprint"):
        repo.get_active_alert_by_fingerprint("too_short_fingerprint")


# =========================================================================
# Scenario 9: Protection of Frozen Model and Dataset Artifacts
# =========================================================================

def test_frozen_artifact_protection() -> None:
    """Verify that model artifact and benchmark datasets retain canonical SHA-256 hashes."""
    model_path = config.MODELS_DIR / "baseline_rf_binary.joblib"
    train_path = config.RAW_DATA_DIR / "KDDTrain+.txt"
    test_path = config.RAW_DATA_DIR / "KDDTest+.txt"

    assert _hash_file(model_path) == CANONICAL_MODEL_HASH
    assert _hash_file(train_path) == CANONICAL_TRAIN_HASH
    assert _hash_file(test_path) == CANONICAL_TEST_HASH


# =========================================================================
# Scenario 10: Default Database Isolation Safety
# =========================================================================

def test_default_database_isolation_safety() -> None:
    """Confirm the production default database is never created or touched during testing."""
    default_db_path = config.DATABASE_PATH
    assert not default_db_path.exists(), (
        f"Production default database '{default_db_path}' was unexpectedly created!"
    )
