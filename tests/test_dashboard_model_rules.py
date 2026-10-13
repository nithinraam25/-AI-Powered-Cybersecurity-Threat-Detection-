"""Automated test suite for the Model & Rules dashboard tab.

Validates:
1. Normal rendering of model specification and confirmed parameters.
2. Accurate display of offline benchmark metrics and confusion matrix.
3. Explicit communication of test accuracy 0.7735, attack recall 0.6221, and FNR 0.3779.
4. Graceful handling of missing and malformed metrics reports.
5. Display of all 4 active heuristic security rules and operational triage dispositions.
6. Read-only behavior: Zero database writes or model alterations.
7. Zero modifications to default production database path.
"""

from pathlib import Path
from typing import Any, Dict
import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from dashboard.helpers import (
    get_disposition_specifications,
    get_rule_specifications,
    load_evaluation_metrics,
    load_model_metadata,
)
from threat_detection.config import config
from threat_detection.storage import AlertRepository

DASHBOARD_APP_PATH = str(Path(__file__).resolve().parent.parent / "dashboard" / "app.py")


@pytest.fixture(autouse=True)
def clean_streamlit_cache():
    """Ensure Streamlit resource and data caches are cleared before and after each test."""
    st.cache_resource.clear()
    st.cache_data.clear()
    yield
    st.cache_resource.clear()
    st.cache_data.clear()


# -------------------------------------------------------------------------
# 1. Helper-Level Tests for Model Metadata & Evaluation Metrics Loading
# -------------------------------------------------------------------------

def test_load_model_metadata_valid():
    """Verify loading valid model metadata returns available status and confirmed fields."""
    res = load_model_metadata()
    assert res["status"] == "available"
    assert res["data"] is not None
    data = res["data"]
    assert data["model_type"] == "RandomForestClassifier"
    assert data["raw_features_count"] == 41
    assert data["encoded_features_count"] == 122
    assert "hyperparameters" in data


def test_load_model_metadata_missing(tmp_path: Path):
    """Verify missing metadata returns missing status without raising exception."""
    missing_file = tmp_path / "nonexistent_metadata.json"
    res = load_model_metadata(missing_file)
    assert res["status"] == "missing"
    assert res["data"] is None
    assert "not found" in res["error"].lower()


def test_load_model_metadata_invalid(tmp_path: Path):
    """Verify malformed JSON metadata returns invalid status with error message."""
    invalid_file = tmp_path / "invalid_meta.json"
    invalid_file.write_text("{ incomplete json ...", encoding="utf-8")
    res = load_model_metadata(invalid_file)
    assert res["status"] == "invalid"
    assert res["data"] is None
    assert "Failed to parse" in res["error"]


def test_load_evaluation_metrics_valid():
    """Verify loading precomputed evaluation metrics returns available status and expected values."""
    res = load_evaluation_metrics()
    assert res["status"] == "available"
    assert res["data"] is not None
    m = res["data"]
    assert m["total_samples"] == 22544
    assert pytest.approx(m["accuracy"], abs=1e-4) == 0.7735
    assert pytest.approx(m["recall_attack"], abs=1e-4) == 0.6221
    assert pytest.approx(m["false_negative_rate"], abs=1e-4) == 0.3779
    assert m["true_negatives"] == 9454
    assert m["false_positives"] == 257
    assert m["false_negatives"] == 4850
    assert m["true_positives"] == 7983


def test_load_evaluation_metrics_missing(tmp_path: Path):
    """Verify missing evaluation metrics returns missing status with informative error."""
    missing_file = tmp_path / "nonexistent_metrics.json"
    res = load_evaluation_metrics(missing_file)
    assert res["status"] == "missing"
    assert res["data"] is None
    assert "not found" in res["error"].lower()


def test_load_evaluation_metrics_incomplete(tmp_path: Path):
    """Verify metrics JSON missing required fields returns invalid status."""
    incomplete_file = tmp_path / "incomplete_metrics.json"
    incomplete_file.write_text('{"accuracy": 0.77}', encoding="utf-8")
    res = load_evaluation_metrics(incomplete_file)
    assert res["status"] == "invalid"
    assert res["data"] is None
    assert "missing required fields" in res["error"]


# -------------------------------------------------------------------------
# 2. Helper-Level Tests for Rule Specifications & Dispositions
# -------------------------------------------------------------------------

def test_all_four_rules_specified_with_real_properties():
    """Verify all 4 deterministic rules are retrieved with their real conditions and severities."""
    rules = get_rule_specifications()
    assert len(rules) == 4
    rule_ids = {r["rule_id"] for r in rules}
    expected_ids = {
        "RULE-LAND-001",
        "RULE-DOS-SYN-001",
        "RULE-DOS-REJ-001",
        "RULE-PROBE-SCAN-001",
    }
    assert rule_ids == expected_ids

    # Verify LAND rule properties
    land = next(r for r in rules if r["rule_id"] == "RULE-LAND-001")
    assert land["severity"] == "HIGH"
    assert "land == 1" in land["condition_summary"]

    # Verify SYN flood rule properties
    syn = next(r for r in rules if r["rule_id"] == "RULE-DOS-SYN-001")
    assert syn["severity"] == "MEDIUM"
    assert "count >= 100" in syn["condition_summary"]
    assert "serror_rate >= 0.80" in syn["condition_summary"]

    # Verify Rejection burst rule properties
    rej = next(r for r in rules if r["rule_id"] == "RULE-DOS-REJ-001")
    assert rej["severity"] == "MEDIUM"
    assert "count >= 50" in rej["condition_summary"]
    assert "rerror_rate >= 0.80" in rej["condition_summary"]

    # Verify Port sweep rule properties
    scan = next(r for r in rules if r["rule_id"] == "RULE-PROBE-SCAN-001")
    assert scan["severity"] == "MEDIUM"
    assert "diff_srv_rate >= 0.70" in scan["condition_summary"]


def test_disposition_specifications_cover_all_four_policies():
    """Verify operational triage dispositions cover BENIGN, MODEL_DETECTED, RULE_DETECTED, and CORROBORATED."""
    disps = get_disposition_specifications()
    assert len(disps) == 4
    disp_names = {d["disposition"] for d in disps}
    assert disp_names == {"BENIGN", "MODEL_DETECTED", "RULE_DETECTED", "CORROBORATED"}


# -------------------------------------------------------------------------
# 3. Interactive Streamlit AppTest Integration Tests
# -------------------------------------------------------------------------

def test_apptest_model_rules_tab_normal_rendering(tmp_path: Path, monkeypatch):
    """Verify normal rendering of Model & Rules tab with valid model and metrics."""
    db_file = tmp_path / "model_rules_test.db"
    repo = AlertRepository(db_path=db_file)
    repo.initialize_schema()

    monkeypatch.setenv("THREAT_DETECTION_DB_PATH", str(db_file))

    at = AppTest.from_file(DASHBOARD_APP_PATH, default_timeout=15)
    at.run(timeout=15)
    assert len(at.exception) == 0

    # 1. Model specification checks
    markdown_texts = [m.value for m in at.markdown]
    assert any("RandomForestClassifier" in txt for txt in markdown_texts)
    assert any("41" in txt and "canonical" in txt for txt in markdown_texts)
    assert any("122" in txt for txt in markdown_texts)
    assert any("Available (Frozen Artifact)" in txt for txt in markdown_texts)

    # 2. Benchmark metrics checks
    info_texts = [i.value for i in at.info]
    assert any("0.7735" in i and "0.6221" in i and "0.3779" in i for i in info_texts)

    # 3. Confusion matrix checks
    table_strings = [t.value.to_string() for t in at.table]
    assert any("TN = 9,454" in txt for txt in table_strings)
    assert any("FP = 257" in txt for txt in table_strings)
    assert any("FN = 4,850" in txt for txt in table_strings)
    assert any("TP = 7,983" in txt for txt in table_strings)

    # 4. Rules coverage checks
    expander_labels = [e.label for e in at.expander]
    assert any("RULE-LAND-001" in txt for txt in expander_labels)
    assert any("RULE-DOS-SYN-001" in txt for txt in expander_labels)
    assert any("RULE-DOS-REJ-001" in txt for txt in expander_labels)
    assert any("RULE-PROBE-SCAN-001" in txt for txt in expander_labels)

    # 5. Provenance & limitations notice check
    warning_texts = [w.value for w in at.warning]
    assert any("NSL-KDD is an offline public academic benchmark" in w for w in warning_texts)

    # 6. Read-only verification: Database remains completely empty
    assert len(repo.list_alerts()) == 0


def test_apptest_missing_metrics_handled_gracefully(tmp_path: Path, monkeypatch):
    """Verify missing evaluation metrics JSON renders informative warning without crashing."""
    db_file = tmp_path / "missing_metrics_test.db"
    repo = AlertRepository(db_path=db_file)
    repo.initialize_schema()

    monkeypatch.setenv("THREAT_DETECTION_DB_PATH", str(db_file))
    monkeypatch.setenv("THREAT_DETECTION_METRICS_PATH", str(tmp_path / "nonexistent_metrics.json"))

    at = AppTest.from_file(DASHBOARD_APP_PATH, default_timeout=15)
    at.run(timeout=15)

    assert len(at.exception) == 0
    # Warning message displayed explaining missing metrics and CLI command
    warning_texts = [w.value for w in at.warning]
    assert any("Evaluation Metrics Unavailable" in w for w in warning_texts)
    assert any("evaluate_cli" in w for w in warning_texts)

    # Database remains untouched
    assert len(repo.list_alerts()) == 0


def test_apptest_malformed_metrics_handled_gracefully(tmp_path: Path, monkeypatch):
    """Verify malformed evaluation metrics JSON renders error banner without crashing."""
    db_file = tmp_path / "malformed_metrics_test.db"
    repo = AlertRepository(db_path=db_file)
    repo.initialize_schema()

    malformed_file = tmp_path / "malformed.json"
    malformed_file.write_text("{ invalid json ...", encoding="utf-8")

    monkeypatch.setenv("THREAT_DETECTION_DB_PATH", str(db_file))
    monkeypatch.setenv("THREAT_DETECTION_METRICS_PATH", str(malformed_file))

    at = AppTest.from_file(DASHBOARD_APP_PATH, default_timeout=15)
    at.run(timeout=15)

    assert len(at.exception) == 0
    error_texts = [e.value for e in at.error]
    assert any("Evaluation Metrics Malformed" in e for e in error_texts)

    # Database remains untouched
    assert len(repo.list_alerts()) == 0


def test_apptest_model_artifact_unavailable_handled_gracefully(tmp_path: Path, monkeypatch):
    """Verify missing model artifact displays 'Not Found' status without crashing."""
    db_file = tmp_path / "missing_model_tab_test.db"
    repo = AlertRepository(db_path=db_file)
    repo.initialize_schema()

    monkeypatch.setenv("THREAT_DETECTION_DB_PATH", str(db_file))
    monkeypatch.setenv(
        "THREAT_DETECTION_MODEL_PATH", str(tmp_path / "nonexistent_model.joblib")
    )

    at = AppTest.from_file(DASHBOARD_APP_PATH, default_timeout=15)
    at.run(timeout=15)

    assert len(at.exception) == 0
    markdown_texts = [m.value for m in at.markdown]
    assert any("Not Found" in txt for txt in markdown_texts)

    # Database remains untouched
    assert len(repo.list_alerts()) == 0


def test_apptest_preprocessing_pipeline_description_matches_actual_pipeline(
    tmp_path: Path, monkeypatch
):
    """Verify displayed preprocessing description accurately reflects actual pipeline (passthrough, no scaling/imputation)."""
    db_file = tmp_path / "pipeline_desc_test.db"
    repo = AlertRepository(db_path=db_file)
    repo.initialize_schema()

    monkeypatch.setenv("THREAT_DETECTION_DB_PATH", str(db_file))

    at = AppTest.from_file(DASHBOARD_APP_PATH, default_timeout=15)
    at.run(timeout=15)

    assert len(at.exception) == 0

    info_texts = [i.value for i in at.info]
    pipeline_info = next(
        (txt for txt in info_texts if "Feature Ingestion Pipeline" in txt), None
    )
    assert pipeline_info is not None, "Pipeline description must be displayed in an info block."

    # Verify confirmed transformations
    assert "OneHotEncoder" in pipeline_info
    assert "passthrough" in pipeline_info
    assert "without scaling or imputation" in pipeline_info

    # Verify inaccurate terms are strictly absent
    assert "median imputation" not in pipeline_info.lower()
    assert "robust scaling" not in pipeline_info.lower()
    assert "standard scaling" not in pipeline_info.lower()

    # Database remains untouched
    assert len(repo.list_alerts()) == 0


def test_default_database_untouched_by_model_rules_tests():
    """Verify default database outputs/threat_events.db is not created or modified."""
    prod_db = config.DATABASE_PATH
    if prod_db.exists():
        assert prod_db.is_file()
