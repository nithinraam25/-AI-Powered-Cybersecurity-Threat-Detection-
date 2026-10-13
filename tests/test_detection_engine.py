"""Automated unit and integration tests for ThreatDetectionEngine and SecurityRules.

All tests utilize small, self-contained artificial records and fixtures.
Zero full-dataset downloads or external network resources are required.
"""

from typing import Any, Dict, List
import numpy as np
import pandas as pd
import pytest

from threat_detection.data.schema import (
    COLUMNS_43,
    FEATURE_COLUMNS,
)
from threat_detection.detection.engine import (
    DetectionFinding,
    ModelDecision,
    ThreatDetectionEngine,
    compute_record_fingerprint,
)
from threat_detection.detection.rules import (
    ConnectionRejectionBurstRule,
    LandAttackRule,
    LandRuleConfig,
    MultiServicePortSweepRule,
    PortScanRuleConfig,
    RejectionBurstRuleConfig,
    RuleMatch,
    SecurityRulesConfig,
    SynFloodHeuristicRule,
    SynFloodRuleConfig,
    create_default_security_rules,
)
from threat_detection.detection.target import (
    BINARY_LABEL_ATTACK,
    BINARY_LABEL_NORMAL,
)
from threat_detection.detection.trainer import (
    ThreatDetectionArtifact,
    train_binary_model,
)


def _make_dummy_feature_row(
    proto: str = "tcp",
    service: str = "http",
    flag: str = "SF",
    duration: int = 0,
    src_bytes: int = 181,
    dst_bytes: int = 5450,
    land: int = 0,
    count: int = 8,
    serror_rate: float = 0.0,
    rerror_rate: float = 0.0,
    diff_srv_rate: float = 0.0,
    dst_host_diff_srv_rate: float = 0.0,
) -> Dict[str, Any]:
    """Generate a dictionary mapping all 41 canonical traffic features."""
    values = [
        duration, proto, service, flag, src_bytes, dst_bytes, land, 0, 0, 0, 0,
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, count, 8,
        serror_rate, 0.0, rerror_rate, 0.0, 1.0, diff_srv_rate, 0.0, 9, 9, 1.0,
        dst_host_diff_srv_rate, 0.11, 0.0, 0.0, 0.0, 0.0, 0.0
    ]
    return dict(zip(FEATURE_COLUMNS, values))


class FakeArtifact:
    """Deterministic mock artifact for focused unit testing."""

    def __init__(self, fixed_label: str = "normal", attack_prob: float = 0.1) -> None:
        self.fixed_label = fixed_label
        self.attack_prob = attack_prob
        # Order: ['attack', 'normal'] to match baseline
        self.classes_ = np.array([BINARY_LABEL_ATTACK, BINARY_LABEL_NORMAL])

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        return np.array([self.fixed_label] * len(X))

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        n = len(X)
        atk = np.full(n, self.attack_prob)
        norm = 1.0 - atk
        # column 0 is attack, column 1 is normal
        return np.column_stack([atk, norm])


# -------------------------------------------------------------------------
# Rule-Specific Tests
# -------------------------------------------------------------------------

def test_land_rule_matches_and_non_matches():
    """Verify RULE-LAND-001 triggers only on land=1 and has initial HIGH severity."""
    rule = LandAttackRule()
    assert rule.rule_id == "RULE-LAND-001"

    match_rec = _make_dummy_feature_row(land=1)
    res = rule.evaluate(match_rec)
    assert res is not None
    assert res.rule_id == "RULE-LAND-001"
    assert res.severity == "HIGH"
    assert res.matched_fields == {"land": 1}

    non_match_rec = _make_dummy_feature_row(land=0)
    assert rule.evaluate(non_match_rec) is None


def test_syn_flood_rule_matches_and_non_matches():
    """Verify RULE-DOS-SYN-001 triggers when count, serror_rate, and flag conditions hold."""
    rule = SynFloodHeuristicRule()
    assert rule.rule_id == "RULE-DOS-SYN-001"

    # Match: count >= 100, serror_rate >= 0.8, flag in {'S0', ...}
    match_rec = _make_dummy_feature_row(count=120, serror_rate=0.85, flag="S0")
    res = rule.evaluate(match_rec)
    assert res is not None
    assert res.rule_id == "RULE-DOS-SYN-001"
    assert res.severity == "MEDIUM"
    assert res.matched_fields["count"] == 120

    # Non-matches (each failing one condition)
    assert rule.evaluate(_make_dummy_feature_row(count=99, serror_rate=0.85, flag="S0")) is None
    assert rule.evaluate(_make_dummy_feature_row(count=120, serror_rate=0.79, flag="S0")) is None
    assert rule.evaluate(_make_dummy_feature_row(count=120, serror_rate=0.85, flag="SF")) is None


def test_rejection_burst_rule_matches_and_non_matches():
    """Verify RULE-DOS-REJ-001 triggers on rejection rate bursts."""
    rule = ConnectionRejectionBurstRule()
    assert rule.rule_id == "RULE-DOS-REJ-001"

    # Match: count >= 50, rerror_rate >= 0.80, flag in {'REJ', 'RSTO', 'RSTR'}
    match_rec = _make_dummy_feature_row(count=60, rerror_rate=0.90, flag="REJ")
    res = rule.evaluate(match_rec)
    assert res is not None
    assert res.rule_id == "RULE-DOS-REJ-001"
    assert res.severity == "MEDIUM"

    # Non-matches
    assert rule.evaluate(_make_dummy_feature_row(count=49, rerror_rate=0.90, flag="REJ")) is None
    assert rule.evaluate(_make_dummy_feature_row(count=60, rerror_rate=0.79, flag="REJ")) is None
    assert rule.evaluate(_make_dummy_feature_row(count=60, rerror_rate=0.90, flag="SF")) is None


def test_port_scan_rule_matches_and_non_matches():
    """Verify RULE-PROBE-SCAN-001 triggers on multi-service probing."""
    rule = MultiServicePortSweepRule()
    assert rule.rule_id == "RULE-PROBE-SCAN-001"

    # Match: count >= 50, diff_srv_rate >= 0.70, dst_host_diff_srv_rate >= 0.70
    match_rec = _make_dummy_feature_row(count=55, diff_srv_rate=0.75, dst_host_diff_srv_rate=0.80)
    res = rule.evaluate(match_rec)
    assert res is not None
    assert res.rule_id == "RULE-PROBE-SCAN-001"
    assert res.severity == "MEDIUM"

    # Non-matches
    assert rule.evaluate(_make_dummy_feature_row(count=49, diff_srv_rate=0.75, dst_host_diff_srv_rate=0.80)) is None
    assert rule.evaluate(_make_dummy_feature_row(count=55, diff_srv_rate=0.69, dst_host_diff_srv_rate=0.80)) is None
    assert rule.evaluate(_make_dummy_feature_row(count=55, diff_srv_rate=0.75, dst_host_diff_srv_rate=0.69)) is None


def test_configurable_rule_thresholds():
    """Verify thresholds can be customized via config dataclass for all rules."""
    # 1. Custom SynFlood threshold
    syn_cfg = SynFloodRuleConfig(
        count_threshold=20,
        serror_rate_threshold=0.50,
        target_flags={"S1"},
        severity="HIGH",
    )
    syn_rule = SynFloodHeuristicRule(config=syn_cfg)
    # Fails default (count < 100), but passes custom threshold (count >= 20)
    rec_syn = _make_dummy_feature_row(count=25, serror_rate=0.55, flag="S1")
    res_syn = syn_rule.evaluate(rec_syn)
    assert res_syn is not None
    assert res_syn.severity == "HIGH"

    # 2. Custom Rejection Burst threshold
    rej_cfg = RejectionBurstRuleConfig(
        count_threshold=15,
        rerror_rate_threshold=0.60,
        target_flags={"RSTO"},
        severity="HIGH",
    )
    rej_rule = ConnectionRejectionBurstRule(config=rej_cfg)
    # Fails default (count < 50), passes custom threshold (count >= 15)
    rec_rej = _make_dummy_feature_row(count=20, rerror_rate=0.65, flag="RSTO")
    res_rej = rej_rule.evaluate(rec_rej)
    assert res_rej is not None
    assert res_rej.severity == "HIGH"

    # 3. Custom Port Scan threshold
    scan_cfg = PortScanRuleConfig(
        count_threshold=25,
        diff_srv_rate_threshold=0.50,
        dst_host_diff_srv_rate_threshold=0.50,
        severity="CRITICAL",
    )
    scan_rule = MultiServicePortSweepRule(config=scan_cfg)
    # Fails default (count < 50), passes custom threshold (count >= 25)
    rec_scan = _make_dummy_feature_row(count=30, diff_srv_rate=0.55, dst_host_diff_srv_rate=0.55)
    res_scan = scan_rule.evaluate(rec_scan)
    assert res_scan is not None
    assert res_scan.severity == "CRITICAL"

    # 4. Custom Land rule severity
    land_cfg = LandRuleConfig(severity="CRITICAL")
    land_rule = LandAttackRule(config=land_cfg)
    rec_land = _make_dummy_feature_row(land=1)
    res_land = land_rule.evaluate(rec_land)
    assert res_land is not None
    assert res_land.severity == "CRITICAL"



# -------------------------------------------------------------------------
# Fingerprint Determinism Tests
# -------------------------------------------------------------------------

def test_deterministic_record_fingerprint():
    """Verify fingerprint is strictly deterministic and identical across runs."""
    rec = _make_dummy_feature_row(src_bytes=200, count=10)
    fp1 = compute_record_fingerprint(rec)
    fp2 = compute_record_fingerprint(rec)

    assert isinstance(fp1, str)
    assert len(fp1) == 64  # SHA-256 hex length
    assert fp1 == fp2


def test_fingerprint_independent_of_timestamp_and_row_index():
    """Verify fingerprint ignores metadata and row index."""
    rec1 = _make_dummy_feature_row(duration=5)
    rec2 = _make_dummy_feature_row(duration=5)

    # Identical features must yield identical fingerprint
    assert compute_record_fingerprint(rec1) == compute_record_fingerprint(rec2)

    # Different feature value yields distinct fingerprint
    rec3 = _make_dummy_feature_row(duration=6)
    assert compute_record_fingerprint(rec1) != compute_record_fingerprint(rec3)


def test_fingerprint_rejects_missing_or_malformed_values():
    """Verify fingerprint raises ValueError on missing features or bad numbers."""
    bad_rec = {"duration": 0}
    with pytest.raises(ValueError, match="missing .* required feature"):
        compute_record_fingerprint(bad_rec)

    bad_num = _make_dummy_feature_row()
    bad_num["src_bytes"] = "not_a_number"
    with pytest.raises(ValueError, match="Invalid non-numeric value"):
        compute_record_fingerprint(bad_num)


# -------------------------------------------------------------------------
# Detection Engine Orchestration & Dispositions
# -------------------------------------------------------------------------

def test_disposition_benign():
    """Verify BENIGN disposition and INFORMATIONAL severity when neither model nor rules trigger."""
    artifact = FakeArtifact(fixed_label=BINARY_LABEL_NORMAL, attack_prob=0.05)
    engine = ThreatDetectionEngine(artifact)

    rec = _make_dummy_feature_row()
    finding = engine.detect_record(rec)

    assert finding.threat_detected is False
    assert finding.disposition == "BENIGN"
    assert finding.overall_severity == "INFORMATIONAL"
    assert finding.model_decision.predicted_label == "normal"
    assert len(finding.rule_matches) == 0


def test_disposition_model_detected():
    """Verify MODEL_DETECTED disposition and MEDIUM severity when only model triggers."""
    artifact = FakeArtifact(fixed_label=BINARY_LABEL_ATTACK, attack_prob=0.85)
    engine = ThreatDetectionEngine(artifact)

    rec = _make_dummy_feature_row()  # Benign feature values, no rule triggers
    finding = engine.detect_record(rec)

    assert finding.threat_detected is True
    assert finding.disposition == "MODEL_DETECTED"
    assert finding.overall_severity == "MEDIUM"
    assert finding.model_decision.predicted_label == "attack"
    assert len(finding.rule_matches) == 0


def test_disposition_rule_detected_including_land():
    """Verify RULE_DETECTED disposition and MEDIUM overall severity (even with LAND rule)."""
    artifact = FakeArtifact(fixed_label=BINARY_LABEL_NORMAL, attack_prob=0.10)
    engine = ThreatDetectionEngine(artifact)

    # Trigger LAND rule only
    rec = _make_dummy_feature_row(land=1)
    finding = engine.detect_record(rec)

    assert finding.threat_detected is True
    assert finding.disposition == "RULE_DETECTED"
    # Per policy: Rule-only detection gets overall_severity=MEDIUM (even with LAND)
    assert finding.overall_severity == "MEDIUM"
    assert len(finding.rule_matches) == 1
    # Individual rule match preserves its own severity (HIGH)
    assert finding.rule_matches[0].rule_id == "RULE-LAND-001"
    assert finding.rule_matches[0].severity == "HIGH"


def test_disposition_corroborated():
    """Verify CORROBORATED disposition and HIGH overall severity when both model and rule trigger."""
    artifact = FakeArtifact(fixed_label=BINARY_LABEL_ATTACK, attack_prob=0.92)
    engine = ThreatDetectionEngine(artifact)

    # Trigger SYN flood rule
    rec = _make_dummy_feature_row(count=150, serror_rate=0.95, flag="S0")
    finding = engine.detect_record(rec)

    assert finding.threat_detected is True
    assert finding.disposition == "CORROBORATED"
    assert finding.overall_severity == "HIGH"
    assert finding.model_decision.predicted_label == "attack"
    assert len(finding.rule_matches) == 1
    assert finding.rule_matches[0].rule_id == "RULE-DOS-SYN-001"


def test_duplicate_rules_deduplicated_per_record():
    """Verify that multiple duplicate rule instances do not produce duplicate matches for same rule ID."""
    artifact = FakeArtifact()
    # Engine configured with duplicate instances of the same rule
    duplicate_rules = [LandAttackRule(), LandAttackRule()]
    engine = ThreatDetectionEngine(artifact, rules=duplicate_rules)

    rec = _make_dummy_feature_row(land=1)
    finding = engine.detect_record(rec)

    # Should only emit 1 match
    assert len(finding.rule_matches) == 1


def test_single_record_dict_and_series_inputs():
    """Verify engine handles dictionary and pandas Series single-record inputs."""
    artifact = FakeArtifact()
    engine = ThreatDetectionEngine(artifact)

    d_rec = _make_dummy_feature_row()
    f_dict = engine.detect(d_rec)
    assert isinstance(f_dict, DetectionFinding)

    s_rec = pd.Series(d_rec)
    f_series = engine.detect(s_rec)
    assert isinstance(f_series, DetectionFinding)
    assert f_dict.record_fingerprint == f_series.record_fingerprint


def test_batch_detection_order_and_count():
    """Verify detect_batch preserves input row order and count."""
    artifact = FakeArtifact()
    engine = ThreatDetectionEngine(artifact)

    rows = [
        _make_dummy_feature_row(duration=i, src_bytes=100 + i)
        for i in range(5)
    ]
    df = pd.DataFrame(rows)

    findings = engine.detect_batch(df, start_index=10)
    assert len(findings) == 5
    for i, finding in enumerate(findings):
        assert finding.record_index == 10 + i


def test_batch_detection_rejects_missing_features():
    """Verify ValueError is raised if batch is missing required features."""
    artifact = FakeArtifact()
    engine = ThreatDetectionEngine(artifact)

    bad_df = pd.DataFrame([{"duration": 0, "protocol_type": "tcp"}])
    with pytest.raises(ValueError, match="missing .* required traffic feature"):
        engine.detect_batch(bad_df)


def test_detection_with_real_trained_model_and_immutability(tmp_path):
    """Verify ThreatDetectionEngine with an actual trained ThreatDetectionArtifact without mutating it."""
    # 1. Train small artifact
    train_rows = []
    for i in range(10):
        train_rows.append(list(_make_dummy_feature_row(duration=i).values()) + ["normal", 21])
    for i in range(10):
        train_rows.append(list(_make_dummy_feature_row(duration=i + 50, src_bytes=500).values()) + ["neptune", 15])
    train_df = pd.DataFrame(train_rows, columns=COLUMNS_43)

    model_path = tmp_path / "model.joblib"
    artifact, _ = train_binary_model(
        data=train_df,
        val_fraction=0.2,
        output_path=model_path,
    )

    initial_estimators = len(artifact.classifier.estimators_)
    initial_classes = list(artifact.classes_)

    # 2. Initialize engine and run detection
    engine = ThreatDetectionEngine(artifact)

    test_rec = _make_dummy_feature_row(count=150, serror_rate=0.9, flag="S0")
    finding = engine.detect_record(test_rec)

    assert isinstance(finding, DetectionFinding)
    assert finding.model_decision.predicted_label in {BINARY_LABEL_NORMAL, BINARY_LABEL_ATTACK}
    assert 0.0 <= finding.model_decision.attack_probability <= 1.0

    # 3. Verify artifact immutability
    assert len(artifact.classifier.estimators_) == initial_estimators
    assert list(artifact.classes_) == initial_classes
    assert artifact.preprocessor.is_fitted is True


def test_detect_batch_and_record_reject_invalid_numeric_values():
    """Verify ValueError is raised if numerical columns contain non-numeric string values."""
    artifact = FakeArtifact()
    engine = ThreatDetectionEngine(artifact)

    bad_rec = _make_dummy_feature_row()
    bad_rec["count"] = "unparseable_string"

    # detect_record fails
    with pytest.raises(ValueError, match="Invalid non-numeric value"):
        engine.detect_record(bad_rec)

    # detect_batch fails
    bad_df = pd.DataFrame([bad_rec])
    with pytest.raises(ValueError, match="Invalid non-numeric value"):
        engine.detect_batch(bad_df)


def test_repeat_run_determinism_and_stability():
    """Verify that repeating detection on the same batch produces strictly identical outputs."""
    artifact = FakeArtifact(fixed_label=BINARY_LABEL_ATTACK, attack_prob=0.88)
    engine = ThreatDetectionEngine(artifact)

    # Multi-record batch with distinct feature combinations
    rows = [
        _make_dummy_feature_row(duration=1, land=1),  # LAND match
        _make_dummy_feature_row(duration=2, count=120, serror_rate=0.85, flag="S0"),  # SYN match
        _make_dummy_feature_row(duration=3, count=60, rerror_rate=0.90, flag="REJ"),  # REJ match
        _make_dummy_feature_row(duration=4),  # Model only
    ]
    df = pd.DataFrame(rows)

    findings_run1 = engine.detect_batch(df)
    findings_run2 = engine.detect_batch(df)

    assert len(findings_run1) == len(findings_run2) == 4

    for f1, f2 in zip(findings_run1, findings_run2):
        # Fingerprint must be strictly identical
        assert f1.record_fingerprint == f2.record_fingerprint
        # Threat detection decision must be identical
        assert f1.threat_detected == f2.threat_detected
        # Disposition and severity must be identical
        assert f1.disposition == f2.disposition
        assert f1.overall_severity == f2.overall_severity
        # Model predictions and probabilities must be identical
        assert f1.model_decision.predicted_label == f2.model_decision.predicted_label
        assert f1.model_decision.attack_probability == pytest.approx(f2.model_decision.attack_probability)
        assert f1.model_decision.confidence == pytest.approx(f2.model_decision.confidence)
        # Rule matches must be identical
        assert len(f1.rule_matches) == len(f2.rule_matches)
        for r1, r2 in zip(f1.rule_matches, f2.rule_matches):
            assert r1.rule_id == r2.rule_id
            assert r1.severity == r2.severity
            assert r1.matched_fields == r2.matched_fields
        # Generation timestamps are valid ISO strings (may differ slightly by millisecond, as expected)
        assert isinstance(f1.timestamp, str)
        assert isinstance(f2.timestamp, str)
