"""Threat detection engine combining frozen ML model scoring with security rules.

Orchestrates input validation, frozen model inference, deterministic heuristic
rule evaluation, and synthesized structured detection findings.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional, Union
import numpy as np
import pandas as pd

from threat_detection.data.schema import (
    DIFFICULTY_COLUMN,
    FEATURE_COLUMNS,
    LABEL_COLUMN,
    NUMERICAL_FEATURES,
)
from threat_detection.detection.rules import (
    BaseSecurityRule,
    RuleMatch,
    create_default_security_rules,
)
from threat_detection.detection.target import (
    BINARY_LABEL_ATTACK,
    BINARY_LABEL_NORMAL,
)
from threat_detection.detection.trainer import ThreatDetectionArtifact
from threat_detection.preprocessing.pipeline import validate_traffic_features


@dataclass
class ModelDecision:
    """Structured telemetry produced by the frozen machine learning classifier.

    Note:
    'confidence' represents the model's estimated maximum class probability,
    reflecting statistical model certainty rather than a guarantee of correctness.
    """

    predicted_label: str
    attack_probability: float
    confidence: float

    def to_dict(self) -> Dict[str, Any]:
        """Convert decision to dictionary."""
        return asdict(self)


@dataclass
class DetectionFinding:
    """Structured finding encapsulating model prediction, rule matches, and triage disposition.

    Allowed dispositions:
    - BENIGN: Neither model nor rules triggered.
    - MODEL_DETECTED: Model predicted attack, no rules matched.
    - RULE_DETECTED: At least one rule matched, model predicted normal.
    - CORROBORATED: Both model predicted attack and at least one rule matched.

    Note:
    Dispositions and severities represent initial operational triage levels;
    they do not constitute confirmed incident-impact assessments.
    """

    record_index: Optional[int]
    timestamp: str
    record_fingerprint: str
    threat_detected: bool
    disposition: str
    overall_severity: str
    model_decision: ModelDecision
    rule_matches: List[RuleMatch]
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "record_index": self.record_index,
            "timestamp": self.timestamp,
            "record_fingerprint": self.record_fingerprint,
            "threat_detected": self.threat_detected,
            "disposition": self.disposition,
            "overall_severity": self.overall_severity,
            "model_decision": self.model_decision.to_dict(),
            "rule_matches": [r.to_dict() for r in self.rule_matches],
            "explanation": self.explanation,
        }


def compute_record_fingerprint(record: Union[Dict[str, Any], pd.Series]) -> str:
    """Generate a deterministic SHA-256 fingerprint for a single traffic record.

    Serializes the 41 canonical feature values in fixed FEATURE_COLUMNS order.
    The resulting hash is strictly independent of record index, execution time,
    or batch position.

    Args:
        record: Dictionary or pd.Series mapping feature names to values.

    Returns:
        Hexadecimal SHA-256 string digest.

    Raises:
        ValueError: If required feature columns are missing or numeric features
            contain unparseable non-numeric values.
    """
    canonical_parts: List[str] = []
    missing_cols: List[str] = []

    for col in FEATURE_COLUMNS:
        if col not in record:
            missing_cols.append(col)
            continue

        raw_val = record[col]

        # Handle missing / null indicators consistently
        if pd.isna(raw_val) or raw_val is None:
            norm_val = "<NA>"
        elif col in NUMERICAL_FEATURES:
            try:
                # Convert to float and format deterministically
                float_val = float(raw_val)
                norm_val = f"{float_val:.6f}"
            except (ValueError, TypeError):
                raise ValueError(
                    f"Invalid non-numeric value for numerical feature '{col}': {raw_val}"
                )
        else:
            # String / categorical feature
            norm_val = str(raw_val).strip().lower()

        canonical_parts.append(f"{col}={norm_val}")

    if missing_cols:
        raise ValueError(
            f"Cannot compute fingerprint: missing {len(missing_cols)} required feature(s): {missing_cols}"
        )

    canonical_repr = "|".join(canonical_parts)
    return hashlib.sha256(canonical_repr.encode("utf-8")).hexdigest()


class ThreatDetectionEngine:
    """Hybrid detection engine combining frozen model scoring with deterministic security rules.

    Guarantees:
    - Never refits or retrains the underlying model or preprocessor.
    - Validates feature schema and data types strictly prior to prediction.
    - Preserves batch order and row counts.
    - Emits structured DetectionFinding telemetry with separate model and rule reporting.
    """

    def __init__(
        self,
        artifact: ThreatDetectionArtifact,
        rules: Optional[List[BaseSecurityRule]] = None,
    ) -> None:
        """Initialize detection engine with a frozen model artifact and rules.

        Args:
            artifact: Pre-loaded and pre-fitted ThreatDetectionArtifact.
            rules: Optional list of BaseSecurityRule instances. Defaults to standard 4 rules.
        """
        self.artifact = artifact
        self.rules: List[BaseSecurityRule] = (
            list(rules) if rules is not None else create_default_security_rules()
        )

        # Dynamically resolve attack class index from model classes_
        classes = list(self.artifact.classes_)
        if BINARY_LABEL_ATTACK not in classes:
            raise ValueError(
                f"Model classes '{classes}' does not contain expected attack label '{BINARY_LABEL_ATTACK}'."
            )
        self._attack_col_idx = classes.index(BINARY_LABEL_ATTACK)

    def _evaluate_rules_for_record(
        self, record: Union[Dict[str, Any], pd.Series]
    ) -> List[RuleMatch]:
        """Evaluate all security rules on a single record, deduplicating by rule_id."""
        matches: List[RuleMatch] = []
        seen_rule_ids = set()

        for rule in self.rules:
            if rule.rule_id in seen_rule_ids:
                continue
            match = rule.evaluate(record)
            if match is not None:
                matches.append(match)
                seen_rule_ids.add(rule.rule_id)

        return matches

    def _determine_disposition_and_severity(
        self, model_is_attack: bool, has_rule_matches: bool
    ) -> tuple[str, str]:
        """Determine disposition and overall severity according to project policy.

        Policy rules:
        - Neither triggers: disposition="BENIGN", severity="INFORMATIONAL"
        - Model-only triggers: disposition="MODEL_DETECTED", severity="MEDIUM"
        - Rule-only triggers: disposition="RULE_DETECTED", severity="MEDIUM"
        - Both trigger: disposition="CORROBORATED", severity="HIGH"
        """
        if model_is_attack and has_rule_matches:
            return "CORROBORATED", "HIGH"
        if model_is_attack:
            return "MODEL_DETECTED", "MEDIUM"
        if has_rule_matches:
            return "RULE_DETECTED", "MEDIUM"
        return "BENIGN", "INFORMATIONAL"

    def _create_explanation(
        self,
        disposition: str,
        pred_label: str,
        confidence: float,
        rule_matches: List[RuleMatch],
    ) -> str:
        """Construct an objective narrative describing the detection findings."""
        if disposition == "BENIGN":
            return (
                f"Flow classified as normal (confidence: {confidence:.2%}). "
                "No heuristic security rules were triggered."
            )
        if disposition == "MODEL_DETECTED":
            return (
                f"Statistical classifier flagged flow as attack (confidence: {confidence:.2%}). "
                "No deterministic security rules were triggered."
            )
        if disposition == "RULE_DETECTED":
            rule_ids = ", ".join(r.rule_id for r in rule_matches)
            return (
                f"Heuristic security rule(s) matched: [{rule_ids}]. "
                f"Statistical classifier predicted normal (confidence: {confidence:.2%})."
            )
        # CORROBORATED
        rule_ids = ", ".join(r.rule_id for r in rule_matches)
        return (
            f"Corroborated threat finding: statistical classifier predicted attack "
            f"(confidence: {confidence:.2%}) and heuristic rule(s) triggered: [{rule_ids}]."
        )

    def detect_record(
        self,
        record: Union[Dict[str, Any], pd.Series],
        record_index: Optional[int] = None,
    ) -> DetectionFinding:
        """Evaluate a single network traffic flow record.

        Args:
            record: Mapping or pd.Series containing all 41 traffic features.
            record_index: Optional index or identifier.

        Returns:
            DetectionFinding instance.
        """
        # Convert single record to 1-row DataFrame
        df_row = pd.DataFrame([dict(record)])
        findings = self.detect_batch(df_row, start_index=record_index)
        return findings[0]

    def detect_batch(
        self,
        records: pd.DataFrame,
        start_index: Optional[int] = None,
    ) -> List[DetectionFinding]:
        """Evaluate a batch of network traffic flow records.

        Args:
            records: DataFrame containing network traffic features.
            start_index: Starting integer index for record_index tagging.

        Returns:
            List of DetectionFinding instances in exact input row order.

        Raises:
            ValueError: If input is not a DataFrame, is missing required features,
                or contains malformed numeric values.
        """
        if not isinstance(records, pd.DataFrame):
            raise TypeError(
                f"Expected pandas DataFrame for detect_batch, got '{type(records).__name__}'."
            )

        if len(records) == 0:
            return []

        # Isolate 41 traffic features, stripping any target/difficulty metadata
        missing_features = [col for col in FEATURE_COLUMNS if col not in records.columns]
        if missing_features:
            raise ValueError(
                f"Input batch is missing {len(missing_features)} required traffic feature(s): {missing_features}"
            )

        # Make copy of feature slice strictly excluding metadata columns
        X = records[FEATURE_COLUMNS].copy()

        # Validate schema and types
        validate_traffic_features(X)

        # Run frozen model inference (preprocessor transform + classifier prediction)
        preds = self.artifact.predict(X)
        probs = self.artifact.predict_proba(X)

        now_timestamp = datetime.now(timezone.utc).isoformat()
        findings: List[DetectionFinding] = []

        for i in range(len(records)):
            row_series = X.iloc[i]
            row_dict = row_series.to_dict()

            # Record index assignment
            idx = (start_index + i) if start_index is not None else i

            # 1. Deterministic fingerprint
            fingerprint = compute_record_fingerprint(row_dict)

            # 2. Model Decision
            pred_label = str(preds[i])
            atk_prob = float(probs[i, self._attack_col_idx])
            conf = float(np.max(probs[i]))

            model_decision = ModelDecision(
                predicted_label=pred_label,
                attack_probability=atk_prob,
                confidence=conf,
            )

            # 3. Rule Evaluation
            rule_matches = self._evaluate_rules_for_record(row_dict)

            # 4. Correlation & Triage
            model_is_attack = (pred_label == BINARY_LABEL_ATTACK)
            has_rules = len(rule_matches) > 0
            threat_detected = model_is_attack or has_rules

            disposition, overall_sev = self._determine_disposition_and_severity(
                model_is_attack, has_rules
            )

            explanation = self._create_explanation(
                disposition=disposition,
                pred_label=pred_label,
                confidence=conf,
                rule_matches=rule_matches,
            )

            findings.append(
                DetectionFinding(
                    record_index=idx,
                    timestamp=now_timestamp,
                    record_fingerprint=fingerprint,
                    threat_detected=threat_detected,
                    disposition=disposition,
                    overall_severity=overall_sev,
                    model_decision=model_decision,
                    rule_matches=rule_matches,
                    explanation=explanation,
                )
            )

        return findings

    def detect(
        self, data: Union[Dict[str, Any], pd.Series, pd.DataFrame]
    ) -> Union[DetectionFinding, List[DetectionFinding]]:
        """Unified entry point accepting a single record or a batch.

        Args:
            data: Single record (dict/Series) or batch (DataFrame).

        Returns:
            DetectionFinding for single record, List[DetectionFinding] for batch.
        """
        if isinstance(data, pd.DataFrame):
            return self.detect_batch(data)
        if isinstance(data, (dict, pd.Series)):
            return self.detect_record(data)
        raise TypeError(f"Unsupported data type for detection: '{type(data).__name__}'")
