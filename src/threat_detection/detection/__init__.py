"""Threat detection and machine learning model subpackage.

Provides training pipelines, binary target transformations, artifact management,
and Random Forest baseline classifiers for cybersecurity intrusion detection.
"""

from threat_detection.detection.engine import (
    DetectionFinding,
    ModelDecision,
    ThreatDetectionEngine,
    compute_record_fingerprint,
)
from threat_detection.detection.evaluator import (
    EvaluationMetrics,
    compute_metrics_from_predictions,
    evaluate_model,
)
from threat_detection.detection.rules import (
    BaseSecurityRule,
    ConnectionRejectionBurstRule,
    LandAttackRule,
    MultiServicePortSweepRule,
    RuleMatch,
    SecurityRulesConfig,
    SynFloodHeuristicRule,
    create_default_security_rules,
)
from threat_detection.detection.target import (
    BINARY_LABEL_ATTACK,
    BINARY_LABEL_NORMAL,
    create_binary_target,
)
from threat_detection.detection.trainer import (
    DEFAULT_RF_HYPERPARAMETERS,
    ThreatDetectionArtifact,
    TrainingSummary,
    train_binary_model,
)

__all__ = [
    "BINARY_LABEL_ATTACK",
    "BINARY_LABEL_NORMAL",
    "BaseSecurityRule",
    "ConnectionRejectionBurstRule",
    "DEFAULT_RF_HYPERPARAMETERS",
    "DetectionFinding",
    "EvaluationMetrics",
    "LandAttackRule",
    "ModelDecision",
    "MultiServicePortSweepRule",
    "RuleMatch",
    "SecurityRulesConfig",
    "SynFloodHeuristicRule",
    "ThreatDetectionArtifact",
    "ThreatDetectionEngine",
    "TrainingSummary",
    "compute_metrics_from_predictions",
    "compute_record_fingerprint",
    "create_binary_target",
    "create_default_security_rules",
    "evaluate_model",
    "train_binary_model",
]
