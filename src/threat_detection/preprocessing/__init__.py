"""Data preprocessing and feature engineering subpackage.

Provides scikit-learn transformers and pipelines for NSL-KDD
traffic feature encoding, scaling, and feature/target separation.
"""

from threat_detection.preprocessing.pipeline import (
    ThreatPreprocessingPipeline,
    create_nsl_kdd_preprocessor,
    split_features_and_target,
    validate_traffic_features,
)

__all__ = [
    "ThreatPreprocessingPipeline",
    "create_nsl_kdd_preprocessor",
    "split_features_and_target",
    "validate_traffic_features",
]
