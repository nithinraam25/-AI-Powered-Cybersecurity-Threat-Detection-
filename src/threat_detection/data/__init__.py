"""Data ingestion and dataset management subpackage.

Provides schema contracts, loaders, validators, and CLI utilities for
the NSL-KDD cybersecurity intrusion detection dataset.
"""

from threat_detection.data.loader import load_nsl_kdd
from threat_detection.data.schema import (
    COLUMNS_42,
    COLUMNS_43,
    FEATURE_COLUMNS,
    LABEL_COLUMN,
    DIFFICULTY_COLUMN,
    NSLKDDVariant,
    NUMERICAL_FEATURES,
    verify_feature_schema,
    ATTACK_CATEGORY_MAPPING,
    KNOWN_ATTACK_LABELS,
)
from threat_detection.data.validator import ValidationReport, validate_nsl_kdd

__all__ = [
    "load_nsl_kdd",
    "validate_nsl_kdd",
    "ValidationReport",
    "NSLKDDVariant",
    "FEATURE_COLUMNS",
    "LABEL_COLUMN",
    "DIFFICULTY_COLUMN",
    "COLUMNS_42",
    "COLUMNS_43",
    "ATTACK_CATEGORY_MAPPING",
    "KNOWN_ATTACK_LABELS",
]
