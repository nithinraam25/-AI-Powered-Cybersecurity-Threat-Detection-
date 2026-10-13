"""NSL-KDD dataset schema definitions and contracts.

Single source of truth for column specifications, supported schema variants,
and canonical attack type taxonomies for the NSL-KDD dataset.
"""

from enum import Enum
from typing import Dict, Final, List, Set

# 41 Canonical traffic features defined by NSL-KDD / KDD Cup 1999
FEATURE_COLUMNS: Final[List[str]] = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

LABEL_COLUMN: Final[str] = "class"
DIFFICULTY_COLUMN: Final[str] = "difficulty_level"

# Schema variants:
# standard_42: 41 features + class label
# with_difficulty_43: 41 features + class label + difficulty level
COLUMNS_42: Final[List[str]] = FEATURE_COLUMNS + [LABEL_COLUMN]
COLUMNS_43: Final[List[str]] = FEATURE_COLUMNS + [LABEL_COLUMN, DIFFICULTY_COLUMN]


class NSLKDDVariant(str, Enum):
    """Supported NSL-KDD file schema variants."""

    STANDARD_42 = "standard_42"
    WITH_DIFFICULTY_43 = "with_difficulty_43"


# Categorical / Symbolic features in NSL-KDD
CATEGORICAL_FEATURES: Final[List[str]] = [
    "protocol_type",
    "service",
    "flag",
]

# Binary indicator features
BINARY_FEATURES: Final[List[str]] = [
    "land",
    "logged_in",
    "is_host_login",
    "is_guest_login",
]

# Continuous numeric features
CONTINUOUS_FEATURES: Final[List[str]] = [
    col for col in FEATURE_COLUMNS if col not in CATEGORICAL_FEATURES and col not in BINARY_FEATURES
]

# All numerical features (binary indicators + continuous metrics = 38 columns)
NUMERICAL_FEATURES: Final[List[str]] = [
    col for col in FEATURE_COLUMNS if col not in CATEGORICAL_FEATURES
]


def verify_feature_schema() -> None:
    """Verify that feature groups form a complete, disjoint partition of FEATURE_COLUMNS.

    Raises:
        ValueError: If categorical and numerical feature groups overlap,
            fail to cover all 41 traffic features, or include target/metadata columns.
    """
    if len(FEATURE_COLUMNS) != 41:
        raise ValueError(
            f"Expected 41 canonical feature columns, got {len(FEATURE_COLUMNS)}."
        )

    cat_set = set(CATEGORICAL_FEATURES)
    num_set = set(NUMERICAL_FEATURES)
    all_set = set(FEATURE_COLUMNS)

    overlap = cat_set & num_set
    if overlap:
        raise ValueError(f"Feature groups overlap on: {overlap}")

    union = cat_set | num_set
    if union != all_set:
        missing = all_set - union
        extra = union - all_set
        raise ValueError(
            f"Feature groups do not partition FEATURE_COLUMNS. Missing: {missing}, Extra: {extra}"
        )

    if LABEL_COLUMN in all_set:
        raise ValueError(f"Target label '{LABEL_COLUMN}' must not be in FEATURE_COLUMNS.")

    if DIFFICULTY_COLUMN in all_set:
        raise ValueError(
            f"Difficulty column '{DIFFICULTY_COLUMN}' must not be in FEATURE_COLUMNS."
        )


# Validate on module load to guarantee schema integrity
verify_feature_schema()

# Standard attack classifications across the 4 major attack families + normal
ATTACK_CATEGORY_MAPPING: Final[Dict[str, str]] = {
    # Benign
    "normal": "normal",
    # Denial of Service (DoS)
    "apache2": "dos",
    "back": "dos",
    "land": "dos",
    "mailbomb": "dos",
    "neptune": "dos",
    "pod": "dos",
    "processtable": "dos",
    "smurf": "dos",
    "teardrop": "dos",
    "udpstorm": "dos",
    # Probe
    "ipsweep": "probe",
    "mscan": "probe",
    "nmap": "probe",
    "portsweep": "probe",
    "saint": "probe",
    "satan": "probe",
    # Remote to Local (R2L)
    "ftp_write": "r2l",
    "guess_passwd": "r2l",
    "httptunnel": "r2l",
    "imap": "r2l",
    "multihop": "r2l",
    "named": "r2l",
    "phf": "r2l",
    "sendmail": "r2l",
    "snmpget": "r2l",
    "snmpguess": "r2l",
    "spy": "r2l",
    "warezclient": "r2l",
    "warezmaster": "r2l",
    "worm": "r2l",
    "xlock": "r2l",
    "xsnoop": "r2l",
    # User to Root (U2R)
    "buffer_overflow": "u2r",
    "loadmodule": "u2r",
    "perl": "u2r",
    "ps": "u2r",
    "rootkit": "u2r",
    "sqlattack": "u2r",
    "xterm": "u2r",
}

KNOWN_ATTACK_LABELS: Final[Set[str]] = set(ATTACK_CATEGORY_MAPPING.keys())
