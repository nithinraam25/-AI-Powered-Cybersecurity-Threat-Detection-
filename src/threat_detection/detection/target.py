"""Target label transformation module for binary threat classification.

Maps canonical NSL-KDD attack and normal labels into binary indicators
('normal' vs 'attack') without altering the original multi-class labels.
"""

from typing import Optional, Set
import pandas as pd

from threat_detection.data.schema import KNOWN_ATTACK_LABELS

BINARY_LABEL_NORMAL = "normal"
BINARY_LABEL_ATTACK = "attack"
VALID_BINARY_LABELS = {BINARY_LABEL_NORMAL, BINARY_LABEL_ATTACK}


def create_binary_target(
    labels: pd.Series,
    on_unknown: str = "error",
    custom_known_attacks: Optional[Set[str]] = None,
) -> pd.Series:
    """Map canonical NSL-KDD class labels into binary classification targets.

    Mapping rules:
    - 'normal' (case and whitespace insensitive) -> 'normal'
    - Any recognized attack label -> 'attack'
    - Unrecognized labels -> Handled per `on_unknown` policy ('error' or 'attack')

    Important:
    - This is a binary baseline target: it distinguishes normal from attack
      telemetry, but does NOT identify specific attack types (DoS, Probe, etc.).
    - The input `labels` Series is never modified in place.

    Args:
        labels: Series containing raw multi-class target labels.
        on_unknown: Policy for handling uncatalogued labels.
            'error': Raise ValueError if uncatalogued labels are encountered.
            'attack': Map uncatalogued labels to 'attack' (treat as zero-day).
        custom_known_attacks: Optional set of known attack names to override default.

    Returns:
        pd.Series containing binary strings ('normal' or 'attack') named 'binary_target'.

    Raises:
        ValueError: If labels is empty, on_unknown policy is invalid,
            or unknown labels are encountered under 'error' policy.
    """
    if len(labels) == 0:
        raise ValueError("Cannot create binary target from an empty labels Series.")

    if on_unknown not in {"error", "attack"}:
        raise ValueError(
            f"Invalid on_unknown policy '{on_unknown}'. Must be 'error' or 'attack'."
        )

    known_attacks = custom_known_attacks or {
        k for k in KNOWN_ATTACK_LABELS if k != BINARY_LABEL_NORMAL
    }

    # Normalize whitespace and casing safely
    normalized = labels.astype(str).str.strip().str.lower()

    # Detect unrecognized labels
    unique_labels = set(normalized.unique())
    recognized = {BINARY_LABEL_NORMAL} | known_attacks
    unknown_labels = unique_labels - recognized

    if unknown_labels and on_unknown == "error":
        raise ValueError(
            f"Uncatalogued target label(s) encountered in binary mapping: "
            f"{sorted(unknown_labels)}. Specify on_unknown='attack' to allow novel labels."
        )

    # Perform mapping
    def _map_label(val: str) -> str:
        if val == BINARY_LABEL_NORMAL:
            return BINARY_LABEL_NORMAL
        if val in known_attacks or on_unknown == "attack":
            return BINARY_LABEL_ATTACK
        raise ValueError(f"Unmapped label: '{val}'")

    binary_series = normalized.map(_map_label)
    binary_series.name = "binary_target"
    binary_series.index = labels.index

    return binary_series
