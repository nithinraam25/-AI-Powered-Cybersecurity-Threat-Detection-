"""NSL-KDD dataset integrity validation and reporting module.

Performs schema verification, quality audit, class distribution analysis,
and distinguishes fatal errors from non-destructive quality warnings.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
import pandas as pd

from threat_detection.data.schema import (
    ATTACK_CATEGORY_MAPPING,
    COLUMNS_42,
    COLUMNS_43,
    DIFFICULTY_COLUMN,
    KNOWN_ATTACK_LABELS,
    LABEL_COLUMN,
    NSLKDDVariant,
)


@dataclass
class ValidationReport:
    """Structured audit report capturing dataset integrity metrics."""

    is_valid: bool
    row_count: int
    column_count: int
    schema_variant: str
    label_column_found: bool
    has_difficulty_field: bool
    duplicate_rows: int
    duplicate_ratio: float
    total_missing_values: int
    missing_values_by_column: Dict[str, int] = field(default_factory=dict)
    class_distribution: Dict[str, int] = field(default_factory=dict)
    attack_family_distribution: Dict[str, int] = field(default_factory=dict)
    unknown_labels: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def summary(self) -> str:
        """Generate a concise, human-readable audit summary."""
        status_label = "VALID" if self.is_valid else "INVALID"
        lines = [
            f"=== NSL-KDD Dataset Validation Report [{status_label}] ===",
            f"Status:               {status_label}",
            f"Schema Variant:       {self.schema_variant} ({self.column_count} columns)",
            f"Total Records:        {self.row_count:,}",
            f"Label Column:         {'Present' if self.label_column_found else 'MISSING'}",
            f"Difficulty Field:     {'Present' if self.has_difficulty_field else 'Absent'}",
            f"Duplicate Records:    {self.duplicate_rows:,} ({self.duplicate_ratio:.2%}) [Preserved]",
            f"Missing Values:       {self.total_missing_values:,}",
        ]

        if self.missing_values_by_column:
            lines.append("Missing by Column:")
            for col, count in self.missing_values_by_column.items():
                lines.append(f"  - {col}: {count:,}")

        if self.attack_family_distribution:
            lines.append("Attack Family Distribution:")
            for family, count in sorted(
                self.attack_family_distribution.items(), key=lambda x: x[1], reverse=True
            ):
                pct = (count / self.row_count) * 100 if self.row_count > 0 else 0.0
                lines.append(f"  - {family.upper():<8}: {count:>8,} ({pct:>5.1f}%)")

        if self.class_distribution:
            top_classes = sorted(
                self.class_distribution.items(), key=lambda x: x[1], reverse=True
            )[:5]
            lines.append(f"Top {len(top_classes)} Specific Classes:")
            for label, count in top_classes:
                pct = (count / self.row_count) * 100 if self.row_count > 0 else 0.0
                lines.append(f"  - {label:<15}: {count:>8,} ({pct:>5.1f}%)")

        if self.warnings:
            lines.append("Quality Warnings:")
            for w in self.warnings:
                lines.append(f"  [WARN] {w}")

        if self.errors:
            lines.append("Fatal Schema / Integrity Errors:")
            for e in self.errors:
                lines.append(f"  [ERROR] {e}")

        lines.append("=" * 55)
        return "\n".join(lines)


def validate_nsl_kdd(
    df: pd.DataFrame,
    expected_variant: Optional[NSLKDDVariant] = None,
    allow_unknown_labels: bool = True,
    custom_known_labels: Optional[Set[str]] = None,
) -> ValidationReport:
    """Validate DataFrame integrity against the NSL-KDD schema specification.

    Performs non-destructive validation. Checks schema constraints, nulls,
    duplicates, and attack label consistency without altering the input data.

    Args:
        df: Input DataFrame to audit.
        expected_variant: Optional specific schema variant to enforce.
        allow_unknown_labels: If True, unfamiliar attack labels produce warnings
            instead of fatal errors (useful for zero-day/novel test sets).
        custom_known_labels: Optional custom set of known labels to evaluate against.

    Returns:
        ValidationReport with audit metrics, warnings, and errors.
    """
    errors: List[str] = []
    warnings: List[str] = []

    row_count = len(df)
    column_count = len(df.columns)

    # 1. Empty dataset check
    if row_count == 0:
        errors.append("Dataset contains 0 rows (empty dataset).")

    # 2. Schema variant & column count verification
    detected_variant = "unknown"
    has_difficulty = False

    if column_count == 42:
        detected_variant = NSLKDDVariant.STANDARD_42.value
    elif column_count == 43:
        detected_variant = NSLKDDVariant.WITH_DIFFICULTY_43.value
        has_difficulty = True
    else:
        errors.append(
            f"Unsupported column count {column_count}. Expected 42 (standard) or 43 (with difficulty)."
        )

    if expected_variant is not None and detected_variant != expected_variant.value:
        errors.append(
            f"Schema variant mismatch: expected '{expected_variant.value}', detected '{detected_variant}'."
        )

    # 3. Label column verification
    label_found = LABEL_COLUMN in df.columns
    if not label_found:
        errors.append(f"Required label column '{LABEL_COLUMN}' is missing from DataFrame.")

    if DIFFICULTY_COLUMN in df.columns:
        has_difficulty = True

    # 4. Missing / Null values audit
    missing_series = df.isnull().sum()
    total_missing = int(missing_series.sum())
    missing_by_col = {
        col: int(count) for col, count in missing_series.items() if count > 0
    }
    if total_missing > 0:
        warnings.append(
            f"Found {total_missing:,} total missing/null values across {len(missing_by_col)} columns."
        )

    # 5. Duplicate rows audit (reported, never dropped)
    duplicate_count = int(df.duplicated().sum())
    duplicate_ratio = (duplicate_count / row_count) if row_count > 0 else 0.0
    if duplicate_count > 0:
        warnings.append(
            f"Found {duplicate_count:,} duplicate rows ({duplicate_ratio:.2%}). "
            f"Duplicates are preserved to maintain data fidelity."
        )

    # 6. Class label analysis
    class_dist: Dict[str, int] = {}
    family_dist: Dict[str, int] = {}
    unknown_labels: List[str] = []

    if label_found and row_count > 0:
        raw_labels = df[LABEL_COLUMN].astype(str).str.strip().str.lower()
        class_dist = {k: int(v) for k, v in raw_labels.value_counts().items()}

        known_pool = custom_known_labels or KNOWN_ATTACK_LABELS

        for label, count in class_dist.items():
            family = ATTACK_CATEGORY_MAPPING.get(label, "unknown")
            family_dist[family] = family_dist.get(family, 0) + count

            if label not in known_pool:
                unknown_labels.append(label)

        if unknown_labels:
            msg = (
                f"Encountered {len(unknown_labels)} uncatalogued attack class label(s): "
                f"{', '.join(sorted(unknown_labels))}."
            )
            if allow_unknown_labels:
                warnings.append(msg)
            else:
                errors.append(msg)

    is_valid = len(errors) == 0

    return ValidationReport(
        is_valid=is_valid,
        row_count=row_count,
        column_count=column_count,
        schema_variant=detected_variant,
        label_column_found=label_found,
        has_difficulty_field=has_difficulty,
        duplicate_rows=duplicate_count,
        duplicate_ratio=duplicate_ratio,
        total_missing_values=total_missing,
        missing_values_by_column=missing_by_col,
        class_distribution=class_dist,
        attack_family_distribution=family_dist,
        unknown_labels=unknown_labels,
        errors=errors,
        warnings=warnings,
    )
