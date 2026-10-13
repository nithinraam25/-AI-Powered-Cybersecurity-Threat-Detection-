"""Evaluation module for frozen threat detection models.

Provides rigorous performance evaluation, metrics computation, confusion matrix
analysis, and error rate calculations on test benchmarks without modifying or
retraining models.
"""

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)

from threat_detection.data.loader import load_nsl_kdd
from threat_detection.data.schema import KNOWN_ATTACK_LABELS
from threat_detection.data.validator import validate_nsl_kdd
from threat_detection.detection.target import (
    BINARY_LABEL_ATTACK,
    BINARY_LABEL_NORMAL,
    create_binary_target,
)
from threat_detection.detection.trainer import ThreatDetectionArtifact
from threat_detection.preprocessing.pipeline import split_features_and_target


@dataclass
class EvaluationMetrics:
    """Structured report holding comprehensive evaluation metrics."""

    total_samples: int
    excluded_samples: int
    accuracy: float
    precision_normal: float
    recall_normal: float
    f1_normal: float
    support_normal: int
    precision_attack: float
    recall_attack: float
    f1_attack: float
    support_attack: int
    macro_precision: float
    macro_recall: float
    macro_f1: float
    weighted_precision: float
    weighted_recall: float
    weighted_f1: float
    true_negatives: int
    false_positives: int
    false_negatives: int
    true_positives: int
    false_positive_rate: float
    false_negative_rate: float
    roc_auc: Optional[float] = None
    pr_auc: Optional[float] = None
    unknown_labels_encountered: int = 0
    unknown_label_names: List[str] = field(default_factory=list)
    unknown_policy: str = "attack"
    dataset_source: str = ""
    model_source: str = ""
    confusion_matrix_grid: Optional[List[List[int]]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to a standard serializable dictionary."""
        return asdict(self)

    def summary(self) -> str:
        """Format metrics into a clear, documented human-readable report."""
        lines = [
            "=================== Model Evaluation Report ===================",
            f"Dataset Source:              {self.dataset_source or 'In-Memory DataFrame'}",
            f"Model Source:                {self.model_source or 'Loaded ThreatDetectionArtifact'}",
            f"Total Evaluated Records:     {self.total_samples:,}",
            f"Excluded Records:            {self.excluded_samples:,}",
            f"Unknown Label Policy:        {self.unknown_policy}",
            f"Unknown Labels Encountered:  {self.unknown_labels_encountered:,} "
            f"(Classes: {', '.join(self.unknown_label_names) if self.unknown_label_names else 'None'})",
            "",
            "--- Confusion Matrix ---",
            "Orientation: Rows = Ground Truth, Columns = Model Prediction",
            f"  Actual Normal (Neg):  TN = {self.true_negatives:,}   |  FP = {self.false_positives:,}",
            f"  Actual Attack (Pos):  FN = {self.false_negatives:,}   |  TP = {self.true_positives:,}",
            "",
            "--- Operational Error Rates ---",
            f"  False-Positive Rate (FPR): {self.false_positive_rate:.4f} ({self.false_positive_rate * 100:.2f}%) "
            "[FP / (FP + TN)]",
            f"  False-Negative Rate (FNR): {self.false_negative_rate:.4f} ({self.false_negative_rate * 100:.2f}%) "
            "[FN / (FN + TP)]",
            "",
            "--- Detailed Classification Metrics ---",
            f"  Overall Accuracy:          {self.accuracy:.4f} ({self.accuracy * 100:.2f}%)",
            f"  Class 'normal' (Negative): Precision={self.precision_normal:.4f}, "
            f"Recall={self.recall_normal:.4f}, F1={self.f1_normal:.4f}, Support={self.support_normal:,}",
            f"  Class 'attack' (Positive): Precision={self.precision_attack:.4f}, "
            f"Recall={self.recall_attack:.4f}, F1={self.f1_attack:.4f}, Support={self.support_attack:,}",
            f"  Macro Average:             Precision={self.macro_precision:.4f}, "
            f"Recall={self.macro_recall:.4f}, F1={self.macro_f1:.4f}",
            f"  Weighted Average:          Precision={self.weighted_precision:.4f}, "
            f"Recall={self.weighted_recall:.4f}, F1={self.weighted_f1:.4f}",
        ]
        if self.roc_auc is not None:
            lines.append(f"  ROC-AUC (Attack Class):    {self.roc_auc:.4f}")
        if self.pr_auc is not None:
            lines.append(f"  PR-AUC (Attack Class):     {self.pr_auc:.4f}")
        lines.append("=" * 63)
        return "\n".join(lines)


def compute_metrics_from_predictions(
    y_true: pd.Series,
    y_pred: np.ndarray,
    y_prob_attack: Optional[np.ndarray] = None,
    total_samples: Optional[int] = None,
    excluded_samples: int = 0,
    unknown_count: int = 0,
    unknown_names: Optional[List[str]] = None,
    unknown_policy: str = "attack",
    dataset_source: str = "",
    model_source: str = "",
) -> EvaluationMetrics:
    """Calculate comprehensive evaluation metrics from ground-truth and predictions.

    Args:
        y_true: Ground-truth binary labels ('normal' or 'attack').
        y_pred: Predicted binary labels ('normal' or 'attack').
        y_prob_attack: Optional predicted probability array for the 'attack' positive class.
        total_samples: Total number of records evaluated.
        excluded_samples: Number of excluded records (if any).
        unknown_count: Number of uncatalogued label rows handled.
        unknown_names: Names of uncatalogued attack classes encountered.
        unknown_policy: Policy used for uncatalogued classes.
        dataset_source: Source file or description.
        model_source: Source model artifact path.

    Returns:
        EvaluationMetrics instance with complete calculated telemetry.
    """
    if len(y_true) != len(y_pred):
        raise ValueError(
            f"Ground truth length ({len(y_true)}) does not match prediction length ({len(y_pred)})."
        )

    if len(y_true) == 0:
        raise ValueError("Cannot calculate evaluation metrics on an empty dataset.")

    n_samples = total_samples if total_samples is not None else len(y_true)

    # Confusion matrix with explicit labels order: ['normal', 'attack']
    # Normal = negative class (index 0)
    # Attack = positive class (index 1)
    # Grid:
    #   [ [TN, FP],
    #     [FN, TP] ]
    labels_order = [BINARY_LABEL_NORMAL, BINARY_LABEL_ATTACK]
    cm = confusion_matrix(y_true, y_pred, labels=labels_order)
    tn, fp, fn, tp = cm.ravel()

    # Error rates
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    # Classification report
    report: Dict[str, Any] = classification_report(
        y_true,
        y_pred,
        labels=labels_order,
        output_dict=True,
        zero_division=0,
    )

    acc = float(report["accuracy"])

    norm_stats = report.get(BINARY_LABEL_NORMAL, {})
    atk_stats = report.get(BINARY_LABEL_ATTACK, {})
    macro_stats = report.get("macro avg", {})
    weighted_stats = report.get("weighted avg", {})

    # ROC-AUC and PR-AUC for attack class
    roc_auc: Optional[float] = None
    pr_auc: Optional[float] = None
    if y_prob_attack is not None and len(y_prob_attack) == len(y_true):
        # Numeric binary indicator for positive class ('attack' -> 1, 'normal' -> 0)
        y_true_binary = (y_true.astype(str) == BINARY_LABEL_ATTACK).astype(int).to_numpy()
        # Require both classes to exist to compute AUC
        if len(np.unique(y_true_binary)) > 1:
            try:
                roc_auc = float(roc_auc_score(y_true_binary, y_prob_attack))
                pr_auc = float(average_precision_score(y_true_binary, y_prob_attack))
            except Exception:
                roc_auc = None
                pr_auc = None

    return EvaluationMetrics(
        total_samples=n_samples,
        excluded_samples=excluded_samples,
        accuracy=acc,
        precision_normal=float(norm_stats.get("precision", 0.0)),
        recall_normal=float(norm_stats.get("recall", 0.0)),
        f1_normal=float(norm_stats.get("f1-score", 0.0)),
        support_normal=int(norm_stats.get("support", 0)),
        precision_attack=float(atk_stats.get("precision", 0.0)),
        recall_attack=float(atk_stats.get("recall", 0.0)),
        f1_attack=float(atk_stats.get("f1-score", 0.0)),
        support_attack=int(atk_stats.get("support", 0)),
        macro_precision=float(macro_stats.get("precision", 0.0)),
        macro_recall=float(macro_stats.get("recall", 0.0)),
        macro_f1=float(macro_stats.get("f1-score", 0.0)),
        weighted_precision=float(weighted_stats.get("precision", 0.0)),
        weighted_recall=float(weighted_stats.get("recall", 0.0)),
        weighted_f1=float(weighted_stats.get("f1-score", 0.0)),
        true_negatives=int(tn),
        false_positives=int(fp),
        false_negatives=int(fn),
        true_positives=int(tp),
        false_positive_rate=fpr,
        false_negative_rate=fnr,
        roc_auc=roc_auc,
        pr_auc=pr_auc,
        unknown_labels_encountered=unknown_count,
        unknown_label_names=unknown_names or [],
        unknown_policy=unknown_policy,
        dataset_source=dataset_source,
        model_source=model_source,
        confusion_matrix_grid=[[int(tn), int(fp)], [int(fn), int(tp)]],
    )


def evaluate_model(
    artifact: ThreatDetectionArtifact,
    data: Union[str, Path, pd.DataFrame],
    on_unknown_labels: str = "attack",
    model_source_desc: str = "",
) -> EvaluationMetrics:
    """Evaluate a frozen model artifact on test telemetry data without refitting.

    Args:
        artifact: Loaded ThreatDetectionArtifact instance.
        data: Path to NSL-KDD test dataset file or pre-loaded DataFrame.
        on_unknown_labels: Policy for uncatalogued attack classes ('error' or 'attack').
        model_source_desc: Human-readable model artifact path or description.

    Returns:
        EvaluationMetrics instance containing complete evaluation telemetry.

    Raises:
        FileNotFoundError: If test dataset file does not exist.
        ValueError: If dataset schema is invalid or targets cannot be derived.
    """
    dataset_desc = "DataFrame"
    if isinstance(data, (str, Path)):
        file_path = Path(data)
        dataset_desc = str(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"Test dataset file not found: '{file_path}'")
        df = load_nsl_kdd(file_path)
        report = validate_nsl_kdd(df)
        if not report.is_valid:
            raise ValueError(f"Test dataset failed schema validation: {report.errors}")
    elif isinstance(data, pd.DataFrame):
        df = data
    else:
        raise TypeError(f"Unsupported data type: '{type(data).__name__}'")

    # Separate raw features and raw target
    X, y_raw = split_features_and_target(df)

    # Detect uncatalogued labels
    normalized_raw = y_raw.astype(str).str.strip().str.lower()
    unique_raw = set(normalized_raw.unique())
    recognized = {BINARY_LABEL_NORMAL} | {k for k in KNOWN_ATTACK_LABELS if k != BINARY_LABEL_NORMAL}
    unknown_classes = sorted(list(unique_raw - recognized))
    unknown_count = int(normalized_raw.isin(unknown_classes).sum())

    # Map binary target using the explicit policy
    y_true = create_binary_target(y_raw, on_unknown=on_unknown_labels)

    # Generate predictions using the frozen artifact API
    y_pred = artifact.predict(X)

    # Extract attack class predicted probabilities if available
    y_prob_attack: Optional[np.ndarray] = None
    if hasattr(artifact, "predict_proba"):
        classes = artifact.classes_
        attack_matches = np.where(classes == BINARY_LABEL_ATTACK)[0]
        if len(attack_matches) == 1:
            attack_col_idx = int(attack_matches[0])
            probs = artifact.predict_proba(X)
            y_prob_attack = probs[:, attack_col_idx]

    return compute_metrics_from_predictions(
        y_true=y_true,
        y_pred=y_pred,
        y_prob_attack=y_prob_attack,
        total_samples=len(df),
        excluded_samples=0,
        unknown_count=unknown_count,
        unknown_names=unknown_classes,
        unknown_policy=on_unknown_labels,
        dataset_source=dataset_desc,
        model_source=model_source_desc,
    )
