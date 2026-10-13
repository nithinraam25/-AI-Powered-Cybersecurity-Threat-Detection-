"""Model training module for binary threat classification.

Orchestrates data loading, validation, feature/target separation,
leakage-free train/validation splitting, Scikit-Learn Random Forest
fitting, and unified artifact serialization.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import sklearn

from threat_detection import __version__ as pkg_version
from threat_detection.config import config
from threat_detection.data.loader import load_nsl_kdd
from threat_detection.data.validator import validate_nsl_kdd
from threat_detection.detection.target import create_binary_target
from threat_detection.preprocessing.pipeline import (
    ThreatPreprocessingPipeline,
    split_features_and_target,
)

DEFAULT_RF_HYPERPARAMETERS: Dict[str, Any] = {
    "n_estimators": 100,
    "max_depth": 20,
    "min_samples_split": 2,
    "min_samples_leaf": 1,
    "class_weight": "balanced",
    "random_state": 42,
    "n_jobs": -1,
}


@dataclass
class TrainingSummary:
    """Structured report capturing the training run telemetry."""

    model_type: str
    target_type: str
    train_samples: int
    val_samples: int
    raw_feature_count: int
    encoded_feature_count: int
    train_accuracy: float
    val_accuracy: float
    train_class_distribution: Dict[str, int]
    val_class_distribution: Dict[str, int]
    hyperparameters: Dict[str, Any]
    random_seed: int
    val_fraction: float
    dataset_source: str
    artifact_path: Optional[str] = None
    created_at: str = ""

    def summary(self) -> str:
        """Format training summary as clean readable text."""
        lines = [
            "=== Random Forest Binary Baseline Training Summary ===",
            f"Model Type:               {self.model_type}",
            f"Target Formulation:       {self.target_type}",
            f"Dataset Source:           {self.dataset_source}",
            f"Partition Sizes:          Train={self.train_samples:,}, Val={self.val_samples:,}",
            f"Raw Features:             {self.raw_feature_count} -> Encoded Features: {self.encoded_feature_count}",
            f"Training Accuracy:        {self.train_accuracy:.4f}",
            f"Validation Accuracy:      {self.val_accuracy:.4f}",
            f"Train Class Distribution: {self.train_class_distribution}",
            f"Val Class Distribution:   {self.val_class_distribution}",
            f"Artifact Destination:     {self.artifact_path or 'Not persisted'}",
            f"Timestamp (UTC):          {self.created_at}",
            "=" * 55,
        ]
        return "\n".join(lines)


class ThreatDetectionArtifact:
    """Unified container encapsulating the fitted preprocessor and classifier."""

    def __init__(
        self,
        preprocessor: ThreatPreprocessingPipeline,
        classifier: RandomForestClassifier,
        metadata: Dict[str, Any],
    ) -> None:
        self.preprocessor = preprocessor
        self.classifier = classifier
        self.metadata = metadata

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """Transform raw traffic features and predict binary class labels."""
        X_trans = self.preprocessor.transform(X)
        return self.classifier.predict(X_trans)

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """Transform raw traffic features and predict class probability distributions."""
        X_trans = self.preprocessor.transform(X)
        return self.classifier.predict_proba(X_trans)

    @property
    def classes_(self) -> np.ndarray:
        """Return the classifier target classes."""
        return self.classifier.classes_

    def save(self, filepath: Union[str, Path]) -> Path:
        """Persist model artifact and companion JSON metadata to disk."""
        target_path = Path(filepath)
        target_path.parent.mkdir(parents=True, exist_ok=True)

        # Save binary model bundle using joblib
        joblib.dump(self, target_path)

        # Save companion human-readable metadata
        meta_path = target_path.with_suffix(".metadata.json")
        with meta_path.open("w", encoding="utf-8") as f:
            json.dump(self.metadata, f, indent=2)

        return target_path

    @classmethod
    def load(cls, filepath: Union[str, Path]) -> "ThreatDetectionArtifact":
        """Load persisted model artifact from disk."""
        target_path = Path(filepath)
        if not target_path.exists():
            raise FileNotFoundError(f"Model artifact not found at: '{target_path}'")
        artifact = joblib.load(target_path)
        if not isinstance(artifact, ThreatDetectionArtifact):
            raise TypeError(
                f"Loaded object is of type '{type(artifact).__name__}', expected ThreatDetectionArtifact."
            )
        return artifact


def train_binary_model(
    data: Union[str, Path, pd.DataFrame],
    val_fraction: float = 0.2,
    random_seed: int = 42,
    hyperparameters: Optional[Dict[str, Any]] = None,
    output_path: Optional[Union[str, Path]] = None,
    on_unknown_labels: str = "error",
) -> Tuple[ThreatDetectionArtifact, TrainingSummary]:
    """Execute reproducible training for binary threat classification.

    Follows strict leakage prevention:
    1. Loads and validates input dataset.
    2. Separates 41 traffic features (X) from original multi-class labels (y).
    3. Derives separate binary target ('normal' vs 'attack').
    4. Performs stratified train/validation split BEFORE preprocessing fit.
    5. Fits ThreatPreprocessingPipeline strictly on X_train.
    6. Fits RandomForestClassifier on transformed training features.
    7. Evaluates on X_val transformed using the fitted preprocessor.
    8. Packages and optionally serializes the unified artifact.

    Args:
        data: Path to NSL-KDD dataset file or pre-loaded DataFrame.
        val_fraction: Proportion of dataset allocated to validation (default 0.2).
        random_seed: Random seed for splitting and classifier reproducibility.
        hyperparameters: Optional dictionary of Random Forest hyperparameters.
        output_path: Optional path to save the model artifact. If provided, persists artifact.
        on_unknown_labels: Policy for uncatalogued attack classes ('error' or 'attack').

    Returns:
        Tuple of (ThreatDetectionArtifact, TrainingSummary).

    Raises:
        FileNotFoundError: If dataset path does not exist.
        ValueError: If data fails validation or has insufficient class distribution.
    """
    dataset_desc = "DataFrame"
    if isinstance(data, (str, Path)):
        file_path = Path(data)
        dataset_desc = str(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"Dataset file for training not found: '{file_path}'")
        df = load_nsl_kdd(file_path)
        report = validate_nsl_kdd(df)
        if not report.is_valid:
            raise ValueError(
                f"Dataset failed schema integrity validation: {report.errors}"
            )
    elif isinstance(data, pd.DataFrame):
        df = data
    else:
        raise TypeError(f"Unsupported data argument type: '{type(data).__name__}'")

    if len(df) < 10:
        raise ValueError(
            f"Dataset has only {len(df)} samples. A minimum of 10 samples is required "
            "to perform train/validation splitting and training."
        )

    # 1. Feature / target separation
    X, y = split_features_and_target(df)

    # 2. Binary target formulation
    y_binary = create_binary_target(y, on_unknown=on_unknown_labels)

    class_counts = y_binary.value_counts().to_dict()
    if len(class_counts) < 2:
        raise ValueError(
            f"Training requires both 'normal' and 'attack' classes, but observed classes are: {class_counts}"
        )

    # 3. Stratified split (with fallback if counts are too low to stratify)
    can_stratify = all(count >= 2 for count in class_counts.values())
    stratify_target = y_binary if can_stratify else None

    X_train, X_val, y_train, y_val = train_test_split(
        X,
        y_binary,
        test_size=val_fraction,
        random_state=random_seed,
        stratify=stratify_target,
    )

    # 4. Leakage-free preprocessing fit on X_train only
    preprocessor = ThreatPreprocessingPipeline(sparse_output=False)
    preprocessor.fit(X_train)

    X_train_trans = preprocessor.transform(X_train)
    X_val_trans = preprocessor.transform(X_val)

    # 5. Classifier configuration & fitting
    rf_params = dict(DEFAULT_RF_HYPERPARAMETERS)
    rf_params["random_state"] = random_seed
    if hyperparameters:
        rf_params.update(hyperparameters)

    classifier = RandomForestClassifier(**rf_params)
    classifier.fit(X_train_trans, y_train)

    train_acc = float(classifier.score(X_train_trans, y_train))
    val_acc = float(classifier.score(X_val_trans, y_val))

    timestamp_str = datetime.now(timezone.utc).isoformat()

    # 6. Metadata generation
    metadata: Dict[str, Any] = {
        "model_type": "RandomForestClassifier",
        "target_definition": "binary (normal vs attack)",
        "package_version": pkg_version,
        "scikit_learn_version": sklearn.__version__,
        "dataset_source": dataset_desc,
        "total_records": len(df),
        "train_samples": len(X_train),
        "val_samples": len(X_val),
        "raw_features_count": len(X.columns),
        "encoded_features_count": X_train_trans.shape[1],
        "train_accuracy": train_acc,
        "val_accuracy": val_acc,
        "train_class_distribution": {k: int(v) for k, v in y_train.value_counts().items()},
        "val_class_distribution": {k: int(v) for k, v in y_val.value_counts().items()},
        "hyperparameters": rf_params,
        "random_seed": random_seed,
        "created_at": timestamp_str,
    }

    # 7. Package artifact
    artifact = ThreatDetectionArtifact(
        preprocessor=preprocessor,
        classifier=classifier,
        metadata=metadata,
    )

    persisted_path_str: Optional[str] = None
    if output_path is not None:
        target_file = Path(output_path)
        artifact.save(target_file)
        persisted_path_str = str(target_file)
        metadata["artifact_path"] = persisted_path_str

    summary = TrainingSummary(
        model_type="RandomForestClassifier",
        target_type="binary ('normal' vs 'attack')",
        train_samples=len(X_train),
        val_samples=len(X_val),
        raw_feature_count=len(X.columns),
        encoded_feature_count=X_train_trans.shape[1],
        train_accuracy=train_acc,
        val_accuracy=val_acc,
        train_class_distribution={k: int(v) for k, v in y_train.value_counts().items()},
        val_class_distribution={k: int(v) for k, v in y_val.value_counts().items()},
        hyperparameters=rf_params,
        random_seed=random_seed,
        val_fraction=val_fraction,
        dataset_source=dataset_desc,
        artifact_path=persisted_path_str,
        created_at=timestamp_str,
    )

    return artifact, summary
