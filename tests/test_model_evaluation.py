"""Automated tests for frozen model evaluation module and CLI.

All tests utilize small, self-contained artificial DataFrames and fixtures.
Zero full-dataset downloads or external network resources are required.
"""

import json
from pathlib import Path
from typing import List
import numpy as np
import pandas as pd
import pytest

from threat_detection.data.schema import (
    COLUMNS_43,
    FEATURE_COLUMNS,
)
from threat_detection.detection.evaluator import (
    EvaluationMetrics,
    compute_metrics_from_predictions,
    evaluate_model,
)
from threat_detection.detection.evaluate_cli import main as evaluate_cli_main
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
) -> List:
    """Generate 41 standard dummy feature values matching NSL-KDD schema."""
    return [
        duration, proto, service, flag, src_bytes, 5450, 0, 0, 0, 0, 0,
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8,
        0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 9, 9, 1.0,
        0.0, 0.11, 0.0, 0.0, 0.0, 0.0, 0.0
    ]


@pytest.fixture
def synthetic_eval_model_and_data(tmp_path: Path):
    """Fixture providing a trained model artifact and separate evaluation test DataFrame."""
    # 1. Training data (20 samples)
    train_rows = []
    for i in range(10):
        train_rows.append(_make_dummy_feature_row(duration=i) + ["normal", 21])
    for i in range(10):
        train_rows.append(_make_dummy_feature_row(duration=i + 50, src_bytes=500 + i) + ["neptune", 15])
    train_df = pd.DataFrame(train_rows, columns=COLUMNS_43)

    model_path = tmp_path / "test_model.joblib"
    artifact, _ = train_binary_model(
        data=train_df,
        val_fraction=0.2,
        random_seed=42,
        output_path=model_path,
    )

    # 2. Evaluation test data (10 samples: 5 normal, 5 attack including unknown)
    eval_rows = []
    for i in range(5):
        eval_rows.append(_make_dummy_feature_row(duration=i + 100) + ["normal", 21])
    eval_rows.append(_make_dummy_feature_row(duration=200, src_bytes=900) + ["neptune", 15])
    eval_rows.append(_make_dummy_feature_row(duration=201, src_bytes=910) + ["smurf", 18])
    eval_rows.append(_make_dummy_feature_row(duration=202, src_bytes=920) + ["satan", 20])
    eval_rows.append(_make_dummy_feature_row(duration=203, src_bytes=930) + ["snmpgetattack", 12])  # Uncatalogued
    eval_rows.append(_make_dummy_feature_row(duration=204, src_bytes=940) + ["guess_passwd", 14])

    eval_df = pd.DataFrame(eval_rows, columns=COLUMNS_43)
    eval_csv_path = tmp_path / "test_eval_data.txt"
    eval_df.to_csv(eval_csv_path, header=False, index=False)

    return model_path, eval_csv_path, eval_df, artifact


def test_metric_calculations_known_fixture():
    """Verify exact metric calculations using known ground truth and predictions."""
    # 5 normal, 5 attack
    y_true = pd.Series(
        [BINARY_LABEL_NORMAL] * 5 + [BINARY_LABEL_ATTACK] * 5
    )
    # Model predictions:
    # 4 normal correct, 1 normal false alarm (FP)
    # 4 attack correct, 1 attack missed (FN)
    y_pred = np.array(
        [BINARY_LABEL_NORMAL] * 4
        + [BINARY_LABEL_ATTACK]
        + [BINARY_LABEL_ATTACK] * 4
        + [BINARY_LABEL_NORMAL]
    )

    metrics = compute_metrics_from_predictions(y_true=y_true, y_pred=y_pred)

    assert metrics.total_samples == 10
    assert metrics.excluded_samples == 0
    assert metrics.accuracy == pytest.approx(0.8)
    assert metrics.true_negatives == 4
    assert metrics.false_positives == 1
    assert metrics.false_negatives == 1
    assert metrics.true_positives == 4
    assert metrics.false_positive_rate == pytest.approx(0.2)  # 1 / (1 + 4)
    assert metrics.false_negative_rate == pytest.approx(0.2)  # 1 / (1 + 4)
    assert metrics.precision_normal == pytest.approx(0.8)     # 4 / 5
    assert metrics.recall_normal == pytest.approx(0.8)        # 4 / 5
    assert metrics.precision_attack == pytest.approx(0.8)     # 4 / 5
    assert metrics.recall_attack == pytest.approx(0.8)        # 4 / 5
    assert metrics.f1_normal == pytest.approx(0.8)
    assert metrics.f1_attack == pytest.approx(0.8)
    assert metrics.macro_f1 == pytest.approx(0.8)
    assert metrics.weighted_f1 == pytest.approx(0.8)


def test_confusion_matrix_orientation_and_rates():
    """Verify confusion matrix orientation: rows are ground-truth, cols are predictions."""
    # 10 Normal, 10 Attack
    y_true = pd.Series([BINARY_LABEL_NORMAL] * 10 + [BINARY_LABEL_ATTACK] * 10)
    # Pred: 8 Normal correct (2 FP), 7 Attack correct (3 FN)
    y_pred = np.array(
        [BINARY_LABEL_NORMAL] * 8
        + [BINARY_LABEL_ATTACK] * 2
        + [BINARY_LABEL_ATTACK] * 7
        + [BINARY_LABEL_NORMAL] * 3
    )

    metrics = compute_metrics_from_predictions(y_true=y_true, y_pred=y_pred)

    assert metrics.confusion_matrix_grid == [[8, 2], [3, 7]]
    assert metrics.true_negatives == 8
    assert metrics.false_positives == 2
    assert metrics.false_negatives == 3
    assert metrics.true_positives == 7
    assert metrics.false_positive_rate == pytest.approx(2 / 10)
    assert metrics.false_negative_rate == pytest.approx(3 / 10)


def test_prediction_target_length_mismatch_raises_error():
    """Verify ValueError is raised if prediction length differs from target length."""
    y_true = pd.Series([BINARY_LABEL_NORMAL, BINARY_LABEL_ATTACK])
    y_pred = np.array([BINARY_LABEL_NORMAL])

    with pytest.raises(ValueError, match="does not match prediction length"):
        compute_metrics_from_predictions(y_true=y_true, y_pred=y_pred)


def test_empty_target_raises_error():
    """Verify ValueError is raised on empty target."""
    with pytest.raises(ValueError, match="empty dataset"):
        compute_metrics_from_predictions(y_true=pd.Series(dtype=str), y_pred=np.array([]))


def test_evaluate_model_with_loaded_artifact_without_retraining(synthetic_eval_model_and_data):
    """Verify evaluate_model evaluates without mutating or retraining the artifact."""
    model_path, eval_csv_path, eval_df, artifact = synthetic_eval_model_and_data

    # Record model parameter state
    initial_n_estimators = artifact.classifier.n_estimators
    initial_classes = list(artifact.classifier.classes_)

    # Run evaluation
    metrics = evaluate_model(
        artifact=artifact,
        data=eval_df,
        on_unknown_labels="attack",
        model_source_desc=str(model_path),
    )

    assert isinstance(metrics, EvaluationMetrics)
    assert metrics.total_samples == 10
    assert metrics.excluded_samples == 0
    assert metrics.unknown_labels_encountered == 1
    assert "snmpgetattack" in metrics.unknown_label_names
    assert metrics.accuracy >= 0.0

    # Verify model parameters and state were not modified
    assert artifact.classifier.n_estimators == initial_n_estimators
    assert list(artifact.classifier.classes_) == initial_classes
    assert artifact.preprocessor.is_fitted is True


def test_evaluate_model_explicit_handling_of_unknown_labels(synthetic_eval_model_and_data):
    """Verify handling of uncatalogued attack labels under both policies."""
    _, _, eval_df, artifact = synthetic_eval_model_and_data

    # Policy 1: 'attack' maps novel label cleanly
    metrics = evaluate_model(artifact, eval_df, on_unknown_labels="attack")
    assert metrics.unknown_labels_encountered == 1
    assert metrics.unknown_policy == "attack"
    assert metrics.total_samples == len(eval_df)

    # Policy 2: 'error' rejects uncatalogued label
    with pytest.raises(ValueError, match="Uncatalogued target label"):
        evaluate_model(artifact, eval_df, on_unknown_labels="error")


def test_evaluate_model_roc_pr_auc_computation():
    """Verify ROC-AUC and PR-AUC computation when positive class probabilities are provided."""
    y_true = pd.Series([BINARY_LABEL_NORMAL] * 5 + [BINARY_LABEL_ATTACK] * 5)
    # Perfect probabilities for attack class
    y_prob_attack = np.array([0.1, 0.2, 0.1, 0.05, 0.2, 0.8, 0.9, 0.85, 0.95, 0.9])
    y_pred = np.array([BINARY_LABEL_NORMAL] * 5 + [BINARY_LABEL_ATTACK] * 5)

    metrics = compute_metrics_from_predictions(
        y_true=y_true,
        y_pred=y_pred,
        y_prob_attack=y_prob_attack,
    )

    assert metrics.roc_auc == pytest.approx(1.0)
    assert metrics.pr_auc == pytest.approx(1.0)


def test_evaluate_cli_success_and_json_output(synthetic_eval_model_and_data, tmp_path):
    """Verify evaluate_cli runs successfully and saves formatted JSON output."""
    model_path, eval_csv_path, _, _ = synthetic_eval_model_and_data
    json_out = tmp_path / "eval_metrics.json"

    exit_code = evaluate_cli_main([
        str(eval_csv_path),
        "--model", str(model_path),
        "--json-output", str(json_out),
    ])

    assert exit_code == 0
    assert json_out.exists()

    with json_out.open("r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["total_samples"] == 10
    assert "accuracy" in data
    assert "false_positive_rate" in data
    assert "false_negative_rate" in data


def test_evaluate_cli_missing_dataset_returns_code_1(synthetic_eval_model_and_data):
    """Verify evaluate_cli returns exit code 1 when test dataset file is missing."""
    model_path, _, _, _ = synthetic_eval_model_and_data

    exit_code = evaluate_cli_main([
        "data/non_existent_test_file.txt",
        "--model", str(model_path),
    ])

    assert exit_code == 1


def test_evaluate_cli_missing_model_returns_code_1(synthetic_eval_model_and_data):
    """Verify evaluate_cli returns exit code 1 when model artifact is missing."""
    _, eval_csv_path, _, _ = synthetic_eval_model_and_data

    exit_code = evaluate_cli_main([
        str(eval_csv_path),
        "--model", "models/non_existent_model.joblib",
    ])

    assert exit_code == 1
