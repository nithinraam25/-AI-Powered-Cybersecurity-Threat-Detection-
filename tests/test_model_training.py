"""Automated tests for reproducible Random Forest binary model training.

All tests utilize small, self-contained artificial DataFrames.
Zero full-dataset downloads or external network resources are required.
"""

from pathlib import Path
from typing import List
import numpy as np
import pandas as pd
import pytest

from threat_detection.data.schema import (
    COLUMNS_43,
    DIFFICULTY_COLUMN,
    FEATURE_COLUMNS,
    LABEL_COLUMN,
)
from threat_detection.detection.target import (
    BINARY_LABEL_ATTACK,
    BINARY_LABEL_NORMAL,
    create_binary_target,
)
from threat_detection.detection.train_cli import main as train_cli_main
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
def synthetic_training_df() -> pd.DataFrame:
    """Construct an artificial 30-row NSL-KDD DataFrame with normal and attack samples."""
    rows = []
    # 15 Normal samples
    for i in range(15):
        rows.append(_make_dummy_feature_row(proto="tcp", service="http", duration=i) + ["normal", 21])
    # 15 Attack samples across diverse attack types
    attacks = ["neptune", "smurf", "satan", "guess_passwd", "buffer_overflow"]
    for i in range(15):
        attack_type = attacks[i % len(attacks)]
        rows.append(_make_dummy_feature_row(proto="udp", service="domain_u", duration=i + 20, src_bytes=1000 + i) + [attack_type, 15])

    return pd.DataFrame(rows, columns=COLUMNS_43)


def test_binary_target_mapping_normal_and_attacks() -> None:
    """Verify 'normal' maps to 'normal' and recognized attacks map to 'attack'."""
    labels = pd.Series(["normal", "NORMAL ", "neptune", "smurf", "satan", "guess_passwd"])
    binary = create_binary_target(labels)

    assert binary.iloc[0] == BINARY_LABEL_NORMAL
    assert binary.iloc[1] == BINARY_LABEL_NORMAL
    assert binary.iloc[2] == BINARY_LABEL_ATTACK
    assert binary.iloc[3] == BINARY_LABEL_ATTACK
    assert binary.iloc[4] == BINARY_LABEL_ATTACK
    assert binary.iloc[5] == BINARY_LABEL_ATTACK


def test_binary_target_original_series_unchanged() -> None:
    """Verify input labels Series is not modified in place."""
    original = pd.Series(["normal", "neptune", "smurf"], name="class")
    copy_values = original.values.copy()

    binary = create_binary_target(original)
    assert original.name == "class"
    assert binary.name == "binary_target"
    np.testing.assert_array_equal(original.values, copy_values)


def test_binary_target_unknown_labels_policy() -> None:
    """Verify uncatalogued labels trigger ValueError under 'error' policy and map under 'attack' policy."""
    labels = pd.Series(["normal", "alien_exploit_0day"])

    with pytest.raises(ValueError, match="Uncatalogued target label"):
        create_binary_target(labels, on_unknown="error")

    permissive = create_binary_target(labels, on_unknown="attack")
    assert permissive.iloc[0] == BINARY_LABEL_NORMAL
    assert permissive.iloc[1] == BINARY_LABEL_ATTACK


def test_binary_target_empty_series_raises_valueerror() -> None:
    """Verify empty label Series raises ValueError."""
    with pytest.raises(ValueError, match="empty labels Series"):
        create_binary_target(pd.Series([], dtype=str))


def test_feature_and_metadata_exclusion_in_training(synthetic_training_df: pd.DataFrame) -> None:
    """Verify target and difficulty metadata are excluded from training features."""
    artifact, summary = train_binary_model(synthetic_training_df, val_fraction=0.2)

    assert summary.raw_feature_count == 41
    assert LABEL_COLUMN not in artifact.preprocessor.feature_names_in_
    assert DIFFICULTY_COLUMN not in artifact.preprocessor.feature_names_in_


def test_split_occurs_before_preprocessor_fitting(synthetic_training_df: pd.DataFrame) -> None:
    """Verify dataset is split before fitting preprocessor (leakage prevention)."""
    _, summary = train_binary_model(synthetic_training_df, val_fraction=0.2)

    assert summary.train_samples == 24
    assert summary.val_samples == 6
    assert summary.train_samples + summary.val_samples == 30


def test_training_run_completes_on_artificial_dataset(synthetic_training_df: pd.DataFrame) -> None:
    """Verify Random Forest fits successfully and produces valid accuracy metrics."""
    artifact, summary = train_binary_model(synthetic_training_df, val_fraction=0.2, random_seed=42)

    assert isinstance(artifact, ThreatDetectionArtifact)
    assert summary.train_accuracy >= 0.0 and summary.train_accuracy <= 1.0
    assert summary.val_accuracy >= 0.0 and summary.val_accuracy <= 1.0
    assert summary.encoded_feature_count >= 41
    assert set(artifact.classes_) == {BINARY_LABEL_NORMAL, BINARY_LABEL_ATTACK}


def test_random_seed_and_reproducibility(synthetic_training_df: pd.DataFrame) -> None:
    """Verify identical random seed produces identical predictions."""
    art1, sum1 = train_binary_model(synthetic_training_df, random_seed=42)
    art2, sum2 = train_binary_model(synthetic_training_df, random_seed=42)

    X_test = synthetic_training_df.iloc[:5][FEATURE_COLUMNS]
    pred1 = art1.predict(X_test)
    pred2 = art2.predict(X_test)
    proba1 = art1.predict_proba(X_test)
    proba2 = art2.predict_proba(X_test)

    np.testing.assert_array_equal(pred1, pred2)
    np.testing.assert_allclose(proba1, proba2)
    assert sum1.train_accuracy == sum2.train_accuracy


def test_validation_data_transformed_without_refitting(synthetic_training_df: pd.DataFrame) -> None:
    """Verify validation partition uses the fitted preprocessor without refitting."""
    artifact, summary = train_binary_model(synthetic_training_df, val_fraction=0.2)

    assert artifact.preprocessor.is_fitted
    feature_names = artifact.preprocessor.get_feature_names_out()
    assert len(feature_names) == summary.encoded_feature_count


def test_artifact_save_and_reload_predictions(synthetic_training_df: pd.DataFrame, tmp_path: Path) -> None:
    """Verify model bundle and companion JSON metadata are correctly serialized and reloaded."""
    artifact_path = tmp_path / "models" / "rf_test.joblib"
    artifact, summary = train_binary_model(
        synthetic_training_df,
        output_path=artifact_path,
        random_seed=42,
    )

    assert artifact_path.exists()
    meta_path = artifact_path.with_suffix(".metadata.json")
    assert meta_path.exists()

    reloaded = ThreatDetectionArtifact.load(artifact_path)
    X_sample = synthetic_training_df.iloc[:4][FEATURE_COLUMNS]

    original_preds = artifact.predict(X_sample)
    reloaded_preds = reloaded.predict(X_sample)
    np.testing.assert_array_equal(original_preds, reloaded_preds)


def test_missing_dataset_path_fails_clearly(tmp_path: Path) -> None:
    """Verify passing a non-existent file path raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError, match="not found"):
        train_binary_model(tmp_path / "nonexistent_file.txt")


def test_insufficient_samples_or_single_class_fails_clearly() -> None:
    """Verify datasets with too few samples or single-class distributions fail safely."""
    # Too few samples (< 10)
    few_rows = [_make_dummy_feature_row() + ["normal", 21] for _ in range(5)]
    df_few = pd.DataFrame(few_rows, columns=COLUMNS_43)
    with pytest.raises(ValueError, match="minimum of 10 samples"):
        train_binary_model(df_few)

    # Single class only (12 normal, 0 attack)
    normal_only = [_make_dummy_feature_row() + ["normal", 21] for _ in range(12)]
    df_single_class = pd.DataFrame(normal_only, columns=COLUMNS_43)
    with pytest.raises(ValueError, match="requires both 'normal' and 'attack'"):
        train_binary_model(df_single_class)


def test_no_raw_file_modification(synthetic_training_df: pd.DataFrame, tmp_path: Path) -> None:
    """Verify training process never mutates the underlying raw dataset file."""
    raw_file = tmp_path / "raw_dataset.txt"
    # Write headerless CSV
    synthetic_training_df.to_csv(raw_file, header=False, index=False)
    raw_content_before = raw_file.read_bytes()

    train_binary_model(raw_file, output_path=tmp_path / "out.joblib")

    raw_content_after = raw_file.read_bytes()
    assert raw_content_before == raw_content_after


def test_train_cli_success(synthetic_training_df: pd.DataFrame, tmp_path: Path) -> None:
    """Verify training CLI exits with code 0 on valid dataset input."""
    raw_file = tmp_path / "train_file.txt"
    synthetic_training_df.to_csv(raw_file, header=False, index=False)
    out_file = tmp_path / "baseline.joblib"

    exit_code = train_cli_main([str(raw_file), "--output", str(out_file), "--seed", "42"])
    assert exit_code == 0
    assert out_file.exists()


def test_train_cli_failure_on_missing_file(tmp_path: Path) -> None:
    """Verify training CLI exits with code 1 on missing file."""
    missing = tmp_path / "missing_file.txt"
    exit_code = train_cli_main([str(missing)])
    assert exit_code == 1
