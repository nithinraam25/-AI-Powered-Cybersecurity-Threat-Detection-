"""Automated tests for NSL-KDD preprocessing and feature engineering.

All tests utilize small, self-contained artificial DataFrames.
Zero full-dataset downloads or external network resources are required.
"""

from typing import List
import numpy as np
import pandas as pd
import pytest
from scipy import sparse
from sklearn.exceptions import NotFittedError

from threat_detection.data.schema import (
    CATEGORICAL_FEATURES,
    COLUMNS_42,
    COLUMNS_43,
    DIFFICULTY_COLUMN,
    FEATURE_COLUMNS,
    LABEL_COLUMN,
    NUMERICAL_FEATURES,
    verify_feature_schema,
)
from threat_detection.preprocessing.pipeline import (
    ThreatPreprocessingPipeline,
    create_nsl_kdd_preprocessor,
    split_features_and_target,
    validate_traffic_features,
)


def _make_sample_row_41(
    proto: str = "tcp",
    service: str = "http",
    flag: str = "SF",
    duration: int = 0,
) -> List:
    """Generate 41 standard dummy feature values matching NSL-KDD schema."""
    return [
        duration, proto, service, flag, 181, 5450, 0, 0, 0, 0, 0,
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8,
        0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 9, 9, 1.0,
        0.0, 0.11, 0.0, 0.0, 0.0, 0.0, 0.0
    ]


@pytest.fixture
def sample_raw_dataframe() -> pd.DataFrame:
    """Construct an artificial 43-column NSL-KDD DataFrame with difficulty field."""
    rows = [
        _make_sample_row_41(proto="tcp", service="http", flag="SF", duration=0) + ["normal", 21],
        _make_sample_row_41(proto="udp", service="domain_u", flag="SF", duration=1) + ["neptune", 15],
        _make_sample_row_41(proto="icmp", service="eco_i", flag="SF", duration=0) + ["smurf", 18],
    ]
    return pd.DataFrame(rows, columns=COLUMNS_43)


def test_split_features_and_target_separation(sample_raw_dataframe: pd.DataFrame) -> None:
    """Verify clean separation of 41 traffic features and original target label."""
    X, y = split_features_and_target(sample_raw_dataframe)

    assert len(X) == 3
    assert len(y) == 3
    assert list(X.columns) == FEATURE_COLUMNS
    assert X.shape[1] == 41

    # Ensure label and difficulty are strictly absent from X
    assert LABEL_COLUMN not in X.columns
    assert DIFFICULTY_COLUMN not in X.columns

    # Verify target series fidelity
    assert y.name == LABEL_COLUMN
    assert y.tolist() == ["normal", "neptune", "smurf"]


def test_split_does_not_mutate_input_dataframe(sample_raw_dataframe: pd.DataFrame) -> None:
    """Verify caller's input DataFrame is preserved without modification."""
    original_cols = list(sample_raw_dataframe.columns)
    original_shape = sample_raw_dataframe.shape
    original_values = sample_raw_dataframe.values.copy()

    X, y = split_features_and_target(sample_raw_dataframe)

    assert list(sample_raw_dataframe.columns) == original_cols
    assert sample_raw_dataframe.shape == original_shape
    np.testing.assert_array_equal(sample_raw_dataframe.values, original_values)


def test_split_missing_target_label_raises_valueerror() -> None:
    """Verify missing target column raises ValueError."""
    rows = [_make_sample_row_41()]
    df_no_label = pd.DataFrame(rows, columns=FEATURE_COLUMNS)

    with pytest.raises(ValueError, match="Required target label column"):
        split_features_and_target(df_no_label)


def test_split_missing_required_features_raises_valueerror() -> None:
    """Verify missing traffic feature column raises ValueError."""
    rows = [_make_sample_row_41() + ["normal"]]
    cols = list(COLUMNS_42)
    cols[0] = "wrong_column_name"
    df_missing_feat = pd.DataFrame(rows, columns=cols)

    with pytest.raises(ValueError, match="missing .* required traffic feature"):
        split_features_and_target(df_missing_feat)


def test_feature_groups_partition_schema_correctly() -> None:
    """Verify categorical and numerical features strictly partition the 41 features."""
    verify_feature_schema()

    assert len(FEATURE_COLUMNS) == 41
    assert len(CATEGORICAL_FEATURES) == 3
    assert len(NUMERICAL_FEATURES) == 38

    # Strict disjointness
    assert set(CATEGORICAL_FEATURES).isdisjoint(set(NUMERICAL_FEATURES))

    # Exact union
    assert set(CATEGORICAL_FEATURES) | set(NUMERICAL_FEATURES) == set(FEATURE_COLUMNS)

    # Exclusions
    assert LABEL_COLUMN not in CATEGORICAL_FEATURES
    assert LABEL_COLUMN not in NUMERICAL_FEATURES
    assert DIFFICULTY_COLUMN not in CATEGORICAL_FEATURES
    assert DIFFICULTY_COLUMN not in NUMERICAL_FEATURES


def test_preprocessor_fit_and_transform_valid_data(sample_raw_dataframe: pd.DataFrame) -> None:
    """Verify pipeline fits on training features and produces dense transformed array."""
    X, _ = split_features_and_target(sample_raw_dataframe)
    pipeline = ThreatPreprocessingPipeline(sparse_output=False)

    assert not pipeline.is_fitted
    transformed = pipeline.fit_transform(X)

    assert pipeline.is_fitted
    assert isinstance(transformed, np.ndarray)
    assert transformed.shape[0] == 3
    # 38 numerical + one-hot encoded categories
    assert transformed.shape[1] >= 38
    assert np.issubdtype(transformed.dtype, np.number)


def test_unseen_categorical_value_handled_without_exception(sample_raw_dataframe: pd.DataFrame) -> None:
    """Verify unseen categories in test batches are ignored without crashing."""
    X_train, _ = split_features_and_target(sample_raw_dataframe)
    pipeline = ThreatPreprocessingPipeline(sparse_output=False)
    pipeline.fit(X_train)

    train_dim = pipeline.transform(X_train).shape[1]

    # Batch with novel/unseen categorical values
    novel_row = _make_sample_row_41(
        proto="unknown_proto_xyz",
        service="alien_service_123",
        flag="NEW_FLAG",
    )
    X_novel = pd.DataFrame([novel_row], columns=FEATURE_COLUMNS)

    transformed_novel = pipeline.transform(X_novel)
    assert isinstance(transformed_novel, np.ndarray)
    assert transformed_novel.shape[0] == 1
    # Dimensionality must remain identical to fitted schema
    assert transformed_novel.shape[1] == train_dim


def test_transformed_feature_dimensions_stability(sample_raw_dataframe: pd.DataFrame) -> None:
    """Verify transformed feature layout and column count remain constant across batches."""
    X, _ = split_features_and_target(sample_raw_dataframe)
    pipeline = ThreatPreprocessingPipeline(sparse_output=False)
    pipeline.fit(X)

    batch1 = pipeline.transform(X.iloc[:1])
    batch2 = pipeline.transform(X.iloc[1:3])

    assert batch1.shape[1] == batch2.shape[1]
    assert batch1.shape[0] == 1
    assert batch2.shape[0] == 2


def test_transformed_feature_names_available(sample_raw_dataframe: pd.DataFrame) -> None:
    """Verify transformed feature names are accessible and match output dimension."""
    X, _ = split_features_and_target(sample_raw_dataframe)
    pipeline = ThreatPreprocessingPipeline(sparse_output=False)
    pipeline.fit(X)

    feature_names = pipeline.get_feature_names_out()
    assert isinstance(feature_names, list)
    assert len(feature_names) == pipeline.transform(X).shape[1]
    assert any("cat__" in name for name in feature_names)
    assert any("num__" in name for name in feature_names)


def test_not_fitted_error_raised_before_fit(sample_raw_dataframe: pd.DataFrame) -> None:
    """Verify attempting to transform before fit raises NotFittedError."""
    X, _ = split_features_and_target(sample_raw_dataframe)
    pipeline = ThreatPreprocessingPipeline(sparse_output=False)

    with pytest.raises(NotFittedError, match="not fitted yet"):
        pipeline.transform(X)

    with pytest.raises(NotFittedError, match="unfitted"):
        pipeline.get_feature_names_out()


def test_invalid_numerical_values_raise_valueerror(sample_raw_dataframe: pd.DataFrame) -> None:
    """Verify non-numeric strings in numerical columns are rejected with ValueError."""
    X, _ = split_features_and_target(sample_raw_dataframe)
    X_corrupt = X.copy()
    X_corrupt["duration"] = X_corrupt["duration"].astype(object)
    X_corrupt.loc[0, "duration"] = "corrupted_text_payload"

    pipeline = ThreatPreprocessingPipeline()
    with pytest.raises(ValueError, match="Invalid non-numeric value"):
        pipeline.fit(X_corrupt)


def test_metadata_columns_cannot_enter_transformer_input(sample_raw_dataframe: pd.DataFrame) -> None:
    """Verify passing metadata/target columns directly to validator raises ValueError."""
    pipeline = ThreatPreprocessingPipeline()

    # Pass DataFrame that still has class label
    with pytest.raises(ValueError, match="Target label column .* must not be present"):
        pipeline.fit(sample_raw_dataframe)


def test_target_ignored_during_preprocessor_fitting(sample_raw_dataframe: pd.DataFrame) -> None:
    """Verify target series y does not influence feature transformation (leakage prevention)."""
    X, y = split_features_and_target(sample_raw_dataframe)

    p1 = ThreatPreprocessingPipeline().fit(X, y=None)
    out1 = p1.transform(X)

    p2 = ThreatPreprocessingPipeline().fit(X, y=y)
    out2 = p2.transform(X)

    np.testing.assert_array_equal(out1, out2)


def test_sparse_output_option(sample_raw_dataframe: pd.DataFrame) -> None:
    """Verify preprocessor can output SciPy sparse matrix when configured."""
    X, _ = split_features_and_target(sample_raw_dataframe)
    pipeline = ThreatPreprocessingPipeline(sparse_output=True)

    transformed = pipeline.fit_transform(X)
    assert sparse.issparse(transformed)
