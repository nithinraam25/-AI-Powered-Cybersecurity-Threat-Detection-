"""Reproducible, leakage-resistant preprocessing pipeline for NSL-KDD.

Provides explicit feature/target separation, schema validation, and
scikit-learn ColumnTransformer composition for categorical and numerical features.
"""

from typing import List, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.exceptions import NotFittedError
from sklearn.preprocessing import OneHotEncoder

from threat_detection.data.schema import (
    CATEGORICAL_FEATURES,
    DIFFICULTY_COLUMN,
    FEATURE_COLUMNS,
    LABEL_COLUMN,
    NUMERICAL_FEATURES,
)


def split_features_and_target(
    df: pd.DataFrame,
) -> Tuple[pd.DataFrame, pd.Series]:
    """Separate a validated NSL-KDD DataFrame into feature matrix X and target series y.

    Enforces that:
    - Target label column ('class') is present.
    - All 41 canonical traffic features are present.
    - Target label and difficulty metadata are strictly excluded from X.
    - The original target labels in y are preserved intact.
    - The caller's input DataFrame is not modified.

    Args:
        df: Input DataFrame conforming to NSL-KDD schema.

    Returns:
        Tuple of (X, y) where X has exactly the 41 traffic feature columns
        and y contains the exact target class labels.

    Raises:
        ValueError: If required target label or traffic feature columns are missing.
    """
    if LABEL_COLUMN not in df.columns:
        raise ValueError(
            f"Required target label column '{LABEL_COLUMN}' is missing from DataFrame."
        )

    missing_features = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing_features:
        raise ValueError(
            f"DataFrame is missing {len(missing_features)} required traffic feature(s): "
            f"{missing_features}"
        )

    # Copy to avoid mutating or viewing caller data
    X = df[FEATURE_COLUMNS].copy()
    y = df[LABEL_COLUMN].copy()

    # Explicit assertion of metadata exclusion
    assert LABEL_COLUMN not in X.columns
    assert DIFFICULTY_COLUMN not in X.columns

    return X, y


def validate_traffic_features(X: pd.DataFrame) -> None:
    """Validate that feature DataFrame X matches the NSL-KDD feature contract.

    Ensures that:
    - All 41 traffic feature columns are present.
    - Target label ('class') and difficulty field are absent.
    - Numerical columns contain valid numerical representations without silent coercion.

    Args:
        X: Feature DataFrame to validate.

    Raises:
        ValueError: If columns are missing, metadata columns are present,
            or numerical columns contain unparseable non-numeric values.
    """
    if LABEL_COLUMN in X.columns:
        raise ValueError(
            f"Target label column '{LABEL_COLUMN}' must not be present in feature matrix X."
        )

    if DIFFICULTY_COLUMN in X.columns:
        raise ValueError(
            f"Metadata column '{DIFFICULTY_COLUMN}' must not be present in feature matrix X."
        )

    missing = [col for col in FEATURE_COLUMNS if col not in X.columns]
    if missing:
        raise ValueError(f"Feature matrix is missing required columns: {missing}")

    # Validate numerical column types and reject invalid strings
    for col in NUMERICAL_FEATURES:
        series = X[col]
        if series.dtype == object or pd.api.types.is_string_dtype(series):
            # Attempt safe numeric parsing check
            numeric_parsed = pd.to_numeric(series, errors="coerce")
            # If any value became NaN that was not previously NaN, it is an invalid non-numeric value
            invalid_mask = numeric_parsed.isna() & series.notna()
            if invalid_mask.any():
                invalid_samples = series[invalid_mask].head(3).tolist()
                raise ValueError(
                    f"Invalid non-numeric value(s) in numerical column '{col}': {invalid_samples}. "
                    "Numerical columns must contain valid numerical data."
                )


def create_nsl_kdd_preprocessor(
    sparse_output: bool = False,
) -> ColumnTransformer:
    """Construct a scikit-learn ColumnTransformer for NSL-KDD traffic features.

    Applies:
    - OneHotEncoder(handle_unknown='ignore') to the 3 categorical features.
    - Passthrough to the 38 numerical features.
    - Remainder='drop' to ensure any non-feature columns are excluded.

    Args:
        sparse_output: If False (default), outputs dense NumPy arrays.
            If True, outputs SciPy sparse matrices.

    Returns:
        Configured ColumnTransformer instance.
    """
    cat_encoder = OneHotEncoder(
        handle_unknown="ignore",
        sparse_output=sparse_output,
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", cat_encoder, CATEGORICAL_FEATURES),
            ("num", "passthrough", NUMERICAL_FEATURES),
        ],
        remainder="drop",
        sparse_threshold=1.0 if sparse_output else 0.0,
    )
    return preprocessor


class ThreatPreprocessingPipeline:
    """Stateful, leakage-resistant preprocessor wrapper for NSL-KDD traffic data.

    Provides a clean, documented interface around scikit-learn's ColumnTransformer,
    guaranteeing strict fit on training sets only, consistent feature layout,
    and handling of unseen categories during inference.
    """

    def __init__(self, sparse_output: bool = False) -> None:
        self.sparse_output = sparse_output
        self.transformer: ColumnTransformer = create_nsl_kdd_preprocessor(
            sparse_output=sparse_output
        )
        self._is_fitted: bool = False
        self._feature_names_out: Optional[List[str]] = None

    @property
    def is_fitted(self) -> bool:
        """Return True if preprocessor has been fitted on training data."""
        return self._is_fitted

    @property
    def n_features_in_(self) -> int:
        """Return number of raw input features expected (41)."""
        return len(FEATURE_COLUMNS)

    @property
    def feature_names_in_(self) -> List[str]:
        """Return raw input feature column names."""
        return list(FEATURE_COLUMNS)

    def fit(
        self,
        X: pd.DataFrame,
        y: Optional[pd.Series] = None,
    ) -> "ThreatPreprocessingPipeline":
        """Fit preprocessor strictly on raw traffic feature matrix X.

        Target label y is explicitly ignored during feature fitting to prevent
        data leakage.

        Args:
            X: Training feature DataFrame containing all 41 traffic features.
            y: Optional target label series (ignored).

        Returns:
            self: The fitted pipeline instance.

        Raises:
            ValueError: If X fails schema or numerical integrity checks.
        """
        validate_traffic_features(X)

        # Fit ColumnTransformer on feature columns
        self.transformer.fit(X[FEATURE_COLUMNS])
        self._is_fitted = True

        # Extract output feature names
        try:
            self._feature_names_out = list(self.transformer.get_feature_names_out())
        except Exception:
            self._feature_names_out = None

        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        """Transform raw traffic features using the fitted transformers.

        Unseen categorical values are handled gracefully by producing zero-vectors
        for unknown categories without raising exceptions.

        Args:
            X: Feature DataFrame containing all 41 traffic features.

        Returns:
            Transformed feature matrix (NumPy array or SciPy sparse matrix).

        Raises:
            NotFittedError: If pipeline has not been fitted.
            ValueError: If X fails schema or numerical integrity checks.
        """
        if not self._is_fitted:
            raise NotFittedError(
                "This ThreatPreprocessingPipeline instance is not fitted yet. "
                "Call 'fit' with training data before using 'transform'."
            )

        validate_traffic_features(X)
        transformed = self.transformer.transform(X[FEATURE_COLUMNS])

        # Convert to float32/float64 ndarray if dense
        if not self.sparse_output and hasattr(transformed, "toarray"):
            transformed = transformed.toarray()

        return transformed

    def fit_transform(
        self,
        X: pd.DataFrame,
        y: Optional[pd.Series] = None,
    ) -> np.ndarray:
        """Fit the preprocessor on X and return the transformed feature matrix.

        Args:
            X: Training feature DataFrame.
            y: Optional target label series (ignored).

        Returns:
            Transformed feature matrix.
        """
        return self.fit(X, y).transform(X)

    def get_feature_names_out(self) -> List[str]:
        """Return transformed feature column names.

        Raises:
            NotFittedError: If preprocessor is not fitted.
        """
        if not self._is_fitted:
            raise NotFittedError("Cannot get feature names from an unfitted pipeline.")

        if self._feature_names_out is not None:
            return list(self._feature_names_out)
        return list(self.transformer.get_feature_names_out())
