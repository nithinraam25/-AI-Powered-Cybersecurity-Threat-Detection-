"""NSL-KDD dataset loading module.

Provides resilient, offline loading of headerless or header-containing
NSL-KDD CSV/text files into pandas DataFrames.
"""

from pathlib import Path
from typing import Optional, Union
import pandas as pd

from threat_detection.config import config
from threat_detection.data.schema import (
    COLUMNS_42,
    COLUMNS_43,
    NSLKDDVariant,
)


def load_nsl_kdd(
    filepath: Optional[Union[str, Path]] = None,
    schema_variant: Optional[NSLKDDVariant] = None,
) -> pd.DataFrame:
    """Load an NSL-KDD dataset file into a pandas DataFrame.

    Handles headerless formats (default NSL-KDD format) as well as
    headered variants. Enforces column count contracts (42 or 43 columns)
    and preserves original raw labels and difficulty scores.

    Args:
        filepath: Path to the dataset file. If None, defaults to
            config.RAW_DATA_DIR / "KDDTrain+.txt".
        schema_variant: Optional expected variant (STANDARD_42 or WITH_DIFFICULTY_43).
            If None, auto-detected from the file column count.

    Returns:
        pd.DataFrame with assigned column names and preserved labels.

    Raises:
        FileNotFoundError: If the specified file does not exist.
        ValueError: If filepath is a directory, the file is empty,
            contains malformed records, or has an unsupported column count.
    """
    if filepath is None:
        target_path = config.RAW_DATA_DIR / "KDDTrain+.txt"
    else:
        target_path = Path(filepath)

    if not target_path.exists():
        raise FileNotFoundError(f"NSL-KDD dataset file not found: '{target_path}'")

    if target_path.is_dir():
        raise ValueError(
            f"Expected a file path, but received a directory: '{target_path}'"
        )

    # First pass: inspect first line to determine header presence and column count
    with target_path.open("r", encoding="utf-8", errors="replace") as f:
        first_line = None
        for line in f:
            stripped = line.strip()
            if stripped:
                first_line = stripped
                break

    if first_line is None:
        raise ValueError(f"NSL-KDD dataset file is empty: '{target_path}'")

    first_tokens = [tok.strip() for tok in first_line.split(",")]
    col_count = len(first_tokens)

    # Detect header presence: standard NSL-KDD begins with numeric 'duration' (e.g. '0')
    has_header = first_tokens[0].lower() == "duration"

    if col_count == 42:
        detected_variant = NSLKDDVariant.STANDARD_42
        expected_names = COLUMNS_42
    elif col_count == 43:
        detected_variant = NSLKDDVariant.WITH_DIFFICULTY_43
        expected_names = COLUMNS_43
    else:
        raise ValueError(
            f"Unsupported column count in '{target_path}': "
            f"expected 42 or 43 columns, got {col_count}."
        )

    if schema_variant is not None and detected_variant != schema_variant:
        raise ValueError(
            f"Schema variant mismatch for '{target_path}': "
            f"expected {schema_variant.value}, detected {detected_variant.value} ({col_count} columns)."
        )

    # Validate that every row has the exact expected field count
    with target_path.open("r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            field_count = len(stripped.split(","))
            if field_count != col_count:
                raise ValueError(
                    f"Malformed records in '{target_path}' at line {line_num}: "
                    f"expected {col_count} fields, found {field_count}."
                )

    # Load with pandas
    try:
        if has_header:
            df = pd.read_csv(target_path, header=0, on_bad_lines="error")
            if len(df.columns) == len(expected_names):
                df.columns = expected_names
            else:
                raise ValueError(
                    f"Header column count {len(df.columns)} does not match expected {len(expected_names)}."
                )
        else:
            df = pd.read_csv(
                target_path,
                header=None,
                names=expected_names,
                on_bad_lines="error",
            )
    except pd.errors.ParserError as e:
        raise ValueError(f"Malformed records in '{target_path}': {e}") from e

    if len(df) == 0:
        raise ValueError(f"NSL-KDD dataset file contains no records: '{target_path}'")

    return df
