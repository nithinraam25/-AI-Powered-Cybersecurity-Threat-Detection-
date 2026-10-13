"""Automated tests for NSL-KDD dataset loading and validation.

All tests utilize small, temporary artificial fixtures and do not
require external network calls or full dataset downloads.
"""

from pathlib import Path
import numpy as np
import pandas as pd
import pytest

from threat_detection.data.cli import main as cli_main
from threat_detection.data.loader import load_nsl_kdd
from threat_detection.data.schema import (
    COLUMNS_42,
    COLUMNS_43,
    DIFFICULTY_COLUMN,
    FEATURE_COLUMNS,
    LABEL_COLUMN,
    NSLKDDVariant,
)
from threat_detection.data.validator import validate_nsl_kdd


def _create_sample_row_41() -> list:
    """Generate 41 standard dummy feature values matching NSL-KDD schema."""
    return [
        "0", "tcp", "http", "SF", "181", "5450", "0", "0", "0", "0", "0",
        "1", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "8", "8",
        "0.0", "0.0", "0.0", "0.0", "1.0", "0.0", "0.0", "9", "9", "1.0",
        "0.0", "0.11", "0.0", "0.0", "0.0", "0.0", "0.0"
    ]


@pytest.fixture
def valid_fixture_42(tmp_path: Path) -> Path:
    """Create a temporary valid headerless 42-column NSL-KDD fixture."""
    file_path = tmp_path / "sample_42.txt"
    row1 = _create_sample_row_41() + ["normal"]
    row2 = _create_sample_row_41() + ["neptune"]
    content = ",".join(row1) + "\n" + ",".join(row2) + "\n"
    file_path.write_text(content, encoding="utf-8")
    return file_path


@pytest.fixture
def valid_fixture_43(tmp_path: Path) -> Path:
    """Create a temporary valid headerless 43-column NSL-KDD fixture with difficulty."""
    file_path = tmp_path / "sample_43.txt"
    row1 = _create_sample_row_41() + ["normal", "21"]
    row2 = _create_sample_row_41() + ["smurf", "15"]
    content = ",".join(row1) + "\n" + ",".join(row2) + "\n"
    file_path.write_text(content, encoding="utf-8")
    return file_path


def test_load_headerless_standard_42(valid_fixture_42: Path) -> None:
    """Verify loading headerless 42-column NSL-KDD file assigns columns correctly."""
    df = load_nsl_kdd(valid_fixture_42)
    assert len(df) == 2
    assert list(df.columns) == COLUMNS_42
    assert df[LABEL_COLUMN].tolist() == ["normal", "neptune"]
    assert DIFFICULTY_COLUMN not in df.columns


def test_load_headerless_with_difficulty_43(valid_fixture_43: Path) -> None:
    """Verify loading headerless 43-column NSL-KDD file preserves difficulty field."""
    df = load_nsl_kdd(valid_fixture_43)
    assert len(df) == 2
    assert list(df.columns) == COLUMNS_43
    assert df[LABEL_COLUMN].tolist() == ["normal", "smurf"]
    assert df[DIFFICULTY_COLUMN].astype(int).tolist() == [21, 15]


def test_load_with_header_row(tmp_path: Path) -> None:
    """Verify file with header row is recognized and not loaded as a data record."""
    file_path = tmp_path / "with_header.csv"
    header = ",".join(COLUMNS_42)
    row = ",".join(_create_sample_row_41() + ["normal"])
    file_path.write_text(header + "\n" + row + "\n", encoding="utf-8")

    df = load_nsl_kdd(file_path)
    assert len(df) == 1
    assert list(df.columns) == COLUMNS_42
    assert df[LABEL_COLUMN].iloc[0] == "normal"


def test_missing_file_raises_filenotfound(tmp_path: Path) -> None:
    """Verify actionable FileNotFoundError when file does not exist."""
    missing = tmp_path / "nonexistent_file.txt"
    with pytest.raises(FileNotFoundError, match="not found"):
        load_nsl_kdd(missing)


def test_directory_path_raises_valueerror(tmp_path: Path) -> None:
    """Verify passing a directory raises ValueError."""
    with pytest.raises(ValueError, match="received a directory"):
        load_nsl_kdd(tmp_path)


def test_empty_file_raises_valueerror(tmp_path: Path) -> None:
    """Verify empty file raises ValueError with clear error message."""
    empty_file = tmp_path / "empty.txt"
    empty_file.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        load_nsl_kdd(empty_file)


def test_wrong_column_count_raises_valueerror(tmp_path: Path) -> None:
    """Verify files with unsupported column count raise ValueError."""
    bad_file = tmp_path / "bad_columns.txt"
    bad_file.write_text("0,tcp,http\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported column count"):
        load_nsl_kdd(bad_file)


def test_malformed_records_raises_valueerror(tmp_path: Path) -> None:
    """Verify malformed row with mismatched columns raises ValueError."""
    bad_file = tmp_path / "malformed.txt"
    row1 = ",".join(_create_sample_row_41() + ["normal"])
    row2 = "0,tcp,truncated_row"
    bad_file.write_text(row1 + "\n" + row2 + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Malformed records"):
        load_nsl_kdd(bad_file)


def test_schema_variant_enforcement_mismatch(valid_fixture_42: Path) -> None:
    """Verify explicit schema variant requirement fails on mismatched file."""
    with pytest.raises(ValueError, match="Schema variant mismatch"):
        load_nsl_kdd(valid_fixture_42, schema_variant=NSLKDDVariant.WITH_DIFFICULTY_43)


def test_validator_duplicate_rows_reporting_without_deletion() -> None:
    """Verify duplicate records are counted and warned without silent deletion."""
    row = _create_sample_row_41() + ["normal"]
    # Create DataFrame with identical rows
    df = pd.DataFrame([row, row, row], columns=COLUMNS_42)
    assert len(df) == 3

    report = validate_nsl_kdd(df)
    assert report.is_valid is True
    assert report.row_count == 3
    assert report.duplicate_rows == 2
    assert any("duplicate" in w.lower() for w in report.warnings)
    # Confirm DataFrame was not modified
    assert len(df) == 3


def test_validator_missing_values() -> None:
    """Verify missing values are accurately reported by column."""
    row = _create_sample_row_41() + ["normal"]
    df = pd.DataFrame([row, row], columns=COLUMNS_42)
    df.loc[0, "duration"] = np.nan
    df.loc[1, "src_bytes"] = np.nan

    report = validate_nsl_kdd(df)
    assert report.total_missing_values == 2
    assert report.missing_values_by_column == {"duration": 1, "src_bytes": 1}
    assert any("missing" in w.lower() for w in report.warnings)


def test_validator_unexpected_labels() -> None:
    """Verify unexpected labels produce warnings by default, or errors in strict mode."""
    row = _create_sample_row_41() + ["zero_day_threat_xyz"]
    df = pd.DataFrame([row], columns=COLUMNS_42)

    # Permissive mode (default): warning
    report_permissive = validate_nsl_kdd(df, allow_unknown_labels=True)
    assert report_permissive.is_valid is True
    assert "zero_day_threat_xyz" in report_permissive.unknown_labels
    assert any("uncatalogued" in w.lower() for w in report_permissive.warnings)

    # Strict mode: fatal error
    report_strict = validate_nsl_kdd(df, allow_unknown_labels=False)
    assert report_strict.is_valid is False
    assert any("uncatalogued" in e.lower() for e in report_strict.errors)


def test_validator_class_and_family_distribution() -> None:
    """Verify calculation of specific attack labels and attack family aggregations."""
    data = [
        _create_sample_row_41() + ["normal"],
        _create_sample_row_41() + ["normal"],
        _create_sample_row_41() + ["neptune"],       # dos
        _create_sample_row_41() + ["satan"],         # probe
        _create_sample_row_41() + ["guess_passwd"],  # r2l
        _create_sample_row_41() + ["buffer_overflow"] # u2r
    ]
    df = pd.DataFrame(data, columns=COLUMNS_42)
    report = validate_nsl_kdd(df)

    assert report.is_valid is True
    assert report.row_count == 6
    assert report.class_distribution["normal"] == 2
    assert report.class_distribution["neptune"] == 1
    assert report.attack_family_distribution == {
        "normal": 2,
        "dos": 1,
        "probe": 1,
        "r2l": 1,
        "u2r": 1,
    }


def test_cli_success_on_valid_fixture(valid_fixture_42: Path) -> None:
    """Verify CLI exit code is 0 on valid dataset input."""
    exit_code = cli_main([str(valid_fixture_42)])
    assert exit_code == 0


def test_cli_failure_on_invalid_fixture(tmp_path: Path) -> None:
    """Verify CLI exit code is 1 on malformed or empty dataset input."""
    bad_file = tmp_path / "corrupt.txt"
    bad_file.write_text("0,bad,data\n", encoding="utf-8")

    exit_code = cli_main([str(bad_file)])
    assert exit_code == 1


def test_cli_failure_on_missing_file(tmp_path: Path) -> None:
    """Verify CLI exit code is 1 when requested file does not exist."""
    missing_file = tmp_path / "missing.txt"
    exit_code = cli_main([str(missing_file)])
    assert exit_code == 1


def test_path_handling_independent_of_cwd(valid_fixture_42: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Verify loading functions work regardless of process current working directory."""
    # Switch working directory to an arbitrary temporary directory
    other_dir = tmp_path / "different_cwd"
    other_dir.mkdir()
    monkeypatch.chdir(other_dir)

    # Loading with absolute path to valid fixture still succeeds
    df = load_nsl_kdd(valid_fixture_42.resolve())
    assert len(df) == 2
    assert list(df.columns) == COLUMNS_42
