# Phase 2: NSL-KDD Dataset Validation Evidence

This document provides runtime telemetry, test execution logs, and verification evidence for **Phase 2: Dataset Ingestion & Schema Validation Layer**.

---

## 1. Files Created and Modified

### Created Files
- [`src/threat_detection/data/schema.py`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/src/threat_detection/data/schema.py): Single source of truth for 41 traffic features, label, difficulty field, schema variants, and attack mappings.
- [`src/threat_detection/data/loader.py`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/src/threat_detection/data/loader.py): Headerless and header-aware CSV loader with line-level malformation checks.
- [`src/threat_detection/data/validator.py`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/src/threat_detection/data/validator.py): Non-destructive schema auditor, null analyzer, duplicate tracker, and distribution reporter.
- [`src/threat_detection/data/cli.py`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/src/threat_detection/data/cli.py): Command-line validation entry point.
- [`tests/test_data_ingestion.py`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/tests/test_data_ingestion.py): 17 unit and integration tests covering fixtures, errors, and CLI.
- [`docs/evidence/phase_2_dataset_validation_evidence.md`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/docs/evidence/phase_2_dataset_validation_evidence.md): This verification artifact.

### Modified Files
- [`src/threat_detection/data/__init__.py`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/src/threat_detection/data/__init__.py): Exposed public API exports.
- [`src/threat_detection/config.py`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/src/threat_detection/config.py): Added default dataset paths (`KDDTrain+.txt`, `KDDTest+.txt`).
- [`docs/02_dataset_and_data_flow.md`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/docs/02_dataset_and_data_flow.md): Documented NSL-KDD benchmark details, schema contracts, attack families, and CLI usage.
- [`docs/05_validation_and_testing_guide.md`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/docs/05_validation_and_testing_guide.md): Logged Phase 2 test milestone.
- [`README.md`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/README.md): Updated project roadmap status for Phase 2.

---

## 2. Supported Schema Variants & Rationale

1. **`standard_42` (`NSLKDDVariant.STANDARD_42`)**:
   - 41 traffic features + 1 target class (`class`).
   - Accommodates legacy preprocessed files or third-party subsets where the difficulty score was omitted.
2. **`with_difficulty_43` (`NSLKDDVariant.WITH_DIFFICULTY_43`)**:
   - 41 traffic features + 1 target class (`class`) + 1 difficulty score (`difficulty_level`).
   - Represents the canonical UNB NSL-KDD release (`KDDTrain+.txt`, `KDDTest+.txt`, `KDDTrain+_20Percent.txt`).
   - The difficulty rating is preserved intact for future evaluation weighting.

---

## 3. Automated Test Execution

### Pytest Command
```bash
.\.venv\Scripts\python.exe -m pytest -v
```

### Pytest Summary
```text
============================= test session starts =============================
platform win32 -- Python 3.13.11, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\nithi\OneDrive\Desktop\AI-Powered-Cybersecurity-Threat-Detection\AI-Powered-Cybersecurity-Threat-Detection
configfile: pyproject.toml
testpaths: tests
plugins: anyio-4.15.1
collected 19 items

tests\test_data_ingestion.py::test_load_headerless_standard_42 PASSED    [  5%]
tests\test_data_ingestion.py::test_load_headerless_with_difficulty_43 PASSED [ 10%]
tests\test_data_ingestion.py::test_load_with_header_row PASSED           [ 15%]
tests\test_data_ingestion.py::test_missing_file_raises_filenotfound PASSED [ 21%]
tests\test_data_ingestion.py::test_directory_path_raises_valueerror PASSED [ 26%]
tests\test_data_ingestion.py::test_empty_file_raises_valueerror PASSED   [ 31%]
tests\test_data_ingestion.py::test_wrong_column_count_raises_valueerror PASSED [ 36%]
tests\test_data_ingestion.py::test_malformed_records_raises_valueerror PASSED [ 42%]
tests\test_data_ingestion.py::test_schema_variant_enforcement_mismatch PASSED [ 47%]
tests\test_data_ingestion.py::test_validator_duplicate_rows_reporting_without_deletion PASSED [ 52%]
tests\test_data_ingestion.py::test_validator_missing_values PASSED       [ 57%]
tests\test_data_ingestion.py::test_validator_unexpected_labels PASSED   [ 63%]
tests\test_data_ingestion.py::test_validator_class_and_family_distribution PASSED [ 68%]
tests\test_data_ingestion.py::test_cli_success_on_valid_fixture PASSED   [ 73%]
tests\test_data_ingestion.py::test_cli_failure_on_invalid_fixture PASSED [ 78%]
tests\test_data_ingestion.py::test_cli_failure_on_missing_file PASSED    [ 84%]
tests\test_data_ingestion.py::test_path_handling_independent_of_cwd PASSED [ 89%]
tests\test_foundation.py::test_package_metadata PASSED                   [ 94%]
tests\test_foundation.py::test_project_config_paths PASSED               [100%]

============================= 19 passed in 0.90s ==============================
```

---

## 4. CLI Validation Evidence

### 4.1 Valid Fixture Execution
```text
Command: .\.venv\Scripts\python.exe -m threat_detection.data.cli data/sample/valid_fixture.txt
Auditing NSL-KDD dataset target: 'data\sample\valid_fixture.txt'

=== NSL-KDD Dataset Validation Report [VALID] ===
Status:               VALID
Schema Variant:       with_difficulty_43 (43 columns)
Total Records:        1
Label Column:         Present
Difficulty Field:     Present
Duplicate Records:    0 (0.00%) [Preserved]
Missing Values:       0
Attack Family Distribution:
  - NORMAL  :        1 (100.0%)
Top 1 Specific Classes:
  - normal         :        1 (100.0%)
=======================================================

[SUCCESS] Dataset schema and integrity audit passed.
Exit Code: 0
```

### 4.2 Invalid Fixture Execution (Malformed Columns)
```text
Command: .\.venv\Scripts\python.exe -m threat_detection.data.cli data/sample/invalid_fixture.txt
Auditing NSL-KDD dataset target: 'data\sample\invalid_fixture.txt'
[FATAL ERROR] Data loading failed: Unsupported column count in 'data\sample\invalid_fixture.txt': expected 42 or 43 columns, got 5.
Exit Code: 1
```

### 4.3 Missing File Execution
```text
Command: .\.venv\Scripts\python.exe -m threat_detection.data.cli data/raw/nonexistent.txt
Auditing NSL-KDD dataset target: 'data\raw\nonexistent.txt'
[FATAL ERROR] File not found: NSL-KDD dataset file not found: 'data\raw\nonexistent.txt'
Exit Code: 1
```

---

## 5. Local Real Dataset Availability Check
- Inspected `data/raw/` and `data/processed/`.
- **Status**: No real full NSL-KDD dataset (`KDDTrain+.txt`, `KDDTest+.txt`) is currently present in the repository.
- **Compliance**: As stipulated by project scope rules, zero real datasets were downloaded automatically over the network, ensuring complete offline safety and test self-containment.

---

## 6. Git Ignore Verification

Verified that:
- `data/raw/*` and `data/processed/*` remain ignored.
- New modules (`src/threat_detection/data/*.py`) and tests (`tests/test_data_ingestion.py`) are tracked.
- No dataset files, SQLite databases, or model artifacts are tracked.

---

## 7. Acceptance Criteria Assessment

| ID | Criterion | Status | Evidence |
| :---: | :--- | :---: | :--- |
| **A** | Dataset schema is documented and represented in one maintainable source of truth. | **PASS** | [`src/threat_detection/data/schema.py`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/src/threat_detection/data/schema.py) defines `FEATURE_COLUMNS`, `COLUMNS_42`, `COLUMNS_43`, variants, and mappings. |
| **B** | Loader handles supported NSL-KDD input variants correctly. | **PASS** | `test_load_headerless_standard_42` and `test_load_headerless_with_difficulty_43` passed. |
| **C** | Malformed, empty, missing, or incompatible inputs fail clearly. | **PASS** | `test_missing_file_...`, `test_empty_file_...`, `test_wrong_column_count_...`, `test_malformed_records_...` all passed. |
| **D** | Validation reports counts, label distribution, and data-quality findings. | **PASS** | `test_validator_class_and_family_distribution` and `test_validator_missing_values` passed; output validated. |
| **E** | Duplicate rows are reported without silent deletion. | **PASS** | `test_validator_duplicate_rows_reporting_without_deletion` verified duplicate counts are warned and row count preserved. |
| **F** | Tests use artificial fixtures and do not require downloading the dataset. | **PASS** | All 17 new tests synthesize tiny in-memory and `tmp_path` fixtures without external network requests. |
| **G** | CLI exit codes correctly distinguish valid and invalid input. | **PASS** | `test_cli_success_on_valid_fixture` returns 0; invalid fixtures and missing files return 1. |
| **H** | Documentation explains setup and execution. | **PASS** | Updated [`docs/02_dataset_and_data_flow.md`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/docs/02_dataset_and_data_flow.md) and [`docs/05_validation_and_testing_guide.md`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/docs/05_validation_and_testing_guide.md). |
| **I** | All automated tests pass in the project-local environment. | **PASS** | 19/19 tests passed in `.\.venv\Scripts\python.exe -m pytest -v`. |
| **J** | Phase 1 behavior remains intact. | **PASS** | `main.py` executed successfully; `test_foundation.py` passed. |
| **K** | Raw datasets are not committed. | **PASS** | `.gitignore` rules verified via `git check-ignore`. |
| **L** | No model training, feature engineering, detection rules, alerting, or dashboard implementation introduced. | **PASS** | Scope strictly constrained to ingestion and validation contracts. |
