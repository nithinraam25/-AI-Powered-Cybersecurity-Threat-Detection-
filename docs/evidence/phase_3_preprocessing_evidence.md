# Phase 3: Preprocessing & Feature Engineering Evidence

This document captures verification evidence, test logs, and architectural contracts for **Phase 3: Reproducible, Leakage-Resistant Preprocessing Pipeline**.

---

## 1. Files Created and Modified

### Created Files
- [`src/threat_detection/preprocessing/pipeline.py`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/src/threat_detection/preprocessing/pipeline.py): Core preprocessing implementations, feature/target split, validation, and `ThreatPreprocessingPipeline`.
- [`tests/test_preprocessing.py`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/tests/test_preprocessing.py): 14 focused unit tests covering X/y separation, zero mutation, feature partitioning, unseen categories, stability, and invalid values.
- [`docs/evidence/phase_3_preprocessing_evidence.md`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/docs/evidence/phase_3_preprocessing_evidence.md): This verification artifact.

### Modified Files
- [`src/threat_detection/data/schema.py`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/src/threat_detection/data/schema.py): Added `NUMERICAL_FEATURES` (38 features) and `verify_feature_schema()` partition validator.
- [`src/threat_detection/data/__init__.py`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/src/threat_detection/data/__init__.py): Exported `NUMERICAL_FEATURES` and `verify_feature_schema`.
- [`src/threat_detection/preprocessing/__init__.py`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/src/threat_detection/preprocessing/__init__.py): Exported `split_features_and_target`, `validate_traffic_features`, `create_nsl_kdd_preprocessor`, and `ThreatPreprocessingPipeline`.
- [`docs/03_modules_and_components.md`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/docs/03_modules_and_components.md): Updated module specifications with data and preprocessing APIs.
- [`docs/05_validation_and_testing_guide.md`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/docs/05_validation_and_testing_guide.md): Logged Phase 3 test milestone.
- [`README.md`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/README.md): Updated Phase 3 status in roadmap and feature list.

---

## 2. Public Preprocessing Interfaces

1. `split_features_and_target(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]`:
   - Extracts `X` (exact 41 traffic features) and `y` (exact original target `class` label).
   - Verifies neither `class` nor `difficulty_level` exists in `X`.
   - Never mutates the caller's DataFrame.
2. `validate_traffic_features(X: pd.DataFrame) -> None`:
   - Validates that all 41 traffic feature columns are present.
   - Rejects non-numeric strings in numerical columns without silent coercion or dropping.
   - Forbids target or metadata columns in `X`.
3. `create_nsl_kdd_preprocessor(sparse_output: bool = False) -> ColumnTransformer`:
   - Factory returning configured Scikit-Learn `ColumnTransformer` with `OneHotEncoder(handle_unknown="ignore")` for categorical features and `passthrough` for numerical features.
4. `ThreatPreprocessingPipeline`:
   - Stateful preprocessor class managing `fit`, `transform`, `fit_transform`, and `get_feature_names_out()`.
   - Fits strictly on `X` (ignores `y` to prevent leakage).
   - Gracefully produces zero-vectors for unseen categorical features in test batches.

---

## 3. Feature Groups & Label Handling

- **Total Canonical Traffic Features**: 41
- **Categorical Features (3)**: `["protocol_type", "service", "flag"]`
- **Numerical Features (38)**: `duration`, `src_bytes`, `dst_bytes`, `land`, `wrong_fragment`, `urgent`, `hot`, `num_failed_logins`, `logged_in`, `num_compromised`, `root_shell`, `su_attempted`, `num_root`, `num_file_creations`, `num_shells`, `num_access_files`, `num_outbound_cmds`, `is_host_login`, `is_guest_login`, `count`, `srv_count`, `serror_rate`, `srv_serror_rate`, `rerror_rate`, `srv_rerror_rate`, `same_srv_rate`, `diff_srv_rate`, `srv_diff_host_rate`, `dst_host_count`, `dst_host_srv_count`, `dst_host_same_srv_rate`, `dst_host_diff_srv_rate`, `dst_host_same_src_port_rate`, `dst_host_srv_diff_host_rate`, `dst_host_serror_rate`, `dst_host_srv_serror_rate`, `dst_host_rerror_rate`, `dst_host_srv_rerror_rate`.
- **Target Label (`class`)**: Preserved as raw string class label; never converted to binary/family at this stage.
- **Difficulty Field (`difficulty_level`)**: Strictly excluded from model inputs (`X`).

---

## 4. Exact Commands Executed

```bash
# Full test suite execution
.\.venv\Scripts\python.exe -m pytest -v

# Verification of application entry point
.\.venv\Scripts\python.exe main.py

# Demonstration of pipeline fit, transform, and unseen category handling
.\.venv\Scripts\python.exe -c "..."
```

---

## 5. Exact Pytest Results

```text
============================= test session starts =============================
platform win32 -- Python 3.13.11, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\nithi\OneDrive\Desktop\AI-Powered-Cybersecurity-Threat-Detection\AI-Powered-Cybersecurity-Threat-Detection
configfile: pyproject.toml
testpaths: tests
plugins: anyio-4.15.1
collected 33 items

tests\test_data_ingestion.py::test_load_headerless_standard_42 PASSED    [  3%]
tests\test_data_ingestion.py::test_load_headerless_with_difficulty_43 PASSED [  6%]
tests\test_data_ingestion.py::test_load_with_header_row PASSED           [  9%]
tests\test_data_ingestion.py::test_missing_file_raises_filenotfound PASSED [ 12%]
tests\test_data_ingestion.py::test_directory_path_raises_valueerror PASSED [ 15%]
tests\test_data_ingestion.py::test_empty_file_raises_valueerror PASSED   [ 18%]
tests\test_data_ingestion.py::test_wrong_column_count_raises_valueerror PASSED [ 21%]
tests\test_data_ingestion.py::test_malformed_records_raises_valueerror PASSED [ 24%]
tests\test_data_ingestion.py::test_schema_variant_enforcement_mismatch PASSED [ 27%]
tests\test_data_ingestion.py::test_validator_duplicate_rows_reporting_without_deletion PASSED [ 30%]
tests\test_data_ingestion.py::test_validator_missing_values PASSED       [ 33%]
tests\test_data_ingestion.py::test_validator_unexpected_labels PASSED   [ 36%]
tests\test_data_ingestion.py::test_validator_class_and_family_distribution PASSED [ 39%]
tests\test_data_ingestion.py::test_cli_success_on_valid_fixture PASSED   [ 42%]
tests\test_data_ingestion.py::test_cli_failure_on_invalid_fixture PASSED [ 45%]
tests\test_data_ingestion.py::test_cli_failure_on_missing_file PASSED    [ 48%]
tests\test_data_ingestion.py::test_path_handling_independent_of_cwd PASSED [ 51%]
tests\test_foundation.py::test_package_metadata PASSED                   [ 54%]
tests\test_foundation.py::test_project_config_paths PASSED               [ 57%]
tests\test_preprocessing.py::test_split_features_and_target_separation PASSED [ 60%]
tests\test_preprocessing.py::test_split_does_not_mutate_input_dataframe PASSED [ 63%]
tests\test_preprocessing.py::test_split_missing_target_label_raises_valueerror PASSED [ 66%]
tests\test_preprocessing.py::test_split_missing_required_features_raises_valueerror PASSED [ 69%]
tests\test_preprocessing.py::test_feature_groups_partition_schema_correctly PASSED [ 72%]
tests\test_preprocessing.py::test_preprocessor_fit_and_transform_valid_data PASSED [ 75%]
tests\test_preprocessing.py::test_unseen_categorical_value_handled_without_exception PASSED [ 78%]
tests\test_preprocessing.py::test_transformed_feature_dimensions_stability PASSED [ 81%]
tests\test_preprocessing.py::test_transformed_feature_names_available PASSED [ 84%]
tests\test_preprocessing.py::test_not_fitted_error_raised_before_fit PASSED [ 87%]
tests\test_preprocessing.py::test_invalid_numerical_values_raise_valueerror PASSED [ 90%]
tests\test_preprocessing.py::test_metadata_columns_cannot_enter_transformer_input PASSED [ 93%]
tests\test_preprocessing.py::test_target_ignored_during_preprocessor_fitting PASSED [ 96%]
tests\test_preprocessing.py::test_sparse_output_option PASSED            [100%]

============================= 33 passed in 2.70s ==============================
```

---

## 6. Fit / Transform & Unseen Category Demonstration

Output from verified demonstration script:
```text
X_train shape: (2, 41) (Features only)
y_train: ['normal', 'neptune']
Class in X_train?: False
Difficulty in X_train?: False
Transformed train shape: (2, 43)
Transformed feature names sample: ['cat__protocol_type_tcp', 'cat__protocol_type_udp', 'cat__service_domain_u', 'cat__service_http', 'cat__flag_SF']
Transformed novel batch shape: (1, 43)
Unseen category transform succeeded without crashing: True
```

---

## 7. Confirmation: Zero Model Training
- No Scikit-Learn classifiers, estimators, Random Forests, Isolation Forests, or neural networks were instantiated or trained.
- The pipeline solely prepares and transforms raw data matrices into numerical representations suitable for future downstream model phases.

---

## 8. Unresolved Issues & Limitations
- **None**: All 33 tests passed, feature separation is strict and non-mutating, unseen categories are safely handled, and invalid numerical strings trigger actionable exceptions.

---

## 9. Acceptance Criteria Table

| ID | Criterion | Status | Supporting Evidence |
| :---: | :--- | :---: | :--- |
| **A** | X/y separation is explicit and tested | **PASS** | `split_features_and_target()` separates X and y, verified via `test_split_features_and_target_separation`. |
| **B** | Original target label is preserved | **PASS** | `y` retains exact original labels (`test_split_features_and_target_separation`). |
| **C** | Difficulty field excluded from model inputs | **PASS** | Verified that `difficulty_level` is absent from `X` (`assert DIFFICULTY_COLUMN not in X.columns`). |
| **D** | All 41 traffic features accounted for exactly once | **PASS** | `verify_feature_schema()` confirms exact 41-feature partition (`test_feature_groups_partition_schema_correctly`). |
| **E** | Categorical and numerical feature groups consistent | **PASS** | Disjoint sets: 3 categorical (`protocol_type`, `service`, `flag`) + 38 numerical. |
| **F** | Preprocessor fits and transforms artificial data successfully | **PASS** | `ThreatPreprocessingPipeline.fit_transform()` verified in `test_preprocessor_fit_and_transform_valid_data`. |
| **G** | Unseen categorical values do not cause transformation failure | **PASS** | `OneHotEncoder(handle_unknown="ignore")` outputs all-zero encoding without crashing (`test_unseen_categorical_value_handled_without_exception`). |
| **H** | Feature transformation layout remains stable after fitting | **PASS** | Column count remains identical across batches (`test_transformed_feature_dimensions_stability`). |
| **I** | Invalid inputs fail clearly without silent data corruption | **PASS** | Non-numeric strings in numerical columns raise `ValueError` with culprit values (`test_invalid_numerical_values_raise_valueerror`). |
| **J** | Caller's input DataFrame is not mutated | **PASS** | Input DataFrame values and structure verified identical before and after split (`test_split_does_not_mutate_input_dataframe`). |
| **K** | Tests are self-contained and require no real dataset | **PASS** | All 14 tests in `tests/test_preprocessing.py` use small synthetic fixtures. |
| **L** | All regression and preprocessing tests pass | **PASS** | 33/33 tests passed in `.\.venv\Scripts\python.exe -m pytest -v`. |
| **M** | Phase 1 and Phase 2 functionality remains intact | **PASS** | `test_foundation.py` and `test_data_ingestion.py` pass 100%; `main.py` runs cleanly. |
| **N** | No model training, evaluation, detection, alerting, database, or dashboard work introduced | **PASS** | Work strictly constrained to preprocessing contracts. |
