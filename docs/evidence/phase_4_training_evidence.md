# Phase 4: Model Training Pipeline Evidence

This document captures verification evidence, test logs, and architectural contracts for **Phase 4: Reproducible Model Training Pipeline (Random Forest Binary Baseline)**.

---

## 1. Files Created and Modified

### Created Files
- [`src/threat_detection/detection/target.py`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/src/threat_detection/detection/target.py): Non-mutating binary target creation (`normal` vs `attack`).
- [`src/threat_detection/detection/trainer.py`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/src/threat_detection/detection/trainer.py): Training workflow, leakage boundary enforcement, and `ThreatDetectionArtifact` container.
- [`src/threat_detection/detection/train_cli.py`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/src/threat_detection/detection/train_cli.py): CLI interface for initiating model training.
- [`tests/test_model_training.py`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/tests/test_model_training.py): 15 comprehensive unit and pipeline tests covering mapping, leakage prevention, serialization, and CLI.
- [`docs/evidence/phase_4_training_evidence.md`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/docs/evidence/phase_4_training_evidence.md): This verification artifact.

### Modified Files
- [`src/threat_detection/detection/__init__.py`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/src/threat_detection/detection/__init__.py): Exported target mapping, trainer, and artifact classes.
- [`docs/04_model_training_and_learning.md`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/docs/04_model_training_and_learning.md): Documented Phase 4 binary baseline architecture, leakage boundaries, hyperparameters, and CLI.
- [`docs/05_validation_and_testing_guide.md`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/docs/05_validation_and_testing_guide.md): Logged Phase 4 test milestone.
- [`README.md`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/README.md): Updated Phase 4 status in roadmap and implementation summary.

---

## 2. Exact Training Configuration

| Parameter | Configuration | Value |
| :--- | :--- | :--- |
| **Model Type** | Scikit-Learn Estimator | `RandomForestClassifier` |
| **Target Formulation** | Binary Classification | `normal` vs `attack` |
| **Validation Split** | Fraction of dataset | `0.2` (80% Train, 20% Val) |
| **Stratification** | Target-based split | Stratified by binary class when class counts permit ($\ge 2$ samples/class) |
| **Random Seed** | Seed for reproducibility | `42` (`config.RANDOM_SEED`) |
| **Trees (`n_estimators`)**| Ensemble tree count | `100` |
| **Max Depth (`max_depth`)**| Maximum decision tree depth | `20` |
| **Class Weight** | Weight balancing | `"balanced"` |
| **Min Samples Split** | Split threshold | `2` |
| **Min Samples Leaf** | Leaf threshold | `1` |
| **Parallelism (`n_jobs`)** | Core allocation | `-1` (all available cores) |

---

## 3. Real NSL-KDD Dataset Status & Training Distinction

- **Dataset File Availability**: Checked `data/raw/KDDTrain+.txt`. File is absent.
- **Strict Distinction**:
  - **No Real Model Training Occurred**: In accordance with project guardrails, no multi-megabyte dataset was downloaded automatically over the network. Real model training was **not** marked as complete.
  - **Pipeline Verification**: The complete training architecture, leakage boundaries, Random Forest estimator, preprocessor fitting, and artifact serialization were fully verified using synthetic NSL-KDD fixtures in automated test suites and CLI tests.

---

## 4. Automated Test Execution

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
collected 48 items

tests\test_data_ingestion.py .................                           [ 35%]
tests\test_foundation.py ..                                              [ 39%]
tests\test_model_training.py ...............                             [ 70%]
tests\test_preprocessing.py ..............                               [100%]

============================= 48 passed in 6.06s ==============================
```

---

## 5. Artifact Creation, Serialization & Reload Results

- **Serialization Method**: `joblib.dump()` bundling the fitted `ThreatPreprocessingPipeline` and `RandomForestClassifier` into a unified `ThreatDetectionArtifact`.
- **Companion Metadata**: Written simultaneously as `<artifact_stem>.metadata.json`.
- **Reload Verification**:
  - Test `test_artifact_save_and_reload_predictions` demonstrated that saving to disk, reloading with `ThreatDetectionArtifact.load()`, and executing inference yields identical predictions and probabilities to the original in-memory instance (`np.testing.assert_array_equal(original_preds, reloaded_preds)`).

---

## 6. Training CLI Evidence

### 6.1 Missing Input File (Safe Failure)
```text
Command: .\.venv\Scripts\python.exe -m threat_detection.detection.train_cli data/raw/nonexistent_dataset.txt
Output:
Starting training workflow using dataset: 'data\raw\nonexistent_dataset.txt'
Target artifact destination: 'models\baseline_rf_binary.joblib'
[FATAL ERROR] Dataset file not found at: 'data\raw\nonexistent_dataset.txt'. Please provide a valid NSL-KDD dataset file to train.
Exit Code: 1
```

### 6.2 Synthetic Test Fixture Execution (Verified Workflow)
```text
Command: .\.venv\Scripts\python.exe -m threat_detection.detection.train_cli data/sample/test_fixture.txt --output models/test_rf_artifact.joblib
Output:
Starting training workflow using dataset: 'data\sample\test_fixture.txt'
Target artifact destination: 'models\test_rf_artifact.joblib'

=== Random Forest Binary Baseline Training Summary ===
Model Type:               RandomForestClassifier
Target Formulation:       binary ('normal' vs 'attack')
Dataset Source:           data\sample\test_fixture.txt
Partition Sizes:          Train=24, Val=6
Raw Features:             41 -> Encoded Features: 43
Training Accuracy:        1.0000
Validation Accuracy:      1.0000
Train Class Distribution: {'attack': 12, 'normal': 12}
Val Class Distribution:   {'normal': 3, 'attack': 3}
Artifact Destination:     models\test_rf_artifact.joblib
Timestamp (UTC):          2026-10-13T10:09:48.519984+00:00
=======================================================

[SUCCESS] Baseline binary model trained and persisted successfully.
Exit Code: 0
```

---

## 7. Git Ignore Protections
- Verified with `git check-ignore -v` that:
  - `models/baseline_rf_binary.joblib` $\rightarrow$ `.gitignore:59:*.joblib` (**Ignored**)
  - `models/baseline_rf_binary.metadata.json` $\rightarrow$ `.gitignore:58:models/*` (**Ignored**)
  - `data/raw/*` and `data/processed/*` remain ignored.
- Confirmed with `git status --short` that zero model weights, training artifacts, or datasets are tracked or staged.

---

## 8. Errors & Unresolved Limitations
- **Binary Scope**: The trained baseline discriminates normal vs attack traffic, but does not classify specific attack sub-categories (DoS, Probe, R2L, U2R). Multi-class classification and anomaly scoring belong to subsequent phases.
- **Offline Data Prerequisite**: Training on the full 125,973-record NSL-KDD benchmark requires users to place `KDDTrain+.txt` in `data/raw/`.

---

## 9. Acceptance Criteria Assessment

| ID | Criterion | Status | Evidence |
| :---: | :--- | :---: | :--- |
| **A** | Binary target mapping is correct and tested | **PASS** | `create_binary_target()` maps `'normal'` to `'normal'` and recognized attacks to `'attack'` (`test_binary_target_mapping_normal_and_attacks`). |
| **B** | Original labels remain unchanged | **PASS** | Verified that original Series values and column names are unmodified (`test_binary_target_original_series_unchanged`). |
| **C** | Feature leakage from labels and difficulty metadata is prevented | **PASS** | `assert LABEL_COLUMN not in feature_names_in_` and `assert DIFFICULTY_COLUMN not in feature_names_in_` (`test_feature_and_metadata_exclusion_in_training`). |
| **D** | Data splitting occurs before preprocessing is fitted | **PASS** | Verified that preprocessor fits on training partition (`X_train`) only (`test_split_occurs_before_preprocessor_fitting`). |
| **E** | Random Forest training is reproducible with documented settings | **PASS** | Verified identical predictions and probability scores under seed 42 (`test_random_seed_and_reproducibility`). |
| **F** | Training and validation use the same fitted preprocessing pipeline | **PASS** | `X_val` is transformed using fitted preprocessor without refitting (`test_validation_data_transformed_without_refitting`). |
| **G** | Artifact serialization and reload are tested | **PASS** | `ThreatDetectionArtifact.save()` and `.load()` verified with prediction parity (`test_artifact_save_and_reload_predictions`). |
| **H** | Training CLI fails safely for missing or invalid data | **PASS** | Exits with code 1 and actionable error when file is missing (`test_train_cli_failure_on_missing_file`). |
| **I** | Automated tests are self-contained and pass | **PASS** | All 48 tests pass cleanly without network calls or external datasets. |
| **J** | Phase 1–3 regressions are absent | **PASS** | `test_foundation.py`, `test_data_ingestion.py`, and `test_preprocessing.py` pass 100%. |
| **K** | Generated artifacts and raw data remain uncommitted | **PASS** | Protected by `.gitignore` rules verified via `git check-ignore`. |
| **L** | Documentation is complete | **PASS** | Updated [`docs/04_model_training_and_learning.md`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/docs/04_model_training_and_learning.md) and [`docs/05_validation_and_testing_guide.md`](file:///c:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/docs/05_validation_and_testing_guide.md). |
| **M** | Truthfully distinguishes artificial-data tests from real NSL-KDD training | **PASS** | Explicitly documented in Section 3 that real model training has not occurred due to absence of local dataset. |
