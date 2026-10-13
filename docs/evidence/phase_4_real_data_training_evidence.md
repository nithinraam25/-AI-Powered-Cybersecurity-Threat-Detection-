# Phase 4: Real-Data Model Training Execution Evidence

This document captures the formal verification and real-world execution evidence for training the baseline Random Forest binary threat classifier on the full NSL-KDD benchmark dataset.

---

## 1. Input Verification & Schema Audit

- **Target Dataset Path**: `data/raw/KDDTrain+.txt`
- **File Existence**: **FOUND** on disk.
- **File Size**: **19,109,424 bytes** (~19.1 MB).
- **Format Integrity**: Verified genuine comma-separated tabular records (not HTML, not empty).
  - First record:
    ```text
    0,tcp,ftp_data,SF,491,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,2,0.00,0.00,0.00,0.00,1.00,0.00,0.00,150,25,0.17,0.03,0.17,0.00,0.00,0.00,0.05,0.00,normal,20
    ```
- **Validation Command**:
  ```powershell
  .\.venv\Scripts\python.exe -m threat_detection.data.cli data/raw/KDDTrain+.txt
  ```
- **Exit Code**: `0`
- **CLI Audit Output**:
  ```text
  Auditing NSL-KDD dataset target: 'data\raw\KDDTrain+.txt'

  === NSL-KDD Dataset Validation Report [VALID] ===
  Status:               VALID
  Schema Variant:       with_difficulty_43 (43 columns)
  Total Records:        125,973
  Label Column:         Present
  Difficulty Field:     Present
  Duplicate Records:    0 (0.00%) [Preserved]
  Missing Values:       0
  Attack Family Distribution:
    - NORMAL  :   67,343 ( 53.5%)
    - DOS     :   45,927 ( 36.5%)
    - PROBE   :   11,656 (  9.3%)
    - R2L     :      995 (  0.8%)
    - U2R     :       52 (  0.0%)
  Top 5 Specific Classes:
    - normal         :   67,343 ( 53.5%)
    - neptune        :   41,214 ( 32.7%)
    - satan          :    3,633 (  2.9%)
    - ipsweep        :    3,599 (  2.9%)
    - portsweep      :    2,931 (  2.3%)
  =======================================================

  [SUCCESS] Dataset schema and integrity audit passed.
  ```

---

## 2. Training Implementation & Architecture Review

- **Inspected Modules**:
  - `src/threat_detection/detection/target.py`
  - `src/threat_detection/detection/trainer.py`
  - `src/threat_detection/detection/train_cli.py`
  - `src/threat_detection/preprocessing/pipeline.py`
  - `docs/04_model_training_and_learning.md`
- **Pipeline Architecture & Leakage Safeguards**:
  - Target formulation: Binary indicator (`normal` vs `attack`).
  - Separation: 41 canonical traffic features isolated from raw labels; metadata (`difficulty_level`) excluded.
  - Leakage prevention: Stratified train/validation splitting performed **strictly before** preprocessor fitting.
  - Preprocessor: ColumnTransformer (OneHotEncoder for 3 categorical features, passthrough for 38 numerical features) fit **only** on the training partition.
  - Classifier: `RandomForestClassifier` fit **only** on transformed training features.

---

## 3. Real-Data Training Execution

- **Exact Training Command**:
  ```powershell
  .\.venv\Scripts\python.exe -m threat_detection.detection.train_cli data/raw/KDDTrain+.txt --output models/baseline_rf_binary.joblib
  ```
- **Exit Code**: `0`
- **Command Output**:
  ```text
  Starting training workflow using dataset: 'data\raw\KDDTrain+.txt'
  Target artifact destination: 'models\baseline_rf_binary.joblib'

  === Random Forest Binary Baseline Training Summary ===
  Model Type:               RandomForestClassifier
  Target Formulation:       binary ('normal' vs 'attack')
  Dataset Source:           data\raw\KDDTrain+.txt
  Partition Sizes:          Train=100,778, Val=25,195
  Raw Features:             41 -> Encoded Features: 122
  Training Accuracy:        0.9998
  Validation Accuracy:      0.9989
  Train Class Distribution: {'normal': 53874, 'attack': 46904}
  Val Class Distribution:   {'normal': 13469, 'attack': 11726}
  Artifact Destination:     models\baseline_rf_binary.joblib
  Timestamp (UTC):          2026-10-13T11:39:12.554422+00:00
  =======================================================

  [SUCCESS] Baseline binary model trained and persisted successfully.
  ```

### Training Telemetry Summary

| Metric / Parameter | Value |
|---|---|
| **Total Input Records** | 125,973 |
| **Training Partition (80%)** | 100,778 samples |
| **Validation Partition (20%)** | 25,195 samples |
| **Train Class Distribution** | `normal`: 53,874 (53.46%), `attack`: 46,904 (46.54%) |
| **Val Class Distribution** | `normal`: 13,469 (53.46%), `attack`: 11,726 (46.54%) |
| **Raw Traffic Features** | 41 features |
| **Encoded Feature Dimension** | 122 features |
| **Random Seed** | 42 |
| **Hyperparameters** | `n_estimators=100`, `max_depth=20`, `min_samples_split=2`, `min_samples_leaf=1`, `class_weight='balanced'`, `n_jobs=-1` |
| **Training Accuracy** | **0.9998** (0.9997816983865526) |
| **Validation Accuracy** | **0.9989** (0.9988886683865846) |

---

## 4. Model Artifact Verification & Smoke Test

- **Persisted Artifact Paths**:
  - Binary model bundle: `models/baseline_rf_binary.joblib` (8,418,958 bytes)
  - Companion metadata: `models/baseline_rf_binary.metadata.json` (887 bytes)
- **Artifact Loading Verification**:
  - Successfully loaded via `ThreatDetectionArtifact.load("models/baseline_rf_binary.joblib")`.
- **Direct Raw Feature Inference**:
  - Raw un-preprocessed feature DataFrame passed directly into `artifact.predict(X_val)`.
  - Internal preprocessor handled transformation cleanly without manual preprocessing steps.
- **Reload Consistency**:
  - Independent reloading instances yielded identical predictions (`np.array_equal == True`) and identical probability distributions (`np.allclose == True`).
- **Smoke Test on Held-Out Validation Samples**:
  - Sample predictions: `['attack', 'normal', 'normal', 'attack', 'attack', 'attack', 'normal', 'attack', 'normal', 'attack']`
  - Ground truth labels: `['attack', 'normal', 'normal', 'attack', 'attack', 'attack', 'normal', 'attack', 'normal', 'attack']`
  - Match: **10 / 10 (100% on sample)**.

---

## 5. Regression Test Suite Execution

- **Command**:
  ```powershell
  .\.venv\Scripts\python.exe -m pytest -v
  ```
- **Exit Code**: `0`
- **Test Results**:
  - `tests/test_data_ingestion.py`: 17 passed
  - `tests/test_foundation.py`: 2 passed
  - `tests/test_model_training.py`: 15 passed
  - `tests/test_preprocessing.py`: 14 passed
  - **Summary**: **48 passed in 6.38s**, 0 failed.

---

## 6. Guardrail Compliance Checklist

- [x] **Real Data**: Genuine NSL-KDD benchmark dataset (`125,973` rows) utilized exclusively; zero synthetic data substituted.
- [x] **No Fabrication**: All reported metrics originate directly from the training and evaluation execution output.
- [x] **Data Integrity**: Zero rows silently dropped or altered.
- [x] **Git Exclusions**: Confirmed `data/raw/*` and `models/*.joblib`, `models/*.metadata.json` are excluded by `.gitignore`.
- [x] **Scope Boundaries**: Phase 5 (multi-class attribution, threshold tuning, alerting) has not been initiated.
