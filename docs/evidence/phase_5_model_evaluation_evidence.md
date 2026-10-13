# Phase 5: Model Evaluation — Formal Benchmark Evidence

This document captures the rigorous evaluation of the frozen baseline Random Forest binary model on the NSL-KDD benchmark test dataset (`data/raw/KDDTest+.txt`).

---

## 1. Test Dataset Specification & Audit

- **Target File Path**: `data/raw/KDDTest+.txt`
- **File Existence**: **FOUND** on disk.
- **File Size**: **3,441,513 bytes** (~3.44 MB).
- **Format Integrity**: Comma-separated tabular records (not HTML, not an error page, not empty).
- **Total Record Count**: **22,544 rows** (0 excluded).
- **Schema Variant**: **with_difficulty_43** (41 traffic features + 1 class label + 1 difficulty score = 43 columns).
- **Validator CLI Execution**:
  ```powershell
  .\.venv\Scripts\python.exe -m threat_detection.data.cli data/raw/KDDTest+.txt
  ```
  - **Exit Code**: `0`
  - **Status**: `VALID`
  - **Missing Values**: `0`
  - **Duplicate Records**: `0` (0.00%)
  - **Attack Family Distribution**:
    - `NORMAL`: 9,711 (43.08%)
    - `DOS`: 7,458 (33.08%)
    - `R2L`: 2,709 (12.02%)
    - `PROBE`: 2,421 (10.74%)
    - `UNKNOWN`: 178 (0.79%)
    - `U2R`: 67 (0.30%)

---

## 2. Test Label Handling & Policy Enforcement

- **Unique Target Classes in Test Set**: **38 distinct classes**.
- **Recognized Catalogued Classes**: 37 classes catalogued in `KNOWN_ATTACK_LABELS` (plus `normal`).
- **Uncatalogued Attack Class**:
  - Class Label: `snmpgetattack`
  - Record Count: **178 rows** (0.79% of test set).
  - Background: A known novel SNMP Remote-to-Local (R2L) probe variant present exclusively in the test partition.
- **Explicit Target Policy**:
  - Executed using `create_binary_target(df['class'], on_unknown="attack")`.
  - Negative Class: `normal` $\rightarrow$ `normal`
  - Positive Class Ground Truth: Catalogued attacks + novel intrusions (`snmpgetattack`) mapped to ground-truth label `attack`. Note that this mapping establishes ground-truth targets only; it does not dictate or imply whether the model successfully predicted these specific records as attacks.
- **Resulting Binary Test Class Distribution**:
  - `attack` (Positive Ground Truth): **12,833 samples** (56.92%)
  - `normal` (Negative Ground Truth): **9,711 samples** (43.08%)
- **Data Integrity**: Zero rows dropped, skipped, or silently coerced.

---

## 3. Frozen Model Preservation

- **Artifact Paths**:
  - Binary bundle: `models/baseline_rf_binary.joblib` (8,418,958 bytes)
  - Metadata: `models/baseline_rf_binary.metadata.json` (887 bytes)
- **Frozen Integrity Verification**:
  - Artifact SHA-256 before evaluation: `0e364ea84fa5f35ba1ce2ff025235ed70b0bee9423611c354ce520f69e60f6c5`
  - Artifact SHA-256 after evaluation:  `0e364ea84fa5f35ba1ce2ff025235ed70b0bee9423611c354ce520f69e60f6c5`
  - File modification timestamp: **Unchanged** (`1791891552.607045`).
- **Evaluation Mechanism**:
  - Loaded strictly via `ThreatDetectionArtifact.load("models/baseline_rf_binary.joblib")`.
  - Predictions generated directly on raw 41-feature rows through the pre-fitted pipeline.
  - Preprocessor and classifier were **neither retrained nor refitted**.

---

## 4. Evaluation CLI Execution & Actual Metrics

- **Exact Execution Command**:
  ```powershell
  .\.venv\Scripts\python.exe -m threat_detection.detection.evaluate_cli data/raw/KDDTest+.txt --model models/baseline_rf_binary.joblib --json-output outputs/evaluation_metrics.json
  ```
- **Exit Code**: `0`

### 4.1 Confusion Matrix

Orientation: Rows = Ground Truth, Columns = Model Prediction

| Actual \ Predicted | Predicted Normal (Neg) | Predicted Attack (Pos) | Total Actual |
| :--- | :---: | :---: | :---: |
| **Actual Normal (Negative)** | **TN = 9,454** | **FP = 257** | 9,711 |
| **Actual Attack (Positive)** | **FN = 4,850** | **TP = 7,983** | 12,833 |
| **Total Predicted** | 14,304 | 8,240 | **22,544** |

### 4.2 Operational Error Rates

- **False-Positive Rate (FPR)**: $\frac{\text{FP}}{\text{FP} + \text{TN}} = \frac{257}{257 + 9,454} =$ **0.0265 (2.65%)**
- **False-Negative Rate (FNR)**: $\frac{\text{FN}}{\text{FN} + \text{TP}} = \frac{4,850}{4,850 + 7,983} =$ **0.3779 (37.79%)**

### 4.3 Detailed Performance Metrics

| Metric | Normal (Negative) | Attack (Positive) | Macro Average | Weighted Average |
| :--- | :---: | :---: | :---: | :---: |
| **Precision** | 0.6609 (66.09%) | **0.9688 (96.88%)** | 0.8149 | 0.8362 |
| **Recall (Detection Rate)** | **0.9735 (97.35%)** | 0.6221 (62.21%) | 0.7978 | 0.7735 |
| **F1-Score** | 0.7873 | 0.7577 | 0.7725 | 0.7704 |
| **Support** | 9,711 | 12,833 | 22,544 | 22,544 |

- **Overall Accuracy**: **0.7735 (77.35%)**
- **Area Under ROC Curve (ROC-AUC)**: **0.9654**
- **Area Under Precision-Recall Curve (PR-AUC)**: **0.9677**

---

## 5. Technical Analysis & Limitations

1. **Attack Precision vs. Detection Coverage**:
   When the model flags network telemetry as an intrusion, it is correct in 96.88% of instances (yielding a low false-alarm rate among alerts, with FPR = 2.65% across benign flows). However, high attack precision does not mean the model detects most attacks: the attack recall is 62.21%, with 4,850 attack flows (37.79%) going undetected.
2. **False-Negative Rate Analysis**:
   The model's false-negative rate was 37.79% across all attack-labelled records in KDDTest+, under the documented binary ground-truth mapping policy. KDDTest+ contains attack categories not represented in KDDTrain+, which may contribute to the generalization challenge; however, these aggregate metrics do not establish how much of the false-negative rate is attributable to novel attack categories. A per-attack-family error analysis would be required to investigate that question.
3. **Offline Benchmark Scope Boundary**:
   These results represent an offline evaluation on standard static benchmark records from NSL-KDD. Benchmark performance does not prove real-world or production readiness, nor does it evaluate live streaming throughput, packet-level processing latency, or resilience against modern live-network threat vectors.

---

## 6. Automated Regression Test Suite Status

- **Command**:
  ```powershell
  .\.venv\Scripts\python.exe -m pytest -v
  ```
- **Exit Code**: `0`
- **Results**:
  - `tests/test_data_ingestion.py`: 17 passed
  - `tests/test_foundation.py`: 2 passed
  - `tests/test_model_evaluation.py`: **10 passed** (New evaluation test suite)
  - `tests/test_model_training.py`: 15 passed
  - `tests/test_preprocessing.py`: 14 passed
  - **Total**: **58 passed in 9.01s**, 0 failed.

---

## 7. Git Exclusions & Compliance

- Confirmed `data/raw/*`, `models/*.joblib`, and `models/*.metadata.json` remain ignored by Git.
- No model weights were committed or modified.
- Phase 6 (Inference API / Real-time Serving) has **not** been started.
