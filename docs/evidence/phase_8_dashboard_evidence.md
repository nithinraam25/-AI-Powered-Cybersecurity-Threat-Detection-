# Phase 8: Streamlit Security Operations, Detection Demo & Model/Rules Evidence

This document captures the implementation, architecture, test verification, and integrity confirmation for the Streamlit Security Operations Console (Task 2), Offline Threat Detection Demo (Task 3), and Model & Rules Specification Tab (Task 4).

---

## 1. Files Created or Changed

- [`dashboard/helpers.py`](file:///C:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/dashboard/helpers.py):
  - Database path resolution (`resolve_database_path`).
  - KPI summary calculations (`compute_kpis`).
  - In-memory page filtering and search (`filter_alerts_on_page`).
  - Table formatting with dual text/symbol severity badges (`format_alert_table_data`, `format_severity_badge`).
  - Curated authentic benchmark flow record presets (`PRESET_FLOW_RECORDS`).
  - Single-row CSV parser and strict schema validator (`parse_and_validate_csv_upload`).
  - Precomputed evaluation metrics report loader with validation and error handling (`load_evaluation_metrics`).
  - Model metadata report loader (`load_model_metadata`).
  - Deterministic security rule specification extractor (`get_rule_specifications`).
  - Operational triage disposition policy specification (`get_disposition_specifications`).
- [`dashboard/app.py`](file:///C:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/dashboard/app.py):
  - Streamlit multi-tab architecture hosting "Alert Triage", "Detection Demo", and "Model & Rules" tabs.
  - Resource and data caches for model loading, evaluation metrics, and metadata.
  - Offline Threat Detection Demo interface with disclaimer and pure in-memory evaluation.
  - Model & Rules technical documentation section covering model architecture, preprocessing pipeline, benchmark metrics, confusion matrix, error rates, heuristic rules, and triage dispositions.
- [`tests/test_dashboard.py`](file:///C:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/tests/test_dashboard.py): Automated test suite containing 19 unit and headless `AppTest` integration tests for Alert Triage.
- [`tests/test_dashboard_demo.py`](file:///C:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/tests/test_dashboard_demo.py): Automated test suite containing 13 unit and headless `AppTest` integration tests for Detection Demo.
- [`tests/test_dashboard_model_rules.py`](file:///C:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/tests/test_dashboard_model_rules.py): Automated test suite containing 13 unit and headless `AppTest` integration tests for Model & Rules tab.
- [`docs/evidence/phase_8_dashboard_evidence.md`](file:///C:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/docs/evidence/phase_8_dashboard_evidence.md): This verification evidence document.

---

## 2. Dashboard Launch Commands

The dashboard can be executed locally from the workspace root using either of the following commands:

```powershell
.\.venv\Scripts\streamlit run dashboard/app.py
```
or
```powershell
.\.venv\Scripts\python.exe -m streamlit run dashboard/app.py
```

Optional database override via environment variable:
```powershell
$env:THREAT_DETECTION_DB_PATH = "outputs/custom_threats.db"
.\.venv\Scripts\streamlit run dashboard/app.py
```

---

## 3. Threat Detection Demo Features & Architecture (Task 3)

### A. Prominent Offline Disclaimer
The Detection Demo tab renders the mandatory offline disclaimer banner prominently at the top:
> **"This is an offline demonstration using network-flow records. It does not capture live traffic or provide real-time protection."**

### B. Input Methods
1. **Curated Record Presets**:
   - 5 authentic flow records sourced directly from the public NSL-KDD benchmark test set (`KDDTest+.txt`).
   - Every preset contains all 41 required network features.
   - Target label (`class`) and `difficulty_level` are completely excluded.
   - Presets are validated via `validate_traffic_features`.
   - UI does not claim or bias the preset towards normal or attack prior to evaluation.

2. **Single-Row CSV Upload**:
   - Strictly accepts exactly one network-flow record.
   - Enforces the 41-feature schema and explicitly rejects extra unexpected columns (including `class` and `difficulty_level`).
   - Rejects empty uploads, header-only files (0 data rows), and multi-row files (>1 data row) with clear error messages.
   - Validates numerical columns strictly using existing pipeline validation without silent NaN or zero coercion.
   - Preserves categorical values for pipeline handling.

### C. In-Memory Evaluation Workflow
- Inference is executed strictly upon clicking the **"Evaluate Flow"** button.
- Uses cached `ThreatDetectionEngine` loaded safely via `@st.cache_resource`.
- Returns an authentic `DetectionFinding` without modifying model weights or retrying training.
- Displays:
  - **Normalized Record Fingerprint**: Accompanied by the clarification that it identifies the normalized feature vector rather than a real-world host identity.
  - **Evaluated in Memory Status**: Clear banner indicating the finding is held in memory and has not been written to the database.
  - **Machine Learning Decision**: Predicted label (`normal` vs `attack`), attack probability percentage, statistical confidence score.
  - **Deterministic Heuristic Rules**: Matched rule IDs, rule descriptions, matched field values, or explicit confirmation when zero rules triggered.
  - **Operational Triage Synthesis**: Synthesized disposition (`BENIGN`, `MODEL_DETECTED`, `RULE_DETECTED`, `CORROBORATED`), overall severity (`INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), and narrative explanation.

### D. Explicit Optional Persistence & Deduplication
- A dedicated **"Persist Finding as Alert"** button is rendered only after an evaluation occurs.
- Pure evaluation never writes to the SQLite database.
- Database write occurs strictly on user button click via `repo.save_finding(finding)`.
- Reuses the active repository and resolved database target.
- **Accurate Persistence & Deduplication Reporting**: The UI displays success strictly after `save_finding()` returns successfully, reporting the exact resulting alert ID, status, and occurrence count (`Alert ID: ... | Status: ... | Occurrence Count: ...`).
- **Failure Resilience**: If the database write fails (e.g. database locked or disk error), the UI renders a clear error banner, does NOT claim the alert was saved, and preserves the evaluated finding in session state so the analyst can retry.
- **Rerun Protection**: A successful persistence action stores the saved alert in `st.session_state["demo_persisted_alert"]` and disables the persistence button (`"Persist Finding as Alert (Already Saved)"`) to prevent accidental duplicate alerts on subsequent Streamlit reruns.
- Input changes or new evaluations clear previous findings from session state, ensuring stale findings cannot be accidentally persisted under a different input.

---

## 4. Curated Presets: Provenance & Verified Model Outputs

| Preset Name | Dataset Provenance | ML Label & Attack Prob | Triggered Rules | Disposition | Overall Severity | Record Fingerprint |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Normal FTP Session** | Authentic `KDDTest+` Row 2 (original: `normal`) | `normal` (0.28%) | *None* | `BENIGN` | `INFORMATIONAL` | `8a8ba0bd4326...4ecbf460` |
| **SYN Flood Burst** | Authentic `KDDTest+` Row 13 (original: `neptune`) | `attack` (82.00%) | `RULE-DOS-SYN-001` | `CORROBORATED` | `HIGH` | `bb79dd989b65...23ea478b` |
| **Connection Rejection Burst** | Authentic `KDDTest+` Row 0 (original: `neptune`) | `attack` (100.00%) | `RULE-DOS-REJ-001` | `CORROBORATED` | `HIGH` | `6d20ea965d14...a06d2ba` |
| **LAND Packet Anomaly** | Authentic `KDDTest+` Row 4892 (original: `land`) | `attack` (51.27%) | `RULE-LAND-001` | `CORROBORATED` | `HIGH` | `aba1afcd8aaa...24c2e100` |
| **Multi-Service Port Sweep** | Authentic `KDDTest+` Row 34 (original: `satan`) | `attack` (100.00%) | `RULE-DOS-REJ-001`, `RULE-PROBE-SCAN-001` | `CORROBORATED` | `HIGH` | `376e56d57ccf...c7690fca` |

---

## 5. Model & Rules Tab Architecture & Benchmark Provenance (Task 4)

### A. Model Specification & Architecture
- **Classifier**: Frozen `RandomForestClassifier` (Scikit-Learn).
- **Target Formulation**: Binary classification (`normal` vs `attack`).
- **Filesystem Location**: `models/baseline_rf_binary.joblib` with companion `models/baseline_rf_binary.metadata.json`.
- **Feature Pipeline**:
  - Consumes the 41 canonical NSL-KDD raw traffic features.
  - Transforms them into 122 encoded features via fitted `ThreatPreprocessingPipeline` (`OneHotEncoder(handle_unknown='ignore')` applied to the 3 categorical features `protocol_type`, `service`, `flag` expanding to 84 binary indicator columns, and `"passthrough"` for the 38 numerical features without scaling or imputation).
- **Confirmed Hyperparameters**:
  - `n_estimators = 100`, `max_depth = 20`, `min_samples_split = 2`, `min_samples_leaf = 1`, `class_weight = "balanced"`, `random_state = 42`.
- **Training Provenance**: Trained on `KDDTrain+.txt` (100,778 train samples, 25,195 validation samples).
- **Read-Only Operation**: Tab operates in pure inspection mode; no retraining, saving, or refitting occurs.

### B. Offline Benchmark Performance (NSL-KDD Test Set)
- Metrics loaded from precomputed `outputs/evaluation_metrics.json` via `@st.cache_data`.
- Never recomputed on page reruns or tab switching.
- Graceful handling: If metrics are missing or malformed, an informative message with CLI generation instructions is displayed without crashing the app.
- **Evaluated Dataset**: `data/raw/KDDTest+.txt` (22,544 total samples, 0 excluded).
- **Target Policy**: Negative ground truth = `normal`; positive ground truth = catalogued attacks + novel intrusions (`snmpgetattack`).
- **Core Measured Benchmark Performance**:
  - **Overall Accuracy**: `0.7735 (77.35%)`
  - **Attack Recall**: `0.6221 (62.21%)`
  - **False-Negative Rate (FNR)**: `0.3779 (37.79%)`
  - **Attack Precision**: `0.9688 (96.88%)`
  - **False-Positive Rate (FPR)**: `0.0265 (2.65%)`
  - **ROC-AUC**: `0.9654`
  - **PR-AUC**: `0.9677`
- **Confusion Matrix**:
  - Orientation: Rows = Ground Truth, Columns = Prediction.
  - True Negatives (TN): `9,454`
  - False Positives (FP - False Alarms): `257` (2.65%)
  - False Negatives (FN - Missed Attacks): `4,850` (37.79%)
  - True Positives (TP - Detected Attacks): `7,983`
- **Detailed Summary Averages**:
  - Normal Class: Precision `0.6609`, Recall `0.9735`, F1 `0.7873`, Support `9,711`
  - Attack Class: Precision `0.9688`, Recall `0.6221`, F1 `0.7577`, Support `12,833`
  - Macro Average: Precision `0.8149`, Recall `0.7978`, F1 `0.7725`, Support `22,544`
  - Weighted Average: Precision `0.8362`, Recall `0.7735`, F1 `0.7704`, Support `22,544`

### C. Deterministic Security Rules & Operational Triage
Retrieved dynamically from `threat_detection.detection.rules.create_default_security_rules()`:
1. `RULE-LAND-001` (Severity: `HIGH`): Self-referential address anomaly (`land == 1`).
2. `RULE-DOS-SYN-001` (Severity: `MEDIUM`): High-volume SYN error state (`count >= 100`, `serror_rate >= 0.80`, `flag in {'S0', 'S1', 'S2', 'S3', 'RSTOS0'}`).
3. `RULE-DOS-REJ-001` (Severity: `MEDIUM`): High-volume connection rejection burst (`count >= 50`, `rerror_rate >= 0.80`, `flag in {'REJ', 'RSTO', 'RSTR'}`).
4. `RULE-PROBE-SCAN-001` (Severity: `MEDIUM`): Multi-service port sweep (`count >= 50`, `diff_srv_rate >= 0.70`, `dst_host_diff_srv_rate >= 0.70`).

**Operational Triage Policy Synthesis**:
- `BENIGN`: Model normal, no rules triggered $\rightarrow$ Severity `INFORMATIONAL`.
- `MODEL_DETECTED`: Model attack, no rules triggered $\rightarrow$ Severity `MEDIUM`.
- `RULE_DETECTED`: Model normal, rule(s) triggered $\rightarrow$ Severity `MEDIUM`.
- `CORROBORATED`: Model attack, rule(s) triggered $\rightarrow$ Severity `HIGH`.
- Rule-specific severity is maintained distinctly from synthesized finding severity.

### D. Educational Provenance & Scope Limits
- Prominently informs the analyst that NSL-KDD is an offline public academic benchmark, not live enterprise telemetry.
- Clarifies that model predictions and rule matches are investigative indicators, not verified proof of real-world compromise.
- Re-states that the application evaluates single flows in memory and does not capture live traffic or provide inline prevention.

---

## 6. Automated Test Suite Execution Results

### A. Focused Model & Rules Test Suite (`tests/test_dashboard_model_rules.py`)
```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_dashboard_model_rules.py -v
```
- **Exit Code**: `0`
- **Output**: `14 passed in 7.03s`, 0 failed.

**Verified Test Scenarios**:
1. `test_load_model_metadata_valid`: Validates model metadata loading and confirmed parameters (41 raw features, 122 encoded features).
2. `test_load_model_metadata_missing`: Validates missing metadata returns missing status without crash.
3. `test_load_model_metadata_invalid`: Validates malformed metadata JSON returns invalid status.
4. `test_load_evaluation_metrics_valid`: Validates metrics report loading, accuracy 0.7735, attack recall 0.6221, FNR 0.3779, and confusion matrix.
5. `test_load_evaluation_metrics_missing`: Validates missing evaluation metrics returns missing status with informative error.
6. `test_load_evaluation_metrics_incomplete`: Validates incomplete JSON returns invalid status.
7. `test_all_four_rules_specified_with_real_properties`: Validates all 4 active rules retrieved with source conditions and severities.
8. `test_disposition_specifications_cover_all_four_policies`: Validates BENIGN, MODEL_DETECTED, RULE_DETECTED, and CORROBORATED coverage.
9. `test_apptest_model_rules_tab_normal_rendering`: Interactive `AppTest` verifying model identity, metrics, confusion matrix, rules expanders, provenance notice, and 0 DB writes.
10. `test_apptest_missing_metrics_handled_gracefully`: Validates missing metrics JSON renders clear warning banner without crash.
11. `test_apptest_malformed_metrics_handled_gracefully`: Validates malformed metrics JSON renders error banner without crash.
12. `test_apptest_model_artifact_unavailable_handled_gracefully`: Validates missing model artifact displays "Not Found" without crash.
13. `test_apptest_preprocessing_pipeline_description_matches_actual_pipeline`: Validates displayed pipeline description accurately states passthrough for numerical features without scaling or imputation.
14. `test_default_database_untouched_by_model_rules_tests`: Confirms `outputs/threat_events.db` is never created or touched during tests.

### B. Detection Demo Test Suite (`tests/test_dashboard_demo.py`)
```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_dashboard_demo.py -v
```
- **Exit Code**: `0`
- **Output**: `13 passed in 7.33s`, 0 failed.

### C. Alert Triage Test Suite (`tests/test_dashboard.py`)
```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_dashboard.py -v
```
- **Exit Code**: `0`
- **Output**: `19 passed in 9.01s`, 0 failed.

### D. Full Project Regression Suite
```powershell
.\.venv\Scripts\python.exe -m pytest -v
```
- **Exit Code**: `0`
- **Output**: **145 passed in 21.66s**, 0 failed across all 10 test modules:
  - `tests/test_alert_storage.py`: 22 passed
  - `tests/test_dashboard.py`: 19 passed
  - `tests/test_dashboard_demo.py`: 13 passed
  - `tests/test_dashboard_model_rules.py`: 14 passed
  - `tests/test_data_ingestion.py`: 17 passed
  - `tests/test_detection_engine.py`: 19 passed
  - `tests/test_foundation.py`: 2 passed
  - `tests/test_model_evaluation.py`: 10 passed
  - `tests/test_model_training.py`: 15 passed
  - `tests/test_preprocessing.py`: 14 passed

---

## 7. Model and Dataset Integrity Confirmation

| File Target | Expected SHA-256 Hash | Verification Status |
| :--- | :--- | :--- |
| `models/baseline_rf_binary.joblib` | `0E364EA84FA5F35BA1CE2FF025235ED70B0BEE9423611C354CE520F69E60F6C5` | **Unchanged (Frozen)** |
| `data/raw/KDDTrain+.txt` | `1B86D2F957B33082081BBA410FE129B475EFEBCC13C9014C3F447C8271AADF95` | **Unchanged** |
| `data/raw/KDDTest+.txt` | `FA46B0935342616AA83B7C2578DB355B6A7AAABBC492248172C7A1E8B7AB8F84` | **Unchanged** |

- **Default Database Isolation**: Confirmed `outputs/threat_events.db` does not exist and was not created or modified by test suites (`Test-Path outputs/threat_events.db` returned `False`).
