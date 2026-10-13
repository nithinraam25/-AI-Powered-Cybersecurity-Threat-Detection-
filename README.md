# AI-Powered Cybersecurity Threat Detection System

An offline, defensive cybersecurity threat detection prototype and security operations triage console designed to evaluate network flow telemetry, detect structural anomalies, and demonstrate hybrid machine learning and heuristic rule-based detection using the NSL-KDD benchmark dataset.

---

## 1. Project Overview & Problem Statement

Modern security operations centers (SOCs) analyze high-volume network telemetry to identify malicious activity. Traditional Intrusion Detection Systems (IDS) rely heavily on static signature rules, which can struggle to identify complex traffic anomalies or zero-day variants, while standalone statistical machine learning models often suffer from high false-alarm rates or lack explainability.

This portfolio project implements a defensive, modular threat detection architecture that combines:
* **Statistical Machine Learning:** A frozen Random Forest binary classifier trained on canonical network flow features to score attack probabilities.
* **Deterministic Heuristic Security Rules:** Configurable, explainable rules detecting specific structural network anomalies (e.g., LAND topology anomalies, high-volume SYN flood bursts, connection rejection bursts, and horizontal port sweeps).
* **Correlation & Triage Engine:** A hybrid detection engine synthesizing statistical model decisions with rule matches to assign operational triage dispositions (`BENIGN`, `MODEL_DETECTED`, `RULE_DETECTED`, `CORROBORATED`) and operational severity levels.
* **Persistent Alert Storage:** An ACID-compliant SQLite repository supporting fingerprint-based active alert deduplication and strict incident lifecycle state transitions (`NEW` $\rightarrow$ `ACKNOWLEDGED` $\rightarrow$ `RESOLVED`).
* **Security Operations Console:** An interactive Streamlit dashboard featuring an Alert Triage queue, an offline Detection Demonstration interface, and a technical Model & Rules specification console.

> **Defensive & Educational Scope Notice:**<br>
> This project is designed exclusively for educational research, benchmarking, and defensive portfolio demonstration. It evaluates static network flow records from public benchmark data; it does **not** capture live network packets, monitor stream interfaces, perform inline traffic blocking, or provide production enterprise network protection.

---

## 2. Implemented Capabilities

1. **NSL-KDD Ingestion & Schema Auditing:**
   * Strict schema contracts for the 41 canonical network flow features, plus target label (`class`) and difficulty score (`difficulty_level`).
   * Non-destructive data validation detecting missing values, duplicates, class distributions, and uncatalogued attack variants.
   * Standalone dataset validation CLI (`threat_detection.data.cli`).
2. **Leakage-Resistant Preprocessing Pipeline:**
   * Strict separation of traffic features and ground-truth target labels.
   * Scikit-Learn `ColumnTransformer` composition applying `OneHotEncoder(handle_unknown='ignore')` to the 3 categorical features (`protocol_type`, `service`, `flag`), expanding them to 84 binary indicators, and passing the 38 numerical features through directly (`passthrough`), yielding exactly 122 dense features with zero imputation and zero feature scaling.
3. **Random Forest Binary Classifier:**
   * Stratified training and validation partitioning with frozen hyperparameter tuning (`n_estimators=100`, `max_depth=20`, `class_weight='balanced'`, `random_state=42`).
   * Self-contained artifact container (`ThreatDetectionArtifact`) encapsulating fitted preprocessor, model weights, and training telemetry.
4. **Deterministic Heuristic Security Rules:**
   * `RULE-LAND-001` (Severity: `HIGH`): Detects self-referential connections where source and destination addresses/ports match (`land == 1`).
   * `RULE-DOS-SYN-001` (Severity: `MEDIUM`): Detects high-volume unestablished SYN flood bursts (`count >= 100`, `serror_rate >= 0.80`, flag in `{'S0', 'S1', 'S2', 'S3', 'RSTOS0'}`).
   * `RULE-DOS-REJ-001` (Severity: `MEDIUM`): Detects repeated connection rejection hammering (`count >= 50`, `rerror_rate >= 0.80`, flag in `{'REJ', 'RSTO', 'RSTR'}`).
   * `RULE-PROBE-SCAN-001` (Severity: `MEDIUM`): Detects multi-service vertical/horizontal port sweeps (`count >= 50`, `diff_srv_rate >= 0.70`, `dst_host_diff_srv_rate >= 0.70`).
5. **Hybrid Threat Detection Engine:**
   * Generates deterministic SHA-256 digests over the 41 canonical feature name-value pairs (`record_fingerprint`).
   * Synthesizes model predictions and rule triggers into standardized operational dispositions (`BENIGN`, `MODEL_DETECTED`, `RULE_DETECTED`, `CORROBORATED`).
   * Emits human-readable diagnostic explanations for analyst triage.
6. **SQLite Alert Storage & Lifecycle Management:**
   * Partial unique index preventing duplicate active (`NEW` or `ACKNOWLEDGED`) alerts for identical flow fingerprints while preserving historically resolved records.
   * Merges duplicate observations by incrementing `occurrence_count`, updating timestamps, aggregating rule evidence, and preserving severity without downgrading.
   * Enforces strict two-step lifecycle state transitions (`NEW` $\rightarrow$ `ACKNOWLEDGED` $\rightarrow$ `RESOLVED`), blocking invalid direct closures.
7. **Interactive Streamlit Security Console:**
   * **Alert Triage Tab:** Real-time KPI summary cards, multi-column status and severity filtering, in-memory page search, alert investigation tabs, and analyst lifecycle actions.
   * **Detection Demo Tab:** Offline evaluation of curated NSL-KDD benchmark presets or single-row CSV uploads with side-by-side ML and rule breakdowns, and optional alert persistence.
   * **Model & Rules Tab:** Complete technical architecture specifications, precomputed benchmark evaluation metrics, confusion matrix analysis, and rule threshold documentation.
8. **Automated Test Suite & Evaluation Tooling:**
   * 155 automated unit and end-to-end integration tests with 100% pass rate.
   * Standalone offline model evaluation CLI (`threat_detection.detection.evaluate_cli`).

---

## 3. Architecture & Data Flow

The diagram below illustrates how a 41-feature network traffic record transitions through validation, model scoring, rule matching, correlation, alert persistence, and dashboard visualization:

```text
       Raw Traffic Flow Record (41 Canonical Features)
         │  (Dict / Series / Validated Single-Row CSV)
         ▼
 ┌──────────────────────────────────────────────────────────────┐
 │                     Input Validation                         │
 │  • Programmatic API: validate_traffic_features()             │
 │  • Demo Upload Boundary: parse_and_validate_csv_upload()     │
 └──────────────────────────────┬───────────────────────────────┘
                                │
                                ▼
 ┌──────────────────────────────────────────────────────────────┐
 │                  ThreatDetectionEngine                       │
 │                                                              │
 │   ┌───────────────────────┐      ┌───────────────────────┐   │
 │   │ Preprocessing (122 D) │      │  Deterministic Rules  │   │
 │   │ • OneHotEncoder (84)  │      │  • LAND Attack        │   │
 │   │ • Passthrough (38)    │      │  • SYN Flood Burst    │   │
 │   └──────────┬────────────┘      │  • Rejection Burst    │   │
 │              │                   │  • Multi-Port Sweep   │   │
 │              ▼                   └──────────┬────────────┘   │
 │   ┌───────────────────────┐                 │                │
 │   │ Frozen Random Forest  │                 │                │
 │   │ • Binary Decision     │                 │                │
 │   │ • Attack Probability  │                 │                │
 │   └──────────┬────────────┘                 │                │
 │              │                              │                │
 │              ▼                              ▼                │
 │       [Model Decision]              [Rule Matches]           │
 │              │                              │                │
 │              └──────────────┬───────────────┘                │
 │                             ▼                                │
 │             [Correlation & Disposition Synthesis]            │
 │             [Deterministic SHA-256 Fingerprint]              │
 └─────────────────────────────┬────────────────────────────────┘
                               │
                               ▼
 ┌──────────────────────────────────────────────────────────────┐
 │                  DetectionFinding (In-Memory)                │
 │  Disposition: BENIGN / MODEL_DETECTED / RULE_DETECTED /      │
 │               CORROBORATED                                   │
 │  Overall Severity: INFORMATIONAL / MEDIUM / HIGH             │
 └─────────────────────────────┬────────────────────────────────┘
                               │ (Optional User Action)
                               ▼
 ┌──────────────────────────────────────────────────────────────┐
 │                 AlertRepository (SQLite)                     │
 │  • Deduplicates on Active Fingerprint (NEW / ACKNOWLEDGED)   │
 │  • Increments occurrence_count on repeat observations        │
 │  • Enforces Lifecycle: NEW -> ACKNOWLEDGED -> RESOLVED       │
 └─────────────────────────────┬────────────────────────────────┘
                               │
                               ▼
 ┌──────────────────────────────────────────────────────────────┐
 │              Streamlit Security Operations Console           │
 │  • Alert Triage Queue & KPI Summaries                        │
 │  • Offline Detection Demonstration                           │
 │  • Model Architecture & Evaluation Documentation             │
 └──────────────────────────────────────────────────────────────┘
```

---

## 4. Technology Stack

* **Language:** Python 3.9+ (Tested on Python 3.13)
* **Data Engineering & Preprocessing:** Pandas, NumPy, Scikit-Learn (`ColumnTransformer`, `OneHotEncoder`)
* **Machine Learning & Serialization:** Scikit-Learn (`RandomForestClassifier`), Joblib
* **Data Storage:** SQLite (Embedded relational storage with transaction control and partial unique indexes)
* **User Interface:** Streamlit (Multi-tab security operations console)
* **Visualization & Reporting:** Matplotlib, Seaborn
* **Testing & Quality Assurance:** Pytest

---

## 5. Repository Structure

```text
AI-Powered-Cybersecurity-Threat-Detection/
├── dashboard/
│   ├── app.py                      # Multi-tab Streamlit console (Triage, Demo, Model & Rules)
│   └── helpers.py                  # Dashboard business logic, KPIs, presets, and formatting
├── data/
│   ├── raw/                        # Public NSL-KDD benchmark datasets (KDDTrain+.txt, KDDTest+.txt)
│   ├── processed/                  # Directory for preprocessed intermediate data
│   └── sample/                     # Synthetic test telemetry fixtures
├── docs/
│   └── evidence/                   # Empirical phase reports, test evidence, and quality gates
├── models/
│   ├── baseline_rf_binary.joblib   # Frozen trained Random Forest classifier bundle
│   └── baseline_rf_binary.metadata.json  # Serialized model hyperparameters & training metadata
├── outputs/
│   ├── evaluation_metrics.json     # Precomputed benchmark test metrics & confusion matrix
│   └── threat_events.db            # Default runtime SQLite database (git-ignored)
├── src/
│   └── threat_detection/
│       ├── __init__.py             # Package exports and version metadata
│       ├── config.py               # Central project path and threshold configuration
│       ├── data/                   # NSL-KDD schemas, loaders, validators, and CLI
│       │   ├── cli.py              # Dataset validation CLI
│       │   ├── loader.py           # Headerless and headered NSL-KDD CSV loader
│       │   ├── schema.py           # 41-feature schema specifications and constants
│       │   └── validator.py        # Non-destructive dataset integrity auditor
│       ├── detection/              # Training, inference engine, evaluation, and rules
│       │   ├── engine.py           # ThreatDetectionEngine and fingerprint computation
│       │   ├── evaluate_cli.py     # Offline evaluation CLI
│       │   ├── evaluator.py        # Metrics calculator and confusion matrix generator
│       │   ├── rules.py            # Deterministic heuristic security rules
│       │   ├── target.py           # Binary target formulation ('normal' vs 'attack')
│       │   ├── train_cli.py        # Model training CLI
│       │   └── trainer.py          # Random Forest training and artifact serialization
│       ├── preprocessing/          # Scikit-learn ColumnTransformer feature pipeline
│       │   └── pipeline.py
│       └── storage/                # SQLite alert persistence and lifecycle state machine
│           ├── models.py           # AlertRecord, AlertStatus, and exception definitions
│           └── repository.py       # AlertRepository with deduplication and partial index
├── tests/                          # 11 test modules with 155 automated unit and E2E tests
│   ├── test_alert_storage.py
│   ├── test_dashboard.py
│   ├── test_dashboard_demo.py
│   ├── test_dashboard_model_rules.py
│   ├── test_data_ingestion.py
│   ├── test_detection_engine.py
│   ├── test_foundation.py
│   ├── test_integration_e2e.py     # End-to-end integration test suite
│   ├── test_model_evaluation.py
│   ├── test_model_training.py
│   └── test_preprocessing.py
├── .env.example                    # Environment variable configuration template
├── .gitignore                      # Git exclusion rules for venvs, datasets, DBs, and weights
├── main.py                         # Application foundation entry point
├── pyproject.toml                  # Modern setuptools packaging configuration
└── requirements.txt                # Pinned development and runtime dependencies
```

---

## 6. Environment Setup (Windows PowerShell)

### Prerequisites
* Windows 10/11 with PowerShell 5.1 or PowerShell 7+
* Python 3.9 to 3.13 installed and available on PATH
* Git installed

### 6.1 Clone the Repository
```powershell
git clone https://github.com/your-username/AI-Powered-Cybersecurity-Threat-Detection.git
cd AI-Powered-Cybersecurity-Threat-Detection
```

### 6.2 Virtual Environment Creation & Activation
Create and activate an isolated Python virtual environment:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

*(If script execution is restricted on your system, run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process` before activating).*

### 6.3 Install Dependencies
Upgrade pip and install runtime and development dependencies:
```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -e ".[dev]"
```

### 6.4 Environment Configuration (Optional)
Copy the environment template if custom overrides are needed:
```powershell
Copy-Item .env.example .env
```

---

## 7. Running the Automated Test Suite

The project includes 155 automated tests across 11 test modules verifying schema contracts, preprocessing, model inference, rule evaluation, SQLite persistence, lifecycle transitions, dashboard helpers, and end-to-end integration:

### Run the Complete Test Suite
```powershell
.\.venv\Scripts\python.exe -m pytest -v
```
*(All 155 tests should pass in under 25 seconds with 0 failures and 0 warnings).*

### Run the Focused End-to-End Integration Suite
```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_integration_e2e.py -v
```

---

## 8. Launching the Security Operations Console

To start the interactive Streamlit dashboard:
```powershell
.\.venv\Scripts\streamlit run dashboard/app.py
```
This opens the web browser to `http://localhost:8501`, providing access to:
1. **Alert Triage:** Real-time KPI summaries, status filtering, in-memory search, alert investigation tabs, and lifecycle actions (`Acknowledge Alert`, `Resolve Alert`).
2. **Detection Demo:** Evaluate curated benchmark flow presets or upload single-row CSV records in memory, inspect ML decisions and rule evidence, and optionally persist findings to the SQLite database.
3. **Model & Rules:** Inspect frozen model specifications, confusion matrix telemetry, error rates, and deterministic rule thresholds.

To stop the dashboard, press `Ctrl + C` in the PowerShell terminal.

---

## 9. Command-Line Interface (CLI) Utilities

### 9.1 Dataset Schema Conformance & Validation CLI
Validate an NSL-KDD dataset file for column counts, null values, duplicate rows, and attack family distributions:

```powershell
# Validate default training set (data/raw/KDDTrain+.txt)
.\.venv\Scripts\python.exe -m threat_detection.data.cli

# Validate test benchmark partition with explicit schema variant check
.\.venv\Scripts\python.exe -m threat_detection.data.cli data/raw/KDDTest+.txt --variant with_difficulty_43
```

### 9.2 Offline Model Evaluation CLI
Evaluate the frozen Random Forest classifier against a test dataset without retraining or modifying model weights:

```powershell
# Evaluate frozen model on KDDTest+ and display summary metrics
.\.venv\Scripts\python.exe -m threat_detection.detection.evaluate_cli data/raw/KDDTest+.txt

# Evaluate and export complete telemetry to a JSON report
.\.venv\Scripts\python.exe -m threat_detection.detection.evaluate_cli data/raw/KDDTest+.txt --json-output outputs/evaluation_metrics.json
```

---

## 10. Model Evaluation Results & Performance Telemetry

The frozen Random Forest binary classifier was evaluated on the independent NSL-KDD test partition (`data/raw/KDDTest+.txt`), comprising **22,544 flow records** (0 excluded). Precomputed results are stored in `outputs/evaluation_metrics.json`:

### Summary Metrics

| Metric | Measured Value | Percentage | Description |
| :--- | :---: | :---: | :--- |
| **Overall Accuracy** | `0.7735` | **77.35%** | Correct classifications across all normal and attack flows |
| **Attack Precision** | `0.9688` | **96.88%** | True attacks divided by all model-flagged attacks |
| **Attack Recall (Detection Rate)** | `0.6221` | **62.21%** | True attacks detected divided by all actual attacks in test set |
| **Attack F1-Score** | `0.7577` | — | Harmonic mean of attack precision and attack recall |
| **False-Positive Rate (FPR)** | `0.0265` | **2.65%** | Normal flows incorrectly flagged as attacks ($FP = 257$) |
| **False-Negative Rate (FNR)** | `0.3779` | **37.79%** | True attacks missed by the model ($FN = 4,850$) |
| **Normal Class Precision** | `0.6609` | **66.09%** | True normal flows divided by all predicted normal flows |
| **Normal Class Recall** | `0.9735` | **97.35%** | Benign sessions correctly identified as normal |
| **ROC-AUC** | `0.9654` | — | Area under the Receiver Operating Characteristic curve |
| **PR-AUC** | `0.9677` | — | Area under the Precision-Recall curve for the positive attack class |

### Confusion Matrix Breakdown

Orientation: Rows represent Ground Truth (Actual Class); Columns represent Model Prediction.

| Ground Truth \ Predicted | Predicted Normal (Negative) | Predicted Attack (Positive) | Actual Total |
| :--- | :---: | :---: | :---: |
| **Actual Normal (Negative)** | **$TN = 9,454$** | **$FP = 257$** *(False Alarm)* | $9,711$ |
| **Actual Attack (Positive)** | **$FN = 4,850$** *(Missed Threat)* | **$TP = 7,983$** *(Detected Threat)* | $12,833$ |
| **Predicted Total** | $14,304$ | $8,240$ | $22,544$ |

### Telemetry Observations & Evaluation Policy
* **Low False-Alarm Rate (FPR = 2.65%):** The classifier exhibits high specificity on benign network sessions, minimizing alert fatigue for standard traffic.
* **Degradation on Novel Attacks (FNR = 37.79%):** The test set includes 17 novel attack types not present in the training distribution. The elevated false-negative rate reflects classifier degradation when encountering zero-day structural variations without adaptive retraining.
* **`snmpgetattack` Ground-Truth Policy:** The test partition contains 178 records of `snmpgetattack`, an attack type uncatalogued in the training taxonomy. Under the documented evaluation policy (`on_unknown="attack"`), uncatalogued labels are mapped to the ground-truth `attack` class for evaluation scoring so that novel intrusions are evaluated as actual threats. This is an evaluation ground-truth assignment, **not** a model prediction override; model inference relies strictly on the 41 network flow features.

---

## 11. Limitations & Responsible-Use Notes

1. **Benchmark Data vs. Live Telemetry:** The NSL-KDD benchmark is an academic dataset derived from the 1999 KDD Cup/DARPA collection. Its feature distributions, synthetic attack mechanisms, and protocol rates do not reflect contemporary encrypted protocols (e.g., TLS 1.3, QUIC) or modern threat actor tactics.
2. **Offline Flow Records:** Flow records represent aggregated session statistics (durations, byte counts, error rates, flag indicators) rather than raw PCAP packet streams.
3. **No Inline Action or Automated Blocking:** The detection engine and dashboard operate purely as an analytical triage advisory. The system does not interface with firewalls, software-defined networks, or endpoint agents.
4. **Non-Proof of Compromise:** A high attack probability or heuristic rule match indicates suspicious structural patterns in telemetry; it does not constitute conclusive forensic proof of an active data breach.

---

## 12. Dataset Provenance & Publishing Guidelines

* **Provenance:** The dataset utilized is NSL-KDD, an established benchmark developed by the University of New Brunswick (UNB) to solve duplicate record and class bias issues in the original KDD'99 collection.
* **Version Control Policy:** Raw dataset files (`data/raw/KDDTrain+.txt`, `data/raw/KDDTest+.txt`) and serialized binary weights (`models/*.joblib`) are excluded from Git tracking via `.gitignore` to prevent repository bloat and respect dataset distribution guidelines.
* **Publishing Instructions:** When publishing this project to public hosting (such as GitHub), do not commit raw benchmark data files or multi-megabyte binary model artifacts. Review licensing terms before redistributing external datasets.

---

## 13. Current Implementation Status

All technical phases of the core development and verification lifecycle are complete:

* **Phase 1 (Project Foundation):** Complete. Modular `src`-layout packaging, configuration, `.gitignore` barriers, and environment templates.
* **Phase 2 (Dataset Validation & Ingestion):** Complete. Schema specifications, headerless CSV parsing, non-destructive validation, and data CLI.
* **Phase 3 (Preprocessing Pipeline):** Complete. Leakage-free `ColumnTransformer` feature engineering producing 122 dense features.
* **Phase 4 (Model Training Pipeline):** Complete. Binary target formulation, Random Forest training workflow, and serialized artifact bundling.
* **Phase 5 (Model Evaluation):** Complete. Comprehensive benchmark scoring, confusion matrix generation, error rate calculation, and evaluation CLI.
* **Phase 6 (Threat Detection Engine & Rules):** Complete. 4 deterministic heuristic security rules, SHA-256 fingerprinting, correlation engine, and operational disposition synthesis.
* **Phase 7 (SQLite Alert Persistence):** Complete. Deduplication-aware SQLite repository, partial unique indexes, multi-column filtering, and lifecycle state machine.
* **Phase 8 (Streamlit Operations Console):** Complete. Alert Triage queue, offline Detection Demonstration tab, and technical Model & Rules documentation console.
* **Phase 9 (End-to-End Integration & Testing):** Complete. 10 focused integration scenarios in `tests/test_integration_e2e.py`, 155 full regression tests passing, artifact SHA-256 digests verified, and final quality gate passed.
* **Phase 10 (Portfolio Documentation & Packaging):** In progress (Task 1: Finalizing README).

---

## 14. Potential Future Enhancements

The following items represent potential extensions and future research directions:

* **Multi-Class Attack Family Classification:** Extending the binary classifier (`normal` vs `attack`) to predict granular attack families (DoS, Probe, R2L, U2R).
* **Unsupervised Anomaly Detection:** Adding Isolation Forests or Autoencoders to improve detection recall on novel zero-day attack patterns that bypass supervised models.
* **Streaming Telemetry Ingestion:** Integrating message queue brokers (e.g., Apache Kafka or RabbitMQ) for simulated streaming batch evaluation.
* **REST API Microservice:** Wrapping the `ThreatDetectionEngine` and `AlertRepository` in a FastAPI service with OpenAPI documentation.
* **Automated Alert Webhook Dispatch:** Emitting incident alerts via webhooks to incident management platforms upon corroborated threat detection.
