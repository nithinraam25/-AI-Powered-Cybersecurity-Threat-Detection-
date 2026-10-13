# 03. Modules & Components

> [!NOTE]
> **Historical Design & Scope Notice:**<br>
> This document records component specifications and module architectures. An earlier proposed layout using non-namespaced directories (`src/ingestion/`, `src/models/`, `src/inference/`) was replaced during implementation with a standardized `src`-layout package under `src/threat_detection/` and a dedicated `dashboard/` application.
>
> For the authoritative reference on current file locations, module APIs, and usage, refer to:
> * The repository root **[`README.md`](../README.md)**
> * The active codebase under **`src/threat_detection/`** and **`dashboard/`**
> * The 155 automated tests under **`tests/`**

---

## 1. Actual Implemented Directory & Codebase Architecture

The project implements a modern, modular `src`-layout packaging structure:

```text
AI-Powered-Cybersecurity-Threat-Detection/
├── dashboard/                              # Streamlit Security Operations Console
│   ├── app.py                              # Multi-tab UI (Alert Triage, Demo, Model & Rules)
│   └── helpers.py                          # Presentation logic, KPIs, presets, and formatting
├── data/                                   # Benchmark Data Directory
│   ├── raw/                                # NSL-KDD benchmark files (KDDTrain+.txt, KDDTest+.txt)
│   ├── processed/                          # Intermediate processed files (git-ignored)
│   └── sample/                             # Synthetic test telemetry fixtures
├── docs/                                   # Project Documentation & Historical Design Notes
│   ├── README.md                           # Master technical documentation index
│   ├── 01_architecture_and_system_design.md
│   ├── 02_dataset_and_data_flow.md
│   ├── 03_modules_and_components.md
│   ├── 04_model_training_and_learning.md
│   ├── 05_validation_and_testing_guide.md
│   └── evidence/                           # Empirical verification evidence across Phases 1–10
├── models/                                 # Serialized Artifacts
│   ├── baseline_rf_binary.joblib           # Frozen Random Forest model bundle
│   └── baseline_rf_binary.metadata.json    # Model hyperparameters and training metadata
├── outputs/                                # Runtime Outputs & Evaluations
│   ├── evaluation_metrics.json             # Benchmark test metrics & confusion matrix
│   └── threat_events.db                    # Default SQLite alert database (git-ignored)
├── src/                                    # Application Source Code
│   └── threat_detection/                   # Namespaced Core Package
│       ├── __init__.py                     # Package version and export definitions
│       ├── config.py                       # Project paths, thresholds, and configuration
│       ├── data/                           # Ingestion, validation, and schema definitions
│       │   ├── __init__.py
│       │   ├── cli.py                      # Dataset integrity validation CLI
│       │   ├── loader.py                   # Headerless/headered NSL-KDD CSV loader
│       │   ├── schema.py                   # 41-feature schema specifications and constants
│       │   └── validator.py                # Non-destructive dataset integrity auditor
│       ├── detection/                      # Inference engine, heuristic rules, and evaluation
│       │   ├── __init__.py
│       │   ├── engine.py                   # ThreatDetectionEngine and fingerprint generator
│       │   ├── evaluate_cli.py             # Offline model evaluation CLI
│       │   ├── evaluator.py                # Benchmark evaluator and confusion matrix calculator
│       │   ├── rules.py                    # Deterministic heuristic security rules
│       │   ├── target.py                   # Binary target mapping ('normal' vs 'attack')
│       │   ├── train_cli.py                # Model training CLI
│       │   └── trainer.py                  # Random Forest training and artifact serialization
│       ├── preprocessing/                  # Feature engineering and transformation
│       │   ├── __init__.py
│       │   └── pipeline.py                 # ColumnTransformer pipeline and input validation
│       └── storage/                        # Persistent alert storage and lifecycle state machine
│           ├── __init__.py
│           ├── models.py                   # AlertRecord, AlertStatus, and custom exceptions
│           └── repository.py               # AlertRepository with deduplication and partial index
├── tests/                                  # 11 test modules with 155 automated unit and E2E tests
│   ├── test_alert_storage.py
│   ├── test_dashboard.py
│   ├── test_dashboard_demo.py
│   ├── test_dashboard_model_rules.py
│   ├── test_data_ingestion.py
│   ├── test_detection_engine.py
│   ├── test_foundation.py
│   ├── test_integration_e2e.py             # End-to-end integration test suite
│   ├── test_model_evaluation.py
│   ├── test_model_training.py
│   └── test_preprocessing.py
├── .env.example                            # Configuration template
├── .gitignore                              # Git exclusion rules
├── main.py                                 # Project foundation entry point
├── pyproject.toml                          # Packaging metadata and dependencies
└── requirements.txt                        # Pinned dependencies
```

---

## 2. Core Subsystems & Module Interfaces

### 2.1 Configuration: `src/threat_detection/config.py`
* Central typed dataclass (`ProjectConfig`) providing immutable paths (`BASE_DIR`, `RAW_DATA_DIR`, `MODELS_DIR`, `OUTPUTS_DIR`, `DATABASE_PATH`), threat scoring thresholds, and random seeds.

### 2.2 Data Ingestion & Validation: `src/threat_detection/data/`
* **`schema.py`**: Single source of truth for the 41 canonical `FEATURE_COLUMNS`, 3 `CATEGORICAL_FEATURES`, 38 `NUMERICAL_FEATURES`, schema variants (`standard_42`, `with_difficulty_43`), and attack taxonomies.
* **`loader.py`**: Resilient parsing of headerless and headered NSL-KDD files into pandas DataFrames (`load_nsl_kdd`).
* **`validator.py`**: Non-destructive data integrity audit (`validate_nsl_kdd`) producing structured `ValidationReport` metrics without modifying data.
* **`cli.py`**: Command-line interface for auditing dataset files.

### 2.3 Preprocessing & Transformation: `src/threat_detection/preprocessing/`
* **`pipeline.py`**:
  * `split_features_and_target`: Separates raw 41 traffic features from target label, strictly preventing target leakage.
  * `validate_traffic_features`: Enforces presence of 41 features, numeric integrity, and strictly blocks `class` and `difficulty_level`.
  * `ThreatPreprocessingPipeline`: Scikit-Learn `ColumnTransformer` applying `OneHotEncoder(handle_unknown='ignore')` to 3 categorical features (84 columns) and `passthrough` to 38 numerical features (122 dense features total; zero imputation, zero scaling).

### 2.4 Threat Detection & Evaluation: `src/threat_detection/detection/`
* **`trainer.py`**: Trains the Random Forest binary classifier using stratified splitting and bundles preprocessor, classifier, and metadata into `ThreatDetectionArtifact`.
* **`rules.py`**: Implements 4 deterministic heuristic security rules (`LandAttackRule`, `SynFloodHeuristicRule`, `ConnectionRejectionBurstRule`, `MultiServicePortSweepRule`).
* **`engine.py`**: `ThreatDetectionEngine` evaluates traffic records against the frozen model and heuristic rules, generates deterministic SHA-256 digests (`compute_record_fingerprint`), and synthesizes operational dispositions (`BENIGN`, `MODEL_DETECTED`, `RULE_DETECTED`, `CORROBORATED`).
* **`evaluator.py` & `evaluate_cli.py`**: Evaluates frozen artifacts against test benchmarks, generating confusion matrices and operational error rates.

### 2.5 Alert Storage & Lifecycle Management: `src/threat_detection/storage/`
* **`models.py`**: Defines typed `AlertRecord`, `AlertStatus` enum (`NEW`, `ACKNOWLEDGED`, `RESOLVED`), severity hierarchies, and lifecycle exceptions.
* **`repository.py`**: Thread-safe SQLite repository (`AlertRepository`) with partial unique indexes for active fingerprint deduplication, occurrence count increments, and two-step lifecycle state enforcement.

### 2.6 Security Operations Console: `dashboard/`
* **`app.py`**: Streamlit console presenting Alert Triage, offline Detection Demo, and Model & Rules technical documentation.
* **`helpers.py`**: Pure utility functions for database path resolution, KPI aggregation, upload CSV validation, and preset flow definitions.
