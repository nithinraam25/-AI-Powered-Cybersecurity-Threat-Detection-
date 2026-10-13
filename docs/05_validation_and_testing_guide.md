# 05. Validation & Testing Guide

> [!NOTE]
> **Historical Design & Scope Notice:**<br>
> This guide records the verification protocols developed across the project lifecycle. Early preliminary benchmarks (such as an aspirational target of $\ge 98\%$ recall) and early module paths (e.g. `src.preprocessing`, `src.inference`) were exploratory design proposals. Actual measured performance on the independent NSL-KDD test benchmark achieves **$62.21\%$ attack recall** ($37.79\%$ false-negative rate) when confronting novel zero-day test intrusions, reflecting realistic generalization without overfitting.
>
> For the authoritative reference on implemented commands, verification suites, and measured benchmark metrics, refer to:
> * The repository root **[`README.md`](../README.md)**
> * Empirical verification evidence in **[`docs/evidence/`](evidence/)**
> * Evaluation metrics in **[`outputs/evaluation_metrics.json`](../outputs/evaluation_metrics.json)**

---

## 1. Verified Automated Testing Commands

To validate the implementation status across all subsystems, execute the following commands using the virtual environment:

```powershell
# Run the complete test suite across all 11 modules (155 tests)
.\.venv\Scripts\python.exe -m pytest -v

# Run the focused end-to-end integration test suite (10 tests)
.\.venv\Scripts\python.exe -m pytest tests/test_integration_e2e.py -v

# Run test suite with coverage report (requires pytest-cov)
.\.venv\Scripts\python.exe -m pytest --cov=threat_detection tests/

# Execute dataset schema validation CLI on the training set
.\.venv\Scripts\python.exe -m threat_detection.data.cli data/raw/KDDTrain+.txt

# Execute offline model evaluation CLI on the test set
.\.venv\Scripts\python.exe -m threat_detection.detection.evaluate_cli data/raw/KDDTest+.txt

# Launch the Streamlit Security Operations Console
.\.venv\Scripts\streamlit run dashboard/app.py
```

---

## 2. Validation Criteria & Performance Reality

| Subsystem / Metric | Historical Aspirational Target (Preliminary) | Actual Measured Result (Verified Benchmark) | Interpretation & Scope Note |
| :--- | :---: | :---: | :--- |
| **Attack Detection Recall** | $\ge 98\%$ *(Preliminary proposal)* | **$62.21\%$** ($0.6221$) | The test partition includes 17 novel zero-day attack variants unseen during training. A $62.21\%$ recall reflects realistic model performance on novel threats without data leakage. |
| **Attack Precision** | $\ge 95\%$ *(Preliminary proposal)* | **$96.88\%$** ($0.9688$) | The model demonstrates high precision, minimizing false alarms on flagged intrusions. |
| **False-Alarm Rate (FPR)** | $< 5\%$ *(Preliminary proposal)* | **$2.65\%$** ($0.0265$) | False-alarm rate of $2.65\%$ ($FP = 257$) ensures low operational alert fatigue on benign sessions. |
| **False-Negative Rate (FNR)** | $< 2\%$ *(Preliminary proposal)* | **$37.79\%$** ($0.3779$) | Transparently documented degradation when confronting uncatalogued zero-day attacks. |
| **Overall Accuracy** | Benchmark dependent | **$77.35\%$** ($0.7735$) | Measured across all $22,544$ records in `KDDTest+.txt`. |
| **Data Leakage Prevention** | Zero target leakage | **Verified** | Strict feature/target separation; target `class` and `difficulty_level` excluded from feature matrix. |
| **Database Isolation** | Zero production DB pollution | **Verified** | All test suites run in isolated `tmp_path` fixtures; `outputs/threat_events.db` is never created during tests. |

---

## 3. Implementation Verification Log

| Phase | Milestone | Scope Verified | Test Suite Count | Result |
| :---: | :--- | :--- | :---: | :---: |
| **Phase 1** | Foundation Scaffolding | Package layout, configuration, git ignore barriers, baseline imports | 2 tests | **Passed** |
| **Phase 2** | NSL-KDD Ingestion | Headerless CSV parsing, non-destructive audit, dataset CLI | 19 tests | **Passed** |
| **Phase 3** | Preprocessing Pipeline | ColumnTransformer, OneHotEncoder (84), passthrough (38), 122 features | 33 tests | **Passed** |
| **Phase 4** | Baseline Model Training | Stratified split, Random Forest binary training, artifact container | 48 tests | **Passed** |
| **Phase 5** | Model Evaluation | Test benchmark scoring, confusion matrix, error rates, evaluate CLI | 58 tests | **Passed** |
| **Phase 6** | Threat Detection Engine | 4 deterministic rules, SHA-256 fingerprinting, disposition synthesis | 77 tests | **Passed** |
| **Phase 7** | SQLite Alert Storage | Deduplication, partial unique index, lifecycle state machine | 99 tests | **Passed** |
| **Phase 8** | Streamlit Console | Alert Triage, offline Detection Demo, Model & Rules console | 145 tests | **Passed** |
| **Phase 9** | End-to-End Integration | 10 cross-subsystem integration scenarios, final quality gate | 155 tests | **Passed** |
| **Phase 10** | Documentation & Audit | Portfolio README finalized, reproducibility audit, technical note alignment | 155 tests | **Passed** |
