# AI-Powered Cybersecurity Threat Detection: Technical Documentation

> [!NOTE]
> **Historical Design & Scope Notice:**<br>
> The numbered technical documents in this directory (`01` through `05`) were authored during the initial project scaffolding phase (Phase 1) and record early architectural proposals, exploratory ideas, and preliminary target specifications. Some proposed technologies (e.g., live stream capture, XGBoost, deep neural networks, unsupervised autoencoders, SHAP attribution) and hypothetical directory layouts were design considerations that were not ultimately implemented.
>
> For the authoritative reference on implemented functionality, actual component APIs, verifiable commands, and measured benchmark performance, please refer to:
> * The repository root **[`README.md`](../README.md)**
> * The active codebase under **`src/threat_detection/`** and **`dashboard/`**
> * The 155 automated tests under **`tests/`**
> * The empirical verification records in **[`docs/evidence/`](evidence/)**

---

## 📚 Documentation Index

| Section | Document | Description | Status & Context |
| :--- | :--- | :--- | :--- |
| **01** | [`01_architecture_and_system_design.md`](01_architecture_and_system_design.md) | High-level system architecture, component interaction, and design blueprint. | Initial architectural design proposal (historical context). |
| **02** | [`02_dataset_and_data_flow.md`](02_dataset_and_data_flow.md) | NSL-KDD dataset specifications, 41-feature dictionary, and ingestion contracts. | Authoritative for NSL-KDD schema and attack family taxonomy. |
| **03** | [`03_modules_and_components.md`](03_modules_and_components.md) | Breakdown of modules, class structures, APIs, and subcomponent interactions. | Updated to reflect the implemented `src/threat_detection/` layout. |
| **04** | [`04_model_training_and_learning.md`](04_model_training_and_learning.md) | Random Forest baseline architecture, leakage-free splitting, and artifact bundling. | Authoritative for the frozen baseline training pipeline. |
| **05** | [`05_validation_and_testing_guide.md`](05_validation_and_testing_guide.md) | Verification scripts, checklists, and testing commands. | Historical testing guide updated with verified commands. |
| **Evidence** | [`docs/evidence/`](evidence/) | Detailed empirical test logs, quality gates, and metric reports across Phases 1–10. | Authoritative empirical verification records. |

---

## 🎯 Project Scope & Implemented Architecture

The implemented project delivers a defensive, educational cybersecurity threat detection prototype and security operations console:
1. **Offline Benchmark Evaluation**: Operates on static NSL-KDD network flow records (`KDDTrain+.txt`, `KDDTest+.txt`); does not capture live packets, inspect stream interfaces, or perform inline traffic blocking.
2. **Hybrid Detection Engine**: Combines a frozen Random Forest binary classifier (`normal` vs `attack`) with 4 deterministic heuristic security rules (LAND topology anomaly, SYN flood burst, connection rejection burst, and multi-service port sweep).
3. **Structured Triage & Explainability**: Generates deterministic SHA-256 digests (`record_fingerprint`), assigns operational dispositions (`BENIGN`, `MODEL_DETECTED`, `RULE_DETECTED`, `CORROBORATED`), and produces diagnostic explanations.
4. **Alert Persistence & Console**: Manages alerts in an ACID-compliant SQLite store with fingerprint-based active deduplication and strict lifecycle transitions (`NEW` $\rightarrow$ `ACKNOWLEDGED` $\rightarrow$ `RESOLVED`), surfaced through an interactive Streamlit operations console (`dashboard/app.py`).
