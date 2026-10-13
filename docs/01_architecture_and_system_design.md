# 01. Architecture & System Design

> [!NOTE]
> **Historical Design & Scope Notice:**<br>
> This document records an initial architectural proposal drafted during the Phase 1 project scaffolding. Some concepts described herein—including live network packet captures (PCAP), NetFlow/IPFIX streaming, deep neural networks, XGBoost, unsupervised autoencoders/Isolation Forests, composite numerical risk scores $[0.0, 100.0]$, and external SIEM/webhook integrations—were early exploratory proposals that were not ultimately implemented.
>
> For the authoritative reference on the implemented offline architecture, data flow, and benchmark evaluation, refer to:
> * The repository root **[`README.md`](../README.md)**
> * The active codebase under **`src/threat_detection/`** and **`dashboard/`**
> * Empirical verification evidence in **[`docs/evidence/`](evidence/)**

---

## 1. Initial Architectural Proposal (Historical Context)

The diagram below illustrates the original exploratory vision drafted during project kickoff:

```mermaid
flowchart TD
    subgraph Data Layer (Exploratory Proposal)
        A[Network Logs / PCAP / Benchmark Telemetry] --> B[Data Ingestion Module]
        B --> C[Preprocessing & Feature Pipeline]
    end

    subgraph Intelligence & Inference Layer (Proposed)
        C --> D[Feature Scaler / Encoder]
        D --> E{Detection Engine}
        E -->|Known Signatures / Patterns| F[Supervised Classifier: Proposed XGBoost / RF / MLP]
        E -->|Zero-Day / Outliers| G[Anomaly Detector: Proposed Autoencoder / Isolation Forest]
    end

    subgraph Decision & Scoring Layer (Proposed)
        F --> H[Ensemble & Risk Scoring Aggregator]
        G --> H
        H --> I{Threat Score >= Threshold?}
    end

    subgraph Action & Notification Layer (Proposed)
        I -->|Yes| J[Alert Generator & Incident Payload]
        I -->|No| K[Benign Traffic Audit Log]
        J --> L[Dashboard / SIEM Integration / Webhook]
    end
```

---

## 2. Implemented Architecture vs. Proposed Concepts

The table below contrasts the early exploratory design proposals with the verified implemented system:

| Architectural Component | Early Exploratory Proposal (Historical) | Actual Implemented System (Authoritative) |
| :--- | :--- | :--- |
| **Telemetry Ingestion** | Live PCAP packet capture, NetFlow/IPFIX streams, multi-dataset ingestion (CIC-IDS2017, UNSW-NB15). | **Offline Benchmark Evaluation**: Consumes canonical 41-feature NSL-KDD benchmark records (`KDDTrain+.txt`, `KDDTest+.txt`) and validated single-row CSV uploads. No live capture or stream monitoring. |
| **Preprocessing** | Separate serialized scalers in `models/scalers/`, robust scaling, median imputation. | **Single Unified Pipeline**: `ColumnTransformer` applying `OneHotEncoder` to 3 categorical features (84 columns) and `passthrough` to 38 numerical features (122 dense features total; zero imputation, zero scaling). |
| **Machine Learning** | Ensemble of XGBoost, Multi-Layer Perceptrons, and unsupervised Autoencoders/Isolation Forests. | **Frozen Random Forest Binary Classifier**: Scikit-Learn `RandomForestClassifier` predicting binary class (`normal` vs `attack`) with associated class probability and confidence. |
| **Heuristic Detection** | Signature-based pattern matching in separate SIEM layer. | **Deterministic Security Rules**: 4 explainable heuristic rules operating directly on flow features (`RULE-LAND-001`, `RULE-DOS-SYN-001`, `RULE-DOS-REJ-001`, `RULE-PROBE-SCAN-001`). |
| **Triage & Scoring** | Continuous numerical Risk Score $[0.0, 100.0]$ with 5-tier classification. | **Structured Operational Dispositions**: Synthesis of ML decision and rule matches into `BENIGN` (`INFORMATIONAL`), `MODEL_DETECTED` (`MEDIUM`), `RULE_DETECTED` (`MEDIUM`), and `CORROBORATED` (`HIGH`). |
| **Alert Persistence** | External SIEM / webhook dispatching. | **Embedded SQLite Repository**: ACID-compliant storage with partial unique indexes for active fingerprint deduplication and two-step lifecycle state machine (`NEW` $\rightarrow$ `ACKNOWLEDGED` $\rightarrow$ `RESOLVED`). |
| **User Interface** | Real-time SIEM dashboard with automated blocking controls. | **Streamlit Operations Console**: Multi-tab offline console (`dashboard/app.py`) for Alert Triage, Detection Demonstration, and Model & Rules specification. |
