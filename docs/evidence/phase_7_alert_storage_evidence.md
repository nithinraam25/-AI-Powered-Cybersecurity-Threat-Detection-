# Phase 7: Alert Management & SQLite Storage Evidence

This document captures the implementation, schema design, test results, and verification evidence for the SQLite persistence layer managing threat alerts.

---

## 1. Implementation Overview & Scope

- **Implemented Modules**:
  - [`src/threat_detection/storage/models.py`](file:///C:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/src/threat_detection/storage/models.py): Defines strongly typed `AlertRecord` dataclass, `AlertStatus` enum, severity orderings, and custom storage exceptions.
  - [`src/threat_detection/storage/repository.py`](file:///C:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/src/threat_detection/storage/repository.py): Implements `AlertRepository` with idempotent DDL, active duplicate merging, partial unique indexing, atomic transactions, and lifecycle state transitions.
  - [`src/threat_detection/storage/__init__.py`](file:///C:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/src/threat_detection/storage/__init__.py): Exposes storage interfaces cleanly.
  - [`tests/test_alert_storage.py`](file:///C:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/tests/test_alert_storage.py): 22 automated tests verifying schema idempotency, CRUD roundtrips, duplicate merging, lifecycle transitions, rollbacks, parameterization safety, and strict fingerprint validation.
- **Model and Dataset Immutability**:
  - Model Artifact SHA-256: `0e364ea84fa5f35ba1ce2ff025235ed70b0bee9423611c354ce520f69e60f6c5` (Unchanged).
  - `KDDTrain+.txt` SHA-256: `1b86d2f957b33082081bba410fe129b475efebcc13c9014c3f447c8271aadf95` (Unchanged).
  - `KDDTest+.txt` SHA-256:  `fa46b0935342616aa83b7c2578db355b6a7aaabbc492248172c7a1e8b7ab8f84` (Unchanged).
- **Scope Enforcement**: The persistence layer operates strictly without Streamlit, dashboard integrations, or streaming queues.

---

## 2. Database Schema & Index Specifications

### 2.1 Table: `alerts`

```sql
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    record_fingerprint TEXT NOT NULL CHECK (length(record_fingerprint) == 64),
    detection_timestamp TEXT NOT NULL,
    threat_detected INTEGER NOT NULL CHECK (threat_detected IN (0, 1)),
    disposition TEXT NOT NULL CHECK (disposition IN ('BENIGN', 'MODEL_DETECTED', 'RULE_DETECTED', 'CORROBORATED')),
    overall_severity TEXT NOT NULL CHECK (overall_severity IN ('INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    predicted_label TEXT NOT NULL CHECK (predicted_label IN ('normal', 'attack')),
    attack_probability REAL NOT NULL CHECK (attack_probability >= 0.0 AND attack_probability <= 1.0),
    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    rule_ids_json TEXT NOT NULL DEFAULT '[]',
    rule_matches_json TEXT NOT NULL DEFAULT '[]',
    explanation TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'NEW' CHECK (status IN ('NEW', 'ACKNOWLEDGED', 'RESOLVED')),
    occurrence_count INTEGER NOT NULL DEFAULT 1 CHECK (occurrence_count >= 1),
    first_seen_timestamp TEXT NOT NULL,
    last_seen_timestamp TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    acknowledged_at TEXT NULL,
    resolved_at TEXT NULL,
    analyst_notes TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint ON alerts (record_fingerprint);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (overall_severity);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (detection_timestamp DESC);

-- Partial unique index ensuring uniqueness only among active alerts
CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_active_fingerprint ON alerts (record_fingerprint)
WHERE status IN ('NEW', 'ACKNOWLEDGED');
```

### 2.2 Schema Design Highlights
- **Zero Raw Dataset Duplication**: The 41 raw traffic features are omitted; the 64-character SHA-256 `record_fingerprint` uniquely identifies flow profiles.
- **Canonical Rule Representations**: Rule IDs are stored as a JSON array (`rule_ids_json`) rather than comma-separated strings.
- **Partial Unique Indexing**: Guarantees transaction-safe uniqueness across active alerts while allowing resolved alerts to remain immutable historical audit records.

---

## 3. Deduplication & Evidence Merging Behavior

### 3.1 Active Duplicate Merging (`status IN ('NEW', 'ACKNOWLEDGED')`)
When a detection arrives matching the fingerprint of an active alert:
1. `occurrence_count` increments by 1.
2. `first_seen_timestamp` and `created_at` are preserved intact.
3. `last_seen_timestamp` is updated with `max(current.last_seen_timestamp, finding.timestamp)`.
4. `detection_timestamp` is updated with the latest finding's timestamp.
5. **Rule Evidence Accumulation**: Prior rule matches are preserved; newly observed `RuleMatch` objects are merged by `rule_id` without duplicate IDs.
6. **Severity Derivation**: Overall severity is evaluated from the accumulated evidence and latest finding; it is **never downgraded** if a subsequent flow is less severe.

### 3.2 Recurrence Following Resolution (`status == 'RESOLVED'`)
When a flow arrives matching the fingerprint of a previously `RESOLVED` alert:
- The closed investigation remains immutable in the database.
- A **new alert record** is generated with a fresh UUID `alert_id` in `NEW` status (`occurrence_count = 1`).

---

## 4. Lifecycle State Machine Transitions

Valid transitions:
- `NEW` $\rightarrow$ `ACKNOWLEDGED`: Sets `acknowledged_at` to current UTC ISO timestamp; preserves notes or updates with provided `analyst_notes`.
- `ACKNOWLEDGED` $\rightarrow$ `RESOLVED`: Sets `resolved_at` to current UTC ISO timestamp; preserves notes or updates with provided `analyst_notes`.
- **Idempotency**: Calling `acknowledge_alert` on an already acknowledged alert or `resolve_alert` on an already resolved alert is idempotent and preserves the original transition timestamp.
- **Invalid Transitions**:
  - `NEW` $\rightarrow$ `RESOLVED` directly: Rejected with `InvalidLifecycleTransitionError` (must be acknowledged first).
  - `RESOLVED` $\rightarrow$ `ACKNOWLEDGED`: Rejected with `InvalidLifecycleTransitionError` (cannot reopen resolved alerts).

---

## 5. Transaction Safety & Rollback Verification

- **Batch Atomicity**: `save_findings_batch()` wraps all operations in an explicit SQLite transaction.
- **Rollback Evidence**: Injected failure test (`test_batch_atomicity_and_rollback_on_injected_error`) confirmed that when one record in a batch fails validation (e.g. malformed fingerprint length), SQLite rolls back all inserts, leaving 0 partial records in the database.
- **Parameterization**: Tested strings containing SQL injection payloads and semicolons (`DROP TABLE alerts; -- ' OR '1'='1`). All executed safely as literal values.

---

## 6. Automated Regression Test Suite Execution

- **Command**:
  ```powershell
  .\.venv\Scripts\python.exe -m pytest -v
  ```
- **Exit Code**: `0`
- **Results**:
  - `tests/test_alert_storage.py`: **22 passed** (New persistence layer suite)
  - `tests/test_data_ingestion.py`: 17 passed
  - `tests/test_detection_engine.py`: 19 passed
  - `tests/test_foundation.py`: 2 passed
  - `tests/test_model_evaluation.py`: 10 passed
  - `tests/test_model_training.py`: 15 passed
  - `tests/test_preprocessing.py`: 14 passed
  - **Total**: **99 passed in 7.51s**, 0 failed.

---

## 7. Scope Boundaries & Technical Limitations

1. **Flow-Profile Granularity**: Fingerprint deduplication operates across the 41 static flow features (lacking IP addresses and temporal headers in NSL-KDD).
2. **Stateless Repository**: The repository stores and transitions alerts; it does not implement streaming event subscribers, background worker queues, or dashboard UIs.
3. **Database Exclusion**: Confirmed `*.db`, `*.sqlite`, `*.sqlite3` in `.gitignore` prevent local database files from being tracked in Git.
