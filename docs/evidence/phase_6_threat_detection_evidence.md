# Phase 6: Threat Detection Logic & Security Rules Evidence

This document captures the implementation, configuration, and verification evidence for combining the frozen Random Forest binary model with deterministic heuristic security rules in a unified detection engine.

---

## 1. Implementation Overview & Scope

- **Implemented Modules**:
  - [`src/threat_detection/detection/rules.py`](file:///C:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/src/threat_detection/detection/rules.py): Implements 4 configurable heuristic security rules, typed rule match data structures, and rule suite builders.
  - [`src/threat_detection/detection/engine.py`](file:///C:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/src/threat_detection/detection/engine.py): Implements `ThreatDetectionEngine`, `compute_record_fingerprint`, `ModelDecision`, and `DetectionFinding`.
  - [`src/threat_detection/detection/__init__.py`](file:///C:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/src/threat_detection/detection/__init__.py): Exposes engine and rule interfaces cleanly.
  - [`tests/test_detection_engine.py`](file:///C:/Users/nithi/OneDrive/Desktop/AI-Powered-Cybersecurity-Threat-Detection/AI-Powered-Cybersecurity-Threat-Detection/tests/test_detection_engine.py): 17 automated unit tests validating rule matching, threshold configurability, severity assignments, fingerprinting, and model immutability.
- **Frozen Model Artifact Integrity**:
  - SHA-256 Before Implementation: `0e364ea84fa5f35ba1ce2ff025235ed70b0bee9423611c354ce520f69e60f6c5`
  - SHA-256 After Implementation:  `0e364ea84fa5f35ba1ce2ff025235ed70b0bee9423611c354ce520f69e60f6c5`
  - The model was strictly loaded read-only; no training, refitting, or weight updates occurred.

---

## 2. Deterministic Security Rules Specifications

All rules operate strictly on the 41 canonical NSL-KDD traffic features. All thresholds are encapsulated in configuration dataclasses and represent configurable operational heuristics rather than empirically validated universal constants.

| Rule ID | Rule Name | Evaluated Fields | Initial Logic / Thresholds | Initial Rule Severity | Rationale & Caveat |
|---|---|---|---|:---:|---|
| `RULE-LAND-001` | Self-Referential Addressing (LAND) | `land` | `land == 1` | `HIGH` | **Rationale**: Source matches destination address/port.<br>**Caveat**: Protocol anomaly; does not guarantee hostile intent. |
| `RULE-DOS-SYN-001` | High-Volume SYN Error State | `count`, `serror_rate`, `flag` | `count >= 100`, `serror_rate >= 0.80`, `flag in {"S0", "S1", "S2", "S3", "RSTOS0"}` | `MEDIUM` | **Rationale**: High connection burst with failing TCP handshakes.<br>**Caveat**: Network dropouts or dead servers may also cause SYN timeouts. |
| `RULE-DOS-REJ-001` | Connection Rejection Burst | `count`, `rerror_rate`, `flag` | `count >= 50`, `rerror_rate >= 0.80`, `flag in {"REJ", "RSTO", "RSTR"}` | `MEDIUM` | **Rationale**: Target host repeatedly rejecting incoming packets.<br>**Caveat**: Firewall teardowns or stopped daemons also cause rejections. |
| `RULE-PROBE-SCAN-001` | Multi-Service Port Sweep | `count`, `diff_srv_rate`, `dst_host_diff_srv_rate` | `count >= 50`, `diff_srv_rate >= 0.70`, `dst_host_diff_srv_rate >= 0.70` | `MEDIUM` | **Rationale**: Traffic burst dispersed across multiple service ports.<br>**Caveat**: Authorized port vulnerability scanners may trigger this rule. |

---

## 3. Structured Finding Telemetry & Triage Policies

Every evaluated network traffic record emits a structured `DetectionFinding` record:

```python
@dataclass
class DetectionFinding:
    record_index: Optional[int]
    timestamp: str             # UTC ISO-8601 generation timestamp
    record_fingerprint: str    # Deterministic SHA-256 hash of 41 feature values
    threat_detected: bool      # True if Model == 'attack' OR len(rule_matches) > 0
    disposition: str           # "BENIGN", "MODEL_DETECTED", "RULE_DETECTED", "CORROBORATED"
    overall_severity: str      # "INFORMATIONAL", "MEDIUM", "HIGH"
    model_decision: ModelDecision
    rule_matches: List[RuleMatch]
    explanation: str
```

### 3.1 Disposition Matrix
- **`BENIGN`**: Statistical model predicts `normal` AND zero security rules triggered.
- **`MODEL_DETECTED`**: Statistical model predicts `attack` AND zero security rules triggered.
- **`RULE_DETECTED`**: At least one security rule triggered AND statistical model predicts `normal`.
- **`CORROBORATED`**: Statistical model predicts `attack` AND at least one security rule triggered.

### 3.2 Overall Severity Assignment Policy
- Neither model nor rules trigger: `INFORMATIONAL`.
- Model-only detection (`MODEL_DETECTED`): `MEDIUM`.
- Rule-only detection (`RULE_DETECTED`): `MEDIUM` (even if individual rule has `HIGH` rule severity, such as `RULE-LAND-001`).
- Corroborated detection (`CORROBORATED`): `HIGH`.

*Note: Dispositions and overall severities represent initial triage labels to aid human analyst prioritization, not confirmed incident-impact assessments.*

---

## 4. Deterministic Record Fingerprinting

- Function: `compute_record_fingerprint(record)`
- Algorithm: SHA-256 over fixed `FEATURE_COLUMNS` order with deterministic float formatting (`f"{float(val):.6f}"`) and lowercase string normalization.
- Properties:
  - Strictly independent of execution timestamp and batch row index.
  - Generates identical hash for identical flow telemetry across independent runs.
  - Rejects missing required columns or malformed non-numeric values with `ValueError`.

---

## 5. Automated Regression Test Suite Status

- **Command**:
  ```powershell
  .\.venv\Scripts\python.exe -m pytest -v
  ```
- **Exit Code**: `0`
- **Results**:
  - `tests/test_data_ingestion.py`: 17 passed
  - `tests/test_detection_engine.py`: **19 passed** (Engine, rules, threshold configs, invalid numeric input rejection, and repeat-run determinism)
  - `tests/test_foundation.py`: 2 passed
  - `tests/test_model_evaluation.py`: 10 passed
  - `tests/test_model_training.py`: 15 passed
  - `tests/test_preprocessing.py`: 14 passed
  - **Total**: **77 passed in 8.32s**, 0 failed.

---

## 6. Reproducible Smoke Test & Repeat-Run Determinism

A controlled verification run and a two-pass determinism check were executed against real records from `data/raw/KDDTest+.txt` using `ThreatDetectionEngine` initialized with the frozen `baseline_rf_binary.joblib` artifact:

### 6.1 Smoke Test Execution (50 Test Records)
- **Total Records Evaluated**: 50
- **Observed Dispositions**:
  - `BENIGN`: 31 records (62.0%)
  - `CORROBORATED`: 12 records (24.0%)
  - `MODEL_DETECTED`: 7 records (14.0%)
  - `RULE_DETECTED`: 0 records (0.0%)
- **Observed Rule Matches**:
  - `RULE-DOS-REJ-001`: 9 matches
  - `RULE-DOS-SYN-001`: 3 matches
  - `RULE-PROBE-SCAN-001`: 1 match

### 6.2 Two-Pass Repeat-Run Determinism (25 Benchmark Records)
- Evaluated the same 25 benchmark records across two consecutive passes:
  - **Predicted Labels**: 100% identical match across all 25 records.
  - **Attack Probabilities & Confidences**: Strictly identical within $10^{-9}$.
  - **Rule Matches & Severities**: Identical matches on every row.
  - **Dispositions & Overall Severities**: 100% identical.
  - **Record Fingerprints**: Strictly identical SHA-256 hashes.
  - **Timestamps**: Valid UTC ISO-8601 timestamps generated independently per run.

### 6.3 Model Artifact Immutability
- **Artifact SHA-256 Checksum**:
  - Initial:         `0e364ea84fa5f35ba1ce2ff025235ed70b0bee9423611c354ce520f69e60f6c5`
  - After Run 1:     `0e364ea84fa5f35ba1ce2ff025235ed70b0bee9423611c354ce520f69e60f6c5`
  - After Run 2:     `0e364ea84fa5f35ba1ce2ff025235ed70b0bee9423611c354ce520f69e60f6c5`
  - Difference: 0 bytes / identical hash confirmed across all executions.


---

## 7. Scope Boundaries & Technical Limitations

1. **Stateless Evaluation**: The engine operates statelessly on flow-by-flow telemetry. Multi-event session state, alert lifecycle management, and persistent deduplication are deferred to Phase 7.
2. **Offline Benchmark Scope**: These rules and models are verified on the NSL-KDD benchmark. They do not constitute a live packet sniffer or production-ready real-time intrusion prevention system (IPS).
3. **Phase 7 Boundaries**: Alert storage, database models, and web dashboard integration have not been started.
