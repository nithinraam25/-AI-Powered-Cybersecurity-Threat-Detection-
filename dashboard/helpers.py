"""Helper utilities and data transformations for the Streamlit threat detection dashboard.

Provides pure functions for database path resolution, KPI aggregation,
in-memory page filtering, and table formatting.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from threat_detection.config import config
from threat_detection.detection.rules import RuleMatch
from threat_detection.storage.models import AlertRecord, AlertStatus


def resolve_database_path() -> Union[str, Path]:
    """Resolve database path from environment override or project config.

    Returns:
        Path or string to SQLite database (e.g. ':memory:' or file Path).
    """
    env_path = os.environ.get("THREAT_DETECTION_DB_PATH")
    if env_path is not None:
        stripped = env_path.strip()
        if stripped == ":memory:":
            return ":memory:"
        return Path(stripped)
    return config.DATABASE_PATH


def compute_kpis(summary_counts: Dict[str, Dict[str, int]]) -> Dict[str, int]:
    """Compute KPI metrics from repository summary counts.

    Args:
        summary_counts: Dictionary with 'by_status' and 'by_severity' mappings.

    Returns:
        Dictionary with total, new, acknowledged, resolved, and high_critical counts.
    """
    by_status = summary_counts.get("by_status", {})
    by_severity = summary_counts.get("by_severity", {})

    new_count = by_status.get(AlertStatus.NEW.value, 0)
    ack_count = by_status.get(AlertStatus.ACKNOWLEDGED.value, 0)
    res_count = by_status.get(AlertStatus.RESOLVED.value, 0)
    total_count = new_count + ack_count + res_count

    high_crit_count = by_severity.get("HIGH", 0) + by_severity.get("CRITICAL", 0)

    return {
        "total": total_count,
        "new": new_count,
        "acknowledged": ack_count,
        "resolved": res_count,
        "high_critical": high_crit_count,
    }


def filter_alerts_on_page(
    alerts: List[AlertRecord], search_query: str
) -> List[AlertRecord]:
    """Filter currently loaded page of alerts by substring match.

    Search scope is explicitly limited to the loaded page records and matches
    against alert_id, record_fingerprint, explanation, analyst_notes, and rule_ids.

    Args:
        alerts: List of AlertRecord instances on the current page.
        search_query: User search text.

    Returns:
        Filtered list of AlertRecord objects.
    """
    query = search_query.strip().lower()
    if not query:
        return alerts

    results: List[AlertRecord] = []
    for a in alerts:
        match_id = query in a.alert_id.lower()
        match_fp = query in a.record_fingerprint.lower()
        match_exp = query in a.explanation.lower()
        match_notes = bool(a.analyst_notes and query in a.analyst_notes.lower())
        match_rules = any(query in rid.lower() for rid in a.rule_ids)

        if match_id or match_fp or match_exp or match_notes or match_rules:
            results.append(a)

    return results


def format_alert_table_data(alerts: List[AlertRecord]) -> List[Dict[str, Any]]:
    """Format alert records into table-friendly dictionary representations.

    Args:
        alerts: List of AlertRecord instances.

    Returns:
        List of dicts for tabular rendering.
    """
    rows: List[Dict[str, Any]] = []
    for a in alerts:
        short_id = f"{a.alert_id[:8]}..."
        prob_str = f"{a.attack_probability * 100:.1f}%"
        rows.append(
            {
                "Alert ID": short_id,
                "Timestamp": a.detection_timestamp,
                "Status": a.status,
                "Severity": a.overall_severity,
                "Disposition": a.disposition,
                "Prediction": a.predicted_label,
                "Attack Prob": prob_str,
                "Count": a.occurrence_count,
                "_full_id": a.alert_id,
            }
        )
    return rows


def format_severity_badge(severity: str) -> str:
    """Format severity with both explicit text label and visual indicator.

    Ensures severity is never communicated by color or symbol alone.

    Args:
        severity: Overall severity string.

    Returns:
        Formatted label with icon and text.
    """
    badges = {
        "CRITICAL": "[CRITICAL] 🔴",
        "HIGH": "[HIGH] 🟠",
        "MEDIUM": "[MEDIUM] 🟡",
        "LOW": "[LOW] 🔵",
        "INFORMATIONAL": "[INFORMATIONAL] ⚪",
    }
    return badges.get(severity.upper(), f"[{severity}]")


# -------------------------------------------------------------------------
# Curated Authentic Benchmark Presets from NSL-KDD (KDDTest+.txt)
# -------------------------------------------------------------------------

PRESET_FLOW_RECORDS: Dict[str, Dict[str, Any]] = {
    "Authentic Benchmark: Normal FTP Session (KDDTest+ Row 2)": {
        "provenance": "Authentic NSL-KDD benchmark test record (row 2; original class: normal)",
        "record": {
            "duration": 2,
            "protocol_type": "tcp",
            "service": "ftp_data",
            "flag": "SF",
            "src_bytes": 12983,
            "dst_bytes": 0,
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": 1,
            "srv_count": 1,
            "serror_rate": 0.0,
            "srv_serror_rate": 0.0,
            "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 134,
            "dst_host_srv_count": 86,
            "dst_host_same_srv_rate": 0.61,
            "dst_host_diff_srv_rate": 0.04,
            "dst_host_same_src_port_rate": 0.61,
            "dst_host_srv_diff_host_rate": 0.02,
            "dst_host_serror_rate": 0.0,
            "dst_host_srv_serror_rate": 0.0,
            "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0,
        },
    },
    "Authentic Benchmark: SYN Flood Burst (KDDTest+ Row 13)": {
        "provenance": "Authentic NSL-KDD benchmark test record (row 13; original class: neptune)",
        "record": {
            "duration": 0,
            "protocol_type": "tcp",
            "service": "telnet",
            "flag": "S0",
            "src_bytes": 0,
            "dst_bytes": 0,
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": 120,
            "srv_count": 120,
            "serror_rate": 1.0,
            "srv_serror_rate": 1.0,
            "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 235,
            "dst_host_srv_count": 171,
            "dst_host_same_srv_rate": 0.73,
            "dst_host_diff_srv_rate": 0.07,
            "dst_host_same_src_port_rate": 0.0,
            "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 0.69,
            "dst_host_srv_serror_rate": 0.95,
            "dst_host_rerror_rate": 0.02,
            "dst_host_srv_rerror_rate": 0.0,
        },
    },
    "Authentic Benchmark: Connection Rejection Burst (KDDTest+ Row 0)": {
        "provenance": "Authentic NSL-KDD benchmark test record (row 0; original class: neptune)",
        "record": {
            "duration": 0,
            "protocol_type": "tcp",
            "service": "private",
            "flag": "REJ",
            "src_bytes": 0,
            "dst_bytes": 0,
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": 229,
            "srv_count": 10,
            "serror_rate": 0.0,
            "srv_serror_rate": 0.0,
            "rerror_rate": 1.0,
            "srv_rerror_rate": 1.0,
            "same_srv_rate": 0.04,
            "diff_srv_rate": 0.06,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 255,
            "dst_host_srv_count": 10,
            "dst_host_same_srv_rate": 0.04,
            "dst_host_diff_srv_rate": 0.06,
            "dst_host_same_src_port_rate": 0.0,
            "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 0.0,
            "dst_host_srv_serror_rate": 0.0,
            "dst_host_rerror_rate": 1.0,
            "dst_host_srv_rerror_rate": 1.0,
        },
    },
    "Authentic Benchmark: LAND Packet Anomaly (KDDTest+ Row 4892)": {
        "provenance": "Authentic NSL-KDD benchmark test record (row 4892; original class: land)",
        "record": {
            "duration": 0,
            "protocol_type": "tcp",
            "service": "finger",
            "flag": "S0",
            "src_bytes": 0,
            "dst_bytes": 0,
            "land": 1,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": 1,
            "srv_count": 2,
            "serror_rate": 1.0,
            "srv_serror_rate": 1.0,
            "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 1.0,
            "dst_host_count": 255,
            "dst_host_srv_count": 1,
            "dst_host_same_srv_rate": 0.0,
            "dst_host_diff_srv_rate": 0.02,
            "dst_host_same_src_port_rate": 0.0,
            "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 0.0,
            "dst_host_srv_serror_rate": 1.0,
            "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0,
        },
    },
    "Authentic Benchmark: Multi-Service Port Sweep (KDDTest+ Row 34)": {
        "provenance": "Authentic NSL-KDD benchmark test record (row 34; original class: satan)",
        "record": {
            "duration": 0,
            "protocol_type": "tcp",
            "service": "private",
            "flag": "REJ",
            "src_bytes": 0,
            "dst_bytes": 0,
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": 483,
            "srv_count": 1,
            "serror_rate": 0.05,
            "srv_serror_rate": 0.0,
            "rerror_rate": 0.92,
            "srv_rerror_rate": 1.0,
            "same_srv_rate": 0.0,
            "diff_srv_rate": 1.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 255,
            "dst_host_srv_count": 1,
            "dst_host_same_srv_rate": 0.0,
            "dst_host_diff_srv_rate": 1.0,
            "dst_host_same_src_port_rate": 0.0,
            "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 0.0,
            "dst_host_srv_serror_rate": 0.0,
            "dst_host_rerror_rate": 0.96,
            "dst_host_srv_rerror_rate": 1.0,
        },
    },
}


def parse_and_validate_csv_upload(file_input: Union[bytes, str]) -> Dict[str, Any]:
    """Parse and validate a single-row CSV network flow record.

    Ensures that:
    - File is not empty.
    - Exactly one flow record is present.
    - Exactly the 41 expected traffic features are present (no missing, no unexpected columns).
    - Extra metadata columns such as target label ('class') or 'difficulty_level' are rejected.
    - Numerical features are strictly valid numbers without silent coercion.

    Args:
        file_input: Raw bytes or string content of the uploaded CSV.

    Returns:
        Dictionary mapping feature names to their values for the single record.

    Raises:
        ValueError: If file is empty, has multi-row data, missing features,
            unexpected columns, or contains invalid numerical values.
    """
    import io
    import pandas as pd
    from threat_detection.data.schema import FEATURE_COLUMNS
    from threat_detection.preprocessing.pipeline import validate_traffic_features

    if isinstance(file_input, bytes):
        text_content = file_input.decode("utf-8", errors="replace")
    else:
        text_content = str(file_input)

    stripped = text_content.strip()
    if not stripped:
        raise ValueError("Uploaded CSV file is empty. Expected exactly one network flow record.")

    try:
        df = pd.read_csv(io.StringIO(stripped))
    except Exception as e:
        raise ValueError(f"Failed to parse CSV file: {e}")

    if len(df) == 0:
        raise ValueError("Uploaded CSV contains 0 data rows. Expected exactly one network flow record.")

    if len(df) > 1:
        raise ValueError(
            f"Uploaded CSV contains multiple rows ({len(df)} rows). "
            "The demonstration interface accepts exactly one flow record at a time."
        )

    # Check for missing required features
    missing_features = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing_features:
        raise ValueError(
            f"Uploaded CSV is missing {len(missing_features)} required traffic feature(s): {missing_features}"
        )

    # Check for unexpected extra columns (e.g. 'class', 'difficulty_level', or arbitrary extra fields)
    unexpected_features = [col for col in df.columns if col not in FEATURE_COLUMNS]
    if unexpected_features:
        raise ValueError(
            f"Uploaded CSV contains unexpected column(s): {unexpected_features}. "
            "Expected exactly the 41 traffic feature columns. Extra metadata columns such as "
            "'class' or 'difficulty_level' are not permitted and must not be included."
        )

    # Validate schema and data types strictly
    X = df[FEATURE_COLUMNS].copy()
    validate_traffic_features(X)

    # Return validated single-row dictionary
    return X.iloc[0].to_dict()


def load_evaluation_metrics(
    metrics_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Load and validate benchmark evaluation metrics from JSON report.

    Args:
        metrics_path: Optional custom path. Defaults to outputs/evaluation_metrics.json.

    Returns:
        Dict with status ('available', 'missing', or 'invalid'), path, and data or error details.
    """
    import json

    if metrics_path:
        target_path = Path(metrics_path)
    elif "THREAT_DETECTION_METRICS_PATH" in os.environ:
        target_path = Path(os.environ["THREAT_DETECTION_METRICS_PATH"].strip())
    else:
        target_path = config.OUTPUTS_DIR / "evaluation_metrics.json"

    if not target_path.exists():
        return {
            "status": "missing",
            "path": str(target_path),
            "data": None,
            "error": f"Evaluation metrics file not found at '{target_path}'.",
        }

    try:
        with target_path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        required_keys = [
            "accuracy",
            "total_samples",
            "precision_attack",
            "recall_attack",
            "f1_attack",
            "confusion_matrix_grid",
        ]
        missing_keys = [k for k in required_keys if k not in data]
        if missing_keys:
            return {
                "status": "invalid",
                "path": str(target_path),
                "data": None,
                "error": f"Metrics JSON is incomplete; missing required fields: {missing_keys}",
            }

        return {
            "status": "available",
            "path": str(target_path),
            "data": data,
            "error": None,
        }
    except Exception as e:
        return {
            "status": "invalid",
            "path": str(target_path),
            "data": None,
            "error": f"Failed to parse evaluation metrics JSON: {e}",
        }


def load_model_metadata(
    metadata_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Load and validate model metadata JSON.

    Args:
        metadata_path: Optional custom path. Defaults to models/baseline_rf_binary.metadata.json.

    Returns:
        Dict with status ('available', 'missing', or 'invalid'), path, and data or error details.
    """
    import json

    if metadata_path:
        target_path = Path(metadata_path)
    elif "THREAT_DETECTION_METADATA_PATH" in os.environ:
        target_path = Path(os.environ["THREAT_DETECTION_METADATA_PATH"].strip())
    else:
        target_path = config.MODELS_DIR / "baseline_rf_binary.metadata.json"

    if not target_path.exists():
        return {
            "status": "missing",
            "path": str(target_path),
            "data": None,
            "error": f"Model metadata file not found at '{target_path}'.",
        }

    try:
        with target_path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        required_keys = ["model_type", "raw_features_count", "hyperparameters"]
        missing_keys = [k for k in required_keys if k not in data]
        if missing_keys:
            return {
                "status": "invalid",
                "path": str(target_path),
                "data": None,
                "error": f"Model metadata JSON is incomplete; missing required fields: {missing_keys}",
            }

        return {
            "status": "available",
            "path": str(target_path),
            "data": data,
            "error": None,
        }
    except Exception as e:
        return {
            "status": "invalid",
            "path": str(target_path),
            "data": None,
            "error": f"Failed to parse model metadata JSON: {e}",
        }


def get_rule_specifications() -> List[Dict[str, Any]]:
    """Retrieve structured specifications for all active deterministic security rules.

    Extracts rule definitions, configured thresholds, severity levels, and condition
    logic directly from threat_detection.detection.rules.

    Returns:
        List of dictionaries with rule properties for dashboard rendering.
    """
    from threat_detection.detection.rules import create_default_security_rules

    rules = create_default_security_rules()
    specs = []
    for r in rules:
        cfg = r.config
        spec = {
            "rule_id": r.rule_id,
            "rule_name": r.rule_name,
            "severity": cfg.severity,
            "description": r.__doc__.strip().split("\n\n")[0] if r.__doc__ else "",
        }

        if r.rule_id == "RULE-LAND-001":
            spec["condition_summary"] = "land == 1 (Source IP and port equal destination IP and port)"
            spec["thresholds"] = {"land": 1}
        elif r.rule_id == "RULE-DOS-SYN-001":
            target_flags = sorted(list(cfg.target_flags))
            spec["condition_summary"] = (
                f"count >= {cfg.count_threshold} AND serror_rate >= {cfg.serror_rate_threshold:.2f} "
                f"AND flag in {target_flags}"
            )
            spec["thresholds"] = {
                "count_threshold": cfg.count_threshold,
                "serror_rate_threshold": cfg.serror_rate_threshold,
                "target_flags": target_flags,
            }
        elif r.rule_id == "RULE-DOS-REJ-001":
            target_flags = sorted(list(cfg.target_flags))
            spec["condition_summary"] = (
                f"count >= {cfg.count_threshold} AND rerror_rate >= {cfg.rerror_rate_threshold:.2f} "
                f"AND flag in {target_flags}"
            )
            spec["thresholds"] = {
                "count_threshold": cfg.count_threshold,
                "rerror_rate_threshold": cfg.rerror_rate_threshold,
                "target_flags": target_flags,
            }
        elif r.rule_id == "RULE-PROBE-SCAN-001":
            spec["condition_summary"] = (
                f"count >= {cfg.count_threshold} AND diff_srv_rate >= {cfg.diff_srv_rate_threshold:.2f} "
                f"AND dst_host_diff_srv_rate >= {cfg.dst_host_diff_srv_rate_threshold:.2f}"
            )
            spec["thresholds"] = {
                "count_threshold": cfg.count_threshold,
                "diff_srv_rate_threshold": cfg.diff_srv_rate_threshold,
                "dst_host_diff_srv_rate_threshold": cfg.dst_host_diff_srv_rate_threshold,
            }
        specs.append(spec)
    return specs


def get_disposition_specifications() -> List[Dict[str, str]]:
    """Retrieve operational triage disposition policy rules.

    Returns:
        List of dicts defining disposition, conditions, severity, and operational meaning.
    """
    return [
        {
            "disposition": "BENIGN",
            "model_condition": "Model predicted 'normal'",
            "rule_condition": "No heuristic rules triggered",
            "overall_severity": "INFORMATIONAL",
            "meaning": "Flow exhibits standard operational traffic patterns with no statistical anomaly or heuristic signature match.",
        },
        {
            "disposition": "MODEL_DETECTED",
            "model_condition": "Model predicted 'attack'",
            "rule_condition": "No heuristic rules triggered",
            "overall_severity": "MEDIUM",
            "meaning": "Statistical classifier identified complex multidimensional anomaly, but no discrete deterministic rule matched.",
        },
        {
            "disposition": "RULE_DETECTED",
            "model_condition": "Model predicted 'normal'",
            "rule_condition": "At least one rule matched",
            "overall_severity": "MEDIUM",
            "meaning": "Deterministic security rule matched a known structural threat pattern, even though the statistical model estimated normal probability.",
        },
        {
            "disposition": "CORROBORATED",
            "model_condition": "Model predicted 'attack'",
            "rule_condition": "At least one rule matched",
            "overall_severity": "HIGH",
            "meaning": "High-confidence finding where both the statistical classifier and independent deterministic heuristic rules independently signaled threat activity.",
        },
    ]
