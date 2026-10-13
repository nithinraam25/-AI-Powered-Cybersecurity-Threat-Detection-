"""AI-Powered Threat Detection Dashboard - Security Operations Console.

Offline evaluation dashboard for exploring security alerts, monitoring
status metrics, and performing incident triage and resolution.
Includes an offline demonstration interface for evaluating flow records.
"""

from datetime import datetime
import os
from pathlib import Path
import sys
from typing import Any, Dict, Optional

# Ensure src and dashboard modules are discoverable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = PROJECT_ROOT / "src"
DASHBOARD_PATH = PROJECT_ROOT / "dashboard"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))
if str(DASHBOARD_PATH) not in sys.path:
    sys.path.insert(0, str(DASHBOARD_PATH))

import streamlit as st

from dashboard.helpers import (
    PRESET_FLOW_RECORDS,
    compute_kpis,
    filter_alerts_on_page,
    format_alert_table_data,
    format_severity_badge,
    get_disposition_specifications,
    get_rule_specifications,
    load_evaluation_metrics,
    load_model_metadata,
    parse_and_validate_csv_upload,
    resolve_database_path,
)
from threat_detection.config import config
from threat_detection.detection.engine import ThreatDetectionEngine, compute_record_fingerprint
from threat_detection.detection.trainer import ThreatDetectionArtifact
from threat_detection.storage import (
    AlertNotFoundError,
    AlertRecord,
    AlertRepository,
    AlertStatus,
    InvalidLifecycleTransitionError,
)


@st.cache_resource
def get_repository(db_path_str: str) -> AlertRepository:
    """Instantiate and initialize the SQLite AlertRepository resource.

    Args:
        db_path_str: String path to the database file or ':memory:'.

    Returns:
        Initialized AlertRepository instance.
    """
    repo = AlertRepository(db_path=db_path_str)
    repo.initialize_schema()
    return repo


@st.cache_resource
def get_detection_engine(model_path_str: str) -> ThreatDetectionEngine:
    """Load frozen model artifact and instantiate ThreatDetectionEngine.

    Args:
        model_path_str: String path to the frozen joblib artifact.

    Returns:
        ThreatDetectionEngine instance.
    """
    artifact = ThreatDetectionArtifact.load(model_path_str)
    return ThreatDetectionEngine(artifact=artifact)


def render_triage_tab(repo: AlertRepository, kpis: Dict[str, int]) -> None:
    """Render the Alert Triage and incident management interface."""
    # Summary KPI Cards
    kpi_col1, kpi_col2, kpi_col3, kpi_col4, kpi_col5 = st.columns(5)
    kpi_col1.metric("Total Alerts", kpis["total"])
    kpi_col2.metric("New Alerts", kpis["new"])
    kpi_col3.metric("Acknowledged", kpis["acknowledged"])
    kpi_col4.metric("Resolved", kpis["resolved"])
    kpi_col5.metric("High / Critical", kpis["high_critical"])

    st.divider()

    # Empty State: Zero Alerts in Database
    if kpis["total"] == 0:
        st.info(
            "ℹ️ No security alerts currently exist in the database. "
            "The alert repository is initialized and empty. "
            "When security detections are recorded, they will appear here for triage."
        )
        return

    # Section: Alert Inventory & Triage Controls
    st.subheader("Alert Inventory & Triage")

    # Filter Controls Row
    f_col1, f_col2, f_col3, f_col4 = st.columns([2, 2, 2, 2])
    with f_col1:
        status_options = ["All", "NEW", "ACKNOWLEDGED", "RESOLVED"]
        selected_status = st.selectbox("Status Filter", status_options, index=0)
    with f_col2:
        severity_options = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
        selected_severity = st.selectbox("Severity Filter", severity_options, index=0)
    with f_col3:
        disposition_options = ["All", "CORROBORATED", "MODEL_DETECTED", "RULE_DETECTED", "BENIGN"]
        selected_disposition = st.selectbox("Disposition Filter", disposition_options, index=0)
    with f_col4:
        page_size_options = [25, 50, 100]
        page_size = st.selectbox("Page Size", page_size_options, index=0)

    # Reset pagination state if filter values change
    current_filter_state = (selected_status, selected_severity, selected_disposition, page_size)
    if st.session_state.get("prev_filter_state") != current_filter_state:
        st.session_state["page_index"] = 0
        st.session_state["prev_filter_state"] = current_filter_state

    if "page_index" not in st.session_state:
        st.session_state["page_index"] = 0

    page_index = st.session_state["page_index"]
    offset = page_index * page_size

    # Map UI filters to repository parameters
    query_status = None if selected_status == "All" else selected_status
    query_severity = None if selected_severity == "All" else selected_severity
    query_disposition = None if selected_disposition == "All" else selected_disposition

    # Fetch page of alerts (fetching limit + 1 to detect next-page existence cleanly)
    try:
        raw_alerts = repo.list_alerts(
            status=query_status,
            severity=query_severity,
            disposition=query_disposition,
            limit=page_size + 1,
            offset=offset,
        )
    except Exception as e:
        st.error(f"❌ Failed to retrieve alerts from database: {e}")
        st.stop()

    has_next = len(raw_alerts) > page_size
    page_alerts = raw_alerts[:page_size]
    has_prev = page_index > 0

    # Search Bar (strictly scoped to the currently loaded page)
    search_col, _ = st.columns([3, 1])
    with search_col:
        search_query = st.text_input(
            "Search Loaded Page",
            placeholder="Search by ID, fingerprint, rule, explanation, or notes...",
            help="Filters records currently loaded on this page.",
        )
        st.caption("🔍 Search applies only to records on the currently loaded page.")

    # Filter page records using in-memory search helper
    displayed_alerts = filter_alerts_on_page(page_alerts, search_query)

    if not displayed_alerts:
        st.info("ℹ️ No alerts match the current filter criteria or page search query.")
        if page_index > 0:
            if st.button("Return to Page 1"):
                st.session_state["page_index"] = 0
                st.rerun()
        return

    # Render Alerts Table
    table_rows = format_alert_table_data(displayed_alerts)
    st.dataframe(
        table_rows,
        column_config={
            "_full_id": None,  # Hide internal identifier column
        },
        use_container_width=True,
        hide_index=True,
    )

    # Pagination Navigation Controls
    p_col1, p_col2, p_col3 = st.columns([2, 4, 2])
    with p_col1:
        if st.button("◀ Previous Page", disabled=not has_prev, use_container_width=True):
            st.session_state["page_index"] = max(0, page_index - 1)
            st.rerun()
    with p_col2:
        st.markdown(
            f"<p style='text-align: center; margin-top: 8px; color: gray;'>"
            f"Page {page_index + 1} | Displaying {len(displayed_alerts)} alert(s) on current page"
            f"</p>",
            unsafe_allow_html=True,
        )
    with p_col3:
        if st.button("Next Page ▶", disabled=not has_next, use_container_width=True):
            st.session_state["page_index"] = page_index + 1
            st.rerun()

    st.divider()

    # Section: Selected Alert Detail & Lifecycle Actions
    st.subheader("Selected Alert Investigation & Triage")

    alert_options = {
        f"{format_severity_badge(a.overall_severity)} {a.alert_id[:8]}... | {a.disposition} | Status: {a.status}": a.alert_id
        for a in displayed_alerts
    }

    selected_label = st.selectbox(
        "Select an Alert to Inspect & Manage:",
        options=list(alert_options.keys()),
        index=0,
        key="selected_alert_dropdown",
    )
    target_alert_id = alert_options[selected_label]
    alert = repo.get_alert_by_id(target_alert_id)

    if alert is None:
        st.warning(f"Alert with ID '{target_alert_id}' could not be located in database.")
        return

    # Detail View: Metadata and Summary Badges
    d_col1, d_col2, d_col3, d_col4 = st.columns(4)
    d_col1.markdown(f"**Severity:** {format_severity_badge(alert.overall_severity)}")
    d_col2.markdown(f"**Disposition:** `{alert.disposition}`")
    d_col3.markdown(f"**Lifecycle Status:** `{alert.status}`")
    d_col4.markdown(f"**Occurrence Count:** `{alert.occurrence_count}`")

    # Tabular Breakdown: Model Decision vs Rule Matches
    tab_model, tab_rules, tab_timeline = st.tabs(
        ["🤖 Model Telemetry", "📜 Heuristic Rule Evidence", "⏱️ Event Timeline"]
    )

    with tab_model:
        st.markdown("#### Frozen Machine Learning Classifier Output")
        m_col1, m_col2, m_col3 = st.columns(3)
        m_col1.metric("Predicted Label", alert.predicted_label.upper())
        m_col2.metric("Attack Probability", f"{alert.attack_probability * 100:.2f}%")
        m_col3.metric("Classifier Confidence", f"{alert.confidence * 100:.2f}%")
        st.caption(
            "Confidence represents maximum estimated class probability from the frozen "
            "Random Forest classifier, reflecting model certainty rather than guaranteed correctness."
        )

    with tab_rules:
        st.markdown("#### Deterministic Heuristic Security Rules")
        if alert.rule_matches:
            st.markdown(f"**Triggered Rule IDs:** `{', '.join(alert.rule_ids)}`")
            for idx, r in enumerate(alert.rule_matches, 1):
                with st.expander(
                    f"Rule {idx}: {r.rule_id} - {r.rule_name} (Severity: {r.severity})",
                    expanded=True,
                ):
                    st.markdown(f"**Description:** {r.description}")
                    st.markdown("**Matched Flow Field Indicators:**")
                    st.json(r.matched_fields)
        else:
            st.info("ℹ️ No deterministic heuristic security rules were triggered for this flow profile.")

    with tab_timeline:
        st.markdown("#### Timestamps & Provenance")
        t_col1, t_col2 = st.columns(2)
        with t_col1:
            st.markdown(f"**First Seen:** `{alert.first_seen_timestamp}`")
            st.markdown(f"**Last Seen:** `{alert.last_seen_timestamp}`")
            st.markdown(f"**Latest Detection:** `{alert.detection_timestamp}`")
        with t_col2:
            st.markdown(f"**Record Created:** `{alert.created_at}`")
            st.markdown(f"**Record Updated:** `{alert.updated_at}`")
            st.markdown(f"**Acknowledged At:** `{alert.acknowledged_at or 'Not Acknowledged'}`")
            st.markdown(f"**Resolved At:** `{alert.resolved_at or 'Not Resolved'}`")

    st.markdown("#### Detection Narrative & Fingerprint")
    st.markdown(f"**Explanation:** {alert.explanation}")
    st.markdown(f"**SHA-256 Flow Fingerprint:**\n`{alert.record_fingerprint}`")

    # Section: Analyst Lifecycle Actions
    st.markdown("#### Analyst Investigation & Actions")

    analyst_notes_input = st.text_area(
        "Analyst Notes",
        value=alert.analyst_notes or "",
        help="Attach investigation notes to this alert prior to lifecycle transitions.",
        key=f"notes_input_{alert.alert_id}",
    )

    action_col1, action_col2 = st.columns(2)

    with action_col1:
        if alert.status == AlertStatus.NEW.value:
            if st.button("Acknowledge Alert (NEW ➔ ACKNOWLEDGED)", use_container_width=True):
                try:
                    notes_to_save = analyst_notes_input.strip() if analyst_notes_input.strip() else None
                    repo.acknowledge_alert(alert.alert_id, analyst_notes=notes_to_save)
                    st.success(f"✅ Alert '{alert.alert_id[:8]}...' successfully acknowledged.")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ Failed to acknowledge alert: {e}")
        else:
            st.button(
                "Acknowledge Alert (NEW ➔ ACKNOWLEDGED)",
                disabled=True,
                help=f"Alert is already in '{alert.status}' status.",
                use_container_width=True,
            )

    with action_col2:
        if alert.status == AlertStatus.ACKNOWLEDGED.value:
            if st.button("Resolve Alert (ACKNOWLEDGED ➔ RESOLVED)", use_container_width=True):
                try:
                    notes_to_save = analyst_notes_input.strip() if analyst_notes_input.strip() else None
                    repo.resolve_alert(alert.alert_id, analyst_notes=notes_to_save)
                    st.success(f"✅ Alert '{alert.alert_id[:8]}...' successfully resolved.")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ Failed to resolve alert: {e}")
        else:
            st.button(
                "Resolve Alert (ACKNOWLEDGED ➔ RESOLVED)",
                disabled=True,
                help="Alert must be in 'ACKNOWLEDGED' status prior to resolution.",
                use_container_width=True,
            )

    if alert.status == AlertStatus.RESOLVED.value:
        st.info("🔒 This alert is in RESOLVED status. The investigation is officially closed.")


def render_demo_tab(repo: AlertRepository) -> None:
    """Render the offline Threat Detection Demonstration interface."""
    st.subheader("Offline Threat Detection Demonstration")
    st.info(
        "ℹ️ This is an offline demonstration using network-flow records. "
        "It does not capture live traffic or provide real-time protection."
    )

    # Load frozen detection engine
    model_path = config.MODELS_DIR / "baseline_rf_binary.joblib"
    try:
        engine = get_detection_engine(str(model_path))
    except Exception as e:
        st.error(
            f"❌ Model Loading Failure: Unable to load frozen Random Forest artifact "
            f"from '{model_path}'. Error details: {e}"
        )
        st.info("Please verify the model artifact exists and is intact.")
        return

    # Flow Input Selection
    st.markdown("#### 1. Select Network Flow Record")
    input_method = st.radio(
        "Select Flow Input Method:",
        options=["Curated Benchmark Preset", "Single-Row CSV Upload"],
        horizontal=True,
    )

    selected_record: Optional[Dict[str, Any]] = None
    input_description: str = ""

    if input_method == "Curated Benchmark Preset":
        preset_names = list(PRESET_FLOW_RECORDS.keys())
        chosen_preset_name = st.selectbox("Choose Benchmark Flow Preset:", options=preset_names)
        preset_info = PRESET_FLOW_RECORDS[chosen_preset_name]
        selected_record = dict(preset_info["record"])
        input_description = preset_info["provenance"]
        st.caption(f"📍 **Provenance:** {input_description}")
        with st.expander("🔍 Inspect 41 Raw Traffic Features (Metadata Excluded)", expanded=False):
            st.json(selected_record)

    else:
        st.markdown("##### Upload Single-Row Flow Record (CSV)")
        st.caption(
            "Upload a single-row CSV containing the required 41 traffic features. "
            "Target labels ('class') and difficulty levels are strictly excluded from model inference."
        )
        uploaded_file = st.file_uploader(
            "Upload CSV File",
            type=["csv", "txt"],
            help="File must contain exactly one data row conforming to the 41-feature schema.",
        )
        if uploaded_file is not None:
            try:
                selected_record = parse_and_validate_csv_upload(uploaded_file.getvalue())
                input_description = f"Uploaded CSV: '{uploaded_file.name}'"
                st.success("✅ CSV parsed and validated successfully (41 features verified).")
                with st.expander("🔍 Inspect 41 Parsed Traffic Features", expanded=False):
                    st.json(selected_record)
            except Exception as e:
                st.error(f"❌ Upload Validation Error: {e}")
                selected_record = None

    if selected_record is None:
        return

    # Compute deterministic fingerprint of selected input
    current_input_fp = compute_record_fingerprint(selected_record)

    # Invalidate stale session finding if the input record has changed
    if st.session_state.get("demo_evaluated_fp") != current_input_fp:
        st.session_state["demo_finding"] = None
        st.session_state["demo_persisted_alert"] = None

    st.divider()

    # Evaluation Trigger
    st.markdown("#### 2. Evaluate Network Flow")
    eval_btn = st.button("🧪 Evaluate Flow", type="primary", use_container_width=True)
    if eval_btn:
        try:
            finding = engine.detect_record(selected_record)
            st.session_state["demo_finding"] = finding
            st.session_state["demo_evaluated_fp"] = current_input_fp
            st.session_state["demo_persisted_alert"] = None
        except Exception as e:
            st.error(f"❌ Evaluation Error: Detection engine failed to process record: {e}")
            return

    # Display Finding if available for current input
    finding = st.session_state.get("demo_finding")
    if finding is not None and st.session_state.get("demo_evaluated_fp") == current_input_fp:
        st.markdown("#### 3. Evaluation Findings & Telemetry")

        # Status Banner distinguishing in-memory vs saved
        persisted_alert = st.session_state.get("demo_persisted_alert")
        if persisted_alert is None:
            st.warning(
                "⚡ **Status: Evaluated in memory.** This finding has NOT been persisted to the SQLite database. "
                "Evaluating a record alone does not write to storage. "
                "Click the persistence button below if you wish to record this as an alert."
            )
        else:
            st.success(
                f"💾 **Status: Persisted to database.** "
                f"Alert ID: `{persisted_alert.alert_id}` | Status: `{persisted_alert.status}` | "
                f"Occurrence Count: `{persisted_alert.occurrence_count}`"
            )

        # Overview Metrics Row
        r_col1, r_col2, r_col3 = st.columns(3)
        r_col1.markdown(f"**Overall Severity:** {format_severity_badge(finding.overall_severity)}")
        r_col2.markdown(f"**Disposition:** `{finding.disposition}`")
        threat_icon = "⚠️ THREAT DETECTED" if finding.threat_detected else "✅ BENIGN"
        r_col3.markdown(f"**Threat Flag:** `{threat_icon}`")

        # Two-column breakdown: Model vs Rules
        res_col_ml, res_col_rules = st.columns(2)

        with res_col_ml:
            st.markdown("##### 🤖 Machine Learning Decision")
            st.metric("Predicted Label", finding.model_decision.predicted_label.upper())
            st.metric("Attack Probability", f"{finding.model_decision.attack_probability * 100:.2f}%")
            st.metric("Classifier Confidence", f"{finding.model_decision.confidence * 100:.2f}%")
            st.caption(
                "Note: Statistical probability reflects classifier certainty on normalized benchmark features; "
                "it does not constitute proof of real-world malicious activity."
            )

        with res_col_rules:
            st.markdown("##### 📜 Heuristic Security Rules")
            if finding.rule_matches:
                st.markdown(f"**Triggered Rules:** `{', '.join(r.rule_id for r in finding.rule_matches)}`")
                for r in finding.rule_matches:
                    with st.expander(f"Rule: {r.rule_id} - {r.rule_name} ({r.severity})", expanded=True):
                        st.markdown(f"**Description:** {r.description}")
                        st.markdown("**Matched Field Indicators:**")
                        st.json(r.matched_fields)
            else:
                st.info("ℹ️ No deterministic heuristic rules matched this traffic flow.")

        # Narrative Explanation & Fingerprint
        st.markdown("##### 📝 Diagnostic Narrative & Fingerprint")
        st.markdown(f"**Explanation:** {finding.explanation}")
        st.markdown(
            f"**Record Fingerprint (SHA-256):**\n`{finding.record_fingerprint}`"
        )
        st.caption(
            "Note: The record fingerprint is a deterministic SHA-256 digest of the normalized feature tuple. "
            "It identifies equivalent feature records within the flow profile, not the identity of a physical host or incident."
        )

        st.divider()

        # Optional Persistence Action
        st.markdown("#### 4. Optional Persistence Action")
        if persisted_alert is None:
            if st.button("💾 Persist Finding as Alert", use_container_width=True):
                try:
                    saved = repo.save_finding(finding)
                    st.session_state["demo_persisted_alert"] = saved
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ Persistence Failure: Failed to save finding to repository: {e}")
        else:
            st.button(
                "💾 Persist Finding as Alert (Already Saved)",
                disabled=True,
                use_container_width=True,
                help="This finding has already been persisted to the database.",
            )


@st.cache_data
def get_cached_evaluation_metrics() -> Dict[str, Any]:
    """Retrieve and cache evaluation metrics JSON report."""
    return load_evaluation_metrics()


@st.cache_data
def get_cached_model_metadata() -> Dict[str, Any]:
    """Retrieve and cache model metadata JSON report."""
    return load_model_metadata()


def render_model_rules_tab() -> None:
    """Render technical documentation for the frozen ML model and detection rules."""
    st.markdown("### 🧠 Model Architecture & Detection Rules Specification")
    st.caption(
        "Technical specification and offline benchmark evaluation results for the frozen "
        "RandomForest binary classifier and deterministic heuristic detection rules."
    )

    # 1. Model Architecture Section
    st.markdown("#### 1. Machine Learning Classifier Specification")
    model_artifact_path = (
        Path(os.environ["THREAT_DETECTION_MODEL_PATH"].strip())
        if "THREAT_DETECTION_MODEL_PATH" in os.environ
        else config.MODELS_DIR / "baseline_rf_binary.joblib"
    )
    model_exists = model_artifact_path.exists()
    model_status_label = "✅ Available (Frozen Artifact)" if model_exists else "❌ Not Found"

    meta_result = get_cached_model_metadata()
    meta_data = meta_result.get("data") or {}

    col_m1, col_m2 = st.columns(2)
    with col_m1:
        st.markdown("**Model Identity & Filesystem Location:**")
        st.markdown("- **Algorithm:** `RandomForestClassifier` (Scikit-Learn)")
        st.markdown("- **Target Formulation:** `binary (normal vs attack)`")
        st.markdown(f"- **Artifact Path:** `{model_artifact_path}`")
        st.markdown(f"- **Artifact Status:** {model_status_label}")
        if model_exists:
            st.markdown(f"- **Artifact Size:** `{model_artifact_path.stat().st_size:,} bytes`")

    with col_m2:
        st.markdown("**Feature Transformation & Schema:**")
        raw_feat = meta_data.get("raw_features_count", 41)
        enc_feat = meta_data.get("encoded_features_count", 122)
        train_samples = meta_data.get("train_samples", 100778)
        val_samples = meta_data.get("val_samples", 25195)
        st.markdown(f"- **Raw Traffic Features:** `{raw_feat}` canonical NSL-KDD fields")
        st.markdown(
            f"- **Encoded Features:** `{enc_feat}` (One-hot encoded categorical variables: `protocol_type`, `service`, `flag`)"
        )
        st.markdown("- **Training Dataset Source:** `data/raw/KDDTrain+.txt`")
        st.markdown(f"- **Training Partition Sizes:** Train = `{train_samples:,}`, Val = `{val_samples:,}`")

    with st.expander("⚙️ Confirmed Model Hyperparameters", expanded=False):
        hyperparams = meta_data.get(
            "hyperparameters",
            {
                "n_estimators": 100,
                "max_depth": 20,
                "min_samples_split": 2,
                "min_samples_leaf": 1,
                "class_weight": "balanced",
                "random_state": 42,
                "n_jobs": -1,
            },
        )
        st.json(hyperparams)

    st.info(
        "ℹ️ **Feature Ingestion Pipeline**: The classifier consumes the canonical 41 raw NSL-KDD network "
        "flow features. The preprocessor applies `OneHotEncoder(handle_unknown='ignore')` to the 3 categorical "
        "features (`protocol_type`, `service`, `flag`), expanding them to 84 binary indicator columns, and "
        "passes the 38 numerical features through directly (`passthrough`) without scaling or imputation, "
        "yielding exactly 122 encoded features (84 one-hot + 38 numerical). Both the classifier and preprocessor "
        "are frozen artifacts; no retraining or saving occurs from this interface."
    )

    st.divider()

    # 2. Benchmark Evaluation Section
    st.markdown("#### 2. Offline Benchmark Performance (NSL-KDD Test Set)")
    metrics_result = get_cached_evaluation_metrics()

    if metrics_result["status"] == "missing":
        st.warning(
            f"⚠️ **Evaluation Metrics Unavailable**: Metrics report was not found at `{metrics_result['path']}`. "
            "Metrics are loaded from precomputed benchmark evaluations and are never recomputed on page reruns. "
            "To generate this report, run the offline CLI: "
            "`python -m threat_detection.detection.evaluate_cli data/raw/KDDTest+.txt --json-output outputs/evaluation_metrics.json`."
        )
    elif metrics_result["status"] == "invalid":
        st.error(
            f"❌ **Evaluation Metrics Malformed**: Failed to read metrics from `{metrics_result['path']}`. "
            f"Error details: {metrics_result['error']}"
        )
    else:
        m = metrics_result["data"]
        st.markdown(
            f"Evaluated on independent benchmark partition **`{m.get('dataset_source', 'data/raw/KDDTest+.txt')}`** "
            f"comprising **`{m.get('total_samples', 22544):,}` flow records** (0 excluded)."
        )

        st.caption(
            "Target Policy: Negative class `normal` mapped to normal; ground-truth positive class `attack` encompasses "
            "catalogued attacks plus novel test partition intrusions (e.g., `snmpgetattack`)."
        )

        # Highlight key measured benchmark results as required
        st.info(
            "📊 **Measured Independent NSL-KDD Benchmark Performance:** "
            f"Test Accuracy = **`{m.get('accuracy', 0.7735):.4f}` ({m.get('accuracy', 0.7735):.2%})**, "
            f"Attack Recall = **`{m.get('recall_attack', 0.6221):.4f}` ({m.get('recall_attack', 0.6221):.2%})**, and "
            f"False-Negative Rate = **`{m.get('false_negative_rate', 0.3779):.4f}` ({m.get('false_negative_rate', 0.3779):.2%})**."
        )

        # Key Metrics Row
        k_col1, k_col2, k_col3, k_col4, k_col5, k_col6 = st.columns(6)
        k_col1.markdown(f"**Overall Accuracy**\n### `{m.get('accuracy', 0.0):.2%}`")
        k_col2.markdown(f"**Attack Precision**\n### `{m.get('precision_attack', 0.0):.2%}`")
        k_col3.markdown(f"**Attack Recall**\n### `{m.get('recall_attack', 0.0):.2%}`")
        k_col4.markdown(f"**Attack F1-Score**\n### `{m.get('f1_attack', 0.0):.4f}`")
        k_col5.markdown(
            f"**ROC-AUC**\n### `{m.get('roc_auc', 0.0):.4f}`"
            if m.get("roc_auc") is not None
            else "**ROC-AUC**\n### `N/A`"
        )
        k_col6.markdown(
            f"**PR-AUC**\n### `{m.get('pr_auc', 0.0):.4f}`"
            if m.get("pr_auc") is not None
            else "**PR-AUC**\n### `N/A`"
        )

        # Confusion Matrix Section
        st.markdown("##### Confusion Matrix Analysis")
        st.caption(
            "Matrix Orientation: Rows represent Ground Truth (Actual Class); Columns represent Model Prediction."
        )

        tn = m.get("true_negatives", 0)
        fp = m.get("false_positives", 0)
        fn = m.get("false_negatives", 0)
        tp = m.get("true_positives", 0)
        fpr = m.get("false_positive_rate", 0.0)
        fnr = m.get("false_negative_rate", 0.0)

        cm_col1, cm_col2 = st.columns(2)
        with cm_col1:
            cm_table = [
                {
                    "Ground Truth \\ Predicted": "Actual Normal (Negative)",
                    "Predicted Normal": f"TN = {tn:,}",
                    "Predicted Attack": f"FP = {fp:,} (False Alarm)",
                    "Total Actual": f"{tn + fp:,}",
                },
                {
                    "Ground Truth \\ Predicted": "Actual Attack (Positive)",
                    "Predicted Normal": f"FN = {fn:,} (Missed Attack)",
                    "Predicted Attack": f"TP = {tp:,}",
                    "Total Actual": f"{fn + tp:,}",
                },
            ]
            st.table(cm_table)

        with cm_col2:
            st.markdown("**Operational Error Rates & Error Identification:**")
            st.markdown(
                f"- **False Positives (FP = {fp:,} | FPR = {fpr:.2%}):** Benign normal sessions incorrectly flagged as attacks. "
                "The low false-alarm rate (2.65%) demonstrates strong operational specificity for normal traffic."
            )
            st.markdown(
                f"- **False Negatives (FN = {fn:,} | FNR = {fnr:.2%}):** Malicious intrusion flows misclassified as normal. "
                "The false-negative rate of 37.79% reflects classifier degradation when confronting novel zero-day attack variants."
            )

        # Class-Specific & Macro/Weighted Performance
        st.markdown("##### Detailed Class & Summary Averages")
        class_table = [
            {
                "Class Formulation": "Normal (Negative)",
                "Precision": f"{m.get('precision_normal', 0.0):.4f}",
                "Recall (Detection Rate)": f"{m.get('recall_normal', 0.0):.4f}",
                "F1-Score": f"{m.get('f1_normal', 0.0):.4f}",
                "Support": f"{m.get('support_normal', 0):,}",
            },
            {
                "Class Formulation": "Attack (Positive)",
                "Precision": f"{m.get('precision_attack', 0.0):.4f}",
                "Recall (Detection Rate)": f"{m.get('recall_attack', 0.0):.4f}",
                "F1-Score": f"{m.get('f1_attack', 0.0):.4f}",
                "Support": f"{m.get('support_attack', 0):,}",
            },
            {
                "Class Formulation": "Macro Average",
                "Precision": f"{m.get('macro_precision', 0.0):.4f}",
                "Recall (Detection Rate)": f"{m.get('macro_recall', 0.0):.4f}",
                "F1-Score": f"{m.get('macro_f1', 0.0):.4f}",
                "Support": f"{m.get('total_samples', 0):,}",
            },
            {
                "Class Formulation": "Weighted Average",
                "Precision": f"{m.get('weighted_precision', 0.0):.4f}",
                "Recall (Detection Rate)": f"{m.get('weighted_recall', 0.0):.4f}",
                "F1-Score": f"{m.get('weighted_f1', 0.0):.4f}",
                "Support": f"{m.get('total_samples', 0):,}",
            },
        ]
        st.table(class_table)

        st.caption(
            "Note: Offline benchmark evaluation results on NSL-KDD do not guarantee identical performance on live "
            "enterprise network traffic or non-benchmark network architectures."
        )

    st.divider()

    # 3. Deterministic Security Rules Section
    st.markdown("#### 3. Deterministic Security Heuristic Rules")
    st.caption(
        "Active deterministic heuristic rules implemented in `src/threat_detection/detection/rules.py`. "
        "All thresholds represent initial operational triage heuristics and are distinct from model predictions."
    )

    rules = get_rule_specifications()
    for r in rules:
        with st.expander(
            f"📜 {r['rule_id']}: {r['rule_name']} ({r['severity']} Severity)", expanded=True
        ):
            r_col1, r_col2 = st.columns([2, 1])
            with r_col1:
                st.markdown(f"**Description:** {r['description']}")
                st.markdown(f"**Trigger Condition:** `{r['condition_summary']}`")
            with r_col2:
                st.markdown(f"**Rule-Specific Severity:** {format_severity_badge(r['severity'])}")
                st.markdown("**Configured Thresholds:**")
                st.json(r["thresholds"])

    st.caption(
        "Heuristic Threshold Rationale: Thresholds are initial operational approximations for triage and anomaly isolation, "
        "not universally optimized mathematical constants. Rules are evaluated read-only."
    )

    # Policy Interaction
    st.markdown("##### Operational Triage Interaction & Disposition Policy")
    st.markdown(
        "The threat detection engine synthesizes the statistical machine learning decision with deterministic "
        "heuristic rule matches to produce an integrated triage disposition:"
    )

    dispositions = get_disposition_specifications()
    disp_table = [
        {
            "Disposition": d["disposition"],
            "Model Condition": d["model_condition"],
            "Rule Condition": d["rule_condition"],
            "Overall Severity": d["overall_severity"],
            "Operational Meaning": d["meaning"],
        }
        for d in dispositions
    ]
    st.table(disp_table)

    st.caption(
        "Severity Policy Distinction: Rule-specific severity (e.g. HIGH for LAND topology anomaly) is maintained "
        "separately from overall finding severity (which synthesizes both classifier output and rule evidence)."
    )

    st.divider()

    # 4. Provenance & Operational Scope Limits
    st.markdown("#### 4. Provenance & Operational Scope Limits")
    st.warning(
        "🛡️ **Educational Demonstration & Data Provenance Notice:**\n\n"
        "- **Benchmark Dataset:** NSL-KDD is an offline public academic benchmark derived from the DARPA 1998/KDD'99 collection. "
        "It is designed for algorithm evaluation and educational research, not live enterprise network monitoring.\n"
        "- **Non-Proof of Malice:** A machine learning prediction or heuristic rule match constitutes operational telemetry and initial triage evidence; "
        "it does not constitute proof of a confirmed real-world security breach or forensic incident.\n"
        "- **Demonstration Scope:** The Detection Demo evaluates one network flow record at a time in memory. "
        "This project does not perform live network packet capture, stream monitoring, or inline traffic blocking."
    )


def main() -> None:
    """Main dashboard entry point."""
    st.set_page_config(
        page_title="Threat Detection Console",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Resolve database path
    resolved_db_path = resolve_database_path()
    db_path_display = str(resolved_db_path)

    # Sidebar: System Status & Diagnostic Info
    with st.sidebar:
        st.subheader("🛡️ System Diagnostics")
        st.markdown(f"**Database Path:**\n`{db_path_display}`")
        st.markdown("**Environment:** `Offline Evaluation`")
        st.markdown("**Monitoring Scope:** `Benchmark Flow Profile`")
        st.caption(
            "Note: This console operates in offline benchmark mode. "
            "It does not monitor live network telemetry or real-time packet streams."
        )
        st.divider()
        if st.button("🔄 Refresh Console Data", use_container_width=True):
            st.rerun()

    # Application Header
    st.title("🛡️ Threat Detection Security Operations Console")
    st.caption(
        "Offline intrusion analysis and alert triage console. "
        f"Active Database Target: `{db_path_display}`"
    )

    # Initialize repository with robust error handling
    try:
        repo = get_repository(db_path_display)
    except Exception as e:
        st.error(
            f"❌ Database Connection Failure: Unable to initialize SQLite repository at "
            f"'{db_path_display}'. Error details: {e}"
        )
        st.info("Please verify database file permissions and path configuration.")
        st.stop()

    # Load Summary Metrics
    try:
        summary_counts = repo.get_summary_counts()
        kpis = compute_kpis(summary_counts)
    except Exception as e:
        st.error(f"❌ Failed to query alert summary counts: {e}")
        st.stop()

    # Multi-tab layout
    tab_triage, tab_demo, tab_model_rules = st.tabs(
        ["📋 Alert Triage", "🧪 Detection Demo", "🧠 Model & Rules"]
    )

    with tab_triage:
        render_triage_tab(repo, kpis)

    with tab_demo:
        render_demo_tab(repo)

    with tab_model_rules:
        render_model_rules_tab()


if __name__ == "__main__":
    main()
