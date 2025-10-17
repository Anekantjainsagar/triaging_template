# components/triaging_integrated.py
"""
Integrated AI-Powered Triaging Module - DYNAMIC DATA VERSION
Uses actual search results instead of hardcoded values
"""

import streamlit as st
import pandas as pd
import traceback

# API Client import
from api_client.search_alert_api_client import get_api_client

# Backend utilities
from routes.src.crew import TriagingCrew
from routes.src.utils import (
    export_rule_incidents_to_excel,
    generate_completed_template,
)

# Template processing imports
from routes.src.template_parser import TemplateParser
from routes.src.web_llm_enhancer import WebLLMEnhancer
from routes.src.template_generator import EnhancedTemplateGenerator
from routes.src.csv_template_generator import generate_blank_triaging_template_csv
from frontend.config.triaging_styles import main_header_style

# Individual step imports
from components.triaging.step2_enhance import show_page as step2_enhance
from components.triaging.step3_walkthrough import show_page as step3_walkthrough
from components.triaging.step4_complete import show_page as step4_complete


@st.cache_resource
def get_cached_api_client():
    """Initialize and cache the API client."""
    try:
        return get_api_client()
    except Exception as e:
        st.warning(f"⚠️ API client unavailable: {str(e)}")
        return None


@st.cache_resource
def get_crew():
    """Initialize and cache the CrewAI instance."""
    return TriagingCrew()


def extract_alert_from_dataframe_row(row: pd.Series, rule_name: str) -> dict:
    """
    Extract alert information from a DataFrame row with flexible column mapping

    Args:
        row: pandas Series (single row from DataFrame)
        rule_name: The rule name/number

    Returns:
        dict: Standardized alert object
    """

    # Helper function to safely get value
    def get_value(keys, default="N/A"):
        for key in keys:
            if key in row.index and pd.notna(row[key]):
                return str(row[key])
        return default

    # Extract incident number
    incident = get_value(["Incident", "INCIDENT", "Incident Number", "INC"], "Unknown")

    # Extract priority
    priority = get_value(["Priority", "PRIORITY", "Severity"], "Medium")

    # Extract data connector
    data_connector = get_value(
        ["Data Connector", "DATA_CONNECTOR", "Source", "Connector"], "Unknown"
    )

    # Extract comments
    comments = get_value(
        ["Resolver Comments", "RESOLVER_COMMENTS", "Comments", "Notes"],
        "No comments available",
    )

    # Extract alert name/description
    alert_name = get_value(
        ["Alert Name", "ALERT_NAME", "Description", "Title"], rule_name
    )

    # Extract timestamps
    created_date = get_value(
        ["Created Date", "CREATED_DATE", "Date", "Timestamp"],
        pd.Timestamp.now().strftime("%Y-%m-%d"),
    )

    reported_time = get_value(
        ["Reported Time", "REPORTED_TIME", "Time", "Created Time"],
        pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
    )

    # Extract status
    status = get_value(["Status", "STATUS", "State"], "Open")

    # Build standardized alert object
    return {
        "rule_number": rule_name,
        "rule": rule_name,
        "alert_name": alert_name,
        "incident": incident,
        "priority": priority,
        "data_connector": data_connector,
        "status": status,
        "type": "Security Alert",
        "description": f"Rule {rule_name}: {alert_name}",
        "resolver_comments": comments,
        "created_date": created_date,
        "reported_time": reported_time,
        # Store original row data for reference
        "_original_row": row.to_dict(),
    }


def create_consolidated_dataframe_from_row(alert: dict) -> pd.DataFrame:
    """
    Create consolidated DataFrame from alert object

    Args:
        alert: Alert dictionary

    Returns:
        pd.DataFrame: Single-row DataFrame with consolidated data
    """
    consolidated_row = {
        "Rule Number": alert["rule_number"],
        "Alert Name": alert["alert_name"],
        "Incident": alert["incident"],
        "Priority": alert["priority"],
        "Resolver Comments": alert["resolver_comments"],
        "Data Connector": alert["data_connector"],
        "Description": alert["description"],
        "Status": alert["status"],
        "Created Date": alert["created_date"],
        "Reported Time": alert["reported_time"],
    }

    return pd.DataFrame([consolidated_row])


def display_incident_selector(data_df: pd.DataFrame, rule_name: str) -> dict:
    """
    Display UI for selecting which incident to triage from available data

    Args:
        data_df: DataFrame with historical incidents
        rule_name: Rule name/number

    Returns:
        dict: Selected alert object
    """
    st.markdown("### 🎯 Select Incident to Triage")

    # Show summary
    total_incidents = len(data_df)
    st.info(f"📊 Found **{total_incidents}** incident(s) for rule: `{rule_name}`")

    if total_incidents == 0:
        st.error("❌ No incidents found for this rule")
        return None

    # Selection mode
    selection_mode = st.radio(
        "Selection Mode:",
        ["📋 Select from List", "🔢 Select by Incident Number", "🚀 Use Most Recent"],
        horizontal=True,
    )

    selected_alert = None

    if selection_mode == "📋 Select from List":
        # Create display strings for each incident
        incident_options = []
        incident_map = {}

        for idx, row in data_df.iterrows():
            alert = extract_alert_from_dataframe_row(row, rule_name)

            display_str = (
                f"🔹 Incident: {alert['incident']} | "
                f"Priority: {alert['priority']} | "
                f"Status: {alert['status']} | "
                f"Date: {alert['created_date']}"
            )

            incident_options.append(display_str)
            incident_map[display_str] = alert

        # Selectbox for incidents
        selected_display = st.selectbox(
            "Choose an incident:", options=incident_options, index=0
        )

        selected_alert = incident_map[selected_display]

    elif selection_mode == "🔢 Select by Incident Number":
        # Extract incident numbers
        incident_col_name = None
        for col in ["Incident", "INCIDENT", "Incident Number", "INC"]:
            if col in data_df.columns:
                incident_col_name = col
                break

        if incident_col_name:
            incident_numbers = data_df[incident_col_name].astype(str).tolist()

            selected_incident_num = st.selectbox(
                "Select Incident Number:", options=incident_numbers, index=0
            )

            # Find matching row
            matching_row = data_df[
                data_df[incident_col_name].astype(str) == selected_incident_num
            ].iloc[0]
            selected_alert = extract_alert_from_dataframe_row(matching_row, rule_name)
        else:
            st.error("❌ Cannot find incident number column in data")
            return None

    else:  # Use Most Recent
        # Try to sort by date
        date_cols = [
            "Created Date",
            "CREATED_DATE",
            "Date",
            "Timestamp",
            "Reported Time",
        ]

        sorted_df = data_df.copy()
        for col in date_cols:
            if col in sorted_df.columns:
                try:
                    sorted_df[col] = pd.to_datetime(sorted_df[col], errors="coerce")
                    sorted_df = sorted_df.sort_values(col, ascending=False)
                    break
                except:
                    continue

        most_recent_row = sorted_df.iloc[0]
        selected_alert = extract_alert_from_dataframe_row(most_recent_row, rule_name)

        st.success(
            f"✅ Auto-selected most recent incident: **{selected_alert['incident']}**"
        )

    # Display selected incident details
    if selected_alert:
        st.markdown("---")
        st.markdown("### 📋 Selected Incident Details")

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Incident", selected_alert["incident"])
        with col2:
            st.metric("Priority", selected_alert["priority"])
        with col3:
            st.metric("Status", selected_alert["status"])
        with col4:
            st.metric("Data Source", selected_alert["data_connector"])

        with st.expander("🔍 View Full Details", expanded=False):
            for key, value in selected_alert.items():
                if not key.startswith("_"):
                    st.text(f"{key}: {value}")

    return selected_alert


def initialize_triaging_state_from_data(
    rule_name: str, data_df: pd.DataFrame, selected_alert: dict = None
):
    """
    Initialize triaging state using actual search data

    Args:
        rule_name: The rule name/number
        data_df: DataFrame with historical data
        selected_alert: Pre-selected alert (optional)
    """

    # If no alert selected, use the first row as default
    if selected_alert is None:
        if data_df.empty:
            st.error("❌ No data available for triaging")
            return False

        selected_alert = extract_alert_from_dataframe_row(data_df.iloc[0], rule_name)

    # Create consolidated data
    consolidated_data = create_consolidated_dataframe_from_row(selected_alert)

    # Initialize session state
    defaults = {
        "triaging_step": 2,  # Start at step 2 (enhance)
        "triaging_alerts": [selected_alert],
        "triaging_all_data": data_df,
        "triaging_consolidated_data": consolidated_data,
        "triaging_selected_alert": selected_alert,
        "selected_alert": selected_alert,  # For step3 compatibility
        "selected_alert_details": selected_alert,
        "consolidated_data": consolidated_data,  # For step3
        "template_content": None,
        "triaging_plan": None,
        "triaging_output": {},
        "predictions": [],
        "triaging_predictions": [],
        "progressive_predictions": {},
        "rule_history": {},
        "current_step_index": 0,
        "analysis_complete": False,
        "excel_template_data": None,
        "original_steps": None,
        "enhanced_steps": None,
        "validation_report": None,
        "real_time_prediction": None,
        "api_client": None,
        "search_results": [selected_alert],
        "current_search_results": [selected_alert],
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value
            
    # 🐛 DEBUG: Verify all required states are set
    st.write("🔍 DEBUG - State Initialization:")
    st.write(f"✅ triaging_selected_alert set: {selected_alert is not None}")
    st.write(f"✅ consolidated_data rows: {len(consolidated_data)}")
    st.write(f"✅ selected_alert incident: {selected_alert.get('incident', 'MISSING')}")

    return True


def display_triaging_workflow(rule_name: str, data: pd.DataFrame):
    """
    Display triaging workflow for a specific rule (embedded in tab)
    OPTIMIZED: Only initializes once per rule selection
    """

    st.markdown("## 🔍 AI-Powered Security Incident Triaging")
    st.markdown("---")

    # ✅ CREATE UNIQUE KEY FOR THIS RULE + DATA COMBINATION
    import hashlib

    data_hash = hashlib.md5(str(data.head().to_dict()).encode()).hexdigest()
    init_key = f"triaging_init_{rule_name}_{data_hash}"

    # ✅ STEP 1: Check if already initialized for THIS specific rule+data
    if init_key not in st.session_state:
        # Auto-select first incident for dashboard workflow
        if data.empty:
            st.error("❌ No data available for triaging")
            return

        st.info("🎯 Initializing triaging state...")

        # Extract first incident
        selected_alert = extract_alert_from_dataframe_row(data.iloc[0], rule_name)

        # Initialize state with selected alert
        if not initialize_triaging_state_from_data(rule_name, data, selected_alert):
            st.error("❌ Failed to initialize triaging state")
            return

        # ✅ Mark as initialized for THIS specific rule+data combo
        st.session_state[init_key] = True
        st.session_state.triaging_initialized = True
        st.session_state.triaging_step = 2

        st.success("✅ Triaging initialized!")
        st.rerun()  # ✅ Force rerun to apply state
        return  # ✅ Stop execution after rerun

    # ✅ VERIFY ALERT EXISTS (even if init_key exists)
    if (
        "triaging_selected_alert" not in st.session_state
        or st.session_state.triaging_selected_alert is None
    ):
        st.error("❌ Alert was not properly initialized. Reinitializing...")

        # 🐛 DEBUG: Show what went wrong
        st.write("🔍 DEBUG - Reinitialization triggered:")
        st.write(f"- init_key: {init_key}")
        st.write(
            f"- triaging_selected_alert: {st.session_state.get('triaging_selected_alert', 'MISSING')}"
        )

        # Clear the bad init_key and force reinitialization
        if init_key in st.session_state:
            del st.session_state[init_key]

        st.rerun()
        return

    # Initialize clients (cached)
    crew = get_crew()
    api_client = get_cached_api_client()
    st.session_state.api_client = api_client

    alert = st.session_state.triaging_selected_alert

    # Display current alert info banner
    st.info(
        f"🎯 **Active Triaging** | Rule: `{alert.get('rule_number')}` | "
        f"Incident: `{alert.get('incident')}` | Priority: `{alert.get('priority')}`"
    )

    st.markdown("---")

    # Step Navigation
    step_names = [
        "🚀 Enhance Template",  # Step 2
        "👥 CrewAI Walkthrough",  # Step 3
        "✨ Complete Analysis",  # Step 4
    ]

    # Navigation buttons
    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button(
            step_names[0],
            key="nav_step2_tab",
            use_container_width=True,
            type="primary" if st.session_state.triaging_step == 2 else "secondary",
        ):
            st.session_state.triaging_step = 2
            st.rerun()

    with col2:
        if st.button(
            step_names[1],
            key="nav_step3_tab",
            use_container_width=True,
            type="primary" if st.session_state.triaging_step == 3 else "secondary",
        ):
            st.session_state.triaging_step = 3
            st.rerun()

    with col3:
        if st.button(
            step_names[2],
            key="nav_step4_tab",
            use_container_width=True,
            type="primary" if st.session_state.triaging_step == 4 else "secondary",
        ):
            st.session_state.triaging_step = 4
            st.rerun()

    # Progress indicator
    display_step = st.session_state.triaging_step - 2
    if 0 <= display_step < len(step_names):
        st.progress(
            (display_step + 1) / len(step_names),
            text=f"Progress: {step_names[display_step]}",
        )

    st.markdown("---")

    # Display current step content
    try:
        if st.session_state.triaging_step == 2:  # Template Enhancement
            step2_enhance(
                st.session_state,
                TemplateParser,
                WebLLMEnhancer,
                EnhancedTemplateGenerator,
            )

        elif st.session_state.triaging_step == 3:  # CrewAI Walkthrough
            step3_walkthrough(st.session_state, crew, traceback)

        elif st.session_state.triaging_step == 4:  # Complete Analysis
            step4_complete(
                st.session_state,
                crew,
                generate_completed_template,
                generate_blank_triaging_template_csv,
                EnhancedTemplateGenerator,
                traceback,
            )

        else:
            st.warning(
                "⚠️ Invalid step detected. Redirecting to Template Enhancement..."
            )
            st.session_state.triaging_step = 2
            st.rerun()

    except AttributeError as e:
        st.error(f"❌ Configuration Error: {str(e)}")
        st.warning("Reinitializing session state...")

        # Force reinitialization
        for key in list(st.session_state.keys()):
            if key.startswith("triaging_") or key in [
                "selected_alert",
                "consolidated_data",
                "predictions",
            ]:
                if key in st.session_state:
                    del st.session_state[key]

        # Reinitialize with current data
        initialize_triaging_state_from_data(rule_name, data)
        st.session_state.triaging_initialized = True
        st.rerun()

    # Action buttons at bottom
    st.markdown("---")

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("🔄 Change Incident", key="change_incident_tab"):
            # Clear initialization flags to show selector again
            if init_key in st.session_state:
                del st.session_state[init_key]
            st.session_state.triaging_initialized = False
            st.session_state.triaging_selected_alert = None
            st.session_state.triaging_step = 2
            st.rerun()

    with col2:
        if st.button("🔄 Reset Workflow", key="reset_triaging_tab"):
            # Clear triaging-specific state including initialization flag
            triaging_keys = [
                k
                for k in st.session_state.keys()
                if k.startswith("triaging_")
                or k.startswith("triaging_init_")  # ✅ Clear init keys too
                or k
                in [
                    "template_content",
                    "progressive_predictions",
                    "rule_history",
                    "current_step_index",
                    "analysis_complete",
                    "excel_template_data",
                    "original_steps",
                    "enhanced_steps",
                    "validation_report",
                    "real_time_prediction",
                    "selected_alert",
                    "consolidated_data",
                    "predictions",
                ]
            ]
            for key in triaging_keys:
                if key in st.session_state:
                    del st.session_state[key]

            st.success("✅ Workflow reset complete!")
            st.rerun()

    with col3:
        # Show raw data inspector
        with st.expander("🔍 View Raw Data", expanded=False):
            st.markdown("**Selected Alert Object:**")
            st.json(alert)

            st.markdown("**Available Historical Data:**")
            st.dataframe(data, height=200)


def display_triaging_page():
    """
    Main triaging page display - STANDALONE VERSION
    (Used when triaging is accessed as a separate page, not embedded in dashboard)
    """

    # Apply custom CSS
    st.markdown(main_header_style, unsafe_allow_html=True)

    # App Title
    st.markdown(
        '<h1 class="main-header">🔍 AI-Powered Security Incident Triaging</h1>',
        unsafe_allow_html=True,
    )

    st.warning(
        "⚠️ **Note:** This is a standalone triaging page. "
        "For best experience, use the triaging feature from the main dashboard "
        "by selecting a rule and navigating to the 'AI Triaging' tab."
    )

    st.markdown("---")

    # Manual rule/incident entry for standalone mode
    st.markdown("### 🎯 Manual Incident Entry")

    col1, col2 = st.columns(2)

    with col1:
        manual_rule = st.text_input(
            "Rule Number/Name:",
            placeholder="e.g., #280 or Rule 280",
            key="manual_rule_input",
        )

    with col2:
        manual_incident = st.text_input(
            "Incident Number:",
            placeholder="e.g., INC123456",
            key="manual_incident_input",
        )

    if st.button("🚀 Start Manual Triaging", type="primary", use_container_width=True):
        if not manual_rule or not manual_incident:
            st.error("❌ Please provide both rule and incident number")
        else:
            # Create a mock alert object
            mock_alert = {
                "rule_number": manual_rule,
                "rule": manual_rule,
                "alert_name": f"Manual Entry: {manual_rule}",
                "incident": manual_incident,
                "priority": "High",
                "data_connector": "Manual",
                "status": "Open",
                "type": "Security Alert",
                "description": f"Manually entered rule {manual_rule}",
                "resolver_comments": "Manual triaging entry",
                "created_date": pd.Timestamp.now().strftime("%Y-%m-%d"),
                "reported_time": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
            }

            # Create mock DataFrame
            mock_df = pd.DataFrame([mock_alert])

            # Initialize triaging
            if initialize_triaging_state_from_data(manual_rule, mock_df, mock_alert):
                st.success("✅ Manual triaging initialized!")
                st.rerun()
            else:
                st.error("❌ Failed to initialize triaging")

    st.markdown("---")
    st.caption(
        "💡 Tip: Use the main SOC Dashboard to search for rules and access triaging with full historical context"
    )
