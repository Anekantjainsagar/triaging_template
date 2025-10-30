import math
import json
import streamlit as st
import pandas as pd
from soc_utils import *
from datetime import datetime
import hashlib
import tempfile
import shutil
import os
import time

# Import SOC analysis components
from api_client.analyzer_api_client import get_analyzer_client
from components.triaging_integrated import display_triaging_workflow
from components.historical_analysis import display_historical_analysis_tab

# Page configuration
st.set_page_config(
    page_title="Microsoft Sentinel - SOC Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for better styling
st.markdown(
    """
    <style>
    .incident-card {
        border: 1px solid #ddd;
        border-radius: 8px;
        padding: 15px;
        margin-bottom: 15px;
        background-color: #f9f9f9;
        cursor: pointer;
        transition: all 0.3s ease;
    }
    .incident-card:hover {
        box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        transform: translateY(-2px);
    }
    .severity-high {
        color: #d32f2f;
        font-weight: bold;
    }
    .severity-medium {
        color: #f57c00;
        font-weight: bold;
    }
    .severity-low {
        color: #fbc02d;
        font-weight: bold;
    }
    .severity-informational {
        color: #1976d2;
        font-weight: bold;
    }
    .status-badge {
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 12px;
        font-weight: bold;
    }
    .status-new {
        background-color: #e3f2fd;
        color: #1976d2;
    }
    .status-active {
        background-color: #fff3e0;
        color: #f57c00;
    }
    .status-closed {
        background-color: #e8f5e9;
        color: #388e3c;
    }
    .alert-card {
        background-color: #fff3e0;
        border-left: 4px solid #f57c00;
        padding: 12px;
        margin: 8px 0;
        border-radius: 4px;
    }
    .entity-badge {
        display: inline-block;
        padding: 4px 8px;
        margin: 2px;
        border-radius: 4px;
        background-color: #e3f2fd;
        color: #1565c0;
        font-size: 12px;
    }
    .pagination-info {
        text-align: center;
        padding: 20px;
        font-size: 16px;
        color: #666;
    }
    .threat-intel-box {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 20px;
        border-radius: 10px;
        margin: 15px 0;
        box-shadow: 0 4px 15px rgba(0,0,0,0.1);
    }
    .analysis-section {
        background-color: #f8f9fa;
        border-left: 4px solid #007bff;
        padding: 15px;
        margin: 10px 0;
        border-radius: 5px;
    }
    analysis-container {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 25px;
        border-radius: 12px;
        margin: 20px 0;
        box-shadow: 0 8px 25px rgba(0,0,0,0.15);
    }
    
    .analysis-section {
        background-color: rgba(255, 255, 255, 0.95);
        color: #333;
        border-left: 5px solid #667eea;
        padding: 20px;
        margin: 15px 0;
        border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.08);
    }
    
    .analysis-section h2 {
        color: #667eea;
        font-size: 1.4em;
        margin-bottom: 15px;
        border-bottom: 2px solid #667eea;
        padding-bottom: 10px;
    }
    
    .analysis-section h3 {
        color: #764ba2;
        font-size: 1.2em;
        margin-top: 15px;
        margin-bottom: 10px;
    }
    
    .mitre-technique {
        background-color: #fff3e0;
        border-left: 4px solid #f57c00;
        padding: 12px;
        margin: 10px 0;
        border-radius: 6px;
    }
    
    .threat-actor {
        background-color: #ffebee;
        border-left: 4px solid #d32f2f;
        padding: 12px;
        margin: 10px 0;
        border-radius: 6px;
    }
    
    .action-item {
        background-color: #e8f5e9;
        border-left: 4px solid #388e3c;
        padding: 10px;
        margin: 8px 0;
        border-radius: 6px;
    }
    
    .risk-badge-critical {
        background-color: #d32f2f;
        color: white;
        padding: 6px 16px;
        border-radius: 20px;
        font-weight: bold;
        display: inline-block;
        margin: 5px 0;
    }
    
    .risk-badge-high {
        background-color: #f57c00;
        color: white;
        padding: 6px 16px;
        border-radius: 20px;
        font-weight: bold;
        display: inline-block;
        margin: 5px 0;
    }
    
    .risk-badge-medium {
        background-color: #fbc02d;
        color: #333;
        padding: 6px 16px;
        border-radius: 20px;
        font-weight: bold;
        display: inline-block;
        margin: 5px 0;
    }
    </style>
""",
    unsafe_allow_html=True,
)

# ============================================================================
# Session State Initialization
# ============================================================================


def initialize_session_state():
    """Initialize all session state variables and auto-load incidents"""
    defaults = {
        "current_page": "overview",
        "incidents": [],
        "selected_incident": None,
        "current_page_num": 1,
        "soc_analysis_data": None,
        "selected_rule_data": None,
        # Triaging-specific states
        "triaging_step": 2,
        "triaging_alerts": [],
        "triaging_selected_alert": None,
        "triaging_template_content": None,
        "triaging_plan": None,
        "triaging_output": {},
        "triaging_predictions": [],
        "progressive_predictions": {},
        "triaging_initialized": False,
        "rule_history": {},
        "current_step_index": 0,
        "analysis_complete": False,
        "excel_template_data": None,
        "original_steps": None,
        "enhanced_steps": None,
        "validation_report": None,
        "real_time_prediction": None,
        "triaging_complete": False,
        "predictions_excel_data": None,
        "predictions_excel_filename": None,
        "predictions_uploaded": False,
        "auto_loaded": False,  # New flag to track auto-load
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

    # Auto-load incidents from file on first run
    if not st.session_state.auto_loaded and not st.session_state.incidents:
        try:
            incidents = load_incidents_from_file()
            if incidents:
                st.session_state.incidents = incidents
                st.session_state.auto_loaded = True
                # Don't show success message here, will show in sidebar
        except Exception as e:
            # Silently fail, user can manually load
            pass


initialize_session_state()

# ============================================================================
# API Status Check
# ============================================================================


@st.cache_data(ttl=60)
def check_api_status():
    """Check if backend API is running"""
    try:
        api_client = get_analyzer_client()
        health = api_client.health_check()

        if health.get("status") == "healthy":
            return True, health
        else:
            return False, health
    except Exception as e:
        return False, {"status": "error", "error": str(e)}


# ============================================================================
# AI Analysis Functions (Real API Integration)
# ============================================================================


# ============================================================================
# UPDATED: main.py display_ai_analysis function
# ============================================================================


def display_ai_analysis(alert_data):
    """Display AI analysis with proper state passing to triaging"""

    # VALIDATE alert_data STRUCTURE
    if not alert_data:
        st.error("❌ No alert data provided")
        return

    # EXTRACT AND VALIDATE alert name
    alert_name = (
        alert_data.get("title")
        or alert_data.get("alert_name")
        or alert_data.get("rule_name")
        or alert_data.get("name")
    )

    if not alert_name or alert_name == "undefined":
        st.error("❌ Alert name is undefined or missing")
        return

    st.markdown("---")
    st.title("🤖 SOC Hub - AI-Powered Analysis")

    # Display alert info
    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown(f"### {alert_name}")
        description = alert_data.get("description", "No description available")
        st.markdown(f"**Description:** {description}")
    with col2:
        severity = alert_data.get("severity", "Unknown")
        status = alert_data.get("status", "Unknown")
        st.markdown(f"**Severity:** `{severity}`")
        st.markdown(f"**Status:** `{status}`")

    st.markdown("---")

    api_client = get_analyzer_client()
    is_healthy, health_data = check_api_status()

    if not is_healthy:
        st.error("❌ SOC Analysis API Not Available")
        return

    # Create tabs
    sanitized_name = (
        alert_name.replace(" ", "_").replace("/", "_").replace("\\", "_").lower()
    )
    analysis_key = (
        f"analysis_{sanitized_name}_{hashlib.md5(alert_name.encode()).hexdigest()}"
    )

    # Initialize if needed
    if analysis_key not in st.session_state:
        st.session_state[f"{analysis_key}_in_progress"] = False

    # Create tab structure
    source = alert_data.get("source", "unknown")
    is_manual = source == "alert_details"
    has_historical_data = alert_data.get("historical_data") is not None

    if is_manual or not has_historical_data:
        tab1, tab2 = st.tabs(["🤖 AI Threat Analysis", "🔍 AI Triaging"])

        with tab1:
            display_ai_threat_analysis_tab(
                alert_name, api_client, analysis_key, alert_data
            )

        with tab2:
            # âœ… FIXED: Pass full alert_data to triaging
            rule_number = alert_data.get("rule_number", f"ALERT_{id(alert_data)}")

            # âœ… IMPORTANT: Store the full alert data for triaging
            enhanced_alert_data = alert_data.copy()
            enhanced_alert_data["rule_number"] = rule_number
            enhanced_alert_data["alert_name"] = alert_name

            # âœ… If we have cached analysis, pass it along
            if analysis_key in st.session_state:
                result = st.session_state[analysis_key]
                if result.get("success"):
                    enhanced_alert_data["analysis_text"] = result.get("analysis", "")

            # Call triaging with full data
            display_triaging_workflow(rule_number, alert_data=enhanced_alert_data)

            st.info(
                """
                **Want Historical Analysis?** If you have historical incident data for this alert, 
                go back and search using the exact rule name from your SOC tracker.
                """
            )
    else:
        # Has historical data - 4 tabs
        tab1, tab2, tab3, tab4 = st.tabs(
            [
                "🤖 AI Threat Analysis",
                "📊 Historical Analysis",
                "🔍 AI Triaging",
                "📮 Predictions & MITRE",
            ]
        )

        with tab1:
            display_ai_threat_analysis_tab(
                alert_name, api_client, analysis_key, alert_data
            )

        with tab2:
            historical_data = alert_data.get("historical_data")
            if historical_data is not None and not historical_data.empty:
                display_historical_analysis_tab(historical_data)
            else:
                st.info("✅ No historical data available for this alert")

        with tab3:
            # âœ… FIXED: Pass full alert_data
            rule_number = alert_data.get("rule_number", f"ALERT_{id(alert_data)}")
            enhanced_alert_data = alert_data.copy()
            enhanced_alert_data["rule_number"] = rule_number
            enhanced_alert_data["alert_name"] = alert_name

            if analysis_key in st.session_state:
                result = st.session_state[analysis_key]
                if result.get("success"):
                    enhanced_alert_data["analysis_text"] = result.get("analysis", "")

            display_triaging_workflow(rule_number, alert_data=enhanced_alert_data)

        with tab4:
            st.markdown("### 📮 True/False Positive Analyzer")
            st.info(
                "Complete the AI Triaging workflow first to unlock predictions analysis"
            )


def display_ai_threat_analysis_tab(alert_name, api_client, analysis_key, alert_data):
    """Display AI threat analysis for an alert"""

    if analysis_key in st.session_state and st.session_state[analysis_key]:
        result = st.session_state[analysis_key]
        if result.get("success"):
            analysis = result.get("analysis", "")

            st.markdown('<div class="threat-intel-box">', unsafe_allow_html=True)
            st.markdown("### 🔋 Comprehensive Threat Intelligence Report")
            st.markdown("</div>", unsafe_allow_html=True)

            # Display sections...
            sections = analysis.split("## ")
            for section in sections:
                if not section.strip():
                    continue
                st.markdown(f"## {section}")

            # Download button
            st.markdown("---")
            col1, col2, col3 = st.columns([1, 1, 1])
            with col2:
                st.download_button(
                    label="📥 Download Analysis Report",
                    data=analysis,
                    file_name=f"threat_analysis_{alert_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                    mime="text/markdown",
                    use_container_width=True,
                    type="primary",
                )
    else:
        # Run analysis
        progress_placeholder = st.empty()

        with progress_placeholder.container():
            progress_bar = st.progress(0)
            status_text = st.empty()

            status_text.text("🚀 Initializing AI analysis engine...")
            progress_bar.progress(20)
            time.sleep(0.3)

            status_text.text("🔍 Analyzing threat patterns...")
            progress_bar.progress(50)
            time.sleep(0.3)

            status_text.text("🌐 Researching threat intelligence...")
            progress_bar.progress(75)

            # Call API
            result = api_client.analyze_alert(alert_name)

            progress_bar.progress(95)
            status_text.text("📊 Finalizing analysis...")
            time.sleep(0.2)
            progress_bar.progress(100)

            time.sleep(0.5)
            progress_placeholder.empty()

        # Cache and display
        st.session_state[analysis_key] = result

        if result.get("success"):
            st.rerun()
        else:
            st.error(f"❌ Analysis failed: {result.get('error')}")


# ============================================================================
# NEW: Placeholder for Predictions Tab
# ============================================================================


def display_predictions_tab():
    """Display predictions analysis tab placeholder"""
    st.markdown("### 📮 True/False Positive Analyzer with MITRE ATT&CK")

    if not st.session_state.get("triaging_complete", False):
        st.warning(
            "⚠️ Complete the AI Triaging workflow first to unlock predictions analysis"
        )
        return

    st.info("📊 Predictions analysis tab content would be displayed here")
    st.markdown(
        """
        This tab will show:
        - 🎯 True/False positive predictions
        - 🗺️ MITRE ATT&CK framework mapping
        - 📈 Analysis metrics and scores
        - 💾 Export capabilities
        """
    )


# ============================================================================
# Alert Display Functions
# ============================================================================


def display_alert(alert, entities_data):
    """Display alert details with entities in accordion format"""
    props = alert.get("properties", {})

    alert_name = props.get("alertDisplayName", "Unknown Alert")
    severity = props.get("severity", "Unknown")
    status = props.get("status", "Unknown")
    description = props.get("description", "")

    accordion_title = f"{alert_name} — {severity} • {status}"

    with st.expander(accordion_title, expanded=False):
        st.markdown(f'<div class="alert-card">', unsafe_allow_html=True)

        # Severity and Status badges
        col1, col2, col3 = st.columns([1, 1, 1])
        with col1:
            st.markdown(
                f'<span class="{get_severity_color(severity)}">Severity: {severity}</span>',
                unsafe_allow_html=True,
            )
        with col2:
            st.markdown(f"*Status: {status}*")
        with col3:
            if st.button(
                "🚀 Analyze in SOC Hub",
                key=f"soc_analysis_{alert_name}_{id(alert)}",
                help="Open this alert in SOC Hub for AI-powered analysis",
                type="primary",
            ):
                alert_data = {
                    "title": alert_name,
                    "description": description or alert_name,
                    "severity": severity,
                    "status": status,
                    "full_alert": alert,
                    "entities": entities_data,
                    "source": "alert_details",
                }
                st.session_state.soc_analysis_data = alert_data
                st.session_state.current_page = "soc_analysis"
                st.rerun()

        st.divider()

        if description:
            st.markdown(f"**Description:** _{description}_")

        # Time information
        start_time = props.get("startTimeUtc")
        end_time = props.get("endTimeUtc")

        col1, col2 = st.columns(2)
        with col1:
            if start_time:
                st.markdown(f"**Started:** {format_datetime(start_time)}")
        with col2:
            if end_time:
                st.markdown(f"**Ended:** {format_datetime(end_time)}")

        st.divider()

        # Tactics and Techniques
        tactics = props.get("tactics", [])
        techniques = props.get("techniques", [])

        if tactics or techniques:
            st.markdown("**MITRE ATT&CK:**")
            if tactics:
                st.markdown(f"Tactics: {', '.join(tactics)}")
            if techniques:
                st.markdown(f"Techniques: {', '.join(techniques)}")

        # Entities
        if entities_data and "entities" in entities_data:
            alert_entities = entities_data["entities"]
            if alert_entities:
                st.markdown("**Associated Entities:**")

                entities_by_type = {}
                for entity in alert_entities:
                    kind = entity.get("kind", "Unknown")
                    if kind not in entities_by_type:
                        entities_by_type[kind] = []
                    entities_by_type[kind].append(entity)

                for entity_type, entities in entities_by_type.items():
                    with st.expander(
                        f"📌 {entity_type} ({len(entities)})", expanded=False
                    ):
                        for entity in entities:
                            st.markdown(f"- {display_entity(entity)}")

        st.markdown("</div>", unsafe_allow_html=True)


def display_incident_overview(incident, index):
    """Display incident as a clickable card in overview"""
    props = incident.get("properties", {})

    title = props.get("title", "Untitled Incident")
    severity = props.get("severity", "Unknown")
    status = props.get("status", "Unknown")
    incident_number = props.get("incidentNumber", "N/A")
    created = props.get("createdTimeUtc")

    additional_data = props.get("additionalData", {})
    alert_count = additional_data.get("alertsCount", 0)

    with st.container():
        if index == 0 or (index % 50 == 0):
            col1, col2, col3, col4, col5, col6 = st.columns([1, 4, 1.5, 1.5, 1.5, 1.5])
            with col1:
                st.caption("incident #")
            with col2:
                st.caption("title")
            with col3:
                st.caption("severity")
            with col4:
                st.caption("status")
            with col5:
                st.caption("alerts")
            with col6:
                st.caption("action")

        col1, col2, col3, col4, col5, col6 = st.columns([1, 4, 1.5, 1.5, 1.5, 1.5])

        with col1:
            st.markdown(f"**#{incident_number}**")

        with col2:
            st.markdown(f"**{title}**")

        with col3:
            st.markdown(
                f'<span class="{get_severity_color(severity)}">{severity}</span>',
                unsafe_allow_html=True,
            )

        with col4:
            st.markdown(
                f'<span class="status-badge {get_status_class(status)}">{status}</span>',
                unsafe_allow_html=True,
            )

        with col5:
            st.markdown(f"**{alert_count}**")

        with col6:
            if st.button("View Details", key=f"view_{index}"):
                st.session_state.selected_incident = incident
                st.session_state.current_page = "detail"
                st.rerun()

        if created:
            st.caption(f"Created: {format_datetime(created)}")

        st.divider()


def display_incident_detail(incident):
    """Display full incident details on detail page"""
    props = incident.get("properties", {})

    title = props.get("title", "Untitled Incident")
    severity = props.get("severity", "Unknown")
    status = props.get("status", "Unknown")
    incident_number = props.get("incidentNumber", "N/A")
    incident_id = incident.get("name")
    description = props.get("description", "")

    # Back button
    if st.button("← Back to Incidents List"):
        st.session_state.current_page = "overview"
        st.rerun()

    st.title(f"🔍 Incident #{incident_number}")
    st.markdown(f"## {title}")

    st.divider()

    # Main incident info
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(f"**Severity:**")
        st.markdown(
            f'<span class="{get_severity_color(severity)}">{severity}</span>',
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(f"**Status:**")
        st.markdown(
            f'<span class="status-badge {get_status_class(status)}">{status}</span>',
            unsafe_allow_html=True,
        )

    with col3:
        st.markdown(f"**Classification:**")
        st.write(props.get("classification", "N/A"))

    with col4:
        st.markdown(f"**Provider:**")
        st.write(props.get("providerName", "N/A"))

    st.divider()

    # Quick Analysis Section
    st.markdown("### 🤖 Quick Analysis")

    col1, col2 = st.columns([3, 1])

    with col1:
        st.info(
            f"Automatically analyze this incident using AI threat intelligence and historical data."
        )

    with col2:
        if st.button(
            "🚀 Analyze Incident in SOC Hub",
            key=f"analyze_incident_{incident_id}",
            type="primary",
            help="Opens SOC Hub with this incident pre-loaded for AI analysis",
        ):
            incident_data = {
                "title": title,
                "description": description or title,
                "incident_number": incident_number,
                "severity": severity,
                "status": status,
                "incident_id": incident_id,
                "full_incident": incident,
                "source": "incident_details",
            }
            st.session_state.soc_analysis_data = incident_data
            st.session_state.current_page = "soc_analysis"
            st.rerun()

    st.divider()

    # Timeline
    st.markdown("### 📅 Timeline")
    col1, col2 = st.columns(2)

    with col1:
        created = props.get("createdTimeUtc")
        first_activity = props.get("firstActivityTimeUtc")
        if created:
            st.write(f"**Created:** {format_datetime(created)}")
        if first_activity:
            st.write(f"**First Activity:** {format_datetime(first_activity)}")

    with col2:
        last_activity = props.get("lastActivityTimeUtc")
        last_modified = props.get("lastModifiedTimeUtc")
        if last_activity:
            st.write(f"**Last Activity:** {format_datetime(last_activity)}")
        if last_modified:
            st.write(f"**Last Modified:** {format_datetime(last_modified)}")

    st.divider()

    # Fetch and display alerts
    additional_data = props.get("additionalData", {})
    alert_count = additional_data.get("alertsCount", 0)

    st.markdown(f"### 🚨 Alerts ({alert_count})")

    if alert_count > 0:
        cache_key = f"incident_details_{incident_id}"

        if cache_key not in st.session_state:
            with st.spinner("Loading alerts and entities..."):
                details = fetch_incident_details(incident_id)
                if details:
                    st.session_state[cache_key] = details

        if cache_key in st.session_state:
            details = st.session_state[cache_key]

            alerts = details.get("alerts", {}).get("value", [])
            entities_data = details.get("entities", {})

            if alerts:
                for idx, alert in enumerate(alerts):
                    display_alert(alert, entities_data)
                    if idx < len(alerts) - 1:
                        st.markdown("---")
            else:
                st.info(
                    f"This incident has {alert_count} alert(s), but details couldn't be loaded."
                )
        else:
            st.warning("Failed to load incident details. Please try again.")
    else:
        st.write("No alerts associated with this incident.")

    # Tactics and Techniques
    if additional_data.get("tactics") or additional_data.get("techniques"):
        st.markdown("### 🎯 MITRE ATT&CK")
        if additional_data.get("tactics"):
            st.write(f"**Tactics:** {', '.join(additional_data['tactics'])}")
        if additional_data.get("techniques"):
            st.write(f"**Techniques:** {', '.join(additional_data['techniques'])}")

    # Owner information
    owner = props.get("owner", {})
    if owner.get("assignedTo"):
        st.markdown("### 👤 Owner")
        st.write(f"**Assigned To:** {owner.get('assignedTo')}")
        if owner.get("email"):
            st.write(f"**Email:** {owner.get('email')}")


# ============================================================================
# Main Application
# ============================================================================


def main():
    """Main Streamlit application"""

    # Navigation sidebar
    with st.sidebar:
        st.title("🛡️ Navigation")
        st.markdown("---")

        # Page selection
        st.markdown("### 📋 Pages")
        if st.button("📊 Incidents Dashboard", use_container_width=True):
            st.session_state.current_page = "overview"
            st.rerun()

        if st.button("🤖 SOC Analysis Hub", use_container_width=True):
            if not st.session_state.soc_analysis_data:
                st.warning("⚠️ Please select an incident or alert first")
            else:
                st.session_state.current_page = "soc_analysis"
                st.rerun()

        st.markdown("---")

        # API Status Check
        st.markdown("### 📡 Backend Status")
        is_healthy, health_data = check_api_status()

        if is_healthy:
            st.success("✅ API Connected")
            with st.expander("API Info", expanded=False):
                st.write(f"**Status:** {health_data.get('status')}")
                st.write(
                    f"**SOC Analyzer:** {'✅' if health_data.get('soc_analyzer_loaded') else '❌'}"
                )
                st.write(
                    f"**Alert Analyzer:** {'✅' if health_data.get('alert_analyzer_loaded') else '❌'}"
                )
        else:
            st.error("❌ API Not Connected")
            st.caption("AI features require backend API")

        st.markdown("---")
        st.markdown("### 🔧 Actions")

        if st.button("🗑️ Clear Cache", use_container_width=True):
            keys_to_remove = [
                key
                for key in st.session_state.keys()
                if key.startswith("incident_details_")
                or key.startswith("analysis_")
                or key.startswith("triaging_")
            ]
            for key in keys_to_remove:
                del st.session_state[key]
            st.success("Cache cleared!")
            st.rerun()

    # Route to appropriate page
    if (
        st.session_state.current_page == "soc_analysis"
        and st.session_state.soc_analysis_data
    ):
        display_ai_analysis(st.session_state.soc_analysis_data)
    elif (
        st.session_state.current_page == "detail" and st.session_state.selected_incident
    ):
        display_incident_detail(st.session_state.selected_incident)
    else:
        display_overview_page()


def display_overview_page():
    """Display the incidents overview page with pagination"""
    st.title("🛡️ Microsoft Sentinel - SOC Intelligence Dashboard")
    st.markdown("---")

    # Sidebar for filters and options
    with st.sidebar:
        st.header("⚙️ Data Source")

        data_source = st.radio(
            "Select Source",
            ["Load from File", "Fetch from Azure"],
            help="Choose to load incidents from a local file or fetch directly from Azure",
        )

        if data_source == "Fetch from Azure":
            st.markdown("### ⏱️ Time Range")

            timespan_option = st.selectbox(
                "Select Timespan",
                [
                    "Last 7 days",
                    "Last 30 days",
                    "Last 90 days",
                    "Last 180 days",
                    "Last 365 days",
                    "Custom",
                ],
                index=2,
            )

            timespan_map = {
                "Last 7 days": 7,
                "Last 30 days": 30,
                "Last 90 days": 90,
                "Last 180 days": 180,
                "Last 365 days": 365,
            }

            if timespan_option == "Custom":
                custom_days = st.number_input(
                    "Enter number of days", min_value=1, max_value=365, value=90
                )
                timespan_days = custom_days
            else:
                timespan_days = timespan_map[timespan_option]

            st.markdown("### 📊 Status Filter (Azure Fetch)")
            azure_status_filter = st.multiselect(
                "Filter by Status",
                options=["New", "Active", "Closed"],
                default=[],
                help="Leave empty to fetch all statuses",
            )

            if st.button("🔄 Fetch Incidents", type="primary"):
                incidents = fetch_incidents_from_azure(
                    timespan_days=timespan_days,
                    status_filters=azure_status_filter if azure_status_filter else None,
                )
                st.session_state.incidents = incidents
                st.session_state.current_page_num = 1

                if incidents:
                    with open(
                        "sentinel_all_incidents.json", "w", encoding="utf-8"
                    ) as f:
                        json.dump({"value": incidents}, f, indent=4, ensure_ascii=False)
                    st.success("💾 Incidents saved to sentinel_all_incidents.json")
        else:
            if st.button("📂 Load from File", type="primary"):
                incidents = load_incidents_from_file()
                st.session_state.incidents = incidents
                st.session_state.current_page_num = 1
                if incidents:
                    st.success(f"✅ Loaded {len(incidents)} incidents from file")

        st.markdown("---")
        st.header("🔍 Filters")

    incidents = st.session_state.incidents

    if not incidents:
        st.warning(
            "No incidents loaded. Please load incidents from file or fetch from Azure."
        )
        return

    # Filters in sidebar
    with st.sidebar:
        st.markdown("### ⏱️ Time Range Filter")
        time_filter = st.selectbox(
            "Filter by Creation Time",
            [
                "All Time",
                "Last 7 days",
                "Last 30 days",
                "Last 90 days",
                "Last 180 days",
                "Last 365 days",
            ],
            index=0,
        )

        time_filter_map = {
            "All Time": 0,
            "Last 7 days": 7,
            "Last 30 days": 30,
            "Last 90 days": 90,
            "Last 180 days": 180,
            "Last 365 days": 365,
        }

        time_filter_days = time_filter_map[time_filter]

        severity_filter = st.multiselect(
            "Severity",
            options=["High", "Medium", "Low", "Informational"],
            default=["High", "Medium", "Low", "Informational"],
        )

        status_filter = st.multiselect(
            "Status",
            options=["New", "Active", "Closed"],
            default=["New", "Active", "Closed"],
        )

        search_term = st.text_input("🔎 Search in title", "")
        incident_number_search = st.text_input(
            "🔢 Search by Incident Number", "", placeholder="e.g., 26"
        )

    # Apply filters
    filtered_incidents = incidents

    if time_filter_days > 0:
        filtered_incidents = apply_time_filter(filtered_incidents, time_filter_days)

    if severity_filter:
        filtered_incidents = [
            inc
            for inc in filtered_incidents
            if inc.get("properties", {}).get("severity") in severity_filter
        ]

    if status_filter:
        filtered_incidents = [
            inc
            for inc in filtered_incidents
            if inc.get("properties", {}).get("status") in status_filter
        ]

    if search_term:
        filtered_incidents = [
            inc
            for inc in filtered_incidents
            if search_term.lower() in inc.get("properties", {}).get("title", "").lower()
        ]

    if incident_number_search:
        try:
            search_number = int(incident_number_search)
            filtered_incidents = [
                inc
                for inc in filtered_incidents
                if inc.get("properties", {}).get("incidentNumber") == search_number
            ]
        except ValueError:
            st.sidebar.warning("Please enter a valid incident number")

    # Display statistics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Incidents", len(filtered_incidents))

    with col2:
        high_severity = len(
            [
                i
                for i in filtered_incidents
                if i.get("properties", {}).get("severity") == "High"
            ]
        )
        st.metric("High Severity", high_severity)

    with col3:
        active_incidents = len(
            [
                i
                for i in filtered_incidents
                if i.get("properties", {}).get("status") in ["New", "Active"]
            ]
        )
        st.metric("Active", active_incidents)

    with col4:
        closed_incidents = len(
            [
                i
                for i in filtered_incidents
                if i.get("properties", {}).get("status") == "Closed"
            ]
        )
        st.metric("Closed", closed_incidents)

    st.markdown("---")

    # Sort options
    col1, col2 = st.columns([3, 1])
    with col2:
        sort_by = st.selectbox(
            "Sort by",
            [
                "Incident Number (Desc)",
                "Incident Number (Asc)",
                "Severity",
                "Alert Count (Desc)",
                "Alert Count (Asc)",
                "Created Time (Recent)",
                "Created Time (Oldest)",
            ],
        )

    # Sort incidents
    if sort_by == "Incident Number (Desc)":
        filtered_incidents = sorted(
            filtered_incidents,
            key=lambda x: x.get("properties", {}).get("incidentNumber", 0),
            reverse=True,
        )
    elif sort_by == "Incident Number (Asc)":
        filtered_incidents = sorted(
            filtered_incidents,
            key=lambda x: x.get("properties", {}).get("incidentNumber", 0),
        )
    elif sort_by == "Severity":
        severity_order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
        filtered_incidents = sorted(
            filtered_incidents,
            key=lambda x: severity_order.get(
                x.get("properties", {}).get("severity", "Low"), 4
            ),
        )
    elif sort_by == "Alert Count (Desc)":
        filtered_incidents = sorted(
            filtered_incidents,
            key=lambda x: x.get("properties", {})
            .get("additionalData", {})
            .get("alertsCount", 0),
            reverse=True,
        )
    elif sort_by == "Alert Count (Asc)":
        filtered_incidents = sorted(
            filtered_incidents,
            key=lambda x: x.get("properties", {})
            .get("additionalData", {})
            .get("alertsCount", 0),
        )
    elif sort_by == "Created Time (Recent)":
        filtered_incidents = sorted(
            filtered_incidents,
            key=lambda x: x.get("properties", {}).get("createdTimeUtc", ""),
            reverse=True,
        )
    elif sort_by == "Created Time (Oldest)":
        filtered_incidents = sorted(
            filtered_incidents,
            key=lambda x: x.get("properties", {}).get("createdTimeUtc", ""),
        )

    # Pagination
    ITEMS_PER_PAGE = 50
    total_incidents = len(filtered_incidents)
    total_pages = (
        math.ceil(total_incidents / ITEMS_PER_PAGE) if total_incidents > 0 else 1
    )

    # Ensure current page is within bounds
    if st.session_state.current_page_num > total_pages:
        st.session_state.current_page_num = total_pages
    if st.session_state.current_page_num < 1:
        st.session_state.current_page_num = 1

    # Calculate pagination indices
    start_idx = (st.session_state.current_page_num - 1) * ITEMS_PER_PAGE
    end_idx = min(start_idx + ITEMS_PER_PAGE, total_incidents)

    # Get current page incidents
    current_page_incidents = filtered_incidents[start_idx:end_idx]

    # Display incidents
    st.markdown("## Incidents")

    if not filtered_incidents:
        st.info("No incidents match the selected filters.")
    else:
        # Pagination controls at top
        col1, col2, col3, col4, col5 = st.columns([1, 1, 2, 1, 1])

        with col1:
            if st.button("⏮️ First", disabled=(st.session_state.current_page_num == 1)):
                st.session_state.current_page_num = 1
                st.rerun()

        with col2:
            if st.button(
                "◀️ Previous", disabled=(st.session_state.current_page_num == 1)
            ):
                st.session_state.current_page_num -= 1
                st.rerun()

        with col3:
            st.markdown(
                f'<div class="pagination-info">Page {st.session_state.current_page_num} of {total_pages} | Showing {start_idx + 1}-{end_idx} of {total_incidents} incidents</div>',
                unsafe_allow_html=True,
            )

        with col4:
            if st.button(
                "Next ▶️", disabled=(st.session_state.current_page_num == total_pages)
            ):
                st.session_state.current_page_num += 1
                st.rerun()

        with col5:
            if st.button(
                "Last ⏭️", disabled=(st.session_state.current_page_num == total_pages)
            ):
                st.session_state.current_page_num = total_pages
                st.rerun()

        st.markdown("---")

        # Display incidents for current page
        for idx, incident in enumerate(current_page_incidents):
            display_incident_overview(incident, idx)

        # Pagination controls at bottom
        if total_pages > 1:
            st.markdown("---")
            col1, col2, col3, col4, col5 = st.columns([1, 1, 2, 1, 1])

            with col1:
                if st.button(
                    "⏮️ First2", disabled=(st.session_state.current_page_num == 1)
                ):
                    st.session_state.current_page_num = 1
                    st.rerun()

            with col2:
                if st.button(
                    "◀️ Previous2", disabled=(st.session_state.current_page_num == 1)
                ):
                    st.session_state.current_page_num -= 1
                    st.rerun()

            with col3:
                st.markdown(
                    f'<div class="pagination-info">Page {st.session_state.current_page_num} of {total_pages} | Showing {start_idx + 1}-{end_idx} of {total_incidents} incidents</div>',
                    unsafe_allow_html=True,
                )

            with col4:
                if st.button(
                    "Next2 ▶️",
                    disabled=(st.session_state.current_page_num == total_pages),
                ):
                    st.session_state.current_page_num += 1
                    st.rerun()

            with col5:
                if st.button(
                    "Last2 ⏭️",
                    disabled=(st.session_state.current_page_num == total_pages),
                ):
                    st.session_state.current_page_num = total_pages
                    st.rerun()


if __name__ == "__main__":
    main()
