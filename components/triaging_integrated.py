# components/triaging_integrated.py
"""
Integrated AI-Powered Triaging Module
Combines alert selection, template enhancement, CrewAI walkthrough, and completion
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

# NEW IMPORTS
from routes.src.template_parser import TemplateParser
from routes.src.web_llm_enhancer import WebLLMEnhancer
from routes.src.template_generator import EnhancedTemplateGenerator
from routes.src.csv_template_generator import generate_blank_triaging_template_csv
from frontend.config.triaging_styles import main_header_style

# Individual step imports
from components.triaging.step2_enhance import show_page as step2_enhance
from components.triaging.step3_walkthrough import show_page as step3_walkthrough
from components.triaging.step4_complete import show_page as step4_complete


# ============================================
# HARDCODED CONFIGURATION (Can be modified)
# ============================================
HARDCODED_RULE_NUMBER = "#280"
HARDCODED_INCIDENT = "INC123456"
HARDCODED_ALERT_NAME = "Suspicious Authentication Activity"
HARDCODED_PRIORITY = "High"
HARDCODED_DATA_CONNECTOR = "Sophos"
# ============================================


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


def create_hardcoded_alert(rule_number=None, incident=None):
    """Create hardcoded alert object with optional overrides"""
    rule = rule_number or HARDCODED_RULE_NUMBER
    inc = incident or HARDCODED_INCIDENT

    return {
        "rule_number": rule,
        "rule": rule,
        "alert_name": HARDCODED_ALERT_NAME,
        "incident": inc,
        "priority": HARDCODED_PRIORITY,
        "data_connector": HARDCODED_DATA_CONNECTOR,
        "status": "Open",
        "type": "Security Alert",
        "description": f"Rule {rule}: {HARDCODED_ALERT_NAME}",
        "resolver_comments": f"Incident: {inc}, Priority: {HARDCODED_PRIORITY}",
        "created_date": "2024-10-14",
        "reported_time": "2024-10-14 10:00:00",
    }


def initialize_triaging_state(rule_number=None, incident=None):
    """Initialize triaging-specific session state with hardcoded or custom alert"""

    # Create alert object
    hardcoded_alert = create_hardcoded_alert(rule_number, incident)

    # Create consolidated data DataFrame
    consolidated_row = {
        "Rule Number": hardcoded_alert["rule_number"],
        "Alert Name": hardcoded_alert["alert_name"],
        "Incident": hardcoded_alert["incident"],
        "Priority": hardcoded_alert["priority"],
        "Resolver Comments": hardcoded_alert["resolver_comments"],
        "Data Connector": hardcoded_alert["data_connector"],
        "Description": hardcoded_alert["description"],
    }

    defaults = {
        "triaging_step": 2,  # Start at step 2 (enhance)
        "triaging_alerts": [hardcoded_alert],
        "triaging_all_data": None,
        "triaging_consolidated_data": pd.DataFrame([consolidated_row]),
        "triaging_selected_alert": hardcoded_alert,
        "selected_alert": hardcoded_alert,  # Add this for step3 compatibility
        "selected_alert_details": hardcoded_alert,
        "consolidated_data": pd.DataFrame([consolidated_row]),  # Add for step3
        "template_content": None,
        "triaging_plan": None,
        "triaging_output": {},
        "predictions": [],  # Add this for step3/step4
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
        "search_results": [hardcoded_alert],
        "current_search_results": [hardcoded_alert],
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def display_triaging_workflow(rule_name: str, data):
    """Display triaging workflow for a specific rule (embedded in tab)"""

    # Extract rule number from rule_name if needed
    import re

    rule_match = re.search(r"#?\d+", rule_name)
    rule_number = rule_match.group(0) if rule_match else HARDCODED_RULE_NUMBER
    if not rule_number.startswith("#"):
        rule_number = f"#{rule_number}"

    # Initialize with the actual rule from the dashboard
    initialize_triaging_state(rule_number=rule_number)

    # Initialize clients
    crew = get_crew()
    api_client = get_cached_api_client()

    # Store in session state for access by sub-components
    st.session_state.api_client = api_client

    # CRITICAL FIX: Ensure triaging_selected_alert is never None
    if st.session_state.triaging_selected_alert is None:
        st.session_state.triaging_selected_alert = create_hardcoded_alert(rule_number)

    if st.session_state.selected_alert is None:
        st.session_state.selected_alert = st.session_state.triaging_selected_alert

    # Display current alert info
    alert = st.session_state.triaging_selected_alert

    col1, col2, col3 = st.columns(3)
    with col1:
        st.info(f"**Rule:** {alert.get('rule_number', 'N/A')}")
    with col2:
        st.info(f"**Incident:** {alert.get('incident', 'N/A')}")
    with col3:
        st.info(f"**Priority:** {alert.get('priority', 'N/A')}")

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
            # Fallback - redirect to step 2
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

        initialize_triaging_state(rule_number)
        st.rerun()

    # Reset button at bottom
    st.markdown("---")
    if st.button("🔄 Reset Triaging Workflow", key="reset_triaging_tab"):
        # Clear triaging-specific state
        triaging_keys = [
            k
            for k in st.session_state.keys()
            if k.startswith("triaging_")
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

        initialize_triaging_state(rule_number)
        st.success("✅ Workflow reset complete!")
        st.rerun()


def display_triaging_page():
    """Main triaging page display"""

    # Apply custom CSS
    st.markdown(main_header_style, unsafe_allow_html=True)

    # Initialize state
    initialize_triaging_state()

    # Initialize clients
    crew = get_crew()
    api_client = get_cached_api_client()

    # Store in session state for access by sub-components
    st.session_state.api_client = api_client

    # App Title
    st.markdown(
        '<h1 class="main-header">🔍 AI-Powered Security Incident Triaging</h1>',
        unsafe_allow_html=True,
    )

    # Display Hardcoded Configuration Banner
    st.info(
        f"🎯 **Hardcoded Mode Active** | Rule: `{HARDCODED_RULE_NUMBER}` | "
        f"Incident: `{HARDCODED_INCIDENT}` | Priority: `{HARDCODED_PRIORITY}`"
    )

    # Step Navigation
    step_names = [
        "🚀 Enhance Template",  # Step 2
        "👥 CrewAI Walkthrough",  # Step 3
        "✨ Complete Analysis",  # Step 4
    ]

    # Top navigation tabs
    st.markdown("### 🎯 Triaging Workflow")

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button(
            step_names[0],
            key="nav_step2",
            use_container_width=True,
            type="primary" if st.session_state.triaging_step == 2 else "secondary",
        ):
            st.session_state.triaging_step = 2
            st.rerun()

    with col2:
        if st.button(
            step_names[1],
            key="nav_step3",
            use_container_width=True,
            type="primary" if st.session_state.triaging_step == 3 else "secondary",
        ):
            st.session_state.triaging_step = 3
            st.rerun()

    with col3:
        if st.button(
            step_names[2],
            key="nav_step4",
            use_container_width=True,
            type="primary" if st.session_state.triaging_step == 4 else "secondary",
        ):
            st.session_state.triaging_step = 4
            st.rerun()

    st.markdown("---")

    # Display current step content
    if st.session_state.triaging_step == 2:  # Template Enhancement
        step2_enhance(
            st.session_state, TemplateParser, WebLLMEnhancer, EnhancedTemplateGenerator
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
        # Fallback - redirect to step 2
        st.warning("⚠️ Invalid step detected. Redirecting to Template Enhancement...")
        st.session_state.triaging_step = 2
        st.rerun()

    # Footer
    st.markdown("---")
    st.markdown("### 🛡️ Security Operations Center - AI Triaging System")

    display_step = st.session_state.triaging_step - 2
    current_step_name = (
        step_names[display_step] if 0 <= display_step < len(step_names) else "Unknown"
    )
    st.caption(f"Current step: {current_step_name}")

    # Action buttons at bottom
    col1, col2 = st.columns([1, 1])

    with col1:
        if st.button("🔄 Reset Triaging Workflow", key="reset_triaging"):
            # Clear triaging-specific state
            triaging_keys = [
                k
                for k in st.session_state.keys()
                if k.startswith("triaging_")
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
                ]
            ]
            for key in triaging_keys:
                if key in st.session_state:
                    del st.session_state[key]

            # Reinitialize
            initialize_triaging_state()
            st.success("✅ Workflow reset complete!")
            st.rerun()

    with col2:
        if st.button(
            "🔧 Edit Configuration",
            key="edit_config",
            help="Modify hardcoded alert details",
        ):
            with st.expander("⚙️ Configuration Settings", expanded=True):
                st.info(
                    "To modify the hardcoded alert details, edit the constants at the top of `triaging_integrated.py`"
                )
                st.code(
                    f"""
HARDCODED_RULE_NUMBER = "{HARDCODED_RULE_NUMBER}"
HARDCODED_INCIDENT = "{HARDCODED_INCIDENT}"
HARDCODED_ALERT_NAME = "{HARDCODED_ALERT_NAME}"
HARDCODED_PRIORITY = "{HARDCODED_PRIORITY}"
HARDCODED_DATA_CONNECTOR = "{HARDCODED_DATA_CONNECTOR}"
                """,
                    language="python",
                )
