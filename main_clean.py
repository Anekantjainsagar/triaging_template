# main.py (Hardcoded Entry Point - Direct to Step 2)
import streamlit as st
import pandas as pd
import traceback

# API Client import
from api_client.search_alert_api_client import get_api_client

# Existing imports from backend utilities (for steps 2-4)
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

# Imports for the individual steps (SKIP STEP 0 & 1)
from components.triaging.step2_enhance import show_page as step2_enhance
from components.triaging.step3_walkthrough import show_page as step3_walkthrough
from components.triaging.step4_complete import show_page as step4_complete

# --- Page Configuration ---
st.set_page_config(
    page_title="AI-Powered Security Incident Triaging",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- Custom CSS ---
st.markdown(
    main_header_style,
    unsafe_allow_html=True,
)

# ============================================
# 🎯 HARDCODED CONFIGURATION - MODIFY THESE
# ============================================
HARDCODED_RULE_NUMBER = "#280"  # ⬅️ CHANGE THIS
HARDCODED_INCIDENT = "INC123456"  # ⬅️ CHANGE THIS
HARDCODED_ALERT_NAME = "Suspicious Authentication Activity"  # ⬅️ CHANGE THIS
HARDCODED_PRIORITY = "High"  # ⬅️ CHANGE THIS
HARDCODED_DATA_CONNECTOR = "Sophos"  # ⬅️ CHANGE THIS
# ============================================


# --- State Management ---
def initialize_session_state():
    """Initialize all session state variables with HARDCODED alert data."""

    # Create hardcoded alert object
    hardcoded_alert = {
        "rule_number": HARDCODED_RULE_NUMBER,
        "rule": HARDCODED_RULE_NUMBER,  # Alias for compatibility
        "alert_name": HARDCODED_ALERT_NAME,
        "incident": HARDCODED_INCIDENT,
        "priority": HARDCODED_PRIORITY,
        "data_connector": HARDCODED_DATA_CONNECTOR,
        "status": "Open",
        "type": "Security Alert",
        "description": f"Rule {HARDCODED_RULE_NUMBER}: {HARDCODED_ALERT_NAME}",
        "resolver_comments": f"Incident: {HARDCODED_INCIDENT}, Priority: {HARDCODED_PRIORITY}",
        "created_date": "2024-10-14",
        "reported_time": "2024-10-14 10:00:00",
    }

    # Create consolidated data DataFrame
    consolidated_row = {
        "Rule Number": HARDCODED_RULE_NUMBER,
        "Alert Name": HARDCODED_ALERT_NAME,
        "Incident": HARDCODED_INCIDENT,
        "Priority": HARDCODED_PRIORITY,
        "Resolver Comments": f"Priority: {HARDCODED_PRIORITY}",
        "Data Connector": HARDCODED_DATA_CONNECTOR,
        "Description": f"Rule {HARDCODED_RULE_NUMBER}: {HARDCODED_ALERT_NAME}",
    }

    defaults = {
        "step": 2,  # 🎯 START DIRECTLY AT STEP 2 (Template Enhancement)
        "alerts": [hardcoded_alert],
        "all_data": None,
        "consolidated_data": pd.DataFrame([consolidated_row]),
        "selected_alert": hardcoded_alert,  # 🎯 PRE-SELECTED
        "selected_alert_details": hardcoded_alert,
        "template_content": None,
        "triaging_plan": None,
        "triaging_output": {},
        "predictions": [],
        "progressive_predictions": {},
        "rule_history": {},
        "current_step_index": 0,
        "analysis_complete": False,
        "excel_template_data": None,
        # API-related state
        "api_client": None,
        "search_results": [hardcoded_alert],
        "current_search_results": [hardcoded_alert],
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


initialize_session_state()


# --- Initialize API Client ---
@st.cache_resource
def get_cached_api_client():
    """Initialize and cache the API client."""
    try:
        return get_api_client()
    except Exception as e:
        st.warning(f"⚠️ API client unavailable: {str(e)}")
        return None


# --- Initialize Crew ---
@st.cache_resource
def get_crew():
    """Initialize and cache the CrewAI instance."""
    return TriagingCrew()


crew = get_crew()
api_client = get_cached_api_client()

# --- App Title ---
st.markdown(
    '<h1 class="main-header">🔍 AI-Powered Security Incident Triaging</h1>',
    unsafe_allow_html=True,
)

# --- Display Hardcoded Configuration Banner ---
st.info(
    f"🎯 **Hardcoded Mode Active** | Rule: `{HARDCODED_RULE_NUMBER}` | Incident: `{HARDCODED_INCIDENT}` | Priority: `{HARDCODED_PRIORITY}`"
)

# --- Step Navigation (3 Steps: Enhance, Walkthrough, Complete) ---
step_names = [
    "🚀 Enhance Template",  # Step 2
    "👥 CrewAI Walkthrough",  # Step 3
    "✨ Complete Analysis",  # Step 4
]

# Sidebar navigation
with st.sidebar:
    st.markdown("### Navigation")

    # Show hardcoded alert info at top
    st.markdown("---")
    st.markdown("### 🎯 Current Alert")
    st.success(f"**Rule:** {HARDCODED_RULE_NUMBER}")
    st.caption(HARDCODED_ALERT_NAME)
    st.caption(f"Incident: {HARDCODED_INCIDENT}")
    st.markdown("---")

    for i, name in enumerate(step_names):
        actual_step = i + 2  # Map to actual steps 2, 3, 4
        if st.button(name, key=f"nav_{i}", use_container_width=True):
            st.session_state.step = actual_step

    st.markdown("---")
    st.markdown("### Current Progress")

    # Map current step to display step
    display_step = st.session_state.step - 2  # 2->0, 3->1, 4->2
    if display_step < 0:
        display_step = 0

    st.progress((display_step + 1) / len(step_names))
    st.write(f"Step {display_step + 1} of {len(step_names)}")

# --- Main Content Area ---
if st.session_state.step == 2:  # Template Enhancement
    step2_enhance(
        st.session_state, TemplateParser, WebLLMEnhancer, EnhancedTemplateGenerator
    )

elif st.session_state.step == 3:  # CrewAI Walkthrough
    step3_walkthrough(st.session_state, crew, traceback)

elif st.session_state.step == 4:  # Complete Analysis
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
    st.session_state.step = 2
    st.rerun()

# --- Footer ---
st.markdown("---")
st.markdown("### 🛡️ Security Operations Center - AI Triaging System")
st.caption(
    f"Hardcoded Direct Entry Mode | Current step: {step_names[display_step] if 0 <= display_step < len(step_names) else 'Unknown'}"
)
