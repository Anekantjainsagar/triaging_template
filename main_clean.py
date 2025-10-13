# main.py

import streamlit as st
import pandas as pd
import traceback

# Existing imports
from routes.src.crew import TriagingCrew
from routes.src.utils import (
    read_all_tracker_sheets,
    search_alerts_in_data,
    export_rule_incidents_to_excel,
    generate_completed_template,
)

# NEW IMPORTS - Add these
from routes.src.template_parser import TemplateParser
from routes.src.web_llm_enhancer import WebLLMEnhancer
from routes.src.template_generator import EnhancedTemplateGenerator
from routes.src.csv_template_generator import generate_blank_triaging_template_csv

from frontend.config.triaging_styles import main_header_style

# Imports for the individual steps
from components.triaging.step0_search import show_page as step0_search
from components.triaging.step1_select import show_page as step1_select
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


# --- State Management ---
def initialize_session_state():
    """Initialize all session state variables."""
    defaults = {
        "step": 0,
        "alerts": [],
        "all_data": None,
        "consolidated_data": None,
        "selected_alert": None,
        "template_content": None,
        "triaging_plan": None,
        "triaging_output": {},
        "predictions": [],
        "progressive_predictions": {},
        "rule_history": {},
        "current_step_index": 0,
        "analysis_complete": False,
        "excel_template_data": None,
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


initialize_session_state()


# --- Load Data on Startup ---
@st.cache_data
def load_tracker_data():
    """Load and cache all tracker sheet data."""
    try:
        df = read_all_tracker_sheets("data")
        return df
    except Exception as e:
        st.error(f"Error loading tracker data: {str(e)}")
        return pd.DataFrame()


# --- Initialize Crew ---
@st.cache_resource
def get_crew():
    """Initialize and cache the CrewAI instance."""
    return TriagingCrew()


crew = get_crew()

# --- App Title ---
st.markdown(
    '<div class="main-header">🛡️ AI-Powered Security Incident Triaging System</div>',
    unsafe_allow_html=True,
)
st.markdown(
    "Automate security alert triaging with AI-powered analysis and comprehensive template generation."
)

# --- Sidebar ---
with st.sidebar:
    st.header("📊 Navigation")
    st.write(f"**Current Step:** {st.session_state.step + 1}/5")

    if st.session_state.step > 0:
        st.markdown("---")
        if st.button("🔄 Start Over"):
            for key in list(st.session_state.keys()):
                if key not in ["all_data"]:
                    del st.session_state[key]
            initialize_session_state()
            st.rerun()


# --- Page Routing ---
if st.session_state.step == 0:
    step0_search(st.session_state, load_tracker_data, search_alerts_in_data)

elif st.session_state.step == 1:
    step1_select(st.session_state, export_rule_incidents_to_excel)

elif st.session_state.step == 2:
    step2_enhance(
        st.session_state, TemplateParser, WebLLMEnhancer, EnhancedTemplateGenerator
    )

elif st.session_state.step == 3:
    step3_walkthrough(st.session_state, crew, traceback)

elif st.session_state.step == 4:
    step4_complete(
        st.session_state,
        crew,
        generate_completed_template,
        generate_blank_triaging_template_csv,
        EnhancedTemplateGenerator,
        traceback,
    )
