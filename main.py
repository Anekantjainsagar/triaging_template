import streamlit as st
from sentinel.backend import *
from components.soc_hub import display_ai_analysis
from styles.soc_dashboard import SOC_DASHBOARD_STYLES
from sentinel.frontend.dashboard import display_overview_page
from sentinel.frontend.incident_details import display_incident_detail


# Page configuration
st.set_page_config(
    page_title="Microsoft Sentinel - SOC Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for better styling
st.markdown(SOC_DASHBOARD_STYLES, unsafe_allow_html=True)


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
        except Exception as e:
            pass


initialize_session_state()

def main():
    # Navigation sidebar
    with st.sidebar:
        st.title("🛡️ Navigation")
        st.markdown("---")

        # Page selection
        st.markdown("### 📋 Pages")
        if st.button("📊 Incidents Dashboard", width="stretch"):
            st.session_state.current_page = "overview"
            st.rerun()

        if st.button("🤖 SOC Analysis Hub", width="stretch"):
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

        if st.button("🗑️ Clear Cache", width="stretch"):
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


if __name__ == "__main__":
    main()
