"""
SOC Intelligence Dashboard - Streamlit Frontend with Integrated Triaging
Updated to include AI-Powered Triaging as a third tab
"""

import pandas as pd
import streamlit as st
from frontend.config.styles import apply_custom_css
from api_client.analyzer_api_client import get_analyzer_client
from components.predictions_page import display_predictions_page
from components.historical_analysis import display_historical_analysis_tab

# Triaging imports
from components.triaging_integrated import (
    display_triaging_workflow,
    extract_alert_from_dataframe_row,
    initialize_triaging_state_from_data,
)

# Page configuration
st.set_page_config(
    page_title="SOC Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

apply_custom_css()


# ============================================================================
# Session State Management
# ============================================================================


def initialize_session_state():
    """Initialize all session state variables"""
    defaults = {
        "chat_history": [],
        "current_suggestions": [],
        "selected_rule_data": None,
        "search_query": "",
        "system_stats": None,
        # Triaging-specific states
        "triaging_step": 2,  # Start at step 2 (enhance)
        "triaging_alerts": [],
        "triaging_selected_alert": None,
        "triaging_template_content": None,
        "triaging_plan": None,
        "triaging_output": {},
        "triaging_predictions": [],
        "progressive_predictions": {},
        "triaging_initialized": False,  # ✅ ADD THIS LIN
        "rule_history": {},
        "current_step_index": 0,
        "analysis_complete": False,
        "excel_template_data": None,
        "original_steps": None,
        "enhanced_steps": None,
        "validation_report": None,
        "real_time_prediction": None,
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


initialize_session_state()


# ============================================================================
# Helper Functions
# ============================================================================

@st.cache_data(ttl=60)  # ✅ Cache for 30 seconds
def check_api_status():
    """Check if backend API is running"""
    api_client = get_analyzer_client()
    health = api_client.health_check()

    if health.get("status") == "healthy":
        return True, health
    else:
        return False, health


def display_rule_suggestion(rule_data, index):
    """Display a rule suggestion as a clickable card"""
    rule_name = rule_data["rule"]
    score = rule_data["score"]
    incident_count = rule_data["incident_count"]
    match_type = rule_data.get("match_type", "text_similarity")

    display_rule = rule_name[:80] + "..." if len(rule_name) > 80 else rule_name
    match_indicator = "🎯" if match_type == "rule_number" else "🔍"

    return st.button(
        f"{match_indicator} {display_rule}\n📊 {incident_count} incidents | 🎯 Score: {score:.1%} | Type: {match_type}",
        key=f"rule_btn_{index}",
        help=f"Click to analyze: {rule_name}",
        use_container_width=True,
    )


# ============================================================================
# Main Dashboard
# ============================================================================
def display_soc_dashboard():
    """Display the main SOC Dashboard page"""

    # Header
    st.title("🛡️ SOC Intelligence Dashboard")
    st.markdown(
        "**Enhanced SOC Tracker Analysis with Threat Intelligence Integration**"
    )

    # Check API status
    api_client = get_analyzer_client()

    # Main search interface
    st.markdown("### 🔍 Rule Search & Analysis")

    user_query = st.text_input(
        "Enter your search query (e.g., 'rule 002', 'conditional access', 'passwordless')",
        placeholder="Type rule name or keywords...",
        key="search_input",
    )

    if st.button("🔎 Search Rules", use_container_width=True) and user_query:
        with st.spinner(f"🔍 Searching for: '{user_query}'"):
            result = api_client.get_rule_suggestions(user_query, top_k=5)

        if result.get("success"):
            suggestions = result.get("suggestions", [])
            if suggestions:
                st.session_state.current_suggestions = suggestions
                st.session_state.search_query = user_query
                st.success(f"Found {len(suggestions)} matching rules")
            else:
                st.warning(
                    "No matching rules found. Try different keywords or phrases."
                )
        else:
            st.error(f"❌ Search failed: {result.get('error')}")

    # Display current suggestions
    if st.session_state.current_suggestions:
        st.markdown("### 🎯 Rule Suggestions")
        st.markdown("Click on a rule to view comprehensive analysis:")

        for i, suggestion in enumerate(st.session_state.current_suggestions):
            if display_rule_suggestion(suggestion, i):
                selected_rule = suggestion["rule"]

                # ✅ CLEAR OLD ANALYSIS CACHE WHEN SELECTING NEW RULE
                old_analysis_keys = [
                    k
                    for k in st.session_state.keys()
                    if k.startswith("analysis_result_")
                ]
                for key in old_analysis_keys:
                    del st.session_state[key]

                with st.spinner(f"📊 Preparing analysis for: {selected_rule}"):
                    # Get historical data
                    historical_result = api_client.get_historical_data(selected_rule)

                    if historical_result.get("success"):
                        data_list = historical_result.get("data", [])

                        if data_list:
                            data_df = pd.DataFrame(data_list)

                            # ✅ UPDATED: Use existing utility functions
                            from routes.src.utils import (
                                extract_rule_number,
                                extract_alert_name,
                            )

                            rule_number = extract_rule_number(selected_rule)
                            alert_name = extract_alert_name(selected_rule)

                            # Fallback: Get alert name from DataFrame if extraction failed
                            if alert_name == selected_rule and not data_df.empty:
                                for col in [
                                    "Alert Name",
                                    "ALERT_NAME",
                                    "Description",
                                    "DESCRIPTION",
                                    "Title",
                                    "alert_incident",
                                ]:
                                    if col in data_df.columns and pd.notna(
                                        data_df[col].iloc[0]
                                    ):
                                        alert_name = str(data_df[col].iloc[0])
                                        break

                            st.session_state.selected_rule_data = {
                                "rule_name": selected_rule,  # Full: "Rule#280 - Suspicious Auth Activity"
                                "rule_number": rule_number,  # Just: "280" or "286/2/002"
                                "alert_name": alert_name,  # Just: "Suspicious Auth Activity"
                                "data": data_df,
                                "query": user_query,
                            }

                            st.session_state.current_suggestions = []
                            st.rerun()
                        else:
                            st.warning("No historical data found for this rule")
                    else:
                        st.error(
                            f"❌ Failed to load historical data: {historical_result.get('error')}"
                        )

    # Display tabbed analysis results
    if st.session_state.selected_rule_data:
        st.markdown("---")

        rule_name = st.session_state.selected_rule_data["rule_name"]
        data = st.session_state.selected_rule_data["data"]
        rule_number = st.session_state.selected_rule_data["rule_number"]

        st.markdown(
            f'<h2 style="color: #2c3e50; text-align: center;">📊 Analysis: {rule_name}</h2>',
            unsafe_allow_html=True,
        )

        import hashlib

        rule_hash = hashlib.md5(rule_name.encode()).hexdigest()
        init_key = f"rule_initialized_{rule_hash}"

        # ✅ INITIALIZE ALL 3 OPERATIONS ONCE
        if init_key not in st.session_state:
            with st.spinner("🚀 Initializing analysis pipeline..."):
                # 1. Prepare triaging (don't auto-select yet)
                if not data.empty:
                    first_alert = extract_alert_from_dataframe_row(data.iloc[0], rule_number)
                    initialize_triaging_state_from_data(rule_number, data, first_alert)
                    st.session_state.triaging_step = 2

                # Mark as initialized
                st.session_state[init_key] = True
                st.rerun()  # Single rerun to apply state

        # Create tabs for different analysis sections
        tab1, tab2, tab3 = st.tabs(
            ["🤖 AI Threat Analysis", "📊 Historical Analysis", "🔍 AI Triaging"]
        )

        with tab1:
            display_alert_analysis_tab_api(rule_name, api_client)

        with tab2:
            display_historical_analysis_tab(data)

        with tab3:
            # Now triaging is already initialized, just display
            st.write("🔍 DEBUG - Before Triaging Call:")
            st.write(f"- Rule number: {rule_number}")
            st.write(f"- Data rows: {len(data)}")
            st.write(f"- triaging_initialized: {st.session_state.get('triaging_initialized', False)}")
            st.write(f"- triaging_selected_alert: {st.session_state.get('triaging_selected_alert', None)}")
                    
            display_triaging_workflow(rule_number, data)


# ============================================================================
# FIXED: display_alert_analysis_tab_api - Prevents Multiple Reruns
# ============================================================================


def display_alert_analysis_tab_api(rule_name: str, api_client):
    """
    Display AI-powered alert analysis tab using API
    OPTIMIZED: Analysis runs only once and is cached in session state
    """

    # ✅ CHECK IF ANALYSIS ALREADY EXISTS IN SESSION STATE
    analysis_key = f"analysis_result_{rule_name}"

    if analysis_key in st.session_state:
        # Analysis already done, just display it (NO RERUN)
        result = st.session_state[analysis_key]

        if result.get("success"):
            analysis = result.get("analysis", "")

            # Display analysis in styled container
            st.markdown('<div class="threat-intel-box">', unsafe_allow_html=True)
            st.markdown(analysis)
            st.markdown("</div>", unsafe_allow_html=True)

            # Download option
            col1, col2, col3 = st.columns([1, 1, 1])
            with col2:
                from datetime import datetime

                st.download_button(
                    label="📄 Download Analysis Report",
                    data=analysis,
                    file_name=f"threat_analysis_{rule_name[:30]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                    mime="text/markdown",
                    use_container_width=True,
                )
        else:
            st.error(f"❌ Analysis failed: {result.get('error')}")

        # Add refresh button (only way to re-run)
        if st.button("🔄 Re-run Analysis", key="rerun_analysis"):
            del st.session_state[analysis_key]
            st.rerun()

        return  # ✅ EXIT EARLY - Don't run analysis again

    # ✅ IF NOT CACHED, RUN ANALYSIS (ONLY ONCE)
    progress_bar = st.progress(0)
    status_text = st.empty()

    try:
        status_text.text("🚀 Initializing AI analysis engine...")
        progress_bar.progress(20)

        status_text.text("🔍 Analyzing alert patterns and mapping to MITRE ATT&CK...")
        progress_bar.progress(40)

        status_text.text("🌐 Researching threat intelligence and actor TTPs...")
        progress_bar.progress(60)

        # Make API call for analysis
        result = api_client.analyze_alert(rule_name)

        # ✅ CACHE THE RESULT (prevents rerun)
        st.session_state[analysis_key] = result

        status_text.text("📊 Assessing business impact and compliance implications...")
        progress_bar.progress(80)

        if result.get("success"):
            analysis = result.get("analysis", "")

            progress_bar.progress(100)
            status_text.text("✅ Analysis complete!")

            # Clear progress indicators
            import time

            time.sleep(1)
            progress_bar.empty()
            status_text.empty()

            # Display analysis
            st.markdown('<div class="threat-intel-box">', unsafe_allow_html=True)
            st.markdown(analysis)
            st.markdown("</div>", unsafe_allow_html=True)

            # Download option
            col1, col2, col3 = st.columns([1, 1, 1])
            with col2:
                from datetime import datetime

                st.download_button(
                    label="📄 Download Analysis Report",
                    data=analysis,
                    file_name=f"threat_analysis_{rule_name[:30]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                    mime="text/markdown",
                    use_container_width=True,
                )
        else:
            progress_bar.empty()
            status_text.empty()
            st.error(f"❌ Analysis failed: {result.get('error')}")

    except Exception as e:
        progress_bar.empty()
        status_text.empty()
        st.error(f"❌ Analysis Error: {str(e)}")
        with st.expander("🔍 View Error Details"):
            st.code(str(e))


# ============================================================================
# Main Application
# ============================================================================


def main():
    """Main Streamlit application with sidebar navigation"""

    # Sidebar navigation
    with st.sidebar:
        st.title("🛡️ SOC Hub")
        st.markdown("---")

        # Check backend status
        st.header("🔌 Backend Status")
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
                if health_data.get("cache_timestamp"):
                    st.write(f"**Cache Time:** {health_data['cache_timestamp'][:19]}")
        else:
            st.error("❌ API Not Connected")
            st.warning("Please start the FastAPI backend server")
            st.code("uvicorn fastapi_backend:app --reload --host 0.0.0.0 --port 8000")
            st.stop()

        st.markdown("---")

        # Navigation - NOW WITH 2 PAGES (Triaging integrated into Dashboard)
        page = st.radio(
            "Navigation",
            ["🏠 Dashboard", "🔮 Predictions & MITRE"],
            label_visibility="collapsed",
        )

        st.markdown("---")

        # System info for dashboard page
        if page == "🏠 Dashboard":
            st.markdown("### 📋 System Information")

            # ✅ CACHE STATS - Only fetch once per session
            if "system_stats_cache" not in st.session_state:
                api_client = get_analyzer_client()
                st.session_state.system_stats_cache = api_client.get_system_stats()

            stats_result = st.session_state.system_stats_cache

            if stats_result.get("success"):
                st.metric("Total Records", f"{stats_result.get('total_records', 0):,}")
                st.metric("Unique Rules", stats_result.get("unique_rules", 0))
                st.metric("Data Sources", stats_result.get("data_sources", 0))
            else:
                st.warning("Unable to load system stats")

            st.markdown("### 🔧 Actions")

            if st.button("🔄 Refresh Data", help="Reload data from backend"):
                with st.spinner("Reloading data..."):
                    result = api_client.load_data()
                    if result.get("success"):
                        st.success(f"✅ {result.get('message')}")
                        st.rerun()
                    else:
                        st.error(f"❌ {result.get('error')}")

            if st.button("🗑️ Clear Selection", help="Clear current selection"):
                st.session_state.current_suggestions = []
                st.session_state.selected_rule_data = None
                # Clear triaging state
                for key in list(st.session_state.keys()):
                    if key.startswith("triaging_"):
                        del st.session_state[key]
                st.rerun()

        st.markdown("---")
        st.caption("© 2025 SOC Intelligence Dashboard")

    # Route to appropriate page
    if page == "🏠 Dashboard":
        display_soc_dashboard()
    else:  # Predictions & MITRE
        display_predictions_page()


if __name__ == "__main__":
    main()
