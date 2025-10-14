"""
SOC Intelligence Dashboard - Streamlit Frontend
Updated to use FastAPI backend via API client
"""

import streamlit as st
from frontend.config.styles import apply_custom_css
from api_client.analyzer_api_client import get_analyzer_client
from components.alert_analysis import display_alert_analysis_tab
from components.predictions_page import display_predictions_page
from components.historical_analysis import display_historical_analysis_tab


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
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


initialize_session_state()


# ============================================================================
# Helper Functions
# ============================================================================


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
        width="stretch",
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

    if st.button("🔎 Search Rules", width="stretch") and user_query:
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

                with st.spinner(f"📊 Preparing analysis for: {selected_rule}"):
                    # Get historical data
                    historical_result = api_client.get_historical_data(selected_rule)

                    if historical_result.get("success"):
                        st.session_state.selected_rule_data = {
                            "rule_name": selected_rule,
                            "data": historical_result.get("data", []),
                            "query": user_query,
                        }

                        st.session_state.current_suggestions = []
                        st.rerun()
                    else:
                        st.error(
                            f"❌ Failed to load historical data: {historical_result.get('error')}"
                        )

    # Display tabbed analysis results
    if st.session_state.selected_rule_data:
        st.markdown("---")

        rule_name = st.session_state.selected_rule_data["rule_name"]
        data = st.session_state.selected_rule_data["data"]

        st.markdown(
            f'<h2 style="color: #2c3e50; text-align: center;">📊 Analysis: {rule_name}</h2>',
            unsafe_allow_html=True,
        )

        # Create tabs for different analysis sections
        tab1, tab2 = st.tabs(["🤖 AI Threat Analysis", "📊 Historical Analysis"])

        with tab1:
            display_alert_analysis_tab_api(rule_name, api_client)

        with tab2:
            display_historical_analysis_tab(data)


def display_alert_analysis_tab_api(rule_name: str, api_client):
    """Display AI-powered alert analysis tab using API"""

    st.markdown(
        """
        ### 🎯 Comprehensive Threat Intelligence
        
        This AI-powered analysis provides:
        - **Technical threat breakdown** with detailed attack vectors
        - **MITRE ATT&CK technique mapping** for framework alignment
        - **Real threat actor intelligence** from global threat databases
        - **Business impact assessment** and compliance implications
        """
    )

    st.markdown("---")

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

        status_text.text("📊 Assessing business impact and compliance implications...")
        progress_bar.progress(80)

        if result.get("success"):
            analysis = result.get("analysis", "")

            progress_bar.progress(100)
            status_text.text("✅ Analysis complete!")

            # Clear progress indicators
            progress_bar.empty()
            status_text.empty()

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
                    width="stretch",
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
        st.header("📌 Backend Status")
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

        # Navigation
        page = st.radio(
            "Navigation",
            ["🏠 Dashboard", "🔮 Predictions & MITRE"],
            label_visibility="collapsed",
        )

        st.markdown("---")

        # System info for dashboard page
        if page == "🏠 Dashboard":
            st.markdown("### 📋 System Information")

            # Get system stats from API
            api_client = get_analyzer_client()
            stats_result = api_client.get_system_stats()

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
                st.rerun()

            st.markdown("---")

        st.caption("© 2025 SOC Intelligence Dashboard")

    # Route to appropriate page
    if page == "🏠 Dashboard":
        display_soc_dashboard()
    else:
        display_predictions_page()


if __name__ == "__main__":
    main()
