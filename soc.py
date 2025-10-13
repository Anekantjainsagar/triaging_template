import os
import sys
from io import StringIO
import streamlit as st

# Suppress CrewAI traces globally
os.environ["CREWAI_TELEMETRY"] = "false"

from frontend.config.styles import apply_custom_css
from components.alert_analysis import display_alert_analysis_tab
from components.predictions_page import display_predictions_page
from components.historical_analysis import display_historical_analysis_tab


# Suppress the execution traces prompt
class SuppressOutput:
    def __enter__(self):
        self._original_stdout = sys.stdout
        self._original_stderr = sys.stderr
        sys.stdout = StringIO()
        sys.stderr = StringIO()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        sys.stdout = self._original_stdout
        sys.stderr = self._original_stderr


try:
    from backend.analyzer_backend import SecurityAlertAnalyzerCrew
    from backend.soc_analyzer import IntelligentSOCAnalyzer
except ImportError:
    st.error("Please make sure required files are in the correct directory")
    st.stop()


# Page configuration
st.set_page_config(
    page_title="SOC Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

apply_custom_css()


@st.cache_resource
def initialize_analyzer():
    """Initialize the SOC analyzer with caching for better performance"""
    try:
        analyzer = IntelligentSOCAnalyzer(
            data_directory="data", ollama_model="qwen2.5:0.5b"
        )
        alert_analyzer = SecurityAlertAnalyzerCrew()

        if analyzer.load_and_process_data():
            return analyzer, alert_analyzer
        else:
            return None, None
    except Exception as e:
        st.error(f"Error initializing analyzer: {e}")
        return None, None


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


def display_soc_dashboard():
    """Display the main SOC Dashboard page"""

    # Header
    st.title("🛡️ SOC Intelligence Dashboard")
    st.markdown(
        "**Enhanced SOC Tracker Analysis with Threat Intelligence Integration**"
    )

    # Initialize session state
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []
    if "current_suggestions" not in st.session_state:
        st.session_state.current_suggestions = []
    if "selected_rule_data" not in st.session_state:
        st.session_state.selected_rule_data = None
    if "analyzer" not in st.session_state:
        st.session_state.analyzer = None
    if "alert_analyzer" not in st.session_state:
        st.session_state.alert_analyzer = None

    # Initialize analyzer
    if st.session_state.analyzer is None:
        with st.spinner("🔄 Initializing SOC Analysis System..."):
            analyzer, alert_analyzer = initialize_analyzer()

            if analyzer:
                st.session_state.analyzer = analyzer
                st.session_state.alert_analyzer = alert_analyzer
                st.success("✅ System initialized successfully!")
            else:
                st.error(
                    "❌ Failed to initialize system. Please check your data directory and files."
                )
                st.stop()

    # Main search interface
    st.markdown("### 🔍 Rule Search & Analysis")

    user_query = st.text_input(
        "Enter your search query (e.g., 'rule 002', 'conditional access', 'passwordless')",
        placeholder="Type rule name or keywords...",
    )

    if st.button("🔎 Search Rules", width="stretch") and user_query:
        with st.spinner(f"🔍 Searching for: '{user_query}'"):
            suggestions = st.session_state.analyzer.get_rule_suggestions(
                user_query, top_k=5
            )

        if suggestions:
            st.session_state.current_suggestions = suggestions
            st.success(f"Found {len(suggestions)} matching rules")
        else:
            st.warning("No matching rules found. Try different keywords or phrases.")

    # Display current suggestions
    if st.session_state.current_suggestions:
        st.markdown("### 🎯 Rule Suggestions")
        st.markdown("Click on a rule to view comprehensive analysis:")

        for i, suggestion in enumerate(st.session_state.current_suggestions):
            if display_rule_suggestion(suggestion, i):
                selected_rule = suggestion["rule"]

                with st.spinner(f"📊 Preparing analysis for: {selected_rule}"):
                    matching_data = st.session_state.analyzer.df[
                        st.session_state.analyzer.df["RULE"] == selected_rule
                    ].copy()

                    if not matching_data.empty:
                        st.session_state.selected_rule_data = {
                            "rule_name": selected_rule,
                            "data": matching_data,
                            "query": user_query,
                        }

                        st.session_state.current_suggestions = []
                        st.rerun()

    # Display tabbed analysis results
    if st.session_state.selected_rule_data:
        st.markdown("---")

        rule_name = st.session_state.selected_rule_data["rule_name"]
        data_df = st.session_state.selected_rule_data["data"]

        st.markdown(
            f'<h2 style="color: #2c3e50; text-align: center;">📊 Analysis: {rule_name}</h2>',
            unsafe_allow_html=True,
        )

        # Create tabs for different analysis sections
        tab1, tab2 = st.tabs(["🤖 AI Threat Analysis", "📊 Historical Analysis"])

        with tab1:
            display_alert_analysis_tab(rule_name, st.session_state.alert_analyzer)

        with tab2:
            display_historical_analysis_tab(data_df)


def main():
    """Main Streamlit application with sidebar navigation"""

    # Sidebar navigation
    with st.sidebar:
        st.title("🛡️ SOC Hub")
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

            if (
                st.session_state.get("analyzer")
                and st.session_state.analyzer.df is not None
            ):
                total_records = len(st.session_state.analyzer.df)
                unique_rules = (
                    st.session_state.analyzer.df["RULE"].nunique()
                    if "RULE" in st.session_state.analyzer.df.columns
                    else 0
                )

                st.metric("Total Records", f"{total_records:,}")
                st.metric("Unique Rules", unique_rules)

                if "source_file" in st.session_state.analyzer.df.columns:
                    sources = st.session_state.analyzer.df["source_file"].nunique()
                    st.metric("Data Sources", sources)

            st.markdown("### 🔧 Actions")
            if st.button("🔄 Refresh System", help="Reload data and reinitialize"):
                st.session_state.analyzer = None
                st.session_state.alert_analyzer = None
                st.rerun()

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
