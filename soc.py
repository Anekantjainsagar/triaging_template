import pandas as pd
import streamlit as st
from frontend.config.styles import apply_custom_css
from api_client.analyzer_api_client import get_analyzer_client
from components.historical_analysis import display_historical_analysis_tab

# Triaging imports
from components.triaging_integrated import display_triaging_workflow
from components.triaging.step2_enhance import _upload_to_predictions_api

import streamlit as st
import shutil
import os
import tempfile


def clear_media_cache():
    """Clear Streamlit media cache to prevent file handler errors"""
    try:
        # Clear Streamlit's internal cache
        st.cache_data.clear()
        st.cache_resource.clear()

        # Clear media cache directories
        media_cache_paths = [
            os.path.join(os.path.expanduser("~"), ".streamlit", "cache"),
            os.path.join(tempfile.gettempdir(), "streamlit"),
        ]

        for cache_path in media_cache_paths:
            if os.path.exists(cache_path):
                shutil.rmtree(cache_path, ignore_errors=True)

        print("✅ Media cache cleared successfully")
    except Exception as e:
        print(f"⚠️ Cache clearing warning: {str(e)}")


# Page configuration
st.set_page_config(
    page_title="SOC Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

apply_custom_css()


# Clear media cache on startup
media_cache = os.path.join(os.path.expanduser("~"), ".streamlit", "cache")
if os.path.exists(media_cache):
    try:
        shutil.rmtree(media_cache, ignore_errors=True)
    except:
        pass

temp_streamlit = os.path.join(tempfile.gettempdir(), "streamlit")
if os.path.exists(temp_streamlit):
    try:
        shutil.rmtree(temp_streamlit, ignore_errors=True)
    except:
        pass


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
        # ✅ NEW: Manual analysis support
        "show_manual_analysis": False,
        "manual_alert_query": None,
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
                # ✅ NEW: No matching rules - offer manual analysis
                st.warning("⚠️ No matching rules found in historical data")
                st.info(
                    "💡 **Alternative Analysis Available**: Analyze this alert without historical context"
                )

                # Store the query for manual analysis
            st.session_state.manual_alert_query = user_query
            st.session_state.show_manual_analysis = True
            st.session_state.current_suggestions = suggestions
        else:
            st.error(f"❌ Search failed: {result.get('error')}")

    # ✅ NEW: Add manual analysis section after suggestions display
    if st.session_state.get("show_manual_analysis", False):
        st.markdown("---")
        st.markdown("### 🆕 Manual Alert Analysis")
        st.markdown(
            "Since no historical data was found, you can still analyze this alert using AI."
        )

        col1, col2 = st.columns([3, 1])

        with col1:
            alert_title = st.text_input(
                "Alert Title/Name:",
                value=st.session_state.get("manual_alert_query", ""),
                key="manual_alert_title",
            )

            alert_description = st.text_area(
                "Alert Description (Optional):",
                placeholder="Provide additional context about this alert...",
                height=100,
                key="manual_alert_description",
            )

        with col2:
            st.markdown("#### Quick Tips")
            st.caption("✓ Use the exact alert name")
            st.caption("✓ Add context if available")
            st.caption("✓ Include rule numbers")

        if st.button("🤖 Analyze Alert (AI Only)", type="primary", width="stretch"):
            if not alert_title.strip():
                st.error("❌ Please provide an alert title")
            else:
                # Create manual alert object
                manual_alert = {
                    "rule_name": alert_title,
                    "rule_number": "MANUAL",
                    "alert_name": alert_title,
                    "description": (
                        alert_description if alert_description else alert_title
                    ),
                    "data": None,  # No historical data
                    "query": alert_title,
                    "is_manual": True,  # Flag to indicate manual analysis
                }

                st.session_state.selected_rule_data = manual_alert
                st.session_state.show_manual_analysis = False
                st.session_state.manual_alert_query = None
                st.rerun()

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
    # ✅ MODIFY: Update the tabbed analysis section
    if st.session_state.selected_rule_data:
        st.markdown("---")

        rule_name = st.session_state.selected_rule_data["rule_name"]
        data = st.session_state.selected_rule_data.get("data")
        rule_number = st.session_state.selected_rule_data["rule_number"]
        is_manual = st.session_state.selected_rule_data.get("is_manual", False)

        # Display appropriate header
        if is_manual:
            st.markdown(
                f'<h2 style="color: #2c3e50; text-align: center;">🤖 AI Analysis: {rule_name}</h2>',
                unsafe_allow_html=True,
            )
            st.info(
                "ℹ️ **Note**: This is a manual analysis without historical data. Only AI threat intelligence is available."
            )
        else:
            st.markdown(
                f'<h2 style="color: #2c3e50; text-align: center;">📊 Analysis: {rule_name}</h2>',
                unsafe_allow_html=True,
            )

        import hashlib

        rule_hash = hashlib.md5(rule_name.encode()).hexdigest()
        init_key = f"rule_initialized_{rule_hash}"

        # Initialize once
        if init_key not in st.session_state:
            st.session_state[init_key] = True

        predictions_enabled = st.session_state.get("triaging_complete", False)

        # ✅ CONDITIONAL TAB DISPLAY based on manual vs historical
        if is_manual:
            # MANUAL MODE: Only AI Analysis tab
            tab1 = st.tabs(["🤖 AI Threat Analysis"])[0]

            with tab1:
                display_alert_analysis_tab_api(rule_name, api_client, is_manual=True)

                # Add note about upgrading to full analysis
                st.markdown("---")
                st.info(
                    """
                    **Want Historical Analysis?**  
                    If you have historical incident data for this alert, search again using the exact rule name 
                    from your SOC tracker to get comprehensive analysis including:
                    - 📊 Historical incident patterns
                    - 📈 Performance metrics (MTTR/MTTD)
                    - 🔍 AI-powered triaging workflows
                    - 🎯 True/False positive predictions
                    """
                )
        else:
            # NORMAL MODE: Full analysis with all tabs
            if predictions_enabled:
                tab1, tab2, tab3, tab4 = st.tabs(
                    [
                        "🤖 AI Threat Analysis",
                        "📊 Historical Analysis",
                        "🔍 AI Triaging",
                        "🔮 Predictions & MITRE",
                    ]
                )
            else:
                tab1, tab2, tab3 = st.tabs(
                    ["🤖 AI Threat Analysis", "📊 Historical Analysis", "🔍 AI Triaging"]
                )

            with tab1:
                display_alert_analysis_tab_api(rule_name, api_client, is_manual=False)

            with tab2:
                if data is not None and not data.empty:
                    display_historical_analysis_tab(data)
                else:
                    st.warning("⚠️ No historical data available for this rule")

            with tab3:
                display_triaging_workflow(rule_number)

            if predictions_enabled:
                with tab4:
                    display_predictions_tab_integrated()

# ============================================================================
# FIXED: display_alert_analysis_tab_api - Prevents Multiple Reruns
# ============================================================================


def display_predictions_tab_integrated():
    """Display predictions analysis tab (unlocked after triaging)"""

    if not st.session_state.get("triaging_complete", False):
        st.warning(
            "⚠️ Complete the AI Triaging workflow first to unlock predictions analysis"
        )
        return

    st.markdown("### 🔮 True/False Positive Analyzer with MITRE ATT&CK")

    # Get the Excel file from session state
    excel_data = st.session_state.get("predictions_excel_data")
    excel_filename = st.session_state.get("predictions_excel_filename")

    if not excel_data:
        st.error("❌ No triaging data found. Please complete triaging first.")
        return

    st.info(f"📄 Using triaging template: {excel_filename}")

    # Initialize API client
    import os
    from io import BytesIO

    final_api_key = os.getenv("GOOGLE_API_KEY")
    predictions_api_url = os.getenv("PREDICTIONS_API_URL", "http://localhost:8000")

    from api_client.predictions_api_client import get_predictions_client

    try:
        client = get_predictions_client(predictions_api_url, final_api_key)

        # ✅ FIX: Always re-upload to ensure data is fresh
        if not st.session_state.get("predictions_uploaded"):
            st.info("📤 Uploading triaging template to analysis engine...")

            with st.spinner("Uploading investigation data..."):
                upload_success = _upload_to_predictions_api(excel_data, excel_filename)

            if upload_success:
                st.success("✅ Template uploaded successfully!")
                st.session_state.predictions_uploaded = True
            else:
                st.error(
                    f"❌ Upload failed: {st.session_state.get('predictions_upload_error', 'Unknown error')}"
                )
                return
        else:
            st.success("✅ Template already uploaded to predictions API")

        # ✅ FIX: Verify upload with preview
        st.info("🔍 Verifying uploaded data...")
        preview_result = client.get_upload_preview()

        if preview_result.get("success"):
            st.success(
                f"✅ Data verified: {preview_result.get('total_rows', 0)} investigation steps loaded"
            )

            # Show preview
            with st.expander("👁️ Preview Uploaded Data", expanded=False):
                preview_data = preview_result.get("preview_data", [])
                if preview_data:
                    st.dataframe(preview_data, width="stretch")
                else:
                    st.info("No preview data available")
        else:
            st.warning("⚠️ Data verification failed, but continuing...")

        # Username input
        st.markdown("---")
        username = st.text_input(
            "Enter username/email to analyze",
            placeholder="e.g., sarah.mitchell@abc.com",
            key="predictions_username",
        )

        # Analysis type selection
        analysis_type = st.radio(
            "Select analysis type:",
            ["Complete Analysis", "Initial Classification Only", "MITRE Mapping Only"],
            key="predictions_analysis_type",
        )

        if st.button(
            "🔍 Analyze Investigation Data", type="primary", key="analyze_btn"
        ):
            if not username:
                st.warning("⚠️ Please enter a username to analyze")
            else:
                # Import the analysis functions from predictions_page
                from components.predictions_page import (
                    perform_complete_analysis,
                    perform_initial_analysis,
                    perform_mitre_analysis,
                )

                if analysis_type == "Complete Analysis":
                    perform_complete_analysis(client, username)
                elif analysis_type == "Initial Classification Only":
                    perform_initial_analysis(client, username)
                else:
                    perform_mitre_analysis(client, username)

    except Exception as e:
        st.error(f"❌ Error: {str(e)}")
        with st.expander("🔍 View Full Error"):
            import traceback

            st.code(traceback.format_exc())


def display_alert_analysis_tab_api(rule_name: str, api_client, is_manual: bool = False):
    """
    Display AI-powered alert analysis tab using API
    ENHANCED: Now supports manual analysis mode without historical data

    Args:
        rule_name: Name of the alert/rule
        api_client: API client instance
        is_manual: If True, shows this is manual analysis without historical data
    """

    analysis_key = f"analysis_result_{rule_name}"

    if analysis_key in st.session_state:
        # Analysis already done, just display it
        result = st.session_state[analysis_key]

        if result.get("success"):
            analysis = result.get("analysis", "")

            # Add manual analysis disclaimer
            if is_manual:
                st.info(
                    """
                    **🤖 AI-Powered Analysis Mode**  
                    This analysis is based on threat intelligence databases and MITRE ATT&CK framework 
                    without historical incident data from your environment.
                    """
                )

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
                    width="stretch",
                )
        else:
            st.error(f"❌ Analysis failed: {result.get('error')}")

        # Add refresh button
        if st.button("🔄 Re-run Analysis", key="rerun_analysis"):
            del st.session_state[analysis_key]
            st.rerun()

        return  # Exit early

    # ✅ IF NOT CACHED, RUN ANALYSIS
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

        # Cache the result
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

            # Add manual mode disclaimer
            if is_manual:
                st.success(
                    "✅ **AI Analysis Complete** - Generated using threat intelligence databases"
                )
                st.info(
                    """
                    **Note**: This analysis provides threat intelligence context but does not include:
                    - Historical incident patterns from your environment
                    - Organization-specific metrics (MTTR/MTTD)
                    - Previous response data
                    - Triaging workflows
                    
                    For complete analysis, ensure the alert exists in your SOC tracker data.
                    """
                )

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
            st.stop()

        st.markdown("---")

        # System info for dashboard page
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
            # ✅ NEW: Clear manual analysis state
            st.session_state.show_manual_analysis = False
            st.session_state.manual_alert_query = None
            # Clear triaging state
            for key in list(st.session_state.keys()):
                if key.startswith("triaging_") or key.startswith("predictions_"):
                    del st.session_state[key]
            if "triaging_complete" in st.session_state:
                del st.session_state["triaging_complete"]
            st.rerun()

        st.markdown("---")
        st.caption("© 2025 SOC Intelligence Dashboard")

    # Route to appropriate page
    display_soc_dashboard()


if __name__ == "__main__":
    main()
