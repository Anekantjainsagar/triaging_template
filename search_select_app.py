import streamlit as st
from frontend.config.triaging_styles import main_header_style
from api_client.search_alert_api_client import get_api_client

# Import frontend step components
from components.triaging.step0_search import show_page as step0_search
from components.triaging.step1_select import show_page as step1_select

# --- Page Configuration ---
st.set_page_config(
    page_title="Security Alert Search & Selection",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- Custom CSS ---
st.markdown(main_header_style, unsafe_allow_html=True)


# --- State Management ---
def initialize_session_state():
    """Initialize all session state variables for search/select module."""
    defaults = {
        "step": 0,
        "alerts": [],
        "alerts_data": [],
        "selected_alert": None,
        "search_query": "",
        "data_loaded": None,
        "total_incidents": 0,
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


initialize_session_state()


# --- Selection Handler ---
def handle_alert_selection(selected_alert, session_state):
    """Handle alert selection and save via API"""
    api_client = get_api_client()

    with st.spinner("Saving selection..."):
        result = api_client.select_alert(
            selected_alert=selected_alert,
            search_query=session_state.get("search_query", ""),
            all_alerts=session_state.get("alerts", []),
        )

    if result.get("success"):
        st.success(f"✅ {result.get('message')}")
        session_state.selected_alert = selected_alert
    else:
        st.error(f"❌ {result.get('error', 'Failed to save selection')}")


# --- Check API Health ---
def check_api_status():
    """Check if backend API is running"""
    api_client = get_api_client()
    health = api_client.health_check()

    if health.get("status") == "healthy":
        return True, health
    else:
        return False, health


# --- App Title ---
st.markdown(
    '<div class="main-header">🔍 Security Alert Search & Selection</div>',
    unsafe_allow_html=True,
)
st.markdown(
    "Search for security alerts and select one for triaging. The selected alert will be processed in the triaging module."
)

# --- Check Backend API ---
with st.sidebar:
    st.header("🔌 Backend Status")

    is_healthy, health_data = check_api_status()

    if is_healthy:
        st.success("✅ API Connected")
        with st.expander("API Info", expanded=False):
            st.write(f"**Status:** {health_data.get('status')}")
            st.write(f"**Data Loaded:** {health_data.get('data_loaded')}")
            if health_data.get("cache_timestamp"):
                st.write(f"**Cache Time:** {health_data['cache_timestamp'][:19]}")
    else:
        st.error("❌ API Not Connected")
        st.stop()

    st.markdown("---")

# --- Sidebar ---
with st.sidebar:
    st.header("📊 Module Info")
    st.write(f"**Current Step:** {st.session_state.step + 1}/2")

    if st.session_state.data_loaded:
        st.metric("Total Incidents", st.session_state.total_incidents)

    st.markdown("---")

    if st.session_state.step > 0:
        if st.button("🔄 Start Over"):
            for key in list(st.session_state.keys()):
                if key not in ["data_loaded", "total_incidents"]:
                    del st.session_state[key]
            initialize_session_state()
            st.rerun()


# ==================== PAGE ROUTING ====================
# Check if alert was already selected
if st.session_state.selected_alert:
    st.success("✅ Alert Already Selected!")

    with st.container():
        st.markdown("### Selected Alert:")
        st.info(f"**Rule:** {st.session_state.selected_alert['rule']}")
        st.info(f"**Incident:** {st.session_state.selected_alert['incident']}")
        st.info(f"**Description:** {st.session_state.selected_alert['description']}")

        st.markdown("---")
        st.markdown("### 📋 Next Steps:")
        st.markdown(
            """
        1. **Close this application** (or keep it open for reference)
        2. **Run the Triaging Module**: `streamlit run main_clean.py`
        3. The triaging module will **automatically load** your selected alert
        """
        )

        if st.button(
            "🔄 Select Different Alert", type="primary", use_container_width=True
        ):
            st.session_state.selected_alert = None
            st.session_state.step = 0
            st.rerun()

elif st.session_state.step == 0:
    # Step 0: Search for alerts
    step0_search(st.session_state)

elif st.session_state.step == 1:
    # Step 1: Select an alert
    step1_select(st.session_state, handle_alert_selection)
