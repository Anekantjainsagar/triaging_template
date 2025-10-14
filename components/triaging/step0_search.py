# step0_search.py (Frontend - API Version)

import streamlit as st
from api_client.search_alert_api_client import get_api_client


def show_page(session_state):
    """Step 0: Search for security alerts using backend API"""

    st.markdown(
        '<div class="step-header"><h2>Step 1: Search for Security Alerts</h2></div>',
        unsafe_allow_html=True,
    )

    # Get API client
    api_client = get_api_client()

    # Load data if not already loaded
    if session_state.data_loaded is None:
        with st.spinner("Loading tracker data..."):
            result = api_client.load_data()

            if not result.get("success"):
                st.error(f"❌ {result.get('error', 'Failed to load data')}")
                st.info(
                    "Please ensure the backend API is running and data files exist."
                )
                st.stop()
            else:
                session_state.data_loaded = True
                session_state.total_incidents = result.get("total_incidents", 0)
                st.success(f"✅ {result.get('message', 'Data loaded successfully')}")

    col1, col2 = st.columns([3, 1])

    with col1:
        default_value = session_state.get("example_query", "")
        search_query = st.text_input(
            "🔍 Enter keywords to search (rule name, incident number, alert type, etc.)",
            value=default_value,
            placeholder="e.g., Sophos, Atypical Travel, Rule#280, Privileged Role...",
            key="search_input",
        )
        if "example_query" in session_state:
            del session_state.example_query

    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        search_button = st.button("Search Alerts", type="primary", width="stretch")

    if search_button and search_query:
        with st.spinner("🔎 Searching for relevant alerts..."):
            try:
                # Call backend API
                result = api_client.search_alerts(search_query, top_n=5)

                if not result.get("success"):
                    st.error(f"❌ {result.get('error', 'Search failed')}")
                    return

                alerts = result.get("alerts", [])

                if alerts:
                    # Store alert titles and full data
                    session_state.alerts = [alert["title"] for alert in alerts]
                    session_state.alerts_data = alerts
                    session_state.search_query = search_query
                    session_state.step = 1
                    st.rerun()
                else:
                    st.warning("⚠️ No relevant alerts found. Try different keywords.")

            except Exception as e:
                st.error(f"❌ Error during search: {str(e)}")
