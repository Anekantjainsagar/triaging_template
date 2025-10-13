import streamlit as st
from utils.data_loader import load_tracker_data
from utils.data_loader import search_alerts


def render_step_0():
    st.markdown(
        '<div class="step-header"><h2>Step 1: Search for Security Alerts</h2></div>',
        unsafe_allow_html=True,
    )

    # Load data if not already loaded
    if st.session_state.all_data is None:
        st.session_state.all_data = load_tracker_data()

    # Render search interface
    search_query = _render_search_input()

    if search_query:
        alerts_list = search_alerts(st.session_state.all_data, search_query)
        if alerts_list:
            st.session_state.alerts = alerts_list
            st.session_state.step = 1
            st.rerun()


def _render_search_input():
    col1, col2 = st.columns([3, 1])

    with col1:
        default_value = st.session_state.get("example_query", "")
        search_query = st.text_input(
            "🔍 Enter keywords to search",
            value=default_value,
            placeholder="e.g., Sophos, Atypical Travel, Rule#280...",
            key="search_input",
        )
        if "example_query" in st.session_state:
            del st.session_state.example_query

    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        search_button = st.button("Search Alerts", type="primary", width="stretch")

    return search_query if search_button and search_query else None
