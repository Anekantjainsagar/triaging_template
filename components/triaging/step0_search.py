# step0_search.py

import streamlit as st

def show_page(session_state, load_tracker_data, search_alerts_in_data):
    st.markdown(
        '<div class="step-header"><h2>Step 1: Search for Security Alerts</h2></div>',
        unsafe_allow_html=True,
    )

    if session_state.all_data is None:
        with st.spinner("Loading tracker data..."):
            session_state.all_data = load_tracker_data()

            if session_state.all_data.empty:
                st.error("❌ No tracker data found!")
                st.info("Please ensure data files exist in `data/` directory.")
                st.stop()
            else:
                st.success(
                    f"✅ Loaded {len(session_state.all_data)} incidents from tracker sheets"
                )

    with st.expander("💡 Example Searches"):
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            if st.button("Sophos"):
                session_state.example_query = "Sophos"
                st.rerun()
        with col2:
            if st.button("Atypical Travel"):
                session_state.example_query = "Atypical Travel"
                st.rerun()
        with col3:
            if st.button("Privileged Role"):
                session_state.example_query = "Privileged Role"
                st.rerun()
        with col4:
            if st.button("Passwordless"):
                session_state.example_query = "Passwordless"
                st.rerun()

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
                alerts_list = search_alerts_in_data(
                    session_state.all_data, search_query, top_n=5
                )

                if alerts_list:
                    session_state.alerts = alerts_list
                    session_state.step = 1
                    st.rerun()
                else:
                    st.warning(
                        "⚠️ No relevant alerts found. Try different keywords."
                    )

            except Exception as e:
                st.error(f"❌ Error during search: {str(e)}")