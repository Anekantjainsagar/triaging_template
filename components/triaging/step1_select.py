# step1_select.py (Frontend - API Version)
import streamlit as st


def show_page(session_state, handle_selection_callback):
    """Step 1: Select an alert and export historical data using backend API"""

    st.markdown(
        '<div class="step-header"><h2>Step 2: Select an Alert & Export Historical Data</h2></div>',
        unsafe_allow_html=True,
    )

    st.markdown(f"**Search Query:** `{session_state.get('search_query', 'N/A')}`")
    st.markdown(f"Found **{len(session_state.alerts)}** relevant alerts:")

    st.markdown("---")

    # Get alerts data from session
    alerts_data = session_state.get("alerts_data", [])

    st.write(alerts_data)

    for idx, alert_data in enumerate(alerts_data):
        alert_title = alert_data["title"]
        metadata = alert_data.get("metadata", {})

        with st.container():
            col1, col2 = st.columns([5, 1])

            with col1:
                st.markdown(f"### {idx + 1}. {alert_title}")

                # Display metadata if available
                if metadata:
                    col_a, col_b, col_c = st.columns(3)
                    with col_a:
                        st.metric("Priority", metadata.get("priority", "N/A"))
                    with col_b:
                        st.metric("Type", metadata.get("type", "N/A"))
                    with col_c:
                        st.metric("Connector", metadata.get("connector", "N/A"))

            with col2:
                st.markdown("<br>", unsafe_allow_html=True)
                if st.button("Select ✅", key=f"select_{idx}", type="primary"):
                    # Parse alert info
                    rule = metadata.get("rule", "Unknown")
                    incident = metadata.get("incident", "Unknown")

                    selected_alert = {
                        "incident": incident,
                        "rule": rule,
                        "description": alert_title,
                    }

                    # Use callback to handle selection
                    handle_selection_callback(selected_alert, session_state)
                    st.rerun()

            st.markdown("---")

    if st.button("← Back to Search"):
        session_state.step = 0
        session_state.alerts = []
        session_state.alerts_data = []
        st.rerun()
