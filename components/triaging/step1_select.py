# step1_select.py (Frontend - API Version)
import streamlit as st
from api_client.search_alert_api_client import get_api_client


def show_page(session_state, handle_selection_callback):
    """Step 1: Select an alert and export historical data using backend API"""

    st.markdown(
        '<div class="step-header">✅ Step 1: Select Alert for Analysis</div>',
        unsafe_allow_html=True,
    )

    # Get API client
    api_client = get_api_client()

    # Check if we have search results
    if not hasattr(session_state, "search_results") or not session_state.search_results:
        st.warning("⚠️ No search results found. Please complete Step 0 first.")
        if st.button("⬅️ Go back to Search", type="secondary"):
            session_state.step = 0
            st.rerun()
        return

    st.markdown(f"### 📋 Available Alerts ({len(session_state.search_results)} found)")

    # Alert selection interface
    selected_alert = None

    for idx, alert in enumerate(session_state.search_results):
        with st.container():
            col1, col2, col3 = st.columns([6, 2, 2])

            with col1:
                st.markdown(
                    f"**{alert.get('rule_number', 'N/A')}** - {alert.get('alert_name', 'Unnamed Alert')}"
                )
                st.caption(
                    f"Incident: {alert.get('incident', 'N/A')} | Priority: {alert.get('priority', 'N/A')}"
                )

            with col2:
                st.metric("Relevance", f"{alert.get('relevance_score', 0):.2f}")

            with col3:
                if st.button(f"Select Alert", key=f"select_{idx}", type="primary"):
                    selected_alert = alert
                    break

            st.markdown("---")

    # Handle alert selection
    if selected_alert:
        try:
            with st.spinner("Fetching detailed alert information..."):
                # Get detailed alert information
                alert_details = api_client.get_alert_details(
                    selected_alert.get("alert_index")
                )

                if alert_details:
                    # Display selected alert details
                    st.markdown("### 🎯 Selected Alert Details")

                    col1, col2 = st.columns(2)

                    with col1:
                        st.markdown(
                            f"**Rule Number:** {alert_details.get('rule_number', 'N/A')}"
                        )
                        st.markdown(
                            f"**Alert Name:** {alert_details.get('alert_name', 'N/A')}"
                        )
                        st.markdown(
                            f"**Incident:** {alert_details.get('incident', 'N/A')}"
                        )
                        st.markdown(
                            f"**Priority:** {alert_details.get('priority', 'N/A')}"
                        )

                    with col2:
                        st.markdown(
                            f"**Data Connector:** {alert_details.get('data_connector', 'N/A')}"
                        )
                        st.markdown(f"**Status:** {alert_details.get('status', 'N/A')}")
                        st.markdown(
                            f"**Created Date:** {alert_details.get('created_date', 'N/A')}"
                        )

                    if alert_details.get("description"):
                        st.markdown(
                            f"**Description:**\n{alert_details.get('description')}"
                        )

                    if alert_details.get("resolver_comments"):
                        st.markdown(
                            f"**Resolver Comments:**\n{alert_details.get('resolver_comments')}"
                        )

                    # Confirmation and selection
                    st.markdown("---")

                    col1, col2, col3 = st.columns([2, 2, 2])

                    with col1:
                        if st.button(
                            "✅ Confirm Selection",
                            type="primary",
                            use_container_width=True,
                        ):
                            # Mark alert as selected on backend
                            try:
                                select_result = api_client.select_alert(
                                    selected_alert.get("alert_index")
                                )
                                if select_result.get("status") == "success":
                                    # Call the selection handler
                                    success = handle_selection_callback(
                                        selected_alert, alert_details
                                    )
                                    if success:
                                        st.success("🎉 Alert selected successfully!")
                                        st.info(
                                            "👉 Proceed to **Step 2: Enhance Template** to continue analysis"
                                        )

                                        # Auto-advance option
                                        if st.button(
                                            "➡️ Go to Step 2", type="secondary"
                                        ):
                                            session_state.step = 2
                                            st.rerun()
                                else:
                                    st.error(
                                        "❌ Failed to mark alert as selected on backend"
                                    )
                            except Exception as e:
                                st.error(f"❌ Selection failed: {str(e)}")

                    with col2:
                        if st.button(
                            "🔄 Choose Different Alert", use_container_width=True
                        ):
                            st.rerun()

                    with col3:
                        if st.button("⬅️ Back to Search", use_container_width=True):
                            session_state.step = 0
                            st.rerun()

                else:
                    st.error("❌ Failed to fetch alert details")

        except Exception as e:
            st.error(f"❌ Error processing alert selection: {str(e)}")

    # Export functionality (if needed for historical analysis)
    if hasattr(session_state, "selected_alert") and session_state.selected_alert:
        st.markdown("---")
        st.markdown("### 📊 Export Options")

        col1, col2 = st.columns(2)

        with col1:
            if st.button(
                "📋 Export Alert History", help="Export related incidents for this rule"
            ):
                try:
                    # This would call your existing export functionality
                    # You might need to adapt this based on your export_rule_incidents_to_excel function
                    st.info("🔄 Export functionality available in next update")
                except Exception as e:
                    st.error(f"❌ Export failed: {str(e)}")

        with col2:
            if st.button("📄 Generate Report", help="Generate preliminary report"):
                st.info("🔄 Report generation available in Step 4")

    # Current selection status
    if hasattr(session_state, "selected_alert") and session_state.selected_alert:
        st.markdown("---")
        st.success(
            f"✅ Currently Selected: {session_state.selected_alert.get('rule_number', 'N/A')} - {session_state.selected_alert.get('alert_name', 'Unnamed Alert')}"
        )
        st.info("Ready to proceed to Step 2: Enhance Template")
