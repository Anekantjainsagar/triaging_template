# step0_search.py (Frontend - API Version with Direct Selection)
import streamlit as st
from api_client.search_alert_api_client import get_api_client


def show_page(session_state):
    """Step 0: Search for security alerts using backend API with direct selection"""

    st.markdown(
        '<div class="step-header">🔍 Step 0: Search & Select Security Alerts</div>',
        unsafe_allow_html=True,
    )

    # Get API client
    api_client = get_api_client()

    # Check API health first
    try:
        health_status = api_client.health_check()
        if health_status.get("status") == "healthy":
            st.success(
                f"✅ API Connected | Data Loaded: {health_status.get('data_loaded', False)} | Records: {health_status.get('total_records', 0)}"
            )
        else:
            st.warning("⚠️ API connection issues detected")
    except Exception as e:
        st.error(f"❌ API Connection Failed: {str(e)}")
        st.info("Please ensure the FastAPI backend is running on http://localhost:8000")
        return

    # Search Interface
    st.markdown("### 🔍 Alert Search")

    col1, col2 = st.columns([3, 1])

    with col1:
        search_query = st.text_input(
            "Enter search terms (rule name, incident type, etc.)",
            placeholder="e.g., 2, authentication, sophos",
            help="Search across rule names, descriptions, incidents, and resolver comments",
        )

    with col2:
        top_n = st.selectbox("Results", options=[5, 10, 15, 20], index=0)

    # Search button and results
    if st.button("🔍 Search Alerts", type="primary", use_container_width=True):
        if search_query.strip():
            try:
                with st.spinner("Searching alerts..."):
                    # Call API search
                    search_results = api_client.search_alerts(search_query, top_n=top_n)

                    # Handle the correct response structure
                    if search_results.get("success"):
                        # Handle both 'results' and 'alerts' keys
                        alerts = search_results.get(
                            "results", search_results.get("alerts", [])
                        )

                        if alerts:
                            session_state.search_results = alerts
                            session_state.alerts = alerts  # For compatibility

                            st.success(f"✅ Found {len(alerts)} matching alerts")

                            # Store for selection processing
                            session_state.current_search_results = alerts
                        else:
                            st.warning(
                                "🔍 No alerts found matching your search criteria"
                            )
                            st.info(
                                "Try different search terms like rule numbers (e.g., '280', '279') or keywords"
                            )
                    else:
                        st.warning("🔍 No alerts found matching your search criteria")
                        st.info(
                            "Try different search terms like rule numbers (e.g., '280', '279') or keywords"
                        )

            except Exception as e:
                st.error(f"❌ Search failed: {str(e)}")
                st.info("Please check your API connection and try again")
        else:
            st.warning("⚠️ Please enter a search query")

    # Display search results with DIRECT SELECTION
    if (
        hasattr(session_state, "current_search_results")
        and session_state.current_search_results
    ):
        st.markdown("---")
        st.markdown("### 📋 Search Results - Select an Alert")

        for idx, alert in enumerate(session_state.current_search_results):
            with st.container():
                # Create columns for alert info and selection button
                col1, col2, col3 = st.columns([5, 2, 2])

                with col1:
                    st.markdown(
                        f"**🚨 Rule {alert.get('rule_number', 'N/A')}** - {alert.get('alert_name', 'Unnamed Alert')}"
                    )

                    # Show metadata if available
                    if "metadata" in alert:
                        metadata = alert["metadata"]
                        st.caption(
                            f"Incident: {metadata.get('incident', 'N/A')} | Priority: {metadata.get('priority', 'N/A')} | Connector: {metadata.get('connector', 'N/A')}"
                        )
                    else:
                        st.caption(
                            f"Incident: {alert.get('incident', 'N/A')} | Priority: {alert.get('priority', 'N/A')} | Connector: {alert.get('data_connector', 'N/A')}"
                        )

                with col2:
                    # Show priority as metric
                    priority = alert.get(
                        "priority", alert.get("metadata", {}).get("priority", "N/A")
                    )
                    if priority != "N/A":
                        color = (
                            "🔴"
                            if priority == "High"
                            else "🟡" if priority == "Medium" else "🟢"
                        )
                        st.metric("Priority", f"{color} {priority}")

                with col3:
                    # DIRECT SELECTION BUTTON
                    if st.button(
                        f"✅ Select & Continue",
                        key=f"select_direct_{idx}",
                        type="primary",
                    ):
                        # Handle selection directly
                        try:
                            # Prepare alert data for step 2
                            selected_alert = alert

                            # Extract metadata properly
                            if "metadata" in alert:
                                metadata = alert["metadata"]
                                alert_details = {
                                    "rule_number": alert.get(
                                        "rule_number",
                                        metadata.get("rule_number", "N/A"),
                                    ),
                                    "alert_name": alert.get(
                                        "alert_name", metadata.get("alert_name", "N/A")
                                    ),
                                    "incident": metadata.get("incident", "N/A"),
                                    "priority": metadata.get("priority", "N/A"),
                                    "data_connector": metadata.get("connector", "N/A"),
                                    "status": metadata.get("status", "N/A"),
                                    "type": metadata.get("type", "N/A"),
                                    "shift_engineer": metadata.get(
                                        "shift_engineer", "N/A"
                                    ),
                                    "reported_time": metadata.get(
                                        "reported_time", "N/A"
                                    ),
                                    "responded_time": metadata.get(
                                        "responded_time", "N/A"
                                    ),
                                    "created_date": metadata.get(
                                        "reported_time", "N/A"
                                    ),
                                    "description": f"Rule {alert.get('rule_number', 'N/A')}: {alert.get('alert_name', 'N/A')}",
                                    "resolver_comments": f"Incident: {metadata.get('incident', 'N/A')}, Priority: {metadata.get('priority', 'N/A')}",
                                }
                            else:
                                alert_details = {
                                    "rule_number": alert.get("rule_number", "N/A"),
                                    "alert_name": alert.get("alert_name", "N/A"),
                                    "incident": alert.get("incident", "N/A"),
                                    "priority": alert.get("priority", "N/A"),
                                    "data_connector": alert.get(
                                        "data_connector", "N/A"
                                    ),
                                    "status": alert.get("status", "N/A"),
                                    "created_date": alert.get("reported_time", "N/A"),
                                    "description": f"Rule {alert.get('rule_number', 'N/A')}: {alert.get('alert_name', 'N/A')}",
                                    "resolver_comments": f"Priority: {alert.get('priority', 'N/A')}",
                                }

                            # Set session state for direct transition to step 2
                            session_state.selected_alert = selected_alert
                            session_state.selected_alert_details = alert_details

                            # Create consolidated data for step 2 compatibility
                            import pandas as pd

                            consolidated_row = {
                                "Rule Number": alert_details.get("rule_number", "N/A"),
                                "Alert Name": alert_details.get("alert_name", "N/A"),
                                "Incident": alert_details.get("incident", "N/A"),
                                "Priority": alert_details.get("priority", "N/A"),
                                "Resolver Comments": alert_details.get(
                                    "resolver_comments", "N/A"
                                ),
                                "Data Connector": alert_details.get(
                                    "data_connector", "N/A"
                                ),
                                "Description": alert_details.get("description", "N/A"),
                            }
                            session_state.consolidated_data = pd.DataFrame(
                                [consolidated_row]
                            )
                            session_state.analysis_complete = False

                            # Mark as selected on backend
                            try:
                                api_client.select_alert(
                                    alert.get(
                                        "rule_number", alert.get("alert_index", "N/A")
                                    )
                                )
                            except:
                                pass  # Continue even if backend selection fails

                            st.success(
                                f"✅ Selected: {alert_details.get('rule_number', 'N/A')} - {alert_details.get('alert_name', 'N/A')}"
                            )
                            st.info(
                                "🚀 Proceeding directly to Step 2: Enhance Template"
                            )

                            # Auto-advance to step 2
                            session_state.step = 2
                            st.rerun()

                        except Exception as e:
                            st.error(f"❌ Selection failed: {str(e)}")

                st.markdown("---")

    # Load data option
    st.markdown("### 🔄 Data Management")

    col1, col2 = st.columns(2)

    with col1:
        if st.button(
            "🔄 Reload Backend Data", help="Force reload tracker data on backend"
        ):
            try:
                with st.spinner("Reloading data..."):
                    load_result = api_client.load_data(force_reload=True)
                    if load_result.get("status") == "success":
                        st.success(
                            f"✅ Data reloaded! Total records: {load_result.get('total_records', 0)}"
                        )
                    else:
                        st.error("❌ Failed to reload data")
            except Exception as e:
                st.error(f"❌ Reload failed: {str(e)}")

    with col2:
        if st.button("📊 Check API Status"):
            try:
                status = api_client.health_check()
                st.json(status)
            except Exception as e:
                st.error(f"❌ Status check failed: {str(e)}")

    # Display current selection if any
    if hasattr(session_state, "selected_alert") and session_state.selected_alert:
        st.markdown("---")
        st.success(
            f"✅ Currently Selected: {session_state.selected_alert.get('rule_number', 'N/A')} - {session_state.selected_alert.get('alert_name', 'Unnamed Alert')}"
        )
        st.info("Ready to proceed to Step 2: Enhance Template")
