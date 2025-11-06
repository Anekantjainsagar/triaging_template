# [file name]: soc_dashboard.py (updated)
import os
import streamlit as st
from sentinel.utils import *
from datetime import datetime
from styles.logs_dashboard import LOGS_STYLES
from sentinel.frontend.detailed_log_utils import *
from sentinel.frontend.detailed_log import logs_display
from components.soc_hub_overlay import display_soc_hub_overlay, prepare_alert_from_log


# Page configuration
st.set_page_config(page_title="Sentinel Logs Dashboard", page_icon="🔒", layout="wide")

# Initialize session state for details view
if "show_details" not in st.session_state:
    st.session_state.show_details = False
if "selected_log" not in st.session_state:
    st.session_state.selected_log = None
if "selected_log_index" not in st.session_state:
    st.session_state.selected_log_index = None
if "show_soc_hub" not in st.session_state:
    st.session_state.show_soc_hub = False
if "soc_alert_data" not in st.session_state:
    st.session_state.soc_alert_data = None

# Custom CSS
st.markdown(LOGS_STYLES, unsafe_allow_html=True)

# Route to appropriate view
if st.session_state.show_soc_hub:
    display_soc_hub_overlay()
elif st.session_state.show_details and st.session_state.selected_log:
    logs_display()
else:
    # MAIN LIST VIEW
    st.markdown(
        '<div class="main-header">🔒 Sentinel Logs Dashboard - SigninLogs</div>',
        unsafe_allow_html=True,
    )

    # Sidebar filters
    st.sidebar.header("⚙️ Filters")

    # Check if sentinel_logs folder exists
    if not os.path.exists("sentinel_logs"):
        st.error(
            "❌ sentinel_logs folder not found. Please run the data collection script first."
        )
        st.stop()

    # Fixed table selection
    selected_table = "SigninLogs"
    st.sidebar.info(f"📊 Currently viewing: **{selected_table}**")
    st.sidebar.caption("(Table selection locked)")

    # Days filter
    days_filter = st.sidebar.slider("📅 Days to Show", 1, 30, 7)

    # Sort options
    sort_by = st.sidebar.selectbox(
        "🔄 Sort By", ["TimeGenerated", "ResultType", "UserPrincipalName"]
    )
    sort_order = st.sidebar.radio("Sort Order", ["Descending", "Ascending"])

    # Auto-refresh for SigninLogs
    st.sidebar.markdown("---")
    st.sidebar.subheader("♻️ Auto-Refresh")

    needs_refresh, status_msg = check_signin_logs_freshness()

    if needs_refresh:
        st.sidebar.warning(f"⚠️ {status_msg}")
        if st.sidebar.button("🔄 Refresh SigninLogs Now"):
            with st.spinner("Refreshing SigninLogs..."):
                success, message = refresh_signin_logs()
                if success:
                    st.sidebar.success("✅ Refresh completed!")
                    st.rerun()
                else:
                    st.sidebar.error(f"❌ Refresh failed: {message}")
    else:
        st.sidebar.success(f"✅ {status_msg}")

    # Load logs
    logs, error = load_logs(selected_table, days_filter)

    if error:
        st.error(f"❌ Error loading logs: {error}")
        st.stop()

    if not logs:
        st.warning(
            f"⚠️ No logs found for {selected_table} in the last {days_filter} days."
        )
        st.stop()

    # Dashboard metrics
    col2, col3 = st.columns(2)

    with col2:
        failed_logins = len([l for l in logs if l.get("ResultType") != "0"])
        st.markdown(
            f"""
        <div class="alert-card">
            <h3>🚨 Failed Sign-ins</h3>
            <h1>{failed_logins:,}</h1>
        </div>
        """,
            unsafe_allow_html=True,
        )

    with col3:
        unique_users = len(set([l.get("UserPrincipalName", "Unknown") for l in logs]))
        st.markdown(
            f"""
        <div class="success-card">
            <h3>👥 Unique Users</h3>
            <h1>{unique_users:,}</h1>
        </div>
        """,
            unsafe_allow_html=True,
        )

    st.markdown("---")

    # Display unique sources
    unique_sources = get_unique_sources(logs)

    # Initialize session state for sources visibility
    if "show_sources" not in st.session_state:
        st.session_state.show_sources = False

    col1, col2 = st.columns([6, 1])
    with col1:
        st.subheader(f"🌐 Unique Sources ({len(unique_sources)})")
    with col2:
        if st.button(
            "▼ Show" if not st.session_state.show_sources else "▲ Hide",
            key="toggle_sources",
        ):
            st.session_state.show_sources = not st.session_state.show_sources

    if st.session_state.show_sources:
        sources_html = "".join(
            [f'<span class="source-badge">{source}</span>' for source in unique_sources]
        )
        st.markdown(sources_html, unsafe_allow_html=True)

    st.markdown("---")

    # Search functionality
    search_query = st.text_input("🔍 Search logs", placeholder="Search by any field...")

    # Filter logs by search query
    if search_query:
        filtered_logs = [
            log
            for log in logs
            if any(search_query.lower() in str(v).lower() for v in log.values())
        ]
    else:
        filtered_logs = logs

    # Pagination
    records_per_page = 50
    total_records = len(filtered_logs)
    total_pages = (total_records + records_per_page - 1) // records_per_page

    if total_pages > 0:
        # Initialize session state for page
        if "current_page" not in st.session_state:
            st.session_state.current_page = 1

        # Pagination buttons
        col1, col2, col3, col4, col5 = st.columns([1, 1, 2, 1, 1])

        with col1:
            if st.button("⏮️ First", disabled=(st.session_state.current_page == 1)):
                st.session_state.current_page = 1
                st.rerun()

        with col2:
            if st.button("⬅️ Prev", disabled=(st.session_state.current_page == 1)):
                st.session_state.current_page -= 1
                st.rerun()

        with col3:
            st.markdown(
                f"<div style='text-align: center; padding: 8px; font-weight: bold;'>Page {st.session_state.current_page} of {total_pages}</div>",
                unsafe_allow_html=True,
            )

        with col4:
            if st.button(
                "Next ➡️", disabled=(st.session_state.current_page == total_pages)
            ):
                st.session_state.current_page += 1
                st.rerun()

        with col5:
            if st.button(
                "Last ⏭️", disabled=(st.session_state.current_page == total_pages)
            ):
                st.session_state.current_page = total_pages
                st.rerun()

        page = st.session_state.current_page
    else:
        page = 1

    start_idx = (page - 1) * records_per_page
    end_idx = min(start_idx + records_per_page, total_records)

    st.subheader(
        f"📋 {selected_table} - Page {page} of {total_pages} ({total_records} total records)"
    )

    # Display logs for current page with compact design
    for idx in range(start_idx, end_idx):
        log = filtered_logs[idx]

        # Extract the three fields
        failure_reason = (
            log.get("Status", {}).get("failureReason", "N/A")
            if isinstance(log.get("Status"), dict)
            else "N/A"
        )
        result_type = log.get("ResultType", "N/A")
        source = log.get("AppDisplayName") or log.get("SourceSystem", "N/A")
        timestamp = log.get("TimeGenerated", "No timestamp")

        # Create columns for card and button
        col_card, col_btn = st.columns([9, 1])

        with col_card:
            # Compact card display
            st.markdown(
                f"""
                <div class="record-card">
                    <div style="display: flex; align-items: start; gap: 12px;">
                        <span style="color: #1f77b4; font-weight: bold; font-size: 0.9rem;">{idx + 1}</span>
                        <div style="flex: 1;">
                            <div style="font-size: 0.75rem; color: #666; margin-bottom: 4px;">
                                📅 {datetime.fromisoformat(timestamp.replace('Z', '+00:00')).strftime('%b %d, %Y %I:%M:%S %p') if timestamp != 'No timestamp' else 'No timestamp'}
                            </div>
                            <div style="font-size: 0.9rem; margin-bottom: 2px;">
                                <strong>Failure:</strong> {failure_reason}
                            </div>
                            <div style="font-size: 0.9rem; margin-bottom: 2px;">
                                <strong>Error:</strong> <span style="color: #dc3545;">{result_type}</span>
                            </div>
                            <div style="font-size: 0.9rem;">
                                <strong>Source:</strong> <span style="color: #1f77b4;">{source}</span>
                            </div>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with col_btn:
            # Button to view details
            if st.button("👁️", key=f"view_{idx}", help="View full details"):
                st.session_state.selected_log = log
                st.session_state.selected_log_index = idx + 1
                st.session_state.show_details = True
                st.rerun()

    # Pagination info
    st.caption(f"Showing records {start_idx + 1} to {end_idx} of {total_records}")

# Footer
st.markdown("---")
st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")