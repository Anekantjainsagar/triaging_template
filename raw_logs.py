import streamlit as st
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
import pandas as pd
import pytz

# Page configuration
st.set_page_config(
    page_title="Security Alerts Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for better styling
st.markdown(
    """
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        margin-bottom: 1rem;
    }
    .alert-card {
        padding: 0.75rem 1rem;
        border-radius: 6px;
        margin-bottom: 0.5rem;
        border-left: 4px solid;
        cursor: pointer;
        transition: all 0.2s ease;
        background-color: white;
    }
    .alert-card:hover {
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        transform: translateX(3px);
    }
    .alert-high {
        background-color: #ffebee;
        border-left-color: #f44336;
    }
    .alert-medium {
        background-color: #fff3e0;
        border-left-color: #ff9800;
    }
    .alert-low {
        background-color: #e8f5e9;
        border-left-color: #4caf50;
    }
    .severity-badge {
        padding: 0.25rem 0.75rem;
        border-radius: 12px;
        font-weight: bold;
        font-size: 0.85rem;
    }
    .severity-high {
        background-color: #f44336;
        color: white;
    }
    .severity-medium {
        background-color: #ff9800;
        color: white;
    }
    .severity-low {
        background-color: #4caf50;
        color: white;
    }
    .metric-card {
        background-color: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        text-align: center;
    }
    .overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(0,0,0,0.7);
        z-index: 999;
        overflow-y: auto;
    }
    .overlay-content {
        background-color: white;
        margin: 2% auto;
        padding: 2rem;
        width: 90%;
        max-width: 1200px;
        border-radius: 12px;
        position: relative;
    }
    .close-btn {
        position: absolute;
        top: 1rem;
        right: 1rem;
        font-size: 2rem;
        cursor: pointer;
        color: #999;
    }
    .detail-section {
        margin-top: 1.5rem;
        padding: 1rem;
        background-color: #f8f9fa;
        border-radius: 8px;
    }
    .timeline-item {
        padding: 0.5rem;
        border-left: 3px solid #1f77b4;
        margin-left: 1rem;
        margin-bottom: 0.5rem;
    }
    .alert-meta {
        font-size: 0.75rem;
        color: #666;
        margin-bottom: 0.25rem;
    }
    .alert-title-row {
        font-weight: 600;
        font-size: 0.95rem;
        color: #333;
        margin-bottom: 0.25rem;
        display: inline-block;
        width: 100%;
    }
    
    .stMarkdown p {
        margin-bottom: 0.5rem;
    }
</style>
""",
    unsafe_allow_html=True,
)

# Initialize session state
if "selected_alert" not in st.session_state:
    st.session_state.selected_alert = None
if "show_overlay" not in st.session_state:
    st.session_state.show_overlay = False
if "current_page" not in st.session_state:
    st.session_state.current_page = 1
if "items_per_page" not in st.session_state:
    st.session_state.items_per_page = 50


def paginate_alerts(alerts, page, items_per_page):
    """Paginate alerts list"""
    start_idx = (page - 1) * items_per_page
    end_idx = start_idx + items_per_page
    return alerts[start_idx:end_idx]


def show_pagination_controls(total_items, current_page, items_per_page, position="top"):
    """Show pagination controls"""
    total_pages = (total_items + items_per_page - 1) // items_per_page

    if total_pages <= 1:
        return current_page

    col1, col2, col3, col4, col5, col6 = st.columns([1, 1, 2, 1, 1, 1])

    with col1:
        if st.button(
            "⏮ First",
            disabled=(current_page == 1),
            width="stretch",
            key=f"first_{position}",
        ):
            st.session_state.current_page = 1
            st.rerun()

    with col2:
        if st.button(
            "◀ Previous",
            disabled=(current_page == 1),
            width="stretch",
            key=f"prev_{position}",
        ):
            st.session_state.current_page = current_page - 1
            st.rerun()

    with col3:
        st.markdown(
            f"<div style='text-align: center; padding: 0.5rem; font-weight: 600;'>Page {current_page} of {total_pages}</div>",
            unsafe_allow_html=True,
        )

    with col4:
        if st.button(
            "Next ▶",
            disabled=(current_page >= total_pages),
            width="stretch",
            key=f"next_{position}",
        ):
            st.session_state.current_page = current_page + 1
            st.rerun()

    with col5:
        if st.button(
            "Last ⏭",
            disabled=(current_page >= total_pages),
            width="stretch",
            key=f"last_{position}",
        ):
            st.session_state.current_page = total_pages
            st.rerun()

    with col6:
        st.markdown(
            f"<div style='text-align: center; padding: 0.5rem;'>{total_items} total</div>",
            unsafe_allow_html=True,
        )

    return current_page


def convert_zulu_to_ist(timestamp_str):
    """Convert Zulu/UTC timestamp to IST (UTC+5:30)"""
    try:
        # Handle various timestamp formats
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f+00:00",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
        ]

        dt_utc = None
        for fmt in formats:
            try:
                dt_utc = datetime.strptime(timestamp_str, fmt)
                break
            except ValueError:
                continue

        if dt_utc is None:
            # Try parsing with timezone info
            if "Z" in timestamp_str or "+00:00" in timestamp_str:
                timestamp_str = timestamp_str.replace("Z", "+00:00")
                dt_utc = datetime.fromisoformat(
                    timestamp_str.replace("+00:00", "")
                ).replace(tzinfo=pytz.UTC)
            else:
                return timestamp_str
        else:
            # Make timezone-aware if it isn't
            if dt_utc.tzinfo is None:
                dt_utc = pytz.UTC.localize(dt_utc)

        # Convert to IST (UTC+5:30)
        ist = pytz.timezone("Asia/Kolkata")
        dt_ist = dt_utc.astimezone(ist)

        return dt_ist.strftime("%Y-%m-%d %I:%M:%S %p IST")
    except Exception as e:
        return timestamp_str


def get_latest_folder(base_dir):
    """Get the latest sentinel_logs folder"""
    if not os.path.exists(base_dir):
        return None

    folders = [f for f in os.listdir(base_dir) if f.startswith("sentinel_logs_")]
    if not folders:
        return None

    folders.sort(reverse=True)
    return os.path.join(base_dir, folders[0])


def load_alerts_from_folder(folder_path):
    """Load both user data and endpoint security alerts from a folder"""
    alerts = []

    # Load user data correlation alerts
    user_data_files = [
        f
        for f in os.listdir(folder_path)
        if f.startswith("correlation_analysis_") and f.endswith(".json")
    ]

    for file in user_data_files:
        try:
            with open(os.path.join(folder_path, file), "r", encoding="utf-8") as f:
                data = json.load(f)

                # Extract timestamp from filename or metadata
                timestamp_str = data.get("report_metadata", {}).get("generated_at", "")
                if not timestamp_str:
                    timestamp_str = (
                        file.split("_")[-2]
                        + " "
                        + file.split("_")[-1].replace(".json", "")
                    )

                # Process all priority events
                for priority in [
                    "high_priority_events",
                    "medium_priority_events",
                    "low_priority_events",
                ]:
                    for event in data.get(priority, []):
                        # Get timestamp from timeline if available
                        event_timestamp = timestamp_str
                        if event.get("timeline") and len(event["timeline"]) > 0:
                            event_timestamp = event["timeline"][0].get(
                                "timestamp", timestamp_str
                            )

                        alert = {
                            "alert_id": f"USER_{event.get('user_id', 'unknown')[:8]}",
                            "title": event.get("alert_title", "Unknown Alert"),
                            "severity": priority.split("_")[0].upper(),
                            "category": "User Activity",
                            "source": "User Data Correlation",
                            "timestamp": event_timestamp,
                            "timestamp_ist": convert_zulu_to_ist(event_timestamp),
                            "user_principal_name": event.get(
                                "user_principal_name", "N/A"
                            ),
                            "user_display_name": event.get("user_display_name", "N/A"),
                            "alert_summary": event.get("alert_summary", "N/A"),
                            "alert_description": event.get("alert_description", "N/A"),
                            "total_events": event.get("total_events", 0),
                            "risk_score": event.get("risk_score", 0),
                            "risk_factors": event.get("risk_factors", []),
                            "locations": event.get("locations", []),
                            "applications": event.get("applications", []),
                            "timeline": event.get("timeline", []),
                            "authentication_summary": event.get(
                                "authentication_summary", {}
                            ),
                            "failure_analysis": event.get("failure_analysis", {}),
                            "behavioral_anomalies": event.get(
                                "behavioral_anomalies", []
                            ),
                            "raw_data": event,
                        }
                        alerts.append(alert)
        except Exception as e:
            st.error(f"Error loading user data file {file}: {e}")

    # Load endpoint security correlation alerts
    endpoint_files = [
        f
        for f in os.listdir(folder_path)
        if f.startswith("endpoint_correlation_") and f.endswith(".json")
    ]

    for file in endpoint_files:
        try:
            with open(os.path.join(folder_path, file), "r", encoding="utf-8") as f:
                data = json.load(f)

                report_timestamp = data.get("report_metadata", {}).get(
                    "generated_at", ""
                )

                for alert_data in data.get("security_alerts", []):
                    # Use evidence timestamp if available
                    alert_timestamp = alert_data.get("evidence", {}).get(
                        "timestamp", report_timestamp
                    )

                    alert = {
                        "alert_id": alert_data.get("alert_id", "Unknown"),
                        "title": alert_data.get("title", "Unknown Alert"),
                        "severity": alert_data.get("severity", "UNKNOWN"),
                        "category": alert_data.get("category", "Unknown"),
                        "source": "Endpoint Security",
                        "timestamp": alert_timestamp,
                        "timestamp_ist": (
                            convert_zulu_to_ist(alert_timestamp)
                            if alert_timestamp
                            else report_timestamp
                        ),
                        "mitre_attack": alert_data.get("mitre_attack", "N/A"),
                        "description": alert_data.get("description", "N/A"),
                        "evidence": alert_data.get("evidence", {}),
                        "risk_assessment": alert_data.get("risk_assessment", "N/A"),
                        "raw_data": alert_data,
                    }
                    alerts.append(alert)
        except Exception as e:
            st.error(f"Error loading endpoint file {file}: {e}")

    return alerts


def load_all_alerts(base_dir):
    """Load alerts from all timeline folders"""
    all_alerts = []

    if not os.path.exists(base_dir):
        return all_alerts

    folders = get_available_folders(base_dir)

    for folder in folders:
        folder_path = os.path.join(base_dir, folder)
        alerts = load_alerts_from_folder(folder_path)
        all_alerts.extend(alerts)

    return all_alerts


def get_available_folders(base_dir):
    """Get all available timeline folders"""
    if not os.path.exists(base_dir):
        return []

    folders = [f for f in os.listdir(base_dir) if f.startswith("sentinel_logs_")]
    folders.sort(reverse=True)
    return folders


def parse_folder_time(folder_name):
    """Parse time information from folder name"""
    # Format: sentinel_logs_2025-11-07 06-00-06-20
    parts = folder_name.replace("sentinel_logs_", "").split(" ")
    if len(parts) == 2:
        date_part = parts[0]
        time_part = parts[1]
        start_time = time_part[:5].replace("-", ":")
        end_time = time_part[6:].replace("-", ":")
        return f"{date_part} {start_time} - {end_time}"
    return folder_name


def get_severity_color(severity):
    """Get color for severity badge"""
    severity_upper = severity.upper()
    if severity_upper == "HIGH":
        return "severity-high"
    elif severity_upper == "MEDIUM":
        return "severity-medium"
    else:
        return "severity-low"


def get_alert_card_class(severity):
    """Get CSS class for alert card"""
    severity_upper = severity.upper()
    if severity_upper == "HIGH":
        return "alert-high"
    elif severity_upper == "MEDIUM":
        return "alert-medium"
    else:
        return "alert-low"


def show_alert_detail_modal(alert):
    """Show detailed alert information in a modal dialog"""
    # Add back button to sidebar
    with st.sidebar:
        st.markdown("## Alert Details")
        if st.button(
            "← Back to Dashboard",
            key="back_button_modal",
            width="stretch",
            type="primary",
        ):
            st.session_state.show_overlay = False
            st.session_state.selected_alert = None
            st.rerun()

    # Header
    st.markdown(f"## {alert['title']}")

    # Severity and metadata in one row
    st.markdown(
        f"""
        <div style="display: flex; gap: 1rem; align-items: center; margin: 1rem 0; flex-wrap: wrap;">
            <span class="severity-badge {get_severity_color(alert['severity'])}">{alert['severity']}</span>
            <span style="color: #666;">Category: {alert['category']}</span>
            <span style="color: #666;">Source: {alert['source']}</span>
            <span style="color: #666;">Alert ID: {alert['alert_id']}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("---")

    # Different layouts based on source
    if alert["source"] == "User Data Correlation":
        show_user_activity_detail(alert)
    else:
        show_endpoint_security_detail(alert)


def show_user_activity_detail(alert):
    """Show user activity alert details"""
    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("### 👤 User Information")
        st.write(f"**Display Name:** {alert.get('user_display_name', 'N/A')}")
        st.write(f"**Principal Name:** {alert.get('user_principal_name', 'N/A')}")
        st.write(f"**Total Events:** {alert.get('total_events', 0)}")
        st.write(f"**Risk Score:** {alert.get('risk_score', 0)}/10")

    with col2:
        st.markdown("### 📊 Summary")
        st.write(f"**Alert Summary:** {alert.get('alert_summary', 'N/A')}")
        st.write(
            f"**Timestamp (IST):** {alert.get('timestamp_ist', alert.get('timestamp', 'N/A'))}"
        )

    with col3:
        st.markdown("### 🔐 Authentication")
        auth_summary = alert.get("authentication_summary", {})
        st.write(f"**MFA Events:** {auth_summary.get('total_mfa', 0)}")
        st.write(f"**Single Factor:** {auth_summary.get('total_single_factor', 0)}")
        st.write(f"**Failed Attempts:** {auth_summary.get('failed_attempts', 0)}")

    # Description
    st.markdown("### 📝 Description")
    st.info(alert.get("alert_description", "No description available"))

    # Risk Factors
    if alert.get("risk_factors"):
        st.markdown("### ⚠️ Risk Factors")
        for factor in alert["risk_factors"]:
            st.markdown(f"- {factor}")

    # Locations
    if alert.get("locations"):
        st.markdown("### 🌍 Locations")
        locations_df = pd.DataFrame(alert["locations"])
        # Convert location timestamps to IST
        if "timestamp" in locations_df.columns:
            locations_df["timestamp_ist"] = locations_df["timestamp"].apply(
                convert_zulu_to_ist
            )
        st.dataframe(locations_df, width="stretch")

    # Applications
    if alert.get("applications"):
        st.markdown("### 📱 Applications Accessed")
        apps_df = pd.DataFrame(alert["applications"])
        st.dataframe(apps_df, width="stretch")

    # Timeline
    if alert.get("timeline"):
        st.markdown("### 📅 Activity Timeline")
        for item in alert["timeline"]:
            timestamp_ist = convert_zulu_to_ist(item.get("timestamp", ""))
            st.markdown(
                f"""
            <div class="timeline-item">
                <strong>{timestamp_ist}</strong><br>
                App: {item.get('app', 'N/A')}<br>
                Location: {item.get('location', 'N/A')}<br>
                Result: {item.get('result', 'N/A')}<br>
                Auth Method: {item.get('auth_method', 'N/A')}
            </div>
            """,
                unsafe_allow_html=True,
            )

    # Failure Analysis
    failure_analysis = alert.get("failure_analysis", {})
    if failure_analysis.get("total_failures", 0) > 0:
        st.markdown("### ❌ Failure Analysis")
        col1, col2 = st.columns(2)
        with col1:
            st.write(f"**Total Failures:** {failure_analysis.get('total_failures', 0)}")
            st.write(
                f"**Success Rate:** {failure_analysis.get('success_rate', 0):.2f}%"
            )
        with col2:
            st.write(
                f"**Critical Failures:** {failure_analysis.get('critical_failures', 0)}"
            )

        if failure_analysis.get("failure_reasons"):
            st.markdown("**Failure Reasons:**")
            for reason in failure_analysis["failure_reasons"]:
                st.markdown(
                    f"- {reason.get('reason', 'Unknown')} (Count: {reason.get('count', 0)})"
                )


def show_endpoint_security_detail(alert):
    """Show endpoint security alert details"""
    # Basic info in one row - compact display
    st.markdown(
        f"""
        <div style="display: flex; gap: 2rem; flex-wrap: wrap; margin-bottom: 1rem;">
            <div><strong>Category:</strong> {alert.get('category', 'N/A')}</div>
            <div><strong>MITRE ATT&CK:</strong> {alert.get('mitre_attack', 'N/A')}</div>
            <div><strong>Timestamp (IST):</strong> {alert.get('timestamp_ist', alert.get('timestamp', 'N/A'))}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("---")

    # Description
    st.markdown("### 📄 Description")
    st.info(alert.get("description", "No description available"))

    # Evidence
    if alert.get("evidence"):
        st.markdown("### 🔍 Evidence")
        evidence = alert["evidence"]

        # Display evidence in a structured way
        for key, value in evidence.items():
            if key == "Key Components":
                # Handle Key Components specially - filter out asterisks
                if isinstance(value, list) and value:
                    filtered_components = [
                        item for item in value if item and item != "*"
                    ]
                    if filtered_components:
                        st.markdown(f"**{key}:**")
                        for item in filtered_components:
                            st.markdown(f"- {item}")
                continue

            if isinstance(value, list) and value:
                st.markdown(f"**{key}:**")
                for item in value:
                    if item and item != "*":  # Skip empty or asterisk items
                        st.markdown(f"- {item}")
            elif value and value != "*":  # Skip empty or asterisk values
                # Convert timestamps in evidence to IST
                if "timestamp" in key.lower() and isinstance(value, str):
                    value_ist = convert_zulu_to_ist(value)
                    st.markdown(f"**{key}:** {value_ist}")
                else:
                    st.markdown(f"**{key}:** {value}")

    # Risk Assessment
    st.markdown("### ⚠️ Risk Assessment")
    st.warning(alert.get("risk_assessment", "No risk assessment available"))


def main():
    # Show modal if alert is selected - MUST BE FIRST
    if st.session_state.get("show_overlay") and st.session_state.get("selected_alert"):
        show_alert_detail_modal(st.session_state.selected_alert)
        return  # Don't show anything else when modal is open

    # Only show header if not in overlay mode
    st.markdown(
        '<h1 class="main-header">🛡️ Unified Security Alerts Dashboard</h1>',
        unsafe_allow_html=True,
    )

    # Sidebar for filters only
    with st.sidebar:
        st.markdown("## 📊 Configuration")

        base_dir = st.text_input("Base Directory", value="sentinel_logs2")

        # Auto-load alerts on startup
        if "alerts" not in st.session_state:
            if os.path.exists(base_dir):
                with st.spinner("Loading all alerts from all timelines..."):
                    st.session_state.alerts = load_all_alerts(base_dir)
                if st.session_state.alerts:
                    st.success(
                        f"✅ Loaded {len(st.session_state.alerts)} alerts from all timelines!"
                    )
            else:
                st.error(f"❌ Directory '{base_dir}' not found")
                st.session_state.alerts = []

        # Manual reload button
        if st.button("🔄 Reload All Alerts", type="primary"):
            if os.path.exists(base_dir):
                with st.spinner("Reloading all alerts..."):
                    st.session_state.alerts = load_all_alerts(base_dir)
                    st.session_state.current_page = 1  # Reset to first page
                st.success(f"✅ Loaded {len(st.session_state.alerts)} alerts!")
            else:
                st.error(f"❌ Directory '{base_dir}' not found")

        st.markdown("---")
        st.markdown("### 🔍 Filters")

        # Filters (only show if alerts are loaded)
        if "alerts" in st.session_state and st.session_state.alerts:
            severity_filter = st.multiselect(
                "Severity",
                options=["HIGH", "MEDIUM", "LOW"],
                default=["HIGH", "MEDIUM", "LOW"],
            )

            source_filter = st.multiselect(
                "Source",
                options=["User Data Correlation", "Endpoint Security"],
                default=["User Data Correlation", "Endpoint Security"],
            )

            category_filter = st.multiselect(
                "Category",
                options=list(set([a["category"] for a in st.session_state.alerts])),
                default=list(set([a["category"] for a in st.session_state.alerts])),
            )

            sort_by = st.selectbox(
                "Sort By", options=["Severity", "Timestamp", "Category", "Source"]
            )

            sort_order = st.radio("Sort Order", ["Ascending", "Descending"])

            # Items per page selector
            st.markdown("---")
            items_per_page = st.selectbox(
                "Items per page",
                options=[10, 25, 50, 100],
                index=2,  # Default to 50
                key="items_per_page_selector",
            )
            if items_per_page != st.session_state.items_per_page:
                st.session_state.items_per_page = items_per_page
                st.session_state.current_page = 1  # Reset to first page
                st.rerun()

            # Apply filters
            st.session_state.severity_filter = severity_filter
            st.session_state.source_filter = source_filter
            st.session_state.category_filter = category_filter
            st.session_state.sort_by = sort_by
            st.session_state.sort_order = sort_order

    # Main content area (only shown when no modal)
    if "alerts" not in st.session_state or not st.session_state.alerts:
        st.info("⏳ Loading alerts... Please wait.")
        st.markdown(
            """
        ### 📋 Dashboard Features
        
        - **Unified View**: All alerts from all timelines combined
        - **Time Conversion**: Timestamps automatically converted from UTC to IST (UTC+5:30)
        - **Smart Filtering**: Filter by severity, source, and category
        - **Detailed Views**: Click any alert to see comprehensive details
        - **Pagination**: Navigate through alerts with easy pagination controls
        """
        )
    else:
        # Filter alerts
        filtered_alerts = [
            a
            for a in st.session_state.alerts
            if a["severity"].upper()
            in st.session_state.get("severity_filter", ["HIGH", "MEDIUM", "LOW"])
            and a["source"]
            in st.session_state.get(
                "source_filter", ["User Data Correlation", "Endpoint Security"]
            )
            and a["category"] in st.session_state.get("category_filter", [])
        ]

        # Sort alerts
        sort_by = st.session_state.get("sort_by", "Severity")
        sort_order = st.session_state.get("sort_order", "Descending")

        if sort_by == "Severity":
            severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
            filtered_alerts.sort(
                key=lambda x: severity_order.get(x["severity"].upper(), 3),
                reverse=(sort_order == "Descending"),
            )
        elif sort_by == "Timestamp":
            filtered_alerts.sort(
                key=lambda x: x.get("timestamp", ""),
                reverse=(sort_order == "Descending"),
            )
        elif sort_by == "Category":
            filtered_alerts.sort(
                key=lambda x: x.get("category", ""),
                reverse=(sort_order == "Descending"),
            )
        elif sort_by == "Source":
            filtered_alerts.sort(
                key=lambda x: x.get("source", ""), reverse=(sort_order == "Descending")
            )

        # Reset to page 1 if current page is out of bounds
        total_pages = (
            len(filtered_alerts) + st.session_state.items_per_page - 1
        ) // st.session_state.items_per_page
        if st.session_state.current_page > total_pages and total_pages > 0:
            st.session_state.current_page = 1

        # Display metrics
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.metric("Total Alerts", len(filtered_alerts))
            st.markdown("</div>", unsafe_allow_html=True)

        with col2:
            high_count = len(
                [a for a in filtered_alerts if a["severity"].upper() == "HIGH"]
            )
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.metric("High Severity", high_count)
            st.markdown("</div>", unsafe_allow_html=True)

        with col3:
            medium_count = len(
                [a for a in filtered_alerts if a["severity"].upper() == "MEDIUM"]
            )
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.metric("Medium Severity", medium_count)
            st.markdown("</div>", unsafe_allow_html=True)

        with col4:
            low_count = len(
                [a for a in filtered_alerts if a["severity"].upper() == "LOW"]
            )
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.metric("Low Severity", low_count)
            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("---")

        # Display alerts
        if filtered_alerts:
            # Pagination controls at top
            st.session_state.current_page = show_pagination_controls(
                len(filtered_alerts),
                st.session_state.current_page,
                st.session_state.items_per_page,
                position="top",
            )

            # Get paginated alerts
            paginated_alerts = paginate_alerts(
                filtered_alerts,
                st.session_state.current_page,
                st.session_state.items_per_page,
            )

            st.markdown(
                f"### 📋 Showing {len(paginated_alerts)} of {len(filtered_alerts)} Alert(s)"
            )

            for idx, alert in enumerate(paginated_alerts):
                # Calculate global index for unique keys
                global_idx = (
                    st.session_state.current_page - 1
                ) * st.session_state.items_per_page + idx

                # Create columns for the alert card
                col_main, col_button = st.columns([5, 1])

                with col_main:
                    # Create compact alert row with all info
                    st.markdown(
                        f"""
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 1rem; 
                             background-color: {'#ffebee' if alert['severity'].upper() == 'HIGH' else '#fff3e0' if alert['severity'].upper() == 'MEDIUM' else '#e8f5e9'}; 
                             border-left: 4px solid {'#f44336' if alert['severity'].upper() == 'HIGH' else '#ff9800' if alert['severity'].upper() == 'MEDIUM' else '#4caf50'}; 
                             border-radius: 6px; margin-bottom: 0.75rem;">
                            <div style="flex: 1;">
                                <div style="font-weight: 600; font-size: 0.95rem; color: #333; margin-bottom: 0.25rem;">
                                    {alert['title']}
                                </div>
                                <div style="font-size: 0.75rem; color: #666;">
                                    {alert['source']} • {alert['category']} • {alert.get('timestamp_ist', alert.get('timestamp', 'N/A'))}
                                </div>
                            </div>
                            <div style="margin-left: 1rem;">
                                <span class="severity-badge {get_severity_color(alert['severity'])}">{alert['severity']}</span>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                with col_button:
                    # View Details button aligned to the right
                    if st.button(
                        "👁️ View",
                        key=f"alert_{global_idx}_{alert['alert_id']}_{st.session_state.current_page}",
                        width="stretch",
                        type="secondary",
                    ):
                        st.session_state.selected_alert = alert
                        st.session_state.show_overlay = True
                        st.rerun()

            # Pagination controls at bottom
            st.markdown("---")
            show_pagination_controls(
                len(filtered_alerts),
                st.session_state.current_page,
                st.session_state.items_per_page,
                position="bottom",
            )
        else:
            st.warning("No alerts match the current filters")


if __name__ == "__main__":
    main()
