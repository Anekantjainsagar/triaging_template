import streamlit as st
import json
import os
from datetime import datetime, timedelta, date
from pathlib import Path
import pandas as pd
import pytz

# Import workflow orchestrator
from backend.fetch_data.workflow import SelectiveWorkflowOrchestrator

# Import SOC Hub components
from components.soc_hub import display_ai_analysis
from sentinel.backend import check_api_status

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
    .fetch-section {
        background-color: #e3f2fd;
        padding: 1.5rem;
        border-radius: 8px;
        margin-bottom: 1rem;
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
if "show_fetch_panel" not in st.session_state:
    st.session_state.show_fetch_panel = False
if "show_soc_analysis" not in st.session_state:
    st.session_state.show_soc_analysis = False
if "soc_analysis_data" not in st.session_state:
    st.session_state.soc_analysis_data = None


def convert_raw_alert_to_soc_format(alert):
    """
    Convert raw alert data to SOC Hub compatible format
    """
    # Determine severity mapping
    severity_map = {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}

    # Base alert structure
    soc_alert = {
        "title": alert.get("title", "Unknown Alert"),
        "alert_name": alert.get("title", "Unknown Alert"),
        "description": alert.get(
            "alert_description",
            alert.get(
                "description", alert.get("alert_summary", "No description available")
            ),
        ),
        "severity": severity_map.get(alert.get("severity", "MEDIUM").upper(), "Medium"),
        "status": "Active",
        "source": "alert_details",
        "rule_number": alert.get("alert_id", f"RAW_{id(alert)}"),
    }

    # Add timestamp information
    timestamp = alert.get("timestamp", "")
    if timestamp:
        soc_alert["timeGenerated"] = timestamp

    # Build full_alert structure with properties
    full_alert = {
        "properties": {
            "alertDisplayName": alert.get("title", "Unknown Alert"),
            "description": soc_alert["description"],
            "severity": soc_alert["severity"],
            "status": soc_alert["status"],
            "timeGenerated": timestamp,
        }
    }

    soc_alert["full_alert"] = full_alert

    # Build entities structure based on alert source
    entities_list = []
    seen_ips = set()  # Track IPs to avoid duplicates

    if alert.get("source") == "User Data Correlation":
        # Extract user entities
        if alert.get("user_principal_name"):
            user_entity = {
                "kind": "Account",
                "properties": {
                    "accountName": (
                        alert.get("user_principal_name", "").split("@")[0]
                        if "@" in alert.get("user_principal_name", "")
                        else alert.get("user_principal_name", "")
                    ),
                    "upnSuffix": (
                        alert.get("user_principal_name", "").split("@")[1]
                        if "@" in alert.get("user_principal_name", "")
                        else ""
                    ),
                    "friendlyName": alert.get("user_display_name", ""),
                    "userPrincipalName": alert.get("user_principal_name", ""),
                },
            }
            entities_list.append(user_entity)

        # Extract location entities with IPs
        for location in alert.get("locations", []):
            # Get IP address from location data
            ip_address = (
                location.get("ip_address")
                or location.get("ipAddress")
                or location.get("ip")
            )

            if ip_address and ip_address not in seen_ips:
                seen_ips.add(ip_address)

                # Parse location info
                location_str = location.get("location", "")
                location_parts = location_str.split(",") if location_str else []

                ip_entity = {
                    "kind": "Ip",
                    "properties": {
                        "address": ip_address,
                    },
                }

                # Add location details if available
                if location_parts:
                    ip_entity["properties"]["location"] = {
                        "city": (
                            location_parts[0].strip() if len(location_parts) > 0 else ""
                        ),
                        "state": (
                            location_parts[1].strip() if len(location_parts) > 1 else ""
                        ),
                        "countryName": (
                            location_parts[-1].strip()
                            if len(location_parts) > 0
                            else ""
                        ),
                    }

                entities_list.append(ip_entity)

        # Extract application entities
        for app in alert.get("applications", []):
            app_entity = {
                "kind": "CloudApplication",
                "properties": {
                    "name": app.get("app", app.get("application", "Unknown App")),
                    "displayName": app.get(
                        "app", app.get("application", "Unknown App")
                    ),
                },
            }
            entities_list.append(app_entity)

    elif alert.get("source") == "Endpoint Security":
        # Extract endpoint entities from evidence
        evidence = alert.get("evidence", {})

        # Host entity
        if evidence.get("Device Name"):
            host_entity = {
                "kind": "Host",
                "properties": {
                    "hostName": evidence.get("Device Name"),
                    "dnsDomain": evidence.get("Device Domain", ""),
                    "osFamily": (
                        "Windows"
                        if "windows" in evidence.get("Device Name", "").lower()
                        else "Unknown"
                    ),
                },
            }
            entities_list.append(host_entity)

        # File entity
        if evidence.get("File Name"):
            file_entity = {
                "kind": "File",
                "properties": {
                    "fileName": evidence.get("File Name"),
                    "name": evidence.get("File Name"),
                    "fileHashValue": evidence.get("File Hash", ""),
                },
            }
            entities_list.append(file_entity)

        # Process entity
        if evidence.get("Process Name"):
            process_entity = {
                "kind": "Process",
                "properties": {
                    "processName": evidence.get("Process Name"),
                    "commandLine": evidence.get("Command Line", ""),
                    "processId": evidence.get("Process ID", ""),
                },
            }
            entities_list.append(process_entity)

        # URL entity
        if evidence.get("URL"):
            url_entity = {"kind": "Url", "properties": {"url": evidence.get("URL")}}
            entities_list.append(url_entity)

        # IP entities - check multiple possible fields
        ip_fields = [
            "Source IP",
            "Destination IP",
            "IP Address",
            "Remote IP",
            "Client IP",
        ]
        for ip_field in ip_fields:
            if evidence.get(ip_field):
                ip_address = evidence.get(ip_field)
                if ip_address and ip_address not in seen_ips:
                    seen_ips.add(ip_address)
                    ip_entity = {
                        "kind": "Ip",
                        "properties": {"address": ip_address},
                    }
                    entities_list.append(ip_entity)

        # Account entity
        if evidence.get("User"):
            account_entity = {
                "kind": "Account",
                "properties": {
                    "accountName": evidence.get("User"),
                    "friendlyName": evidence.get("User"),
                },
            }
            entities_list.append(account_entity)

    # Set entities structure
    soc_alert["entities"] = {"entities": entities_list}

    # Add MITRE ATT&CK if available
    if alert.get("mitre_attack"):
        soc_alert["mitre_attack"] = alert.get("mitre_attack")

    # Add additional context
    soc_alert["raw_alert_data"] = alert.get("raw_data", {})
    soc_alert["alert_category"] = alert.get("category", "Unknown")
    soc_alert["alert_source_type"] = alert.get("source", "Unknown")

    # Add risk information
    if alert.get("risk_score"):
        soc_alert["risk_score"] = alert.get("risk_score")
    if alert.get("risk_factors"):
        soc_alert["risk_factors"] = alert.get("risk_factors")
    if alert.get("risk_assessment"):
        soc_alert["risk_assessment"] = alert.get("risk_assessment")

    return soc_alert


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
            "⮜ First",
            disabled=(current_page == 1),
            key=f"first_{position}",
        ):
            st.session_state.current_page = 1
            st.rerun()

    with col2:
        if st.button(
            "◀ Previous",
            disabled=(current_page == 1),
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
            key=f"next_{position}",
        ):
            st.session_state.current_page = current_page + 1
            st.rerun()

    with col5:
        if st.button(
            "Last ⭢",
            disabled=(current_page >= total_pages),
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
            if "Z" in timestamp_str or "+00:00" in timestamp_str:
                timestamp_str = timestamp_str.replace("Z", "+00:00")
                dt_utc = datetime.fromisoformat(
                    timestamp_str.replace("+00:00", "")
                ).replace(tzinfo=pytz.UTC)
            else:
                return timestamp_str
        else:
            if dt_utc.tzinfo is None:
                dt_utc = pytz.UTC.localize(dt_utc)

        ist = pytz.timezone("Asia/Kolkata")
        dt_ist = dt_utc.astimezone(ist)

        return dt_ist.strftime("%Y-%m-%d %I:%M:%S %p IST")
    except Exception as e:
        return timestamp_str


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

                timestamp_str = data.get("report_metadata", {}).get("generated_at", "")
                if not timestamp_str:
                    timestamp_str = (
                        file.split("_")[-2]
                        + " "
                        + file.split("_")[-1].replace(".json", "")
                    )

                for priority in [
                    "high_priority_events",
                    "medium_priority_events",
                    "low_priority_events",
                ]:
                    for event in data.get(priority, []):
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


def get_severity_color(severity):
    """Get color for severity badge"""
    severity_upper = severity.upper()
    if severity_upper == "HIGH":
        return "severity-high"
    elif severity_upper == "MEDIUM":
        return "severity-medium"
    else:
        return "severity-low"


def show_alert_detail_modal(alert):
    """Show detailed alert information in a modal dialog"""
    with st.sidebar:
        st.markdown("## Alert Details")
        if st.button(
            "← Back to Dashboard",
            key="back_button_modal",
            type="primary",
            width="stretch",
        ):
            st.session_state.show_overlay = False
            st.session_state.selected_alert = None
            st.rerun()

        st.markdown("---")

        # Add Analyze in SOC Hub button in sidebar
        st.markdown("### 🤖 AI Analysis")
        if st.button(
            "🚀 Analyze in SOC Hub",
            key="analyze_soc_sidebar",
            type="secondary",
            width="stretch",
            help="Open in SOC Hub for AI-powered analysis",
        ):
            # Convert raw alert to SOC format
            soc_alert_data = convert_raw_alert_to_soc_format(alert)

            # Set session state for SOC analysis
            st.session_state.soc_analysis_data = soc_alert_data
            st.session_state.show_soc_analysis = True
            st.session_state.show_overlay = False
            st.session_state.selected_alert = None
            st.rerun()

    st.markdown(f"## {alert['title']}")

    # Add Analyze button at the top as well
    col_badge, col_btn = st.columns([3, 1])

    with col_badge:
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

    with col_btn:
        if st.button(
            "🤖 Analyze in SOC Hub",
            key="analyze_soc_top",
            type="primary",
            width="stretch",
            help="Open in SOC Hub for AI-powered analysis",
        ):
            # Convert raw alert to SOC format
            soc_alert_data = convert_raw_alert_to_soc_format(alert)

            # Set session state for SOC analysis
            st.session_state.soc_analysis_data = soc_alert_data
            st.session_state.show_soc_analysis = True
            st.session_state.show_overlay = False
            st.session_state.selected_alert = None
            st.rerun()

    st.markdown("---")

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

    st.markdown("### 📝 Description")
    st.info(alert.get("alert_description", "No description available"))

    if alert.get("risk_factors"):
        st.markdown("### ⚠️ Risk Factors")
        for factor in alert["risk_factors"]:
            st.markdown(f"- {factor}")

    if alert.get("locations"):
        st.markdown("### 🌍 Locations & IP Addresses")
        locations_df = pd.DataFrame(alert["locations"])

        # Add IST timestamp if available
        if "timestamp" in locations_df.columns:
            locations_df["timestamp_ist"] = locations_df["timestamp"].apply(
                convert_zulu_to_ist
            )

        # Reorder columns to show IP prominently
        cols = locations_df.columns.tolist()
        if "ip_address" in cols:
            cols.remove("ip_address")
            cols.insert(0, "ip_address")
            locations_df = locations_df[cols]
        elif "ipAddress" in cols:
            cols.remove("ipAddress")
            cols.insert(0, "ipAddress")
            locations_df = locations_df[cols]

        st.dataframe(locations_df, width="stretch")

    if alert.get("applications"):
        st.markdown("### 📱 Applications Accessed")
        apps_df = pd.DataFrame(alert["applications"])
        st.dataframe(apps_df, width="stretch")

    if alert.get("timeline"):
        st.markdown("### 📅 Activity Timeline")
        for item in alert["timeline"]:
            timestamp_ist = convert_zulu_to_ist(item.get("timestamp", ""))
            ip_info = item.get("ip_address", item.get("ipAddress", "N/A"))

            st.markdown(
                f"""
            <div class="timeline-item">
                <strong>{timestamp_ist}</strong><br>
                App: {item.get('app', 'N/A')}<br>
                Location: {item.get('location', 'N/A')}<br>
                IP Address: {ip_info}<br>
                Result: {item.get('result', 'N/A')}<br>
                Auth Method: {item.get('auth_method', 'N/A')}
            </div>
            """,
                unsafe_allow_html=True,
            )


def show_endpoint_security_detail(alert):
    """Show endpoint security alert details"""
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

    st.markdown("### 📄 Description")
    st.info(alert.get("description", "No description available"))

    if alert.get("evidence"):
        st.markdown("### 🔍 Evidence")
        evidence = alert["evidence"]

        # Highlight IP addresses at the top
        ip_fields = [
            "Source IP",
            "Destination IP",
            "IP Address",
            "Remote IP",
            "Client IP",
        ]
        ip_found = False

        st.markdown("**🌐 Network Information:**")
        for ip_field in ip_fields:
            if evidence.get(ip_field):
                st.markdown(f"- **{ip_field}:** `{evidence.get(ip_field)}`")
                ip_found = True

        if ip_found:
            st.markdown("---")

        for key, value in evidence.items():
            # Skip IP fields as they're already shown
            if key in ip_fields:
                continue

            if key == "Key Components":
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
                    if item and item != "*":
                        st.markdown(f"- {item}")
            elif value and value != "*":
                if "timestamp" in key.lower() and isinstance(value, str):
                    value_ist = convert_zulu_to_ist(value)
                    st.markdown(f"**{key}:** {value_ist}")
                else:
                    st.markdown(f"**{key}:** {value}")

    st.markdown("### ⚠️ Risk Assessment")
    st.warning(alert.get("risk_assessment", "No risk assessment available"))


def convert_ist_to_utc(ist_date, ist_hour):
    """
    Convert IST date and hour to UTC date and hour
    IST is UTC+5:30

    Args:
        ist_date: date object in IST
        ist_hour: hour (0-23) in IST

    Returns:
        tuple: (utc_date, utc_hour)
    """
    # Create IST datetime
    ist = pytz.timezone("Asia/Kolkata")
    ist_datetime = datetime.combine(
        ist_date, datetime.min.time().replace(hour=ist_hour)
    )
    ist_datetime = ist.localize(ist_datetime)

    # Convert to UTC
    utc_datetime = ist_datetime.astimezone(pytz.UTC)

    return utc_datetime.date(), utc_datetime.hour


def show_fetch_panel():
    """Show data fetching panel with IST to UTC conversion"""
    st.markdown('<div class="fetch-section">', unsafe_allow_html=True)
    st.markdown("### 🔄 Fetch New Alert Data")

    # Add timezone info
    st.info(
        "ℹ️ Enter times in IST (Indian Standard Time). They will be automatically converted to UTC for fetching."
    )

    col1, col2 = st.columns(2)

    with col1:
        fetch_start_date = st.date_input(
            "Start Date (IST)", value=date.today(), key="fetch_start_date"
        )
        fetch_start_hour = st.number_input(
            "Start Hour IST (0-23)",
            min_value=0,
            max_value=23,
            value=0,
            key="fetch_start_hour",
            help="Enter hour in IST timezone",
        )
        fetch_interval = st.number_input(
            "Interval (minutes)",
            min_value=1,
            max_value=1440,
            value=60,
            key="fetch_interval",
        )

    with col2:
        fetch_end_date = st.date_input(
            "End Date (IST)", value=date.today(), key="fetch_end_date"
        )
        fetch_end_hour = st.number_input(
            "End Hour IST (0-23)",
            min_value=0,
            max_value=23,
            value=23,
            key="fetch_end_hour",
            help="Enter hour in IST timezone",
        )

    # Show UTC conversion preview
    if fetch_start_date and fetch_start_hour is not None:
        utc_start_date, utc_start_hour = convert_ist_to_utc(
            fetch_start_date, fetch_start_hour
        )
        utc_end_date, utc_end_hour = convert_ist_to_utc(fetch_end_date, fetch_end_hour)

        st.markdown("---")
        st.markdown("#### 🌐 UTC Conversion Preview")
        col_utc1, col_utc2 = st.columns(2)

        with col_utc1:
            st.info(f"**Start (UTC):** {utc_start_date} at {utc_start_hour:02d}:00")
        with col_utc2:
            st.info(f"**End (UTC):** {utc_end_date} at {utc_end_hour:02d}:00")

    st.markdown("---")
    st.markdown("#### Processing Options")
    col3, col4 = st.columns(2)

    with col3:
        process_user_data = st.checkbox("Process User Data", value=True)
        skip_fetch = st.checkbox("Skip Fetch (use existing)", value=False)

    with col4:
        process_endpoint = st.checkbox("Process Endpoint Security", value=True)
        skip_clean = st.checkbox("Skip Clean (use existing)", value=False)

    skip_correlation = st.checkbox("Skip Correlation (use existing)", value=False)

    st.markdown("</div>", unsafe_allow_html=True)

    col_btn1, col_btn2 = st.columns([1, 4])

    with col_btn1:
        if st.button("🚀 Fetch & Process", type="primary", width="stretch"):
            base_dir = st.session_state.get("base_dir", "sentinel_logs1")

            # Validate dates
            if fetch_end_date < fetch_start_date:
                st.error("End date must be after start date!")
                return

            # Convert IST to UTC
            utc_start_date, utc_start_hour = convert_ist_to_utc(
                fetch_start_date, fetch_start_hour
            )
            utc_end_date, utc_end_hour = convert_ist_to_utc(
                fetch_end_date, fetch_end_hour
            )

            # Show conversion info
            st.info(
                f"📅 Fetching data from {utc_start_date} {utc_start_hour:02d}:00 UTC to {utc_end_date} {utc_end_hour:02d}:00 UTC"
            )

            with st.spinner("Processing... This may take a while..."):
                try:
                    orchestrator = SelectiveWorkflowOrchestrator(
                        base_output_dir="sentinel_logs1"
                    )

                    # Show progress
                    progress_placeholder = st.empty()
                    progress_placeholder.info("🔄 Starting workflow...")

                    # Pass UTC times to the orchestrator
                    results = orchestrator.run_selective_workflow(
                        start_date=utc_start_date.strftime("%Y-%m-%d"),
                        end_date=utc_end_date.strftime("%Y-%m-%d"),
                        start_hour=utc_start_hour,
                        end_hour=utc_end_hour,
                        interval_minutes=fetch_interval,
                        process_user_data=process_user_data,
                        process_endpoint_security=process_endpoint,
                        skip_fetch=skip_fetch,
                        skip_clean=skip_clean,
                        skip_correlation=skip_correlation,
                    )

                    progress_placeholder.empty()

                    # Show results summary
                    st.success("✅ Workflow completed successfully!")

                    if results:
                        st.markdown("#### Results Summary")

                        if "user_data" in results:
                            user_data = results["user_data"]
                            st.info(
                                f"👤 User Data: {len(user_data.get('cleaned', []))} files cleaned, "
                                f"{len(user_data.get('analyzed', []))} analyzed"
                            )

                        if "endpoint_security" in results:
                            endpoint_data = results["endpoint_security"]
                            total_alerts = sum(
                                r.get("alerts_generated", 0)
                                for r in endpoint_data.get("correlated", [])
                            )
                            st.info(
                                f"🔒 Endpoint Security: {len(endpoint_data.get('cleaned', []))} files cleaned, "
                                f"{len(endpoint_data.get('correlated', []))} correlated, "
                                f"{total_alerts} alerts generated"
                            )

                    # Reload alerts
                    st.session_state.alerts = load_all_alerts(base_dir)
                    st.session_state.current_page = 1
                    st.session_state.show_fetch_panel = False
                    st.rerun()

                except Exception as e:
                    st.error(f"❌ Error during workflow execution: {str(e)}")
                    st.exception(e)

    with col_btn2:
        if st.button("Cancel", width="stretch"):
            st.session_state.show_fetch_panel = False
            st.rerun()


def main():
    # Show SOC Hub analysis if requested
    if st.session_state.get("show_soc_analysis") and st.session_state.get(
        "soc_analysis_data"
    ):
        # Sidebar for going back
        with st.sidebar:
            st.markdown("## 🤖 SOC Hub Analysis")
            if st.button(
                "← Back to Alerts Dashboard",
                key="back_to_dashboard",
                type="primary",
                width="stretch",
            ):
                st.session_state.show_soc_analysis = False
                st.session_state.soc_analysis_data = None
                st.rerun()

            st.markdown("---")

            # API Status Check
            st.markdown("### 📡 Backend Status")
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
            else:
                st.error("❌ API Not Connected")
                st.caption("AI features require backend API")

        # Display the SOC Hub analysis
        display_ai_analysis(st.session_state.soc_analysis_data)
        return

    # Show modal if alert is selected
    if st.session_state.get("show_overlay") and st.session_state.get("selected_alert"):
        show_alert_detail_modal(st.session_state.selected_alert)
        return

    # Show fetch panel if requested
    if st.session_state.get("show_fetch_panel"):
        st.markdown(
            '<h1 class="main-header">🛡️ Unified Security Alerts Dashboard</h1>',
            unsafe_allow_html=True,
        )
        show_fetch_panel()
        return

    st.markdown(
        '<h1 class="main-header">🛡️ Unified Security Alerts Dashboard</h1>',
        unsafe_allow_html=True,
    )

    # Sidebar for configuration and filters
    with st.sidebar:
        st.markdown("## 📊 Configuration")

        base_dir = st.text_input(
            "Base Directory", value="sentinel_logs1", key="base_dir_input"
        )
        if base_dir != st.session_state.get("base_dir"):
            st.session_state.base_dir = base_dir

        # Fetch data button
        if st.button("🔄 Fetch New Data", type="primary", width="stretch"):
            st.session_state.show_fetch_panel = True
            st.rerun()

        # Auto-load alerts on startup
        if "alerts" not in st.session_state:
            if os.path.exists(base_dir):
                with st.spinner("Loading all alerts from all timelines..."):
                    st.session_state.alerts = load_all_alerts(base_dir)
                if st.session_state.alerts:
                    st.success(f"✅ Loaded {len(st.session_state.alerts)} alerts!")
            else:
                st.error(f"❌ Directory '{base_dir}' not found")
                st.session_state.alerts = []

        # Manual reload button
        if st.button("🔃 Reload Alerts", width="stretch"):
            if os.path.exists(base_dir):
                with st.spinner("Reloading all alerts..."):
                    st.session_state.alerts = load_all_alerts(base_dir)
                    st.session_state.current_page = 1
                st.success(f"✅ Loaded {len(st.session_state.alerts)} alerts!")
            else:
                st.error(f"❌ Directory '{base_dir}' not found")

        st.markdown("---")

        # API Status Check in sidebar
        st.markdown("### 📡 Backend Status")
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
        else:
            st.warning("⚠️ API Not Connected")
            st.caption("AI analysis features unavailable")

        st.markdown("---")
        st.markdown("### 🔍 Filters")

        # Filters
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

            st.markdown("---")
            items_per_page = st.selectbox(
                "Items per page",
                options=[10, 25, 50, 100],
                index=2,
                key="items_per_page_selector",
            )
            if items_per_page != st.session_state.items_per_page:
                st.session_state.items_per_page = items_per_page
                st.session_state.current_page = 1
                st.rerun()

            st.session_state.severity_filter = severity_filter
            st.session_state.source_filter = source_filter
            st.session_state.category_filter = category_filter
            st.session_state.sort_by = sort_by
            st.session_state.sort_order = sort_order

    # Main content area
    if "alerts" not in st.session_state or not st.session_state.alerts:
        st.info("⏳ No alerts loaded. Click '🔄 Fetch New Data' to get started.")
        st.markdown(
            """
        ### 📋 Dashboard Features
        
        - **Unified View**: All alerts from all timelines combined
        - **Time Conversion**: Timestamps automatically converted from UTC to IST (UTC+5:30)
        - **Smart Filtering**: Filter by severity, source, and category
        - **Detailed Views**: Click any alert to see comprehensive details
        - **SOC Hub Analysis**: AI-powered threat analysis with ML predictions
        - **Pagination**: Navigate through alerts with easy pagination controls
        - **Data Fetching**: Fetch new data directly from Azure Sentinel
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
                col_main, col_btn_view, col_btn_analyze = st.columns([4, 1, 1])

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

                with col_btn_view:
                    # View Details button
                    if st.button(
                        "👁️ View",
                        key=f"view_{global_idx}_{alert['alert_id']}_{st.session_state.current_page}",
                        width="stretch",
                        type="secondary",
                    ):
                        st.session_state.selected_alert = alert
                        st.session_state.show_overlay = True
                        st.rerun()

                with col_btn_analyze:
                    # Analyze in SOC Hub button
                    if st.button(
                        "🤖 Analyze",
                        key=f"analyze_{global_idx}_{alert['alert_id']}_{st.session_state.current_page}",
                        width="stretch",
                        type="primary",
                        help="Open in SOC Hub for AI-powered analysis",
                    ):
                        # Convert raw alert to SOC format
                        soc_alert_data = convert_raw_alert_to_soc_format(alert)

                        # Set session state for SOC analysis
                        st.session_state.soc_analysis_data = soc_alert_data
                        st.session_state.show_soc_analysis = True
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

    # Footer
    st.markdown("---")
    st.markdown(
        """
        <div style="text-align: center; color: #666; padding: 1rem;">
            🛡️ Security Alerts Dashboard | Integrated with Azure Sentinel & SOC Hub AI Analysis
        </div>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
