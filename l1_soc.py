import streamlit as st
import json
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
import requests
from azure.identity import DefaultAzureCredential
import math

# Page configuration
st.set_page_config(
    page_title="Microsoft Sentinel - Incidents Dashboard", page_icon="🛡️", layout="wide"
)

# Custom CSS for better styling
st.markdown(
    """
    <style>
    .incident-card {
        border: 1px solid #ddd;
        border-radius: 8px;
        padding: 15px;
        margin-bottom: 15px;
        background-color: #f9f9f9;
        cursor: pointer;
        transition: all 0.3s ease;
    }
    .incident-card:hover {
        box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        transform: translateY(-2px);
    }
    .severity-high {
        color: #d32f2f;
        font-weight: bold;
    }
    .severity-medium {
        color: #f57c00;
        font-weight: bold;
    }
    .severity-low {
        color: #fbc02d;
        font-weight: bold;
    }
    .severity-informational {
        color: #1976d2;
        font-weight: bold;
    }
    .status-badge {
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 12px;
        font-weight: bold;
    }
    .status-new {
        background-color: #e3f2fd;
        color: #1976d2;
    }
    .status-active {
        background-color: #fff3e0;
        color: #f57c00;
    }
    .status-closed {
        background-color: #e8f5e9;
        color: #388e3c;
    }
    .alert-card {
        background-color: #fff3e0;
        border-left: 4px solid #f57c00;
        padding: 12px;
        margin: 8px 0;
        border-radius: 4px;
    }
    .entity-badge {
        display: inline-block;
        padding: 4px 8px;
        margin: 2px;
        border-radius: 4px;
        background-color: #e3f2fd;
        color: #1565c0;
        font-size: 12px;
    }
    .pagination-info {
        text-align: center;
        padding: 20px;
        font-size: 16px;
        color: #666;
    }
    </style>
""",
    unsafe_allow_html=True,
)


def load_incidents_from_file(file_path="sentinel_all_incidents.json"):
    """Load incidents from JSON file"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("value", [])
    except FileNotFoundError:
        st.error(f"File {file_path} not found. Please run the fetch script first.")
        return []
    except json.JSONDecodeError:
        st.error("Error parsing JSON file.")
        return []


def fetch_incident_details(incident_id):
    """Fetch detailed incident data including alerts and entities"""
    load_dotenv()

    subscription_id = os.getenv("SUBSCRIPTION_ID")
    resource_group = os.getenv("RESOURCE_GROUP")
    workspace_name = os.getenv("WORKSPACE_NAME")

    if not all([subscription_id, resource_group, workspace_name]):
        return None

    try:
        credential = DefaultAzureCredential()
        token = credential.get_token("https://management.azure.com/.default").token
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        incident_resource_id = (
            f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/"
            f"Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/"
            f"Microsoft.SecurityInsights/Incidents/{incident_id}"
        )

        details = {}

        # Fetch alerts
        alerts_url = f"https://management.azure.com{incident_resource_id}/alerts?api-version=2025-09-01"
        try:
            alerts_response = requests.post(alerts_url, headers=headers)
            if alerts_response.status_code == 200:
                details["alerts"] = alerts_response.json()
        except:
            pass

        # Fetch entities
        entities_url = f"https://management.azure.com{incident_resource_id}/entities?api-version=2025-09-01"
        try:
            entities_response = requests.post(entities_url, headers=headers)
            if entities_response.status_code == 200:
                details["entities"] = entities_response.json()
        except:
            pass

        return details
    except Exception as e:
        st.error(f"Error fetching incident details: {str(e)}")
        return None


def fetch_incidents_from_azure(timespan_days=90, status_filters=None):
    """Fetch incidents directly from Azure with filters"""
    load_dotenv()

    subscription_id = os.getenv("SUBSCRIPTION_ID")
    resource_group = os.getenv("RESOURCE_GROUP")
    workspace_name = os.getenv("WORKSPACE_NAME")

    if not all([subscription_id, resource_group, workspace_name]):
        st.error("Missing environment variables. Please check your .env file.")
        return []

    try:
        credential = DefaultAzureCredential()
        token = credential.get_token("https://management.azure.com/.default").token

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        # Define time range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=timespan_days)

        # Format dates in ISO 8601 format
        start_date_str = start_date.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_date_str = end_date.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Build filter
        filters = [
            f"properties/createdTimeUtc ge {start_date_str}",
            f"properties/createdTimeUtc le {end_date_str}",
        ]

        # Add status filters if specified
        if status_filters:
            if len(status_filters) == 1:
                filters.append(f"properties/status eq '{status_filters[0]}'")
            elif len(status_filters) > 1:
                status_conditions = " or ".join(
                    [f"properties/status eq '{s}'" for s in status_filters]
                )
                filters.append(f"({status_conditions})")

        filter_query = " and ".join(filters)

        base_url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights"
            f"/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/incidents"
        )

        url = f"{base_url}?api-version=2025-09-01&$filter={filter_query}"

        all_incidents = []

        progress_bar = st.progress(0)
        status_text = st.empty()

        page = 0
        while url:
            page += 1
            status_text.text(f"Fetching page {page}...")

            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                incidents = data.get("value", [])
                all_incidents.extend(incidents)

                # Update progress
                progress_bar.progress(min(len(all_incidents) / 100, 1.0))

                # Get the nextLink for pagination
                url = data.get("nextLink", None)
            else:
                st.error(f"Error fetching incidents: {response.status_code}")
                break

        progress_bar.empty()
        status_text.empty()

        # Analyze status distribution
        status_counts = {}
        for incident in all_incidents:
            status = incident.get("properties", {}).get("status", "Unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

        st.success(f"✅ Fetched {len(all_incidents)} incidents")
        with st.expander("Status Distribution"):
            for status, count in status_counts.items():
                st.write(f"**{status}:** {count}")

        return all_incidents
    except Exception as e:
        st.error(f"Error connecting to Azure: {str(e)}")
        return []


def get_severity_color(severity):
    """Return CSS class based on severity"""
    severity_map = {
        "High": "severity-high",
        "Medium": "severity-medium",
        "Low": "severity-low",
        "Informational": "severity-informational",
    }
    return severity_map.get(severity, "")


def get_status_class(status):
    """Return CSS class based on status"""
    status_map = {
        "New": "status-new",
        "Active": "status-active",
        "Closed": "status-closed",
    }
    return status_map.get(status, "status-new")


def format_datetime(dt_string):
    """Format datetime string to readable format"""
    try:
        dt = datetime.fromisoformat(dt_string.replace("Z", "+00:00"))
        return dt.strftime("%d %b %Y, %I:%M %p UTC")
    except:
        return dt_string


def display_entity(entity):
    """Display entity information"""
    kind = entity.get("kind", "Unknown")
    properties = entity.get("properties", {})

    entity_info = f"**{kind}**"

    # Extract relevant information based on entity type
    if kind == "Account":
        name = properties.get("accountName") or properties.get("displayName")
        upn = properties.get("userPrincipalName")
        if name:
            entity_info += f": {name}"
        if upn:
            entity_info += f" ({upn})"
    elif kind == "Ip":
        address = properties.get("address")
        location = properties.get("location", {})
        if address:
            entity_info += f": {address}"
        if location:
            country = location.get("countryName") or location.get("countryCode")
            if country:
                entity_info += f" ({country})"
    elif kind == "Host":
        hostname = properties.get("hostName") or properties.get("dnsDomain")
        os_family = properties.get("osFamily")
        if hostname:
            entity_info += f": {hostname}"
        if os_family:
            entity_info += f" ({os_family})"
    elif kind == "File":
        filename = properties.get("fileName")
        file_hash = properties.get("fileHashValue")
        if filename:
            entity_info += f": {filename}"
        if file_hash:
            entity_info += f" (Hash: {file_hash[:16]}...)"
    elif kind == "Url":
        url = properties.get("url")
        if url:
            entity_info += f": {url[:60]}..."
    elif kind == "Process":
        process_name = properties.get("processName")
        command_line = properties.get("commandLine")
        if process_name:
            entity_info += f": {process_name}"
        if command_line:
            entity_info += f" ({command_line[:40]}...)"
    elif kind == "MailMessage":
        subject = properties.get("subject")
        sender = properties.get("sender")
        if subject:
            entity_info += f": {subject[:50]}..."
        if sender:
            entity_info += f" (From: {sender})"
    elif kind == "CloudApplication":
        app_name = properties.get("appName")
        if app_name:
            entity_info += f": {app_name}"
    elif kind == "RegistryKey":
        key = properties.get("key")
        if key:
            entity_info += f": {key[:60]}..."
    elif kind == "RegistryValue":
        key = properties.get("key")
        value = properties.get("value")
        if key:
            entity_info += f": {key}"
        if value:
            entity_info += f" = {value}"

    return entity_info


def display_alert(alert, entities_data):
    """Display alert details with entities in accordion format"""
    props = alert.get("properties", {})

    alert_name = props.get("alertDisplayName", "Unknown Alert")
    severity = props.get("severity", "Unknown")
    status = props.get("status", "Unknown")
    description = props.get("description", "")

    # Create accordion header with severity and status badges
    accordion_title = f"{alert_name} — {severity} • {status}"

    with st.expander(accordion_title, expanded=False):
        st.markdown(f'<div class="alert-card">', unsafe_allow_html=True)

        # Severity and Status badges
        col1, col2 = st.columns([1, 1])
        with col1:
            st.markdown(
                f'<span class="{get_severity_color(severity)}">Severity: {severity}</span>',
                unsafe_allow_html=True,
            )
        with col2:
            st.markdown(f"*Status: {status}*")

        st.divider()

        # Alert description
        if description:
            st.markdown(f"**Description:** _{description}_")

        # Time information
        start_time = props.get("startTimeUtc")
        end_time = props.get("endTimeUtc")

        col1, col2 = st.columns(2)
        with col1:
            if start_time:
                st.markdown(f"**Started:** {format_datetime(start_time)}")
        with col2:
            if end_time:
                st.markdown(f"**Ended:** {format_datetime(end_time)}")

        st.divider()

        # Tactics and Techniques
        tactics = props.get("tactics", [])
        techniques = props.get("techniques", [])

        if tactics or techniques:
            st.markdown("**MITRE ATT&CK:**")
            if tactics:
                st.markdown(f"Tactics: {', '.join(tactics)}")
            if techniques:
                st.markdown(f"Techniques: {', '.join(techniques)}")

        # Entities associated with this alert
        if entities_data and "entities" in entities_data:
            alert_entities = entities_data["entities"]
            if alert_entities:
                st.markdown("**Associated Entities:**")

                # Group entities by type
                entities_by_type = {}
                for entity in alert_entities:
                    kind = entity.get("kind", "Unknown")
                    if kind not in entities_by_type:
                        entities_by_type[kind] = []
                    entities_by_type[kind].append(entity)

                # Display entities by type in nested expanders
                for entity_type, entities in entities_by_type.items():
                    with st.expander(
                        f"📌 {entity_type} ({len(entities)})", expanded=False
                    ):
                        for entity in entities:
                            st.markdown(f"- {display_entity(entity)}")

        st.markdown("</div>", unsafe_allow_html=True)


def display_incident_overview(incident, index):
    """Display incident as a clickable card in overview"""
    props = incident.get("properties", {})

    title = props.get("title", "Untitled Incident")
    severity = props.get("severity", "Unknown")
    status = props.get("status", "Unknown")
    incident_number = props.get("incidentNumber", "N/A")
    created = props.get("createdTimeUtc")

    # Get alert count
    additional_data = props.get("additionalData", {})
    alert_count = additional_data.get("alertsCount", 0)

    # Create a container for the incident card
    with st.container():
        # Display column headers on first incident
        if index == 0 or (index % 50 == 0):
            col1, col2, col3, col4, col5, col6 = st.columns([1, 4, 1.5, 1.5, 1.5, 1.5])
            with col1:
                st.caption("incident #")
            with col2:
                st.caption("title")
            with col3:
                st.caption("severity")
            with col4:
                st.caption("status")
            with col5:
                st.caption("alerts")
            with col6:
                st.caption("action")

        col1, col2, col3, col4, col5, col6 = st.columns([1, 4, 1.5, 1.5, 1.5, 1.5])

        with col1:
            st.markdown(f"**#{incident_number}**")

        with col2:
            st.markdown(f"**{title}**")

        with col3:
            st.markdown(
                f'<span class="{get_severity_color(severity)}">{severity}</span>',
                unsafe_allow_html=True,
            )

        with col4:
            st.markdown(
                f'<span class="status-badge {get_status_class(status)}">{status}</span>',
                unsafe_allow_html=True,
            )

        with col5:
            st.markdown(f"**{alert_count}**")

        with col6:
            if st.button("View Details", key=f"view_{index}"):
                st.session_state.selected_incident = incident
                st.session_state.page = "detail"
                st.rerun()

        if created:
            st.caption(f"Created: {format_datetime(created)}")

        st.divider()


def display_incident_detail(incident):
    """Display full incident details on detail page"""
    props = incident.get("properties", {})

    title = props.get("title", "Untitled Incident")
    severity = props.get("severity", "Unknown")
    status = props.get("status", "Unknown")
    incident_number = props.get("incidentNumber", "N/A")
    incident_id = incident.get("name")

    # Back button
    if st.button("← Back to Incidents List"):
        st.session_state.page = "overview"
        st.rerun()

    st.title(f"🔔 Incident #{incident_number}")
    st.markdown(f"## {title}")

    st.divider()

    # Main incident info
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(f"**Severity:**")
        st.markdown(
            f'<span class="{get_severity_color(severity)}">{severity}</span>',
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(f"**Status:**")
        st.markdown(
            f'<span class="status-badge {get_status_class(status)}">{status}</span>',
            unsafe_allow_html=True,
        )

    with col3:
        st.markdown(f"**Classification:**")
        st.write(props.get("classification", "N/A"))

    with col4:
        st.markdown(f"**Provider:**")
        st.write(props.get("providerName", "N/A"))

    st.divider()

    # Timeline
    st.markdown("### 📅 Timeline")
    col1, col2 = st.columns(2)

    with col1:
        created = props.get("createdTimeUtc")
        first_activity = props.get("firstActivityTimeUtc")
        if created:
            st.write(f"**Created:** {format_datetime(created)}")
        if first_activity:
            st.write(f"**First Activity:** {format_datetime(first_activity)}")

    with col2:
        last_activity = props.get("lastActivityTimeUtc")
        last_modified = props.get("lastModifiedTimeUtc")
        if last_activity:
            st.write(f"**Last Activity:** {format_datetime(last_activity)}")
        if last_modified:
            st.write(f"**Last Modified:** {format_datetime(last_modified)}")

    st.divider()

    # Fetch and display alerts
    additional_data = props.get("additionalData", {})
    alert_count = additional_data.get("alertsCount", 0)

    st.markdown(f"### 🚨 Alerts ({alert_count})")

    if alert_count > 0:
        # Check if we have cached details
        cache_key = f"incident_details_{incident_id}"

        if cache_key not in st.session_state:
            with st.spinner("Loading alerts and entities..."):
                details = fetch_incident_details(incident_id)
                if details:
                    st.session_state[cache_key] = details

        if cache_key in st.session_state:
            details = st.session_state[cache_key]

            alerts = details.get("alerts", {}).get("value", [])
            entities_data = details.get("entities", {})

            if alerts:
                for idx, alert in enumerate(alerts):
                    display_alert(alert, entities_data)
                    if idx < len(alerts) - 1:
                        st.markdown("---")
            else:
                st.info(
                    f"This incident has {alert_count} alert(s), but details couldn't be loaded."
                )
        else:
            st.warning("Failed to load incident details. Please try again.")
    else:
        st.write("No alerts associated with this incident.")

    # Tactics and Techniques
    if additional_data.get("tactics") or additional_data.get("techniques"):
        st.markdown("### 🎯 MITRE ATT&CK")
        if additional_data.get("tactics"):
            st.write(f"**Tactics:** {', '.join(additional_data['tactics'])}")
        if additional_data.get("techniques"):
            st.write(f"**Techniques:** {', '.join(additional_data['techniques'])}")

    # Owner information
    owner = props.get("owner", {})
    if owner.get("assignedTo"):
        st.markdown("### 👤 Owner")
        st.write(f"**Assigned To:** {owner.get('assignedTo')}")
        if owner.get("email"):
            st.write(f"**Email:** {owner.get('email')}")


def apply_time_filter(incidents, days):
    """Filter incidents by time range"""
    if days == 0:  # All time
        return incidents

    cutoff_date = datetime.utcnow() - timedelta(days=days)

    filtered = []
    for incident in incidents:
        created_str = incident.get("properties", {}).get("createdTimeUtc")
        if created_str:
            try:
                created_date = datetime.fromisoformat(
                    created_str.replace("Z", "+00:00")
                )
                if created_date.replace(tzinfo=None) >= cutoff_date:
                    filtered.append(incident)
            except:
                filtered.append(incident)  # Include if we can't parse the date
        else:
            filtered.append(incident)

    return filtered


# Main application
def main():
    # Initialize session state
    if "page" not in st.session_state:
        st.session_state.page = "overview"

    if "incidents" not in st.session_state:
        st.session_state.incidents = load_incidents_from_file()

    if "selected_incident" not in st.session_state:
        st.session_state.selected_incident = None

    if "current_page" not in st.session_state:
        st.session_state.current_page = 1

    # Route to appropriate page
    if st.session_state.page == "detail" and st.session_state.selected_incident:
        display_incident_detail(st.session_state.selected_incident)
    else:
        display_overview_page()


def display_overview_page():
    """Display the incidents overview page with pagination"""
    st.title("🛡️ Microsoft Sentinel - Incidents Dashboard")
    st.markdown("---")

    # Sidebar for filters and options
    with st.sidebar:
        st.header("⚙️ Data Source")

        data_source = st.radio(
            "Select Source",
            ["Load from File", "Fetch from Azure"],
            help="Choose to load incidents from a local file or fetch directly from Azure",
        )

        if data_source == "Fetch from Azure":
            st.markdown("### ⏱️ Time Range")

            # Timespan selector
            timespan_option = st.selectbox(
                "Select Timespan",
                [
                    "Last 7 days",
                    "Last 30 days",
                    "Last 90 days",
                    "Last 180 days",
                    "Last 365 days",
                    "Custom",
                ],
                index=2,  # Default to Last 90 days
            )

            # Map timespan to days
            timespan_map = {
                "Last 7 days": 7,
                "Last 30 days": 30,
                "Last 90 days": 90,
                "Last 180 days": 180,
                "Last 365 days": 365,
            }

            if timespan_option == "Custom":
                custom_days = st.number_input(
                    "Enter number of days", min_value=1, max_value=365, value=90
                )
                timespan_days = custom_days
            else:
                timespan_days = timespan_map[timespan_option]

            # Status filter for Azure fetch
            st.markdown("### 📊 Status Filter (Azure Fetch)")
            azure_status_filter = st.multiselect(
                "Filter by Status",
                options=["New", "Active", "Closed"],
                default=[],
                help="Leave empty to fetch all statuses",
            )

            if st.button("🔄 Fetch Incidents", type="primary"):
                incidents = fetch_incidents_from_azure(
                    timespan_days=timespan_days,
                    status_filters=azure_status_filter if azure_status_filter else None,
                )
                st.session_state.incidents = incidents
                st.session_state.current_page = 1  # Reset to first page

                # Save to file
                if incidents:
                    with open(
                        "sentinel_all_incidents.json", "w", encoding="utf-8"
                    ) as f:
                        json.dump({"value": incidents}, f, indent=4, ensure_ascii=False)
                    st.success("💾 Incidents saved to sentinel_all_incidents.json")
        else:
            if st.button("📂 Load from File", type="primary"):
                incidents = load_incidents_from_file()
                st.session_state.incidents = incidents
                st.session_state.current_page = 1  # Reset to first page
                if incidents:
                    st.success(f"✅ Loaded {len(incidents)} incidents from file")

        st.markdown("---")
        st.header("🔍 Filters")

    incidents = st.session_state.incidents

    if not incidents:
        st.warning(
            "No incidents loaded. Please load incidents from file or fetch from Azure."
        )
        return

    # Filters in sidebar
    with st.sidebar:
        # Time filter for loaded data
        st.markdown("### ⏱️ Time Range Filter")
        time_filter = st.selectbox(
            "Filter by Creation Time",
            [
                "All Time",
                "Last 7 days",
                "Last 30 days",
                "Last 90 days",
                "Last 180 days",
                "Last 365 days",
            ],
            index=0,
        )

        time_filter_map = {
            "All Time": 0,
            "Last 7 days": 7,
            "Last 30 days": 30,
            "Last 90 days": 90,
            "Last 180 days": 180,
            "Last 365 days": 365,
        }

        time_filter_days = time_filter_map[time_filter]

        severity_filter = st.multiselect(
            "Severity",
            options=["High", "Medium", "Low", "Informational"],
            default=["High", "Medium", "Low", "Informational"],
        )

        status_filter = st.multiselect(
            "Status",
            options=["New", "Active", "Closed"],
            default=["New", "Active", "Closed"],
        )

        search_term = st.text_input("🔎 Search in title", "")

        incident_number_search = st.text_input(
            "🔢 Search by Incident Number", "", placeholder="e.g., 26"
        )

        # Clear cache button
        if st.button("🗑️ Clear Alert Cache"):
            # Clear all cached incident details
            keys_to_remove = [
                key
                for key in st.session_state.keys()
                if key.startswith("incident_details_")
            ]
            for key in keys_to_remove:
                del st.session_state[key]
            st.success("Cache cleared!")

    # Apply filters
    filtered_incidents = incidents

    # Apply time filter
    if time_filter_days > 0:
        filtered_incidents = apply_time_filter(filtered_incidents, time_filter_days)

    if severity_filter:
        filtered_incidents = [
            inc
            for inc in filtered_incidents
            if inc.get("properties", {}).get("severity") in severity_filter
        ]

    if status_filter:
        filtered_incidents = [
            inc
            for inc in filtered_incidents
            if inc.get("properties", {}).get("status") in status_filter
        ]

    if search_term:
        filtered_incidents = [
            inc
            for inc in filtered_incidents
            if search_term.lower() in inc.get("properties", {}).get("title", "").lower()
        ]

    if incident_number_search:
        try:
            search_number = int(incident_number_search)
            filtered_incidents = [
                inc
                for inc in filtered_incidents
                if inc.get("properties", {}).get("incidentNumber") == search_number
            ]
        except ValueError:
            st.sidebar.warning("Please enter a valid incident number")

    # Display statistics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Incidents", len(filtered_incidents))

    with col2:
        high_severity = len(
            [
                i
                for i in filtered_incidents
                if i.get("properties", {}).get("severity") == "High"
            ]
        )
        st.metric("High Severity", high_severity)

    with col3:
        active_incidents = len(
            [
                i
                for i in filtered_incidents
                if i.get("properties", {}).get("status") in ["New", "Active"]
            ]
        )
        st.metric("Active", active_incidents)

    with col4:
        closed_incidents = len(
            [
                i
                for i in filtered_incidents
                if i.get("properties", {}).get("status") == "Closed"
            ]
        )
        st.metric("Closed", closed_incidents)

    st.markdown("---")

    # Sort options
    col1, col2 = st.columns([3, 1])
    with col2:
        sort_by = st.selectbox(
            "Sort by",
            [
                "Incident Number (Desc)",
                "Incident Number (Asc)",
                "Severity",
                "Alert Count (Desc)",
                "Alert Count (Asc)",
                "Created Time (Recent)",
                "Created Time (Oldest)",
            ],
        )

    # Sort incidents
    if sort_by == "Incident Number (Desc)":
        filtered_incidents = sorted(
            filtered_incidents,
            key=lambda x: x.get("properties", {}).get("incidentNumber", 0),
            reverse=True,
        )
    elif sort_by == "Incident Number (Asc)":
        filtered_incidents = sorted(
            filtered_incidents,
            key=lambda x: x.get("properties", {}).get("incidentNumber", 0),
        )
    elif sort_by == "Severity":
        severity_order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
        filtered_incidents = sorted(
            filtered_incidents,
            key=lambda x: severity_order.get(
                x.get("properties", {}).get("severity", "Low"), 4
            ),
        )
    elif sort_by == "Alert Count (Desc)":
        filtered_incidents = sorted(
            filtered_incidents,
            key=lambda x: x.get("properties", {})
            .get("additionalData", {})
            .get("alertsCount", 0),
            reverse=True,
        )
    elif sort_by == "Alert Count (Asc)":
        filtered_incidents = sorted(
            filtered_incidents,
            key=lambda x: x.get("properties", {})
            .get("additionalData", {})
            .get("alertsCount", 0),
        )
    elif sort_by == "Created Time (Recent)":
        filtered_incidents = sorted(
            filtered_incidents,
            key=lambda x: x.get("properties", {}).get("createdTimeUtc", ""),
            reverse=True,
        )
    elif sort_by == "Created Time (Oldest)":
        filtered_incidents = sorted(
            filtered_incidents,
            key=lambda x: x.get("properties", {}).get("createdTimeUtc", ""),
        )

    # Pagination
    ITEMS_PER_PAGE = 50
    total_incidents = len(filtered_incidents)
    total_pages = (
        math.ceil(total_incidents / ITEMS_PER_PAGE) if total_incidents > 0 else 1
    )

    # Ensure current page is within bounds
    if st.session_state.current_page > total_pages:
        st.session_state.current_page = total_pages
    if st.session_state.current_page < 1:
        st.session_state.current_page = 1

    # Calculate pagination indices
    start_idx = (st.session_state.current_page - 1) * ITEMS_PER_PAGE
    end_idx = min(start_idx + ITEMS_PER_PAGE, total_incidents)

    # Get current page incidents
    current_page_incidents = filtered_incidents[start_idx:end_idx]

    # Display incidents
    st.markdown("## Incidents")

    if not filtered_incidents:
        st.info("No incidents match the selected filters.")
    else:
        # Pagination controls at top
        col1, col2, col3, col4, col5 = st.columns([1, 1, 2, 1, 1])

        with col1:
            if st.button("⏮️ First", disabled=(st.session_state.current_page == 1)):
                st.session_state.current_page = 1
                st.rerun()

        with col2:
            if st.button("◀️ Previous", disabled=(st.session_state.current_page == 1)):
                st.session_state.current_page -= 1
                st.rerun()

        with col3:
            st.markdown(
                f'<div class="pagination-info">Page {st.session_state.current_page} of {total_pages} | '
                f"Showing {start_idx + 1}-{end_idx} of {total_incidents} incidents</div>",
                unsafe_allow_html=True,
            )

        with col4:
            if st.button(
                "Next ▶️", disabled=(st.session_state.current_page == total_pages)
            ):
                st.session_state.current_page += 1
                st.rerun()

        with col5:
            if st.button(
                "Last ⏭️", disabled=(st.session_state.current_page == total_pages)
            ):
                st.session_state.current_page = total_pages
                st.rerun()

        st.markdown("---")

        # Display incidents for current page
        for idx, incident in enumerate(current_page_incidents):
            display_incident_overview(incident, start_idx + idx)

        # Pagination controls at bottom
        st.markdown("---")
        col1, col2, col3, col4, col5 = st.columns([1, 1, 2, 1, 1])

        with col1:
            if st.button(
                "⏮️ First ",
                key="first_bottom",
                disabled=(st.session_state.current_page == 1),
            ):
                st.session_state.current_page = 1
                st.rerun()

        with col2:
            if st.button(
                "◀️ Previous ",
                key="prev_bottom",
                disabled=(st.session_state.current_page == 1),
            ):
                st.session_state.current_page -= 1
                st.rerun()

        with col3:
            st.markdown(
                f'<div class="pagination-info">Page {st.session_state.current_page} of {total_pages} | '
                f"Showing {start_idx + 1}-{end_idx} of {total_incidents} incidents</div>",
                unsafe_allow_html=True,
            )

        with col4:
            if st.button(
                "Next ▶️ ",
                key="next_bottom",
                disabled=(st.session_state.current_page == total_pages),
            ):
                st.session_state.current_page += 1
                st.rerun()

        with col5:
            if st.button(
                "Last ⏭️ ",
                key="last_bottom",
                disabled=(st.session_state.current_page == total_pages),
            ):
                st.session_state.current_page = total_pages
                st.rerun()


if __name__ == "__main__":
    main()
