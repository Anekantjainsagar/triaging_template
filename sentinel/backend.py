import json
import os
import requests
import streamlit as st
from dotenv import load_dotenv
from datetime import datetime, timedelta
from azure.identity import DefaultAzureCredential
from api_client.analyzer_api_client import get_analyzer_client


@st.cache_data(ttl=60)
def check_api_status():
    """Check if backend API is running"""
    try:
        api_client = get_analyzer_client()
        health = api_client.health_check()

        if health.get("status") == "healthy":
            return True, health
        else:
            return False, health
    except Exception as e:
        return False, {"status": "error", "error": str(e)}


def check_signin_logs_freshness():
    """Check if SigninLogs.json needs to be refreshed"""
    signin_logs_path = "sentinel_logs/SigninLogs.json"

    if not os.path.exists(signin_logs_path):
        return True, "File does not exist"

    try:
        with open(signin_logs_path, "r") as f:
            data = json.load(f)
            timestamp_str = data.get("timestamp")

            if not timestamp_str:
                return True, "No timestamp found"

            file_timestamp = datetime.fromisoformat(
                timestamp_str.replace("Z", "+00:00")
            )
            current_time = datetime.utcnow()
            time_diff = current_time - file_timestamp.replace(tzinfo=None)

            if time_diff > timedelta(hours=1):
                return True, f"Data is {time_diff.total_seconds()/3600:.1f} hours old"
            else:
                return False, f"Data is {time_diff.total_seconds()/60:.1f} minutes old"
    except Exception as e:
        return True, f"Error: {str(e)}"




def load_logs(table_name, days_filter=30):
    """Load logs from JSON file with time filtering"""
    file_path = f"sentinel_logs/{table_name}.json"

    if not os.path.exists(file_path):
        return None, f"File not found: {file_path}"

    try:
        with open(file_path, "r") as f:
            data = json.load(f)

        logs = data.get("data", [])

        if not logs:
            return [], "No logs available"

        # Filter by days
        cutoff_date = datetime.utcnow() - timedelta(days=days_filter)
        filtered_logs = []

        for log in logs:
            time_generated = log.get("TimeGenerated")
            if time_generated:
                try:
                    log_time = datetime.fromisoformat(
                        time_generated.replace("Z", "+00:00")
                    )
                    if log_time.replace(tzinfo=None) >= cutoff_date:
                        filtered_logs.append(log)
                except:
                    filtered_logs.append(log)
            else:
                filtered_logs.append(log)

        return filtered_logs, None
    except Exception as e:
        return None, str(e)


def format_entity_display(entity):
    kind = entity.get("kind", "Unknown")
    props = entity.get("properties", {})

    if kind == "Account":
        account_name = props.get("accountName", "")
        upn_suffix = props.get("upnSuffix", "")
        friendly_name = props.get("friendlyName", "")

        # Format as accountName@upnSuffix
        if account_name and upn_suffix:
            primary = f"{account_name}@{upn_suffix}"
        elif account_name:
            primary = account_name
        else:
            primary = friendly_name or "Unknown Account"

        # Add friendly name if different
        if friendly_name and friendly_name != account_name:
            return f"👤 **{primary}** (Friendly: {friendly_name})"
        else:
            return f"👤 **{primary}**"

    elif kind == "Ip":
        address = props.get("address", "Unknown IP")
        location = props.get("location", {})
        country = location.get("countryName", "") if location else ""

        if country:
            return f"🌐 **{address}** ({country})"
        else:
            return f"🌐 **{address}**"

    elif kind == "Host":
        hostname = props.get("hostName") or props.get("netBiosName") or "Unknown Host"
        os = props.get("oSFamily", "")

        if os:
            return f"💻 **{hostname}** (OS: {os})"
        else:
            return f"💻 **{hostname}**"

    elif kind == "Url":
        url = props.get("url", "Unknown URL")
        return f"🔗 **{url}**"

    elif kind == "File":
        filename = props.get("name") or props.get("fileName") or "Unknown File"
        file_hash = props.get("fileHashValue", "")

        if file_hash:
            return f"📄 **{filename}** (Hash: {file_hash[:16]}...)"
        else:
            return f"📄 **{filename}**"

    elif kind == "Process":
        process_name = props.get("processName") or props.get(
            "commandLine", "Unknown Process"
        )
        process_id = props.get("processId", "")

        if process_id:
            return f"⚙️ **{process_name}** (PID: {process_id})"
        else:
            return f"⚙️ **{process_name}**"

    elif kind == "MailMessage":
        sender = props.get("sender", "Unknown Sender")
        recipient = props.get("recipient", "Unknown Recipient")
        subject = props.get("subject", "No Subject")

        mail_info = f"📧 **From:** {sender}"
        if recipient:
            mail_info += f" | **To:** {recipient}"
        mail_info += f" | **Subject:** {subject}"
        return mail_info

    elif kind == "CloudApplication":
        app_name = props.get("name") or props.get("displayName") or "Unknown App"
        return f"☁️ **{app_name}**"

    else:
        # Generic display for unknown entity types
        name = (
            props.get("name")
            or props.get("displayName")
            or props.get("friendlyName")
            or f"Unknown {kind}"
        )
        return f"📋 **{name}**"


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
