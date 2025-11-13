import json
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta

load_dotenv()


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


def refresh_signin_logs():
    """Refresh SigninLogs by calling the function directly"""
    try:
        import os
        import json
        import requests
        from dotenv import load_dotenv
        from datetime import datetime, timedelta
        from azure.identity import DefaultAzureCredential

        load_dotenv()

        subscription_id = os.getenv("SUBSCRIPTION_ID")
        resource_group = os.getenv("RESOURCE_GROUP")
        workspace_name = os.getenv("WORKSPACE_NAME")

        credential = DefaultAzureCredential()
        token = credential.get_token("https://api.loganalytics.io/.default").token
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        mgmt_token = credential.get_token("https://management.azure.com/.default").token
        mgmt_headers = {
            "Authorization": f"Bearer {mgmt_token}",
            "Content-Type": "application/json",
        }

        workspace_url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights"
            f"/workspaces/{workspace_name}?api-version=2022-10-01"
        )

        workspace_response = requests.get(workspace_url, headers=mgmt_headers)
        workspace_id = workspace_response.json()["properties"]["customerId"]

        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30)

        query = """
        SigninLogs
        | where TimeGenerated >= ago(7d)
        | where ResultType != "0"
        | order by TimeGenerated desc
        | take 1000000
        """

        url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
        payload = {
            "query": query,
            "timespan": f"{start_date.isoformat()}/{end_date.isoformat()}",
        }

        response = requests.post(url, headers=headers, json=payload)
        data = response.json()

        if data.get("tables") and len(data["tables"]) > 0:
            columns = [col["name"] for col in data["tables"][0]["columns"]]
            rows = data["tables"][0]["rows"]
            results = []

            for row in rows:
                record = dict(zip(columns, row))

                # Parse nested JSON fields
                for key, value in record.items():
                    if isinstance(value, str) and value.strip().startswith("{"):
                        try:
                            record[key] = json.loads(value)
                        except json.JSONDecodeError:
                            # If it fails to parse, keep the original string
                            pass

                results.append(record)

            output_data = {
                "data": results,
                "timestamp": datetime.utcnow().isoformat(),
                "records": len(results),
            }

            os.makedirs("sentinel_logs", exist_ok=True)
            with open("sentinel_logs/SigninLogs.json", "w", encoding="utf-8") as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False, default=str)

            return True, f"SUCCESS: Refreshed {len(results)} records"
        else:
            return True, "NO_DATA"

    except Exception as e:
        return False, str(e)


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
