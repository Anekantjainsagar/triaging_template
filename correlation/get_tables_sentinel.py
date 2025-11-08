import os
import json
import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential

load_dotenv()

subscription_id = os.getenv("SUBSCRIPTION_ID")
resource_group = os.getenv("RESOURCE_GROUP")
workspace_name = os.getenv("WORKSPACE_NAME")

credential = DefaultAzureCredential()
token = credential.get_token("https://api.loganalytics.io/.default").token

headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

# Get workspace ID
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
if workspace_response.status_code == 200:
    workspace_id = workspace_response.json()["properties"]["customerId"]
    print(f"Workspace ID: {workspace_id}")
else:
    print(
        f"Error getting workspace ID: {workspace_response.status_code} - {workspace_response.text}"
    )
    exit(1)



def generate_time_intervals(
    start_hour, end_hour, interval_minutes=20, start_date=None, end_date=None
):
    """
    Generate time intervals continuously from start_date to end_date.

    Args:
        start_hour: Starting hour on start_date (e.g., 6)
        end_hour: Ending hour on end_date (e.g., 7)
        interval_minutes: Minutes per interval (default 20)
        start_date: Start date (e.g., datetime(2025, 11, 4).date() or None for today)
        end_date: End date (e.g., datetime(2025, 11, 5).date() or None for today)

    Returns:
        List of tuples (start_time, end_time, label)
    """
    if start_date is None:
        start_date = datetime.utcnow().date()
    if end_date is None:
        end_date = datetime.utcnow().date()

    intervals = []

    # Create start and end datetimes
    start_datetime = datetime.combine(
        start_date, datetime.min.time().replace(hour=start_hour)
    )
    end_datetime = datetime.combine(
        end_date, datetime.min.time().replace(hour=end_hour)
    )

    current_time = start_datetime

    # Generate intervals from start to end
    while current_time < end_datetime:
        start_time = current_time
        end_time = current_time + timedelta(minutes=interval_minutes)

        # Don't exceed end_datetime
        if end_time > end_datetime:
            end_time = end_datetime

        # Create label
        label = f"{start_time.strftime('%Y-%m-%d %H:%M')}-{end_time.strftime('%H:%M')}"

        intervals.append((start_time, end_time, label))

        current_time = end_time

    return intervals


# Usage: Pass start hour, end hour, interval minutes, start date, and end date
time_intervals = generate_time_intervals(
    start_hour=5,
    end_hour=10,
    interval_minutes=60,
    start_date=datetime(2025, 11, 7).date(),  # or None for today
    end_date=datetime(2025, 11, 7).date(),  # or None for today
)

for start, end, label in time_intervals:
    print(label)


# Define table categories
TABLE_CATEGORIES = {
    "Platform_Operations": [
        "AzureDiagnostics",
        "Operation",
        "SentinelAudit",
        "SentinelHealth",
        "Usage",
    ],
    "Endpoint_Security": [
        "DeviceEvents",
        "DeviceFileEvents",
        "DeviceFileCertificateInfo",
        "DeviceImageLoadEvents",
        "DeviceInfo",
        "DeviceLogonEvents",
        "DeviceNetworkEvents",
        "DeviceNetworkInfo",
        "DeviceProcessEvents",
        "DeviceRegistryEvents",
    ],
    "User_Data": [
        "IdentityInfo",
        "SigninLogs",
        "UserPeerAnalytics",
        "BehaviorAnalytics",
    ],
}


def parse_nested_json_fields(record):
    """
    Dynamically parse JSON strings in any field at runtime
    """
    for field, value in record.items():
        # If it's a string, try to parse as JSON
        if isinstance(value, str) and value:
            try:
                # Check if it looks like JSON (starts with { or [)
                if value.strip().startswith(("{", "[")):
                    parsed = json.loads(value)
                    record[field] = parsed
            except (json.JSONDecodeError, TypeError):
                # If parsing fails, keep original value
                pass

    return record


def get_all_tables():
    query = """
    search *
    | distinct $table
    | sort by $table asc
    """

    url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
    payload = {"query": query}

    try:
        response = requests.post(url, headers=headers, json=payload)
        if response.status_code == 200:
            data = response.json()
            if data.get("tables") and len(data["tables"]) > 0:
                tables = [row[0] for row in data["tables"][0]["rows"]]
                print(f"✓ Found {len(tables)} tables in workspace")
                # Remove SecurityIncident and SecurityAlert as in original code
                if "SecurityIncident" in tables:
                    tables.remove("SecurityIncident")
                if "SecurityAlert" in tables:
                    tables.remove("SecurityAlert")
                return tables
            else:
                print("⚠ No tables found in workspace")
                return []
        else:
            print(
                f"✗ Error fetching tables: {response.status_code} - {response.text[:200]}"
            )
            return []
    except Exception as e:
        print(f"✗ Exception occurred while fetching tables: {str(e)}")
        return []


def query_table_data(table_name, start_time, end_time):
    query = f"""
    {table_name}
    | where TimeGenerated >= datetime({start_time.isoformat()})
    | where TimeGenerated < datetime({end_time.isoformat()})
    | order by TimeGenerated asc
    """

    url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
    payload = {"query": query}

    try:
        response = requests.post(url, headers=headers, json=payload)
        if response.status_code == 200:
            data = response.json()
            if data.get("tables") and len(data["tables"]) > 0:
                table_data = data["tables"][0]
                columns = [col["name"] for col in table_data.get("columns", [])]
                rows = table_data.get("rows", [])

                # Convert rows to list of dictionaries and parse nested JSON fields
                records = []
                for row in rows:
                    record = dict(zip(columns, row))
                    # Parse nested JSON fields
                    record = parse_nested_json_fields(record)
                    records.append(record)

                return records
            else:
                return []
        else:
            print(f"  ✗ Error querying {table_name}: {response.status_code}")
            return []
    except Exception as e:
        print(f"  ✗ Exception querying {table_name}: {str(e)}")
        return []


# Create main sentinel_logs folder
main_folder = "sentinel_logs1"
os.makedirs(main_folder, exist_ok=True)
print(f"\n📁 Created main folder: {main_folder}")

# Get all tables once
tables = get_all_tables()
print("Available tables:", tables)

# Process each 20-minute interval
for start_time, end_time, interval_label in time_intervals:
    print(f"\n{'='*60}")
    print(f"Processing interval: {interval_label} AM")
    print(f"Time range: {start_time} to {end_time} UTC")
    print(f"{'='*60}")

    # Create folder for this interval under sentinel_logs
    folder_name = os.path.join(
        main_folder, f"sentinel_logs_{interval_label.replace(':', '-')}"
    )
    os.makedirs(folder_name, exist_ok=True)
    print(f"\n📁 Created folder: {folder_name}")

    # Query data from all tables and separate by category
    category_data = {
        "Platform_Operations": {},
        "Endpoint_Security": {},
        "User_Data": {},
    }
    total_records = 0

    print("\nQuerying tables by category...")

    for category, table_list in TABLE_CATEGORIES.items():
        print(f"\n  === {category} ===")
        category_records = 0

        for table in table_list:
            if table in tables:
                print(f"    Querying {table}...", end=" ")
                records = query_table_data(table, start_time, end_time)
                category_data[category][table] = records
                category_records += len(records)
                total_records += len(records)
                print(f"✓ {len(records)} records")
            else:
                print(f"    ⚠ Table {table} not found in workspace")

        print(f"    Total records in {category}: {category_records}")

    # Save to separate JSON files in the interval folder
    timestamp = start_time.strftime("%Y%m%d_%H%M")
    for category, data in category_data.items():
        if data:  # Only create file if there's data
            output_filename = os.path.join(
                folder_name,
                f"sentinel_{category.lower()}_{timestamp}_{end_time.strftime('%H%M')}.json",
            )

            with open(output_filename, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)

            print(f"\n  ✓ Successfully saved {category} data to {output_filename}")
            print(f"    File size: {os.path.getsize(output_filename) / 1024:.2f} KB")

    print(f"\n  🎯 Summary for {interval_label}: {total_records} total records")

print("\n" + "=" * 60)
print("✅ All intervals processed successfully!")
print("=" * 60)
print("\nFolders created:")
for _, _, interval_label in time_intervals:
    folder_name = f"sentinel_logs_{interval_label.replace(':', '-')}"
    print(f"  - {folder_name}/")
