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

# Create output directory
output_folder = f"sentinel_logs"
os.makedirs(output_folder, exist_ok=True)

print(f"\nCreated output folder: {output_folder}")

# Define time range
end_date = datetime.utcnow()
start_date = end_date - timedelta(days=30)

# Tables to query
tables_to_query = [
    "DeviceProcessEvents",
    "DeviceFileEvents",
    "UserPeerAnalytics",
    "DeviceRegistryEvents",
    "SigninLogs",
    "DeviceEvents",
    "DeviceNetworkEvents",
    "DeviceNetworkInfo",
    "Usage",
    "IdentityInfo",
    "DeviceLogonEvents",
    "BehaviorAnalytics",
    "AlertEvidence",
    "DeviceInfo",
    "DeviceFileCertificateInfo",
    "SecurityIncident",
    "SentinelHealth",
    "SecurityAlert",
    "DeviceImageLoadEvents",
    "AlertInfo",
    "Operation",
]


def parse_json_fields(record):
    """Parse all JSON string fields into proper JSON objects"""
    for key, value in record.items():
        if isinstance(value, str):
            # Try to parse any string that looks like JSON
            value_stripped = value.strip()
            if (value_stripped.startswith("{") and value_stripped.endswith("}")) or (
                value_stripped.startswith("[") and value_stripped.endswith("]")
            ):
                try:
                    record[key] = json.loads(value)
                except (json.JSONDecodeError, ValueError):
                    pass  # Keep as string if parsing fails
    return record


def run_query(table_name, limit=1000):
    """Run a KQL query against a specific table"""
    print(f"\n{'='*60}")
    print(f"Querying table: {table_name}")
    print(f"{'='*60}")

    # Add filter for SigninLogs to exclude ResultType "0"
    if table_name == "SigninLogs":
        query = f"""
{table_name}
| where TimeGenerated >= ago(30d)
| where ResultType != "0"
| order by TimeGenerated desc
| take {limit}
"""
        print("  ℹ Filtering: Excluding ResultType = '0' (successful sign-ins)")
    else:
        query = f"""
{table_name}
| where TimeGenerated >= ago(30d)
| order by TimeGenerated desc
| take {limit}
"""

    url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
    payload = {
        "query": query,
        "timespan": f"{start_date.isoformat()}/{end_date.isoformat()}",
    }

    try:
        response = requests.post(url, headers=headers, json=payload)

        if response.status_code == 200:
            data = response.json()

            if data.get("tables") and len(data["tables"]) > 0:
                columns = [col["name"] for col in data["tables"][0]["columns"]]
                rows = data["tables"][0]["rows"]

                # Convert to list of dictionaries and parse all JSON fields
                results = []
                for row in rows:
                    record = dict(zip(columns, row))
                    record = parse_json_fields(record)
                    results.append(record)

                print(f"✓ Fetched {len(results)} log entries")

                if results:
                    # Create custom format with timestamp and record count
                    output_data = {
                        "data": results,
                        "timestamp": datetime.utcnow().isoformat(),
                        "records": len(results),
                    }

                    # Save as formatted JSON
                    json_filename = os.path.join(output_folder, f"{table_name}.json")
                    with open(json_filename, "w", encoding="utf-8") as f:
                        json.dump(
                            output_data, f, indent=2, ensure_ascii=False, default=str
                        )
                    print(f"  → JSON saved: {json_filename}")
                    print(f"  → Records: {output_data['records']}")
                    print(f"  → Timestamp: {output_data['timestamp']}")

                    # Print sample of first entry
                    print(f"\n  Sample (first entry - first 3 fields):")
                    for key, value in list(results[0].items())[:3]:
                        if isinstance(value, dict):
                            print(f"    {key}: <nested object>")
                        else:
                            print(f"    {key}: {str(value)[:100]}")

                return results
            else:
                print(f"⚠ No data found in table: {table_name}")
                # Save empty result with custom format
                output_data = {
                    "data": [],
                    "timestamp": datetime.utcnow().isoformat(),
                    "records": 0,
                }
                json_filename = os.path.join(output_folder, f"{table_name}.json")
                with open(json_filename, "w", encoding="utf-8") as f:
                    json.dump(output_data, f, indent=2, ensure_ascii=False, default=str)
                return []
        else:
            print(
                f"✗ Error fetching logs: {response.status_code} - {response.text[:200]}"
            )
            return None
    except Exception as e:
        print(f"✗ Exception occurred: {str(e)}")
        return None


# Main execution
print("\n" + "=" * 60)
print("Starting Sentinel Log Collection")
print("=" * 60)
print(
    f"Time Range: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}"
)
print(f"Total Tables: {len(tables_to_query)}")
print("=" * 60)

summary = {
    "execution_time": datetime.utcnow().isoformat(),
    "time_range": {
        "start": start_date.isoformat(),
        "end": end_date.isoformat(),
    },
    "tables_queried": {},
}

# Query each table
total_records = 0
for idx, table_name in enumerate(tables_to_query, 1):
    print(f"\n[{idx}/{len(tables_to_query)}] Processing: {table_name}")
    try:
        results = run_query(table_name, limit=1000000)
        if results is not None:
            record_count = len(results)
            total_records += record_count
            summary["tables_queried"][table_name] = {
                "status": "success",
                "record_count": record_count,
            }
        else:
            summary["tables_queried"][table_name] = {
                "status": "failed",
                "record_count": 0,
            }
    except Exception as e:
        print(f"✗ Error processing {table_name}: {str(e)}")
        summary["tables_queried"][table_name] = {
            "status": "error",
            "error": str(e),
            "record_count": 0,
        }

# Save summary
summary_file = os.path.join(output_folder, "summary.json")
with open(summary_file, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2, ensure_ascii=False)

print("\n" + "=" * 60)
print("Log Collection Complete!")
print("=" * 60)
print(f"Output folder: {output_folder}")
print(f"Total records collected: {total_records:,}")
print(f"Summary file: {summary_file}")
print("=" * 60)
