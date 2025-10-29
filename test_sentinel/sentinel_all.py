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
token = credential.get_token("https://management.azure.com/.default").token

headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

# Define time range (e.g., last 90 days)
end_date = datetime.utcnow()
start_date = end_date - timedelta(days=90)

# Format dates in ISO 8601 format
start_date_str = start_date.strftime("%Y-%m-%dT%H:%M:%SZ")
end_date_str = end_date.strftime("%Y-%m-%dT%H:%M:%SZ")

# Build filter - you can combine multiple conditions
# Options for status: New, Active, Closed
filters = [
    f"properties/createdTimeUtc ge {start_date_str}",
    f"properties/createdTimeUtc le {end_date_str}",
    # Uncomment to filter by status:
    # "properties/status eq 'Active'",  # Only active incidents
    # "properties/status ne 'Closed'",  # Exclude closed incidents
]

filter_query = " and ".join(filters)

# Initial URL with filter
base_url = (
    f"https://management.azure.com/subscriptions/{subscription_id}"
    f"/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights"
    f"/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/incidents"
)

url = f"{base_url}?api-version=2025-09-01&$filter={filter_query}"

all_incidents = []

while url:
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        incidents = data.get("value", [])
        all_incidents.extend(incidents)

        # Print progress
        print(f"Fetched {len(incidents)} incidents (Total: {len(all_incidents)})")

        # Get the nextLink for pagination
        url = data.get("nextLink", None)
    else:
        print(f"Error fetching incidents: {response.status_code} - {response.text}")
        break

print(f"\nTotal incidents fetched: {len(all_incidents)}")

# Analyze status distribution
status_counts = {}
for incident in all_incidents:
    status = incident.get("properties", {}).get("status", "Unknown")
    status_counts[status] = status_counts.get(status, 0) + 1

print("\nIncident Status Distribution:")
for status, count in status_counts.items():
    print(f"  {status}: {count}")

# Save all incidents to a JSON file
with open("sentinel_all_incidents.json", "w", encoding="utf-8") as f:
    json.dump({"value": all_incidents}, f, indent=4, ensure_ascii=False)

print("\nIncidents saved to sentinel_all_incidents.json")
