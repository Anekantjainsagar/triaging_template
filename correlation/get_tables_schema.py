import os
import json
import requests
from datetime import datetime
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


def get_table_schema(table_name):
    """
    Get the schema for a specific table by querying a sample of records
    and analyzing the column structure and data types
    """
    query = f"""
    {table_name}
    | getschema
    | project ColumnName, ColumnOrdinal, DataType, Description
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

                # Convert to list of dictionaries
                schema = []
                for row in rows:
                    record = dict(zip(columns, row))
                    schema.append(record)

                return schema
            else:
                return []
        else:
            print(f"  ✗ Error getting schema for {table_name}: {response.status_code}")
            return []
    except Exception as e:
        print(f"  ✗ Exception getting schema for {table_name}: {str(e)}")
        return []


def get_table_schema_alternative(table_name):
    """
    Alternative method to get schema by sampling a few records
    """
    query = f"""
    {table_name}
    | take 1
    """

    url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
    payload = {"query": query}

    try:
        response = requests.post(url, headers=headers, json=payload)
        if response.status_code == 200:
            data = response.json()
            if data.get("tables") and len(data["tables"]) > 0:
                table_data = data["tables"][0]
                columns_info = []

                for col in table_data.get("columns", []):
                    column_info = {
                        "name": col["name"],
                        "type": col.get("type", "unknown"),
                        "description": "",  # Description not available in this method
                    }
                    columns_info.append(column_info)

                return columns_info
            else:
                return []
        else:
            print(
                f"  ✗ Error getting alternative schema for {table_name}: {response.status_code}"
            )
            return []
    except Exception as e:
        print(f"  ✗ Exception getting alternative schema for {table_name}: {str(e)}")
        return []


# Get all tables
tables = get_all_tables()
print("Tables found:", tables)

# Gather schemas for all tables
all_schemas = {}
total_columns = 0

print("\nGathering table schemas...")
for table in tables:
    print(f"  Getting schema for {table}...", end=" ")

    # Try the primary method first (using getschema)
    schema = get_table_schema(table)

    # If primary method fails or returns no results, use alternative method
    if not schema:
        schema = get_table_schema_alternative(table)

    if schema:
        all_schemas[table] = schema
        column_count = len(schema)
        total_columns += column_count
        print(f"✓ {column_count} columns")
    else:
        print(f"✗ No schema found")

# Add metadata to the schema collection
schema_collection = {
    "workspace_info": {
        "workspace_name": workspace_name,
        "workspace_id": workspace_id,
        "resource_group": resource_group,
        "subscription_id": subscription_id,
        "schema_retrieval_time": datetime.utcnow().isoformat() + "Z",
    },
    "statistics": {
        "total_tables": len(all_schemas),
        "total_columns": total_columns,
        "tables_with_schema": len([t for t in all_schemas if all_schemas[t]]),
    },
    "schemas": all_schemas,
}

# Save to JSON file
output_filename = (
    f"sentinel_table_schemas_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
)

with open(output_filename, "w", encoding="utf-8") as f:
    json.dump(schema_collection, f, indent=2, default=str)

print(
    f"\n✓ Successfully saved schemas for {len(all_schemas)} tables to {output_filename}"
)
print(f"  Total columns: {total_columns}")
print(f"  File size: {os.path.getsize(output_filename) / 1024:.2f} KB")

# Print summary
print(f"\nSchema Collection Summary:")
print(f"  Tables processed: {len(all_schemas)}")
for table, schema in all_schemas.items():
    column_count = len(schema) if schema else 0
    print(f"    {table}: {column_count} columns")
