import os
import requests
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential

# Load environment variables if needed
workspace_id = "674f96b1-63d6-48ca-9fe6-d613e4292c7f"  # Log Analytics Workspace ID

kql_query = """
SigninLogs
| where TimeGenerated > ago(1d)
| take 10
"""

credential = DefaultAzureCredential()

token = credential.get_token("https://api.loganalytics.io/.default").token
url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
body = {"query": kql_query, "timespan": "P1D"}

response = requests.post(url, headers=headers, json=body)

if response.status_code == 200:
    results = response.json()
    print(results)
else:
    print(f"KQL query failed: {response.status_code} - {response.text}")
