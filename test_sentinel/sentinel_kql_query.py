import os
import json
import requests
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential


def main():
    load_dotenv()

    workspace_id = os.getenv(
        "LOG_ANALYTICS_WORKSPACE_ID", "674f96b1-63d6-48ca-9fe6-d613e4292c7f"
    )

    # kql_query = """
    # AuditLogs
    # | take 1
    # """
    # kql_query = """
    # let reference_datetime = datetime(2025-10-03 12:45:00Z);
    # SigninLogs 
    # | where TimeGenerated > reference_datetime - 7d and TimeGenerated <= reference_datetime
    # | where UserPrincipalName in ("shrish.s@yashtechnologies841.onmicrosoft.com", "aarushi.trivedi@yashtechnologies841.onmicrosoft.com", "saratkumar.indukuri@yashtechnologies841.onmicrosoft.com", "ketan.patel@yashtechnologies841.onmicrosoft.com")
    # | summarize SignInCount = count(), UniqueIPs = dcount(IPAddress), FailedAttempts = countif(ResultType != "0"), UniqueLocations = dcount(tostring(LocationDetails.countryOrRegion)) by UserPrincipalName
    # """
    kql_query = """
    let reference_datetime = datetime(2025-10-03 12:45:00Z);
    SigninLogs 
    | where TimeGenerated > reference_datetime - 7d and TimeGenerated <= reference_datetime
    | where UserPrincipalName in ("shrish.s@yashtechnologies841.onmicrosoft.com", "aarushi.trivedi@yashtechnologies841.onmicrosoft.com", "saratkumar.indukuri@yashtechnologies841.onmicrosoft.com", "ketan.patel@yashtechnologies841.onmicrosoft.com")
    | summarize SignInCount = count(), UniqueIPs = dcount(IPAddress), FailedAttempts = countif(ResultType != "0"), UniqueLocations = dcount(tostring(LocationDetails.countryOrRegion)) by UserPrincipalName
    """

    credential = DefaultAzureCredential()
    token = credential.get_token("https://api.loganalytics.io/.default").token

    url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    body = {"query": kql_query, "timespan": "P1D"}

    response = requests.post(url, headers=headers, json=body)

    if response.status_code == 200:
        results = response.json()
        # Save to JSON file
        with open("kql.json", "w") as f:
            json.dump(results, f, indent=4)
        print("Response saved to kql.json")
    else:
        print(f"KQL query failed: {response.status_code} - {response.text}")


if __name__ == "__main__":
    main()
