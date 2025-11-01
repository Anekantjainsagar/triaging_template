import os
import json
import requests
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential


def save_as_markdown(results, filename="kql_results.md"):
    """Convert KQL results to markdown table format"""

    if not results.get("tables"):
        with open(filename, "w") as f:
            f.write("# KQL Query Results\n\nNo data returned.\n")
        return

    table = results["tables"][0]
    columns = table["columns"]
    rows = table["rows"]

    with open(filename, "w") as f:
        # Write column headers
        headers = [col["name"] for col in columns]
        f.write("| " + " | ".join(headers) + " |\n")

        # Write separator
        f.write("| " + " | ".join(["---"] * len(headers)) + " |\n")

        # Write rows
        if rows:
            for row in rows:
                row_str = "| " + " | ".join(str(cell) for cell in row) + " |\n"
                f.write(row_str)
        else:
            f.write("| " + " | ".join(["No data"] * len(headers)) + " |\n")

    print(f"Results saved to {filename}")


def main():
    load_dotenv()

    workspace_id = os.getenv("LOG_ANALYTICS_WORKSPACE_ID")

    # kql_query = """
    # SigninLogs
    # | where TimeGenerated > ago(7d)
    # | where UserPrincipalName in ("sudheer.karimisetti@yashtechnologies841.onmicrosoft.com", "omkar.vyavahare@yashtechnologies841.onmicrosoft.com", "vishwajeet.dange@yashtechnologies841.onmicrosoft.com")
    # | extend Country = tostring(LocationDetails.countryOrRegion)
    # | extend City = tostring(LocationDetails.city)
    # | summarize
    #     SignInCount = count(),
    #     UniqueLocations = dcount(Country),
    #     Countries = make_set(Country),
    #     Cities = make_set(City)
    #     by UserPrincipalName, IPAddress
    # | where UniqueLocations > 1
    # | project UserPrincipalName, IPAddress, Countries, Cities, SignInCount, UniqueLocations
    # | order by UniqueLocations desc
    # """
    kql_query = """
    SigninLogs
    | where TimeGenerated > datetime(2025-10-15 00:45:24Z) and TimeGenerated <= datetime(2025-10-22 00:45:24Z)
    | where IPAddress in ("2401:4900:1cb5:29f1:9f:a136:3173:e31b", "2409:40c2:5019:3af4:ece3:93e9:9ef3:8820", "103.50.78.48")
    | summarize
        SignInAttempts = count(),
        UniqueUsers = dcount(UserPrincipalName),
        UniqueApps = dcount(AppDisplayName),
        SuccessfulLogins = countif(ResultType == "0"),
        FailedLogins = countif(ResultType != "0"),
        RiskySignIns = countif(IsRisky == true),
        HighRiskSignIns = countif(RiskLevelAggregated == "high"),
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        Locations = make_set(tostring(LocationDetails.countryOrRegion), 5),
        Users = make_set(UserPrincipalName, 10),
        Apps = make_set(AppDisplayName, 5)
        by IPAddress
    """

    credential = DefaultAzureCredential()
    token = credential.get_token("https://api.loganalytics.io/.default").token

    url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    body = {"query": kql_query, "timespan": "P1D"}

    response = requests.post(url, headers=headers, json=body)

    if response.status_code == 200:
        results = response.json()

        # Save as JSON
        with open("kql.json", "w") as f:
            json.dump(results, f, indent=4)
        print("Response saved to kql.json")

        # Save as Markdown table
        save_as_markdown(results, "kql_results.md")
    else:
        print(f"KQL query failed: {response.status_code} - {response.text}")


if __name__ == "__main__":
    main()
