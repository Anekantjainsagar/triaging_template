import os
import json
import requests
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential


def save_as_markdown(results, filename="kql_results.md"):
    """Convert KQL results to markdown table format"""

    if not results.get("tables"):
        with open(filename, "w", encoding="utf-8") as f:  # Add encoding here
            f.write("# KQL Query Results\n\nNo data returned.\n")
        return

    table = results["tables"][0]
    columns = table["columns"]
    rows = table["rows"]

    with open(filename, "w", encoding="utf-8") as f:  # Add encoding here
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

    kql_query = """SigninLogs | where TimeGenerated > datetime(2025-10-18 06:45:23Z) and TimeGenerated <= datetime(2025-10-25 06:45:23Z) | where UserPrincipalName in ("sweta.tiwari@yashtechnologies841.onmicrosoft.com", "ganesh.tanneru@yashtechnologies841.onmicrosoft.com", "chirag.gupta@yashtechnologies841.onmicrosoft.com", "urvashi.upadhyay@yashtechnologies841.onmicrosoft.com", "umapreethi.v@yash.com")
|summarize 
TotalSignIns = count(),
UniqueIPAddresses = dcount(IPAddress),
UniqueLocations = dcount(tostring(LocationDetails.countryOrRegion)),
UniqueApplications = dcount(AppDisplayName),
SuccessfulSignIns = countif(ResultType == "0"),
FailedSignIns = countif(ResultType != "0"),
RiskySignIns = countif(IsRisky == true),
InteractiveSignIns = countif(IsInteractive == true),
NonInteractiveSignIns = countif(IsInteractive == false),
FirstActivity = min(TimeGenerated),
LastActivity = max(TimeGenerated),
IPAddressesList = make_set(IPAddress, 10),
LocationsList = make_set(tostring(LocationDetails.countryOrRegion), 5),
ApplicationsList = make_set(AppDisplayName, 10)
by UserPrincipalName, UserDisplayName | extend
SuccessRate = round(100.0 * SuccessfulSignIns / TotalSignIns, 2),
RiskScore = (FailedSignIns * 2) + (RiskySignIns * 5),
ActivitySpanDays = datetime_diff('day', LastActivity, FirstActivity) | extend
ThreatLevel = case(
RiskySignIns > 5, "Critical",
RiskySignIns > 2, "High",
FailedSignIns > 10, "Medium",
"Low"
) | project-reorder UserPrincipalName, UserDisplayName, ThreatLevel, RiskScore, TotalSignIns, SuccessRate"""

    credential = DefaultAzureCredential()
    token = credential.get_token("https://api.loganalytics.io/.default").token

    url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    body = {"query": kql_query}

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
