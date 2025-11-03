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

    kql_query = """// VIP User Verification Query
// Alert Time Generated: 2025-10-25 06:45:23Z
// Query Time Range: 2025-10-18 06:45:23Z to 2025-10-25 06:45:23Z (7 days)
// Analyst-provided VIP users: 3 user(s)
// Alert-affected users: 5 user(s)

let VIPUsers = datatable(UserPrincipalName:string)
[
    "ceo@company.com",
    "cfo@company.com",
    "admin@company.com"
];
SigninLogs
| where TimeGenerated > datetime(2025-10-18 06:45:23Z) and TimeGenerated <= datetime(2025-10-25 06:45:23Z)
| where UserPrincipalName in ("urvashi.upadhyay@yashtechnologies841.onmicrosoft.com", "sweta.tiwari@yashtechnologies841.onmicrosoft.com", "umapreethi.v@yash.com", "chirag.gupta@yashtechnologies841.onmicrosoft.com", "ganesh.tanneru@yashtechnologies841.onmicrosoft.com")
| extend IsVIP = iff(UserPrincipalName in (VIPUsers), "⭐ VIP ACCOUNT", "Regular User")
| summarize
TotalSignIns = count(),
    UniqueIPAddresses = dcount(IPAddress),
    UniqueCountries = dcount(tostring(LocationDetails.countryOrRegion)),
    HighRiskSignIns = countif(RiskLevelAggregated == "high"),
    MediumRiskSignIns = countif(RiskLevelAggregated == "medium"),
    FailedAttempts = countif(ResultType != "0"),
    SuccessfulSignIns = countif(ResultType == "0")
    by UserPrincipalName, UserDisplayName, IsVIP
| extend
    VIPRiskScore = (HighRiskSignIns * 10) + (MediumRiskSignIns * 5) + (FailedAttempts * 2) + (UniqueCountries * 3)
| extend
    AccountClassification = case(
        VIPRiskScore > 30, "🔴 Critical - Executive at High Risk",
        VIPRiskScore > 15, "🟠 High - VIP Requires Attention",
        VIPRiskScore > 5, "🟡 Medium - Monitor Closely", 
        "🟢 Low - Normal Activity"
    )
| project-reorder UserPrincipalName, UserDisplayName, IsVIP, AccountClassification, VIPRiskScore
| order by VIPRiskScore desc"""

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
