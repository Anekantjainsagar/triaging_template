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

    kql_query = """
    // VIP User Verification Query - PLACEHOLDER
    // This query will be dynamically generated during triaging with:
    //   - VIP user list (provided by analyst)
    //   - Affected users (from alert entities)  
    //   - Alert timestamp (for accurate time range)

    let VIPUsers = datatable(UserPrincipalName:string)
    [
        "sweta.tiwari@yashtechnologies841.onmicrosoft.com"
    ];
    SigninLogs
    | where TimeGenerated > datetime(2025-2-01 10:30:00Z) and TimeGenerated <= datetime(2025-11-03 10:30:00Z)
    | where UserPrincipalName == "sweta.tiwari@yashtechnologies841.onmicrosoft.com"
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
    | extend VIPRiskScore = (HighRiskSignIns * 10) + (MediumRiskSignIns * 5) + (FailedAttempts * 2)
    | extend AccountClassification = case(
        VIPRiskScore > 30, "🔴 Critical - Executive at High Risk",
        VIPRiskScore > 15, "🟠 High - VIP Requires Attention", 
        VIPRiskScore > 5, "🟡 Medium - Monitor Closely",
        "🟢 Low - Normal Activity"
    )
    | project-reorder UserPrincipalName, UserDisplayName, IsVIP, AccountClassification, VIPRiskScore
    | order by VIPRiskScore desc
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
