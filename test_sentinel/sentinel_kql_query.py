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
    SigninLogs | where TimeGenerated > datetime(2025-09-26 12:45:20Z) and TimeGenerated <= datetime(2025-10-03 12:45:20Z) | where IPAddress in ("49.249.104.218", "14.143.131.254", "111.125.237.218", "27.6.153.93") | extend Country = tostring(LocationDetails.countryOrRegion), City = tostring(LocationDetails.city), ISP = tostring(AutonomousSystemNumber) | summarize TotalAttempts = count(), UniqueUsers = dcount(UserPrincipalName), UniqueApplications = dcount(AppDisplayName), SuccessfulLogins = countif(ResultType == "0"), FailedLogins = countif(ResultType != "0"), RiskySignIns = countif(IsRisky == true), HighRiskSignIns = countif(RiskLevelAggregated == "high"), MediumRiskSignIns = countif(RiskLevelAggregated == "medium"), InteractiveLogins = countif(IsInteractive == true), NonInteractiveLogins = countif(IsInteractive == false), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), UniqueCountries = dcount(Country), UniqueCities = dcount(City), UsersList = make_set(UserPrincipalName, 20), ApplicationsList = make_set(AppDisplayName, 10), CountriesList = make_set(Country, 5), RiskEvents = make_set(RiskEventTypes_V2, 10) by IPAddress, ISP | extend DaysSeen = datetime_diff('day', LastSeen, FirstSeen) + 1, SuccessRate = round(100.0 * SuccessfulLogins / TotalAttempts, 2), IPThreatScore = (HighRiskSignIns * 10) + (MediumRiskSignIns * 5) + (FailedLogins * 2) + (UniqueUsers * 3), ThreatClassification = case( HighRiskSignIns > 5, "🔴 Critical Threat - Malicious Actor", HighRiskSignIns > 0, "🟠 High Risk - Known Threat", FailedLogins > 20, "🟡 Suspicious - Brute Force Pattern", SuccessRate < 40, "⚠️ Concerning - Low Success Rate", UniqueUsers > 10, "📊 Shared IP - Multiple Users", "🟢 Normal Activity" ), UsagePattern = case( DaysSeen == 1 and TotalAttempts > 20, "Burst Activity", DaysSeen > 7, "Persistent Access", TotalAttempts > 50, "High Volume", "Standard Usage" ) | project-reorder IPAddress, ThreatClassification, IPThreatScore, TotalAttempts, UniqueUsers, SuccessRate | order by IPThreatScore desc
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
