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

    kql_query = """AuditLogs
| where TimeGenerated > datetime(2025-09-25 00:45:25Z) and TimeGenerated <= datetime(2025-10-25 00:45:25Z)
| where OperationName has_any ("Add member to role", "Add app role assignment", "Consent to application", "Add owner")
| where InitiatedBy.user.UserPrincipalName in ("urvashi.upadhyay@yashtechnologies841.onmicrosoft.com", "umapreethi.v@yash.com", "chirag.gupta@yashtechnologies841.onmicrosoft.com", "ganesh.tanneru@yashtechnologies841.onmicrosoft.com", "sweta.tiwari@yashtechnologies841.onmicrosoft.com") or TargetResources[0].UserPrincipalName in ("urvashi.upadhyay@yashtechnologies841.onmicrosoft.com", "umapreethi.v@yash.com", "chirag.gupta@yashtechnologies841.onmicrosoft.com", "ganesh.tanneru@yashtechnologies841.onmicrosoft.com", "sweta.tiwari@yashtechnologies841.onmicrosoft.com")
| extend
    ActionType = case(
        OperationName has "Add member to role", "Role Assignment",
        OperationName has "Add app role assignment", "App Role Assignment", 
        OperationName has "Consent to application", "App Consent",
        OperationName has "Add owner", "Owner Assignment",
        "Other"
    ),
    IsInitiator = iff(InitiatedBy.user.UserPrincipalName in ("urvashi.upadhyay@yashtechnologies841.onmicrosoft.com", "umapreethi.v@yash.com", "chirag.gupta@yashtechnologies841.onmicrosoft.com", "ganesh.tanneru@yashtechnologies841.onmicrosoft.com", "sweta.tiwari@yashtechnologies841.onmicrosoft.com"), true, false),
    TargetUser = tostring(TargetResources[0].userPrincipalName)
| summarize
    TotalOperations = count(),
    SuccessfulOperations = countif(Result == "success"),
    FailedOperations = countif(Result == "failure"),
    RoleAssignments = countif(ActionType == "Role Assignment"),
    AppRoleAssignments = countif(ActionType == "App Role Assignment"),
    AppConsents = countif(ActionType == "App Consent"),
    OwnerAssignments = countif(ActionType == "Owner Assignment"),
    UniqueTargets = dcount(TargetUser),
    FirstOperation = min(TimeGenerated),
    LastOperation = max(TimeGenerated)
    by UserPrincipalName = "urvashi.upadhyay@yashtechnologies841.onmicrosoft.com", "umapreethi.v@yash.com", "chirag.gupta@yashtechnologies841.onmicrosoft.com", "ganesh.tanneru@yashtechnologies841.onmicrosoft.com", "sweta.tiwari@yashtechnologies841.onmicrosoft.com", InvolvementType = iff(IsInitiator, "Initiator", "Target")
| extend
    SuccessRate = round(100.0 * SuccessfulOperations / TotalOperations, 2),
    RiskScore = (RoleAssignments * 5) + (AppRoleAssignments * 4) + (AppConsents * 6) + (OwnerAssignments * 7)
| extend
    RiskLevel = case(
        RiskScore > 50, "🔴 Critical - Excessive Privilege Changes",
        RiskScore > 30, "🟠 High - Significant Role Activity", 
        RiskScore > 15, "🟡 Medium - Moderate Privilege Changes",
        RiskScore > 5, "⚠️ Low - Some Activity",
        "🟢 Normal"
    ),
    ActivityFrequency = case(
        TotalOperations > 50, "Very High",
        TotalOperations > 20, "High",
        TotalOperations > 10, "Moderate", 
        TotalOperations > 5, "Low",
        "Very Low"
    )
| project-reorder UserPrincipalName, InvolvementType, RiskLevel, RiskScore, TotalOperations, SuccessRate, ActivityFrequency
| order by RiskScore desc"""

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
