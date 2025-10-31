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

    kql_query = """
    SigninLogs
    | where TimeGenerated > ago(7d)
    | where UserPrincipalName in ("aarushi.trivedi@yashtechnologies841.onmicrosoft.com", "shrish.s@yashtechnologies841.onmicrosoft.com", "ketan.patel@yashtechnologies841.onmicrosoft.com", "saratkumar.indukuri@yashtechnologies841.onmicrosoft.com")
    | extend StepNumber = 3
    | summarize 
        TotalSignIns = count(),
        UniqueUsers = dcount(UserPrincipalName),
        UniqueIPs = dcount(IPAddress),
        UniqueApps = dcount(AppDisplayName),
        SuccessfulSignIns = countif(ResultType == "0"),
        FailedSignIns = countif(ResultType != "0"),
        UniqueDays = dcount(format_datetime(TimeGenerated, 'yyyy-MM-dd'))
    | extend ImpactScore = (UniqueUsers * 10) + (FailedSignIns * 2)
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
