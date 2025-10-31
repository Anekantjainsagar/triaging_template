"""
KQL Query Executor Module
Handles execution of KQL queries against Azure Log Analytics workspace
"""

import os
import json
import requests
import pandas as pd
from typing import Dict, Optional, Tuple
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential


class KQLExecutor:
    """Execute KQL queries and format results"""

    def __init__(self):
        load_dotenv()
        self.workspace_id = os.getenv("LOG_ANALYTICS_WORKSPACE_ID")
        self.credential = None
        self.token = None

        if not self.workspace_id:
            raise ValueError("LOG_ANALYTICS_WORKSPACE_ID not found in environment")

    def _get_auth_token(self) -> str:
        """Get authentication token for Log Analytics API"""
        if not self.credential:
            self.credential = DefaultAzureCredential()

        self.token = self.credential.get_token(
            "https://api.loganalytics.io/.default"
        ).token
        return self.token

    def execute_query(
        self, kql_query: str, timespan: str = "P7D"
    ) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """
        Execute KQL query and return formatted results

        Args:
            kql_query: The KQL query to execute
            timespan: Time range for the query (default: P7D = 7 days)

        Returns:
            Tuple of (success: bool, formatted_output: str, raw_results: dict)
        """
        try:
            # Get authentication token
            token = self._get_auth_token()

            # Prepare API request
            url = f"https://api.loganalytics.io/v1/workspaces/{self.workspace_id}/query"
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }

            body = {"query": kql_query, "timespan": timespan}

            # Execute query
            response = requests.post(url, headers=headers, json=body, timeout=60)

            if response.status_code == 200:
                results = response.json()
                formatted_output = self._format_results(results)
                return True, formatted_output, results
            else:
                error_msg = f"Query failed: {response.status_code} - {response.text}"
                return False, error_msg, None

        except Exception as e:
            error_msg = f"Execution error: {str(e)}"
            return False, error_msg, None

    def _format_results(self, results: Dict) -> str:
        """
        Format query results into readable text output

        Args:
            results: Raw API response

        Returns:
            Formatted string output
        """
        if not results.get("tables"):
            return "No results returned from query."

        table = results["tables"][0]
        columns = table["columns"]
        rows = table["rows"]

        if not rows:
            return "Query executed successfully but returned no data."

        # Build formatted output
        output_lines = []
        output_lines.append(f"Results: {len(rows)} row(s) returned\n")
        output_lines.append("=" * 80)

        # Create column headers
        headers = [col["name"] for col in columns]
        col_widths = [max(len(str(h)), 15) for h in headers]

        # Adjust column widths based on data
        for row in rows[:10]:  # Sample first 10 rows for width calculation
            for idx, cell in enumerate(row):
                cell_len = len(str(cell))
                if cell_len > col_widths[idx]:
                    col_widths[idx] = min(cell_len, 50)  # Max 50 chars per column

        # Format header row
        header_row = " | ".join(
            str(h).ljust(col_widths[idx]) for idx, h in enumerate(headers)
        )
        output_lines.append(header_row)
        output_lines.append("-" * len(header_row))

        # Format data rows
        for row in rows:
            row_str = " | ".join(
                str(cell)[: col_widths[idx]].ljust(col_widths[idx])
                for idx, cell in enumerate(row)
            )
            output_lines.append(row_str)

        output_lines.append("=" * 80)
        output_lines.append(f"\nTotal Records: {len(rows)}")

        return "\n".join(output_lines)

    def format_results_as_markdown(self, results: Dict) -> str:
        """
        Format query results as markdown table

        Args:
            results: Raw API response

        Returns:
            Markdown formatted string
        """
        if not results.get("tables"):
            return "No results returned from query."

        table = results["tables"][0]
        columns = table["columns"]
        rows = table["rows"]

        if not rows:
            return "Query executed successfully but returned no data."

        # Build markdown table
        md_lines = []
        md_lines.append(f"**Results:** {len(rows)} row(s)\n")

        # Headers
        headers = [col["name"] for col in columns]
        md_lines.append("| " + " | ".join(headers) + " |")
        md_lines.append("| " + " | ".join(["---"] * len(headers)) + " |")

        # Rows
        for row in rows:
            row_str = "| " + " | ".join(str(cell) for cell in row) + " |"
            md_lines.append(row_str)

        return "\n".join(md_lines)

    def save_results_to_file(
        self, results: Dict, filename: str, format: str = "json"
    ) -> bool:
        """
        Save query results to file

        Args:
            results: Raw API response
            filename: Output filename
            format: 'json', 'csv', or 'markdown'

        Returns:
            Success status
        """
        try:
            if format == "json":
                with open(filename, "w") as f:
                    json.dump(results, f, indent=4)

            elif format == "csv":
                if results.get("tables"):
                    table = results["tables"][0]
                    df = pd.DataFrame(
                        table["rows"], columns=[col["name"] for col in table["columns"]]
                    )
                    df.to_csv(filename, index=False)

            elif format == "markdown":
                md_content = self.format_results_as_markdown(results)
                with open(filename, "w") as f:
                    f.write(md_content)

            return True

        except Exception as e:
            print(f"Error saving results: {e}")
            return False


# Convenience function for quick execution
def execute_kql(
    query: str, timespan: str = "P7D"
) -> Tuple[bool, Optional[str], Optional[Dict]]:
    """
    Quick function to execute a KQL query

    Args:
        query: KQL query string
        timespan: Time range (default: P7D)

    Returns:
        Tuple of (success, formatted_output, raw_results)
    """
    executor = KQLExecutor()
    return executor.execute_query(query, timespan)
