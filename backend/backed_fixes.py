import pandas as pd
import numpy as np
from typing import List, Dict, Any
import logging

# Setup logging for FastAPI
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def filter_kql_output_by_user(output_text: str, username: str, step_name: str) -> str:
    """Filters structured KQL output to include only rows relevant to the username."""
    # Bypass filtering for IP reputation steps or small outputs
    step_name_lower = step_name.lower()
    if (
        "reputation" in step_name_lower
        or "virustotal" in step_name_lower
        or len(output_text) < 100
    ):
        return output_text

    lines = output_text.split("\n")
    if not lines:
        return output_text

    # Try to find the header section
    header_lines = []
    data_start_index = -1

    # Identify initial summary lines (like "Results: 22 row(s) returned")
    initial_summary = ""
    if lines[0].startswith("Results:"):
        initial_summary = lines[0]
        lines = lines[1:]  # Remove summary for easier parsing

    # Find the header and delimiter lines
    for i, line in enumerate(lines):
        if "UserPrincipalName" in line:
            header_lines.append(line)
            if i + 1 < len(lines) and lines[i + 1].startswith("---"):
                header_lines.append(lines[i + 1])
                data_start_index = i + 2
            break

    if not header_lines:
        # Not a structured KQL output we need to filter
        return output_text

    # Filter data rows by username
    # Ensure username comparison is case-insensitive for robustness
    user_rows = [
        line for line in lines[data_start_index:] if username.lower() in line.lower()
    ]

    # Find the total records line at the end
    total_records_line = ""
    for line in output_text.split("\n"):
        if line.startswith("Total Records:"):
            total_records_line = line
            break

    # Reconstruct the final output
    filtered_lines = []
    if initial_summary:
        filtered_lines.append(initial_summary)

    filtered_lines.extend(header_lines)
    filtered_lines.extend(user_rows)

    if total_records_line:
        filtered_lines.append(total_records_line)

    final_output = "\n".join(filtered_lines)

    # Return original if the filtering resulted in almost no relevant lines (safety net)
    if len(final_output.split("\n")) < 5 and len(output_text.split("\n")) > 10:
        return output_text

    return final_output


def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Clean DataFrame by replacing all NaN/NULL/None values properly"""
    df_clean = df.copy()

    # Replace all types of NaN/NULL values
    df_clean = df_clean.replace(
        {
            pd.NA: None,
            pd.NaT: None,
            np.nan: None,
            float("inf"): None,
            float("-inf"): None,
        }
    )

    # Use where to replace remaining NaN values
    df_clean = df_clean.where(pd.notna(df_clean), None)

    return df_clean


def extract_investigation_steps_fixed(
    df: pd.DataFrame, username: str
) -> List[Dict[str, Any]]:
    """FIXED: Extract investigation steps with USER-SPECIFIC output filtering"""

    logger.info(f"=" * 60)
    logger.info(f"EXTRACTING STEPS FOR: {username}")
    logger.info(f"Total rows in DataFrame: {len(df)}")
    logger.info(f"Columns: {df.columns.tolist()}")

    investigation_steps = []

    for idx, row in df.iterrows():
        step_value = row.get("Step")

        # ✅ SKIP HEADER ROW - Check if Step is NULL/NaN
        if step_value is None or pd.isna(step_value):
            logger.info(
                f"Row {idx}: SKIPPED (Header row - Step={step_value}, Name={row.get('Name')})"
            )
            continue

        # ✅ VALIDATE STEP NUMBER
        try:
            step_num = int(float(step_value))  # Convert via float first to handle "1.0"
            if step_num < 1:
                logger.warning(f"Row {idx}: SKIPPED (Invalid step: {step_value})")
                continue
        except (ValueError, TypeError):
            logger.warning(f"Row {idx}: SKIPPED (Non-numeric step: {step_value})")
            continue

        # ✅ EXTRACT AND CLEAN ALL FIELDS
        def safe_str(val):
            if val is None or pd.isna(val):
                return ""
            s = str(val).strip()
            return "" if s.lower() in ["nan", "none", "null", "<na>", ""] else s

        step_name = safe_str(row.get("Name")) or f"Step {step_num}"
        explanation = safe_str(row.get("Explanation"))
        kql_query = safe_str(row.get("KQL Query"))
        output = safe_str(row.get("Output"))
        remarks = safe_str(row.get("Remarks/Comments"))

        # 🚨 CRITICAL FIX: Filter output by username
        if output:
            output = filter_kql_output_by_user(output, username, step_name)
            logger.info(
                f"Row {idx}: Filtered output for {username}: {len(output)} chars"
            )

        # ✅ CREATE STEP DATA
        step_data = {
            "step_number": step_num,
            "step_name": step_name,
            "explanation": explanation,
            "kql_query": kql_query,
            "output": output,
            "remarks": remarks,
            "analyst_notes": remarks,
        }

        # ✅ ONLY ADD IF HAS MEANINGFUL DATA
        if output or remarks or explanation:
            investigation_steps.append(step_data)
            logger.info(
                f"Row {idx}: ✅ Step {step_num} - {step_name[:50]} (Output: {len(output)}ch, Remarks: {len(remarks)}ch)"
            )
        else:
            logger.info(f"Row {idx}: ⭕ Step {step_num} SKIPPED (No data)")

    logger.info(f"=" * 60)
    logger.info(f"EXTRACTION COMPLETE: {len(investigation_steps)} steps extracted")

    if not investigation_steps:
        logger.error("❌ NO STEPS EXTRACTED! Check Excel format.")

    return investigation_steps
