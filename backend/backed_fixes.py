import pandas as pd
import numpy as np
from typing import List, Dict, Any
import logging

# Setup logging for FastAPI
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


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
    """FIXED: Extract investigation steps with proper NULL handling"""

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
            logger.info(f"Row {idx}: ⏭️  Step {step_num} SKIPPED (No data)")

    logger.info(f"=" * 60)
    logger.info(f"EXTRACTION COMPLETE: {len(investigation_steps)} steps extracted")

    if not investigation_steps:
        logger.error("❌ NO STEPS EXTRACTED! Check Excel format.")

    return investigation_steps
