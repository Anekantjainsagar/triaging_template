import pandas as pd
import numpy as np
from typing import List, Dict, Any


def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean DataFrame by replacing all NaN/NULL/None values properly

    Args:
        df: Input DataFrame

    Returns:
        Cleaned DataFrame with NaN values handled
    """
    # Create a copy
    df_clean = df.copy()

    # Replace all types of NaN/NULL values
    df_clean = df_clean.replace(
        {
            pd.NA: None,
            pd.NaT: None,
            float("nan"): None,
            float("inf"): None,
            float("-inf"): None,
            "nan": None,
            "NaN": None,
            "NaT": None,
            "<NA>": None,
        }
    )

    # Use where to replace remaining NaN values
    df_clean = df_clean.where(pd.notna(df_clean), None)

    return df_clean


def extract_investigation_steps_fixed(
    df: pd.DataFrame, username: str
) -> List[Dict[str, Any]]:
    """
    FIXED: Extract investigation steps with proper NULL handling and debugging

    Args:
        df: Investigation data DataFrame
        username: Username to extract data for

    Returns:
        List of investigation step dictionaries
    """
    print(f"\n{'='*60}")
    print(f"🔍 EXTRACTING INVESTIGATION STEPS FOR: {username}")
    print(f"{'='*60}")

    investigation_steps = []

    # Debug: Print DataFrame info
    print(f"\n📊 DataFrame Info:")
    print(f"  - Total rows: {len(df)}")
    print(f"  - Columns: {df.columns.tolist()}")

    if len(df) > 0:
        print(f"\n📋 First row sample:")
        first_row = df.iloc[0]
        for col in df.columns:
            value = first_row.get(col)
            print(f"  - {col}: {repr(value)} (type: {type(value).__name__})")

    # Process each row
    for idx, row in df.iterrows():
        # ✅ CHECK IF THIS IS HEADER ROW
        step_value = row.get("Step", None)

        # Skip if Step is NULL/NaN (header row)
        if pd.isna(step_value) or step_value is None:
            print(f"\n⏭️  Row {idx}: SKIPPED (Header row - Step is NULL)")
            print(f"     Name value: {repr(row.get('Name'))}")
            continue

        # ✅ VALIDATE STEP NUMBER
        try:
            step_num = int(step_value)
            if step_num < 1:
                print(f"\n⏭️  Row {idx}: SKIPPED (Invalid step number: {step_value})")
                continue
        except (ValueError, TypeError) as e:
            print(
                f"\n⏭️  Row {idx}: SKIPPED (Non-numeric step: {step_value}, error: {e})"
            )
            continue

        # ✅ EXTRACT ALL FIELDS
        step_name = row.get("Name", "Unknown Step")
        explanation = row.get("Explanation", "")
        kql_query = row.get("KQL Query", "")
        output_value = row.get("Output", "")
        remarks_value = row.get("Remarks/Comments", "")

        # ✅ CLEAN VALUES
        def clean_value(val):
            """Helper to clean a single value"""
            if val is None or pd.isna(val):
                return ""
            val_str = str(val).strip()
            if val_str.lower() in ["nan", "none", "null", "", "<na>"]:
                return ""
            return val_str

        output_str = clean_value(output_value)
        remarks_str = clean_value(remarks_value)
        explanation_str = clean_value(explanation)
        kql_str = clean_value(kql_query)
        step_name_str = clean_value(step_name) or f"Step {step_num}"

        # ✅ CREATE STEP DICTIONARY
        step_data = {
            "step_number": step_num,
            "step_name": step_name_str,
            "explanation": explanation_str,
            "kql_query": kql_str,
            "output": output_str,
            "remarks": remarks_str,
            "analyst_notes": remarks_str,  # Duplicate for compatibility
        }

        # ✅ CHECK IF STEP HAS MEANINGFUL DATA
        has_meaningful_data = output_str or remarks_str or explanation_str or kql_str

        if has_meaningful_data:
            investigation_steps.append(step_data)
            print(f"\n✅ Row {idx}: Step {step_num} - {step_name_str}")
            print(f"     Output: {len(output_str)} chars")
            print(f"     Remarks: {len(remarks_str)} chars")
            print(f"     Explanation: {len(explanation_str)} chars")
        else:
            print(f"\n⚠️  Row {idx}: Step {step_num} SKIPPED (No meaningful data)")

    # ✅ FINAL SUMMARY
    print(f"\n{'='*60}")
    print(f"📊 EXTRACTION SUMMARY")
    print(f"{'='*60}")
    print(f"✅ Total steps extracted: {len(investigation_steps)}")

    if investigation_steps:
        print(f"\n📝 Extracted Steps:")
        for step in investigation_steps[:5]:  # Show first 5
            print(f"  - Step {step['step_number']}: {step['step_name']}")
            print(f"    • Output: {len(step['output'])} chars")
            print(f"    • Remarks: {len(step['remarks'])} chars")

        if len(investigation_steps) > 5:
            print(f"  ... and {len(investigation_steps) - 5} more steps")
    else:
        print(f"\n❌ NO STEPS EXTRACTED!")
        print(f"   This will cause analysis to fail.")
        print(f"   Please check if the Excel file has the correct format:")
        print(f"   - Step column should have numbers (1, 2, 3...)")
        print(f"   - Output column should have data")
        print(f"   - First row should be the template header (Step = NULL)")

    print(f"{'='*60}\n")

    return investigation_steps


def validate_extracted_steps(steps: List[Dict[str, Any]], username: str) -> bool:
    """
    Validate extracted steps have required data

    Args:
        steps: List of extracted steps
        username: Username being analyzed

    Returns:
        True if valid, False otherwise
    """
    if not steps:
        print(f"❌ VALIDATION FAILED: No steps extracted for {username}")
        return False

    if len(steps) < 2:
        print(f"⚠️  WARNING: Only {len(steps)} step(s) extracted for {username}")
        print(f"   This may not be enough for comprehensive analysis")

    # Check if at least one step has output
    has_output = any(step.get("output") for step in steps)
    if not has_output:
        print(f"❌ VALIDATION FAILED: No steps have output data")
        return False

    print(f"✅ VALIDATION PASSED: {len(steps)} steps with valid data")
    return True
