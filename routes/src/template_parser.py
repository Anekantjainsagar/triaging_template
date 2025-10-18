import pandas as pd
from typing import List, Dict


class TemplateParser:
    def parse_csv_template(self, csv_path: str) -> List[Dict]:
        """Parse CSV with ZERO modification"""
        print(f"\n📋 Parsing CSV: {csv_path}")

        df = None
        for encoding in ["utf-8", "latin1", "cp1252"]:
            try:
                df = pd.read_csv(csv_path, encoding=encoding)
                print(f"✅ Read with {encoding}")
                break
            except:
                continue

        if df is None:
            print("❌ Could not read CSV")
            return []

        return self._extract_from_original_template(df)

    def parse_excel_template(self, excel_path: str) -> List[Dict]:
        """Parse Excel with ZERO modification"""
        print(f"\n📋 Parsing Excel: {excel_path}")

        try:
            df = pd.read_excel(excel_path, engine="openpyxl")
            print(f"✅ Read Excel successfully")
            return self._extract_from_original_template(df)
        except Exception as e:
            print(f"❌ Failed: {str(e)}")
            return []

    def _extract_from_original_template(self, df: pd.DataFrame) -> List[Dict]:
        """
        ✅ EXTRACT FROM ORIGINAL TEMPLATE STRUCTURE

        Your template has these columns:
        - Sr.No. = Step number
        - Inputs Required = THE REAL STEP NAME (what we want!)
        - INPUT details = Input data
        - Instructions = Explanation
        """
        df.columns = df.columns.str.strip()

        print(f"\n📊 Columns found: {list(df.columns)}")
        print(f"📏 Total rows: {len(df)}")

        # Map to YOUR template structure
        step_name_col = "Inputs Required"  # ✅ THIS is the original step name!
        explanation_col = "Instructions"
        input_col = "INPUT details"
        kql_col = None  # Your template doesn't have KQL in original

        # Check if columns exist
        if step_name_col not in df.columns:
            print(f"❌ Column '{step_name_col}' not found!")
            print(f"Available columns: {list(df.columns)}")
            return []

        print(f"\n✅ Using columns:")
        print(f"   Step Name: '{step_name_col}'")
        print(f"   Explanation: '{explanation_col}'")
        print(f"   Input: '{input_col}'")

        steps = []

        for idx, row in df.iterrows():
            # Get ORIGINAL step name from "Inputs Required" column
            original_step_name = str(row.get(step_name_col, "")).strip()
            explanation = (
                str(row.get(explanation_col, "")).strip()
                if explanation_col in df.columns
                else ""
            )
            input_details = (
                str(row.get(input_col, "")).strip() if input_col in df.columns else ""
            )

            # Skip empty rows
            if (
                not original_step_name
                or original_step_name == "nan"
                or len(original_step_name) < 2
            ):
                continue

            # Skip metadata headers
            if self._is_metadata_header(original_step_name):
                print(f"⏭️ Skipping metadata: {original_step_name}")
                continue

            # Clean 'nan' strings only
            if explanation == "nan":
                explanation = ""
            if input_details == "nan":
                input_details = ""

            # ✅ STORE EXACT ORIGINAL
            step = {
                "step_name": original_step_name,  # ✅ FROM "Inputs Required" - THE REAL NAME!
                "explanation": explanation,  # ✅ FROM "Instructions"
                "input_required": input_details,  # ✅ FROM "INPUT details"
                "kql_query": "",  # Empty - KQL will be added by enhancer
            }

            print(f"\n✅ Step {len(steps) + 1}: '{original_step_name}'")
            if explanation:
                print(f"   Explanation: {explanation[:80]}...")

            steps.append(step)

        print(f"\n✅ EXTRACTED {len(steps)} ORIGINAL STEPS")
        return steps

    def _is_metadata_header(self, text: str) -> bool:
        """Skip only obvious metadata headers"""
        text_lower = text.lower().strip()

        metadata_patterns = [
            text_lower.startswith("rule#"),
            text_lower.startswith("rule #"),
            text_lower.startswith("incident"),
            text_lower.startswith("reported time"),
            text_lower == "sr.no.",
            text_lower == "inputs required",
            text_lower == "instructions",
            text_lower == "input details",
        ]

        return any(metadata_patterns)
