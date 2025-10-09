import pandas as pd
import re
from typing import List, Dict


class TemplateParser:
    """
    ✅ FIXED: DIRECT extraction with ZERO modification
    """

    def parse_csv_template(self, csv_path: str) -> List[Dict]:
        """Parse CSV and return EXACT steps as-is"""
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

        return self._extract_steps_direct(df)

    def parse_excel_template(self, excel_path: str) -> List[Dict]:
        """Parse Excel and return EXACT steps as-is"""
        print(f"\n📋 Parsing Excel: {excel_path}")

        try:
            df = pd.read_excel(excel_path, engine="openpyxl")
            print(f"✅ Read Excel successfully")
            return self._extract_steps_direct(df)
        except Exception as e:
            print(f"❌ Failed: {str(e)}")
            return []

    def _extract_steps_direct(self, df: pd.DataFrame) -> List[Dict]:
        """
        ✅ EXTRACT STEPS EXACTLY AS THEY ARE - NO MODIFICATIONS
        """
        df.columns = df.columns.str.strip()

        print(f"\n📊 Columns: {list(df.columns)}")
        print(f"📏 Shape: {df.shape}")

        # Find columns (flexible matching)
        step_col = self._find_column(
            df, ["Inputs Required", "Step Name", "Step", "Name", "Sr.No."]
        )
        explanation_col = self._find_column(
            df, ["Instructions", "Explanation", "Description"]
        )
        input_col = self._find_column(df, ["INPUT details", "Input", "Input Required"])
        kql_col = self._find_column(df, ["KQL Query", "Query", "KQL"])

        if not step_col:
            print("❌ No step column found")
            return []

        print(
            f"✅ Mapped - Step: {step_col}, Explanation: {explanation_col}, Input: {input_col}, KQL: {kql_col}"
        )

        steps = []
        skipped = []

        for idx, row in df.iterrows():
            step_name = str(row.get(step_col, "")).strip()

            # Skip empty
            if not step_name or step_name == "nan" or len(step_name) < 2:
                continue

            # Skip only OBVIOUS metadata
            if self._is_metadata_row(step_name):
                skipped.append(f"Row {idx}: {step_name}")
                continue

            # ✅ EXTRACT EXACTLY AS-IS
            explanation = (
                str(row.get(explanation_col, "")).strip() if explanation_col else ""
            )
            input_details = str(row.get(input_col, "")).strip() if input_col else ""
            kql_query = str(row.get(kql_col, "")).strip() if kql_col else ""

            # Clean 'nan' strings
            if explanation == "nan":
                explanation = ""
            if input_details == "nan":
                input_details = ""
            if kql_query == "nan":
                kql_query = ""

            # ✅ MINIMAL CLEANUP - PRESERVE ORIGINAL
            clean_step_name = self._minimal_cleanup(step_name)
            clean_explanation = self._minimal_cleanup(explanation)
            clean_kql = self._minimal_kql_cleanup(kql_query)

            # ✅ STORE EXACTLY AS-IS
            step = {
                "step_name": clean_step_name,  # Original name preserved
                "explanation": clean_explanation,  # Original explanation preserved
                "input_required": (
                    input_details if input_details else "Investigation data"
                ),
                "kql_query": clean_kql,  # Original KQL preserved
            }

            print(f"\n✅ Extracted Step {len(steps) + 1}: {clean_step_name}")
            if explanation:
                print(f"   Explanation: {explanation[:60]}...")
            if kql_query:
                print(f"   KQL: {len(kql_query)} chars")

            steps.append(step)

        print(f"\n✅ EXTRACTED {len(steps)} ORIGINAL STEPS")
        if skipped:
            print(f"⏭️ Skipped {len(skipped)} metadata rows")

        return steps

    def _is_metadata_row(self, step_name: str) -> bool:
        """Identify ONLY metadata rows (be conservative)"""
        step_lower = step_name.lower().strip()

        # Only skip these EXACT patterns
        skip_patterns = [
            r"^rule\s*#?\d+\s*-",  # "Rule#183 - "
            r"^incident\s*number",
            r"^reported\s*time",
            r"^username\s*:",
            r"^vip\s*users?\s*list",
            r"^sr\.?\s*no\.?\s*$",
            r"^step\s*$",
            r"^inputs?\s*required\s*$",
            r"^instructions?\s*$",
        ]

        return any(re.match(pattern, step_lower) for pattern in skip_patterns)

    def _minimal_cleanup(self, text: str) -> str:
        """MINIMAL cleanup - preserve original as much as possible"""
        if not text:
            return text

        # Remove ONLY leading numbers
        text = re.sub(r"^\d+\.?\s*", "", text)
        text = re.sub(r"^Step\s*\d+:?\s*", "", text, flags=re.IGNORECASE)

        # Remove excessive whitespace
        text = " ".join(text.split())

        return text.strip()

    def _minimal_kql_cleanup(self, kql: str) -> str:
        """MINIMAL KQL cleanup - preserve structure"""
        if not kql or kql.strip().upper() in ["N/A", "NA", ""]:
            return ""

        # Remove ONLY code blocks
        kql = re.sub(r"```[a-z]*\s*\n?", "", kql)
        kql = re.sub(r"\n?```", "", kql)

        # Preserve structure
        lines = [line.rstrip() for line in kql.split("\n") if line.strip()]
        kql = "\n".join(lines)

        return kql.strip()

    def _find_column(self, df: pd.DataFrame, possible_names: List[str]) -> str:
        """Find column by name matching"""
        for col in df.columns:
            col_lower = col.lower().strip()
            for possible in possible_names:
                if possible.lower() in col_lower:
                    return col
        return None
