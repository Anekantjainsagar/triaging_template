import pandas as pd
import re
from typing import List, Dict


class TemplateParser:
    def parse_csv_template(self, csv_path: str) -> List[Dict]:
        """Parse CSV template and extract ALL steps"""
        print(f"\n📋 Parsing CSV template: {csv_path}")

        df = None
        for encoding in ["utf-8", "latin1", "cp1252"]:
            try:
                df = pd.read_csv(csv_path, encoding=encoding)
                print(f"✅ Successfully read CSV with {encoding} encoding")
                break
            except:
                continue

        if df is None:
            print("❌ Could not read CSV")
            return []

        return self._extract_steps(df)

    def parse_excel_template(self, excel_path: str) -> List[Dict]:
        """Parse Excel template and extract ALL steps"""
        print(f"\n📋 Parsing Excel template: {excel_path}")

        try:
            df = pd.read_excel(excel_path, engine="openpyxl")
            print(f"✅ Successfully read Excel file")
            return self._extract_steps(df)
        except Exception as e:
            print(f"❌ Failed to read Excel: {str(e)}")
            return []

    def _extract_steps(self, df: pd.DataFrame) -> List[Dict]:
        """
        Extract ALL steps from DataFrame.
        CRITICAL: This function must NEVER skip valid investigation steps.
        """
        # Clean column names
        df.columns = df.columns.str.strip()

        print(f"\n📊 DataFrame columns: {list(df.columns)}")
        print(f"📏 DataFrame shape: {df.shape} (rows x columns)")

        # Identify columns (flexible matching)
        step_col = self._find_column(
            df, ["Inputs Required", "Step Name", "Step", "Name", "Sr.No."]
        )
        explanation_col = self._find_column(
            df, ["Instructions", "Explanation", "Description"]
        )
        input_col = self._find_column(df, ["INPUT details", "Input", "Input Required"])
        kql_col = self._find_column(df, ["KQL Query", "Query", "KQL"])

        print(f"✅ Mapped columns:")
        print(f"   Step: {step_col}")
        print(f"   Explanation: {explanation_col}")
        print(f"   Input: {input_col}")
        print(f"   KQL: {kql_col}")

        if not step_col:
            print("❌ Could not find step column - trying fallback...")
            return self._extract_from_first_column(df)

        steps = []
        skipped_rows = []

        for idx, row in df.iterrows():
            step_name = str(row.get(step_col, "")).strip()

            # Skip completely empty rows
            if not step_name or step_name == "nan" or len(step_name) < 2:
                continue

            # ✅ FIXED: Only skip OBVIOUS metadata rows
            if self._is_metadata_row(step_name):
                skipped_rows.append(f"Row {idx}: {step_name} (metadata)")
                continue

            # Extract explanation and input
            explanation = (
                str(row.get(explanation_col, "")).strip() if explanation_col else ""
            )
            input_details = str(row.get(input_col, "")).strip() if input_col else ""
            kql_query = str(row.get(kql_col, "")).strip() if kql_col else ""

            # Clean 'nan' values
            if explanation == "nan":
                explanation = ""
            if input_details == "nan":
                input_details = ""
            if kql_query == "nan":
                kql_query = ""

            # ✅ KEEP ORIGINAL STEP NAME (just basic cleanup)
            clean_step_name = self._clean_step_name_only(step_name)

            # Build step dictionary
            step = {
                "step_name": clean_step_name,  # ✅ ORIGINAL NAME PRESERVED
                "explanation": explanation,  # ✅ ORIGINAL EXPLANATION PRESERVED
                "input_required": self._extract_inputs(step_name, explanation),
                "kql_query": self._basic_kql_cleanup(
                    kql_query
                ),  # ✅ BASIC CLEANUP ONLY
            }

            print(f"\n📋 Extracted Step {len(steps) + 1}: {clean_step_name}")
            if explanation:
                print(f"   Has explanation: {explanation[:60]}...")
            if kql_query:
                print(f"   Has KQL query: {len(kql_query)} chars")
            steps.append(step)

        # Report skipped rows
        if skipped_rows:
            print(f"\n⏭️ Skipped {len(skipped_rows)} metadata rows:")
            for skipped in skipped_rows[:3]:  # Show first 3
                print(f"   {skipped}")

        print(f"\n✅ Total investigation steps extracted: {len(steps)}")

        # ✅ VALIDATION: Warn if too few steps
        if len(steps) < 3:
            print(
                f"⚠️ WARNING: Only {len(steps)} steps found. Template may be incomplete."
            )

        return steps

    def _is_metadata_row(self, step_name: str) -> bool:
        """
        ✅ FIXED: Only skip OBVIOUS metadata - be very conservative.
        """
        step_lower = step_name.lower().strip()

        # ✅ ONLY skip these exact patterns
        metadata_patterns = [
            r"^rule\s*#?\d+\s*-",  # "Rule#183 - " (only with dash)
            r"^incident\s*number\s*:",  # "Incident Number:"
            r"^reported\s*time\s*:",  # "Reported Time:"
            r"^username\s*:",  # "Username:"
            r"^vip\s*users?\s*list",  # "VIP Users List"
            r"^sr\.?\s*no\.?\s*$",  # Just "Sr.No." or "Sr No"
            r"^step\s*$",  # Just the word "Step"
            r"^inputs?\s*required\s*$",  # Column header
            r"^instructions?\s*$",  # Column header
            r"^\s*$",  # Empty
        ]

        for pattern in metadata_patterns:
            if re.match(pattern, step_lower):
                return True

        return False

    def _clean_step_name_only(self, step_name: str) -> str:
        """
        ✅ MINIMAL cleaning - preserve original name as much as possible
        """
        # Remove only leading numbers like "1. " or "Step 1: "
        clean = re.sub(r"^\d+\.?\s*", "", step_name)
        clean = re.sub(r"^Step\s*\d+:?\s*", "", clean, flags=re.IGNORECASE)

        # Remove excessive whitespace
        clean = " ".join(clean.split())

        return clean.strip() if clean else step_name

    def _basic_kql_cleanup(self, kql: str) -> str:
        """
        ✅ BASIC cleanup only - preserve the query structure
        """
        if not kql or kql.strip().upper() in ["N/A", "NA", ""]:
            return ""

        # Remove markdown code blocks only
        kql = re.sub(r"```[a-z]*\s*\n?", "", kql)
        kql = re.sub(r"\n?```", "", kql)

        # Clean excessive whitespace but preserve line breaks
        lines = [line.strip() for line in kql.split("\n") if line.strip()]
        kql = "\n".join(lines)

        return kql.strip()

    def _extract_from_first_column(self, df: pd.DataFrame) -> List[Dict]:
        """Fallback: Extract from first column if column detection fails"""
        print("⚠️ Using fallback extraction from first column...")

        steps = []
        first_col = df.columns[0]

        for idx, row in df.iterrows():
            value = str(row[first_col]).strip()

            if value and value != "nan" and len(value) > 2:
                if not self._is_metadata_row(value):
                    steps.append(
                        {
                            "step_name": self._clean_step_name_only(value),
                            "explanation": "",  # Will be enhanced later
                            "input_required": "Investigation data",
                            "kql_query": "",
                        }
                    )

        print(f"✅ Fallback extracted {len(steps)} steps")
        return steps

    def _extract_inputs(self, step_name: str, explanation: str) -> str:
        """Determine what inputs are needed for this step"""
        step_lower = step_name.lower()
        exp_lower = explanation.lower() if explanation else ""
        combined = f"{step_lower} {exp_lower}"

        # Pattern matching for common step types
        if "vip" in combined:
            return "User principal name, VIP user list"
        elif "kql" in combined or "query" in combined or "log" in combined:
            return "User principal name, Time range (last 7 days)"
        elif "ip" in combined and "reputation" in combined:
            return "Source IP address"
        elif "device" in combined:
            return "Device ID or device name"
        elif "user" in combined and ("confirm" in combined or "contact" in combined):
            return "User contact information (email/phone)"
        elif "application" in combined or "app" in combined:
            return "Application name, User principal name"
        elif "classification" in combined or "final" in combined:
            return "All investigation findings from previous steps"
        elif "mfa" in combined or "authentication" in combined:
            return "User principal name, Authentication logs"
        elif "escalat" in combined:
            return "Classification decision, Escalation path"
        else:
            return "Investigation findings from previous steps"

    def _find_column(self, df: pd.DataFrame, possible_names: List[str]) -> str:
        """Find column by trying multiple possible names"""
        for col in df.columns:
            col_lower = col.lower().strip()
            for possible in possible_names:
                if possible.lower() in col_lower:
                    return col
        return None
