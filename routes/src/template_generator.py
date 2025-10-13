import pandas as pd
import re
from io import BytesIO
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side


class CompleteTemplateGenerator:

    def __init__(self, kql_generator=None, step_name_generator=None):
        # Import generators
        from routes.src.kql_generation import DynamicKQLGenerator
        from routes.src.step_name import IntelligentStepNameGenerator

        self.kql_gen = kql_generator or DynamicKQLGenerator()
        self.name_gen = step_name_generator or IntelligentStepNameGenerator()

        # Updated columns - NO INPUT COLUMN
        self.template_columns = [
            "Step",
            "Name",
            "Explanation",
            "KQL Query",
            "Execute",
            "Output",
            "Remarks/Comments",
        ]

    def generate_template(
        self, rule_number: str, parsed_steps: list, rule_history: dict
    ) -> pd.DataFrame:
        """
        Main generation function

        Args:
            rule_number: Rule identifier (e.g., "Rule#014")
            parsed_steps: Steps from template parser
            rule_history: Historical data for this rule

        Returns:
            Clean DataFrame ready for Excel export
        """
        print(f"\n{'='*80}")
        print(f"GENERATING TEMPLATE FOR {rule_number}")
        print(f"{'='*80}")

        template_rows = []

        # Header row
        header_row = {
            "Step": "",
            "Name": rule_number,
            "Explanation": "",
            "KQL Query": "",
            "Execute": "",
            "Output": "",
            "Remarks/Comments": "",
        }
        template_rows.append(header_row)

        # Process each step
        for i, step in enumerate(parsed_steps, 1):
            print(f"\n--- Processing Step {i} ---")

            # 1. Generate clear step name
            raw_name = step.get("step_name", f"Step {i}")
            explanation = step.get("explanation", "")

            clear_name = self.name_gen.generate_step_name(
                raw_name=raw_name,
                explanation=explanation,
                step_num=i,
                context=rule_number,
            )
            print(f"âœ… Step Name: {clear_name}")

            # 2. Generate KQL query
            kql_query = self.kql_gen.generate_kql_query(
                step_name=clear_name, explanation=explanation, context=rule_number
            )

            if kql_query:
                print(f"âœ… KQL Generated: {len(kql_query)} chars")
            else:
                print("âš ï¸ No KQL query (documentation step)")

            # 3. Create clean explanation
            clean_explanation = self._clean_explanation(explanation)

            # 4. Build row (NO INPUT COLUMN)
            step_row = {
                "Step": i,
                "Name": clear_name,
                "Explanation": clean_explanation,
                "KQL Query": kql_query,
                "Execute": "",  # For manual checkbox/completion
                "Output": "",  # For findings
                "Remarks/Comments": "",
            }

            template_rows.append(step_row)

        print(f"\nâœ… Generated {len(template_rows)-1} investigation steps")
        return pd.DataFrame(template_rows)

    def _clean_explanation(self, explanation: str) -> str:
        """Clean explanation text"""
        if not explanation:
            return "Complete this investigation step and document findings"

        # Remove markdown
        text = re.sub(r"\*\*\*+", "", explanation)
        text = re.sub(r"\*\*", "", text)
        text = re.sub(r"\*", "", text)
        text = re.sub(r"#+\s*", "", text)
        text = re.sub(r"`", "", text)

        # Remove prefixes
        text = re.sub(
            r"^(Explanation:|Instructions:|Description:)\s*",
            "",
            text,
            flags=re.IGNORECASE,
        )

        # Clean whitespace
        text = " ".join(text.split())

        return text.strip()

    def export_to_excel(self, df: pd.DataFrame, rule_number: str) -> BytesIO:
        """Export to professionally formatted Excel"""
        output = BytesIO()

        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            df.to_excel(writer, sheet_name="Triaging_Template", index=False)

            workbook = writer.book
            worksheet = writer.sheets["Triaging_Template"]

            # Format worksheet
            self._format_worksheet(worksheet, df)

        output.seek(0)
        return output

    def _format_worksheet(self, worksheet, df):
        """Apply professional Excel formatting"""

        # Header style
        header_font = Font(bold=True, color="FFFFFF", size=11)
        header_fill = PatternFill(
            start_color="366092", end_color="366092", fill_type="solid"
        )
        header_alignment = Alignment(
            horizontal="center", vertical="center", wrap_text=True
        )

        # Apply header formatting
        for col_num, column_title in enumerate(df.columns, 1):
            cell = worksheet.cell(row=1, column=col_num)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = header_alignment

        # Column widths (UPDATED - no Input column)
        column_widths = {
            "A": 8,  # Step
            "B": 35,  # Name
            "C": 50,  # Explanation
            "D": 65,  # KQL Query (wider!)
            "E": 12,  # Execute
            "F": 25,  # Output
            "G": 40,  # Remarks/Comments
        }

        for col_letter, width in column_widths.items():
            worksheet.column_dimensions[col_letter].width = width

        # Cell formatting
        thin_border = Border(
            left=Side(style="thin", color="CCCCCC"),
            right=Side(style="thin", color="CCCCCC"),
            top=Side(style="thin", color="CCCCCC"),
            bottom=Side(style="thin", color="CCCCCC"),
        )

        cell_alignment = Alignment(vertical="top", wrap_text=True, horizontal="left")

        # Apply to all data cells
        for row_idx, row in enumerate(worksheet.iter_rows(min_row=2), start=2):
            for cell in row:
                cell.border = thin_border
                cell.alignment = cell_alignment

                # Alternate row colors
                if row_idx % 2 == 0:
                    cell.fill = PatternFill(
                        start_color="F9F9F9", end_color="F9F9F9", fill_type="solid"
                    )

        # Highlight rule header row
        for col_idx in range(1, len(df.columns) + 1):
            cell = worksheet.cell(row=2, column=col_idx)
            cell.fill = PatternFill(
                start_color="E8F4F8", end_color="E8F4F8", fill_type="solid"
            )
            cell.font = Font(bold=True, size=11)

        # KQL Query column - code font
        kql_col_idx = list(df.columns).index("KQL Query") + 1
        for row_idx in range(3, len(df) + 2):
            cell = worksheet.cell(row=row_idx, column=kql_col_idx)
            cell.font = Font(name="Consolas", size=9)
            cell.alignment = Alignment(
                vertical="top", wrap_text=True, horizontal="left"
            )

        # Freeze header
        worksheet.freeze_panes = "A2"


# Integration wrapper for existing codebase
class EnhancedTemplateGenerator:

    def __init__(self):
        from routes.src.kql_generation import DynamicKQLGenerator
        from routes.src.step_name import IntelligentStepNameGenerator

        self.kql_gen = DynamicKQLGenerator()
        self.name_gen = IntelligentStepNameGenerator()
        self.generator = CompleteTemplateGenerator(self.kql_gen, self.name_gen)

        # Keep old column names for compatibility
        self.template_columns = [
            "Step",
            "Name",
            "Explanation",
            "KQL Query",
            "Execute",
            "Output",
            "Remarks/Comments",
        ]

    def generate_clean_template(
        self, rule_number: str, enhanced_steps: list
    ) -> pd.DataFrame:
        """
        Generate clean template (compatibility wrapper)

        Args:
            rule_number: Rule identifier
            enhanced_steps: Steps from web_llm_enhancer

        Returns:
            DataFrame with clean template
        """
        # Get rule history
        from routes.src.utils import read_all_tracker_sheets, consolidate_rule_data

        try:
            all_data = read_all_tracker_sheets("data")
            rule_history = consolidate_rule_data(all_data, rule_number)
        except:
            rule_history = {"fp_rate": 50, "tp_rate": 50, "total_incidents": 0}

        return self.generator.generate_template(
            rule_number, enhanced_steps, rule_history
        )

    def export_to_excel(self, df: pd.DataFrame, rule_number: str) -> BytesIO:
        """Export to Excel (compatibility wrapper)"""
        return self.generator.export_to_excel(df, rule_number)
