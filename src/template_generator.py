import pandas as pd
import re
from io import BytesIO
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter


class TriagingTemplateGenerator:
    """
    Generates clean, structured triaging templates in Excel format.
    No asterisks, proper formatting, comprehensive details with KQL queries.
    """

    def __init__(self):
        self.template_columns = [
            "Step",
            "Name",
            "Explanation",
            "Input",
            "KQL Query",
            "Execute",
            "Output",
            "Remarks/Comments",
        ]

    def generate_structured_template(
        self, rule_number: str, triaging_steps: list, rule_history: dict
    ) -> pd.DataFrame:
        """Generate structured template as DataFrame for Excel export"""
        template_rows = []

        # Add rule header row
        header_row = {
            "Step": "",
            "Name": rule_number,
            "Explanation": "",
            "Input": f"",
            "KQL Query": "",
            "Execute": "",
            "Output": "",
            "Remarks/Comments": f"",
        }
        template_rows.append(header_row)

        # Add investigation steps
        for i, step in enumerate(triaging_steps, 1):
            step_row = self._create_step_row(i, step, rule_history)
            template_rows.append(step_row)

        # Add final assessment steps
        final_steps = self._create_final_assessment_steps(
            len(triaging_steps) + 1, rule_history
        )
        template_rows.extend(final_steps)

        return pd.DataFrame(template_rows)

    def _create_step_row(self, step_num: int, step: dict, rule_history: dict) -> dict:
        """Create a single step row with clean formatting and complete data"""
        step_name = step.get("step_name", f"Investigation Step {step_num}")
        explanation = step.get("explanation", "")  # ⭐ Use this, don't hardcode data
        input_required = step.get("input_required", "")
        expected_output = step.get("expected_output", "")
        kql_query = step.get("kql_query", "")

        # Clean up the step name (remove markdown, asterisks, numbering)
        clean_name = self._clean_step_name(step_name)

        # Clean up explanation (remove markdown formatting)
        clean_explanation = self._clean_text(explanation)
        
        # ⭐ IMPORTANT: Don't put data here, only instructions
        if not clean_explanation or clean_explanation == step_name:
            clean_explanation = f"Complete {clean_name} and document findings"

        # Clean and format KQL query
        clean_kql = self._clean_kql_query(kql_query)

        # Create comprehensive remarks with expected output
        remarks = ""

        return {
            "Step": step_num,
            "Name": clean_name,
            "Explanation": clean_explanation,  # ⭐ Instructions, NOT data
            "Input": "",  # ⭐ Empty - user fills during investigation
            "KQL Query": clean_kql,
            "Execute": "",  # ⭐ Empty for manual filling
            "Output": "",  # ⭐ Empty for manual filling
            "Remarks/Comments": remarks,  # ⭐ Expected findings
        }

    def _clean_step_name(self, step_name: str) -> str:
        """Clean and SIMPLIFY step name - make it action-focused and concise"""
        if not step_name:
            return "Investigation Step"

        # Remove all markdown formatting
        clean = re.sub(r"\*+", "", step_name)
        clean = re.sub(r"#+", "", clean)
        clean = re.sub(r"^Step\s*\d+:?\s*", "", clean, flags=re.IGNORECASE)
        clean = re.sub(r"^\d+\.\s*", "", clean)
        clean = re.sub(r"^[\-\*]\s*", "", clean)

        # Remove common verbose phrases
        clean = re.sub(
            r"^(Please\s+)?(Perform\s+)?(Complete\s+)?", "", clean, flags=re.IGNORECASE
        )
        clean = re.sub(r"\s+(step|phase|task)$", "", clean, flags=re.IGNORECASE)

        # Simplify overly long names (keep first 6-7 words max)
        words = clean.split()

        # Clean whitespace
        clean = " ".join(clean.strip().split())

        return clean if clean else "Investigation Step"

    def _clean_text(self, text: str) -> str:
        """Clean explanation text - remove markdown and keep CONCISE"""
        if not text:
            return ""

        # Remove markdown
        clean_text = re.sub(r"\*\*\*+", "", text)
        clean_text = re.sub(r"\*\*", "", clean_text)
        clean_text = re.sub(r"\*", "", clean_text)
        clean_text = re.sub(r"#+\s*", "", clean_text)
        clean_text = re.sub(r"```[a-z]*\n", "", clean_text)
        clean_text = re.sub(r"\n```", "", clean_text)
        clean_text = re.sub(r"`([^`]+)`", r"\1", clean_text)

        # Remove common verbose prefixes
        clean_text = re.sub(
            r"^(Explanation:|EXPLANATION:|Description:|DESCRIPTION:|Instructions:|INSTRUCTIONS:)\s*",
            "",
            clean_text,
            flags=re.IGNORECASE,
        )

        # Limit explanation length (max 200 chars for conciseness)
        if len(clean_text) > 200:
            # Try to cut at sentence boundary
            sentences = clean_text.split(". ")
            clean_text = sentences[0]
            if len(sentences) > 1 and len(clean_text) < 150:
                clean_text += ". " + sentences[1]
            if not clean_text.endswith("."):
                clean_text += "."

        # Clean whitespace
        clean_text = re.sub(r"\s+", " ", clean_text)
        clean_text = clean_text.strip()

        return clean_text

    def _clean_kql_query(self, kql: str) -> str:
        """Clean and format KQL query for Excel display"""
        if not kql or kql.strip() == "" or kql.strip().upper() == "N/A":
            return ""

        # Remove markdown code block formatting
        clean_kql = re.sub(r"```[a-z]*\s*\n?", "", kql)
        clean_kql = re.sub(r"\n?```", "", clean_kql)

        # Clean up excessive whitespace but preserve line structure
        lines = [line.strip() for line in clean_kql.split("\n") if line.strip()]

        # Format KQL query properly
        formatted_lines = []
        for line in lines:
            # Add proper spacing for pipe operators
            if line.startswith("|"):
                formatted_lines.append(line)
            else:
                formatted_lines.append(line)

        clean_kql = "\n".join(formatted_lines)

        return clean_kql.strip()

    def _create_final_assessment_steps(
        self, start_num: int, rule_history: dict
    ) -> list:
        """Create standardized final assessment steps"""
        steps = []
        current_num = start_num

        # Final Classification
        steps.append(
            {
                "Step": current_num,
                "Name": "Final Classification",
                "Explanation": "Classify the incident based on all investigation findings and evidence collected from previous steps. Consider the overall context, user behavior patterns, and threat indicators.",
                "Input": "All investigation findings from previous steps",
                "KQL Query": "",
                "Execute": "",
                "Output": "",
                "Remarks/Comments": f"Options: True Positive, False Positive, Benign Positive. Historical baseline: {rule_history.get('fp_rate', 0)}% FP, {rule_history.get('tp_rate', 0)}% TP",
            }
        )
        current_num += 1

        # Confidence Assessment
        steps.append(
            {
                "Step": current_num,
                "Name": "Confidence Level Assessment",
                "Explanation": "Assess your confidence level in the classification based on the quality and completeness of evidence gathered. High confidence requires strong, corroborating evidence from multiple sources.",
                "Input": "Evidence quality, completeness, and consistency",
                "KQL Query": "",
                "Execute": "",
                "Output": "",
                "Remarks/Comments": "Scale: High (strong evidence from multiple sources), Medium (moderate evidence with some gaps), Low (limited or conflicting evidence)",
            }
        )
        current_num += 1

        # Detailed Justification
        steps.append(
            {
                "Step": current_num,
                "Name": "Detailed Justification",
                "Explanation": "Provide comprehensive reasoning for the classification decision. Reference specific findings from investigation steps, including IP reputation, user behavior, MFA status, and any anomalies detected.",
                "Input": "Classification decision and supporting evidence",
                "KQL Query": "",
                "Execute": "",
                "Output": "",
                "Remarks/Comments": "Be specific - reference step numbers and exact findings that support your conclusion",
            }
        )
        current_num += 1

        # Actions Taken
        steps.append(
            {
                "Step": current_num,
                "Name": "Actions Taken",
                "Explanation": "Document all investigative actions performed during the triage process. Include queries executed, logs reviewed, external tools used, users or teams contacted, and timeline of investigation activities.",
                "Input": "Investigation activities log",
                "KQL Query": "",
                "Execute": "",
                "Output": "",
                "Remarks/Comments": "Include: KQL queries run, threat intelligence checks, user confirmations, system checks performed",
            }
        )
        current_num += 1

        # Escalation Decision
        steps.append(
            {
                "Step": current_num,
                "Name": "Escalation Decision",
                "Explanation": "Determine if the incident requires escalation based on classification, severity, and organizational escalation policy. Consider factors such as confirmed malicious activity, VIP user involvement, or data exposure.",
                "Input": "Final classification, severity assessment, escalation criteria",
                "KQL Query": "",
                "Execute": "",
                "Output": "",
                "Remarks/Comments": "Escalate to: L3 SOC (confirmed threats), IT Team (system issues), Security Manager (VIP/critical), Incident Response Team (active compromise)",
            }
        )

        return steps

    def export_to_excel(self, df: pd.DataFrame, rule_number: str) -> BytesIO:
        """Export DataFrame to Excel with professional formatting"""
        output = BytesIO()

        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            df.to_excel(writer, sheet_name="Triaging_Template", index=False)

            # Get the workbook and worksheet
            workbook = writer.book
            worksheet = writer.sheets["Triaging_Template"]

            # Apply comprehensive formatting
            self._format_excel_worksheet(worksheet, df)

        output.seek(0)
        return output

    def _format_excel_worksheet(self, worksheet, df):
        """Format Excel worksheet for maximum readability"""
        # Header formatting
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

        # Adjust column widths for better visibility
        column_widths = {
            "A": 10,  # Step
            "B": 30,  # Name
            "C": 60,  # Explanation (wider for full text)
            "D": 35,  # Input
            "E": 50,  # KQL Query (wider for queries)
            "F": 15,  # Execute
            "G": 15,  # Output
            "H": 40,  # Remarks/Comments
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

        # Apply to all cells
        for row_idx, row in enumerate(worksheet.iter_rows(min_row=2), start=2):
            for cell in row:
                cell.border = thin_border
                cell.alignment = cell_alignment

                # Alternate row colors for better readability
                if row_idx % 2 == 0:
                    cell.fill = PatternFill(
                        start_color="F9F9F9", end_color="F9F9F9", fill_type="solid"
                    )

        # Highlight header rows (rule description, historical reference)
        for row_idx in range(1, worksheet.max_row + 1):
            cell_value = str(worksheet.cell(row=row_idx, column=2).value or "")
            if "Rule Analysis:" in cell_value or "HISTORICAL REFERENCE" in cell_value:
                for col_idx in range(1, len(df.columns) + 1):
                    cell = worksheet.cell(row=row_idx, column=col_idx)
                    cell.fill = PatternFill(
                        start_color="E8F4F8", end_color="E8F4F8", fill_type="solid"
                    )
                    cell.font = Font(bold=True, size=11)

        # Set row heights for better readability
        for row in worksheet.iter_rows():
            worksheet.row_dimensions[row[0].row].height = None  # Auto-adjust

        # Freeze the header row
        worksheet.freeze_panes = "A2"