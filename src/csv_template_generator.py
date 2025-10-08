import csv
from io import StringIO
import re


class CSVTemplateGenerator:
    """
    Generates clean CSV templates for manual triaging with all details.
    Ensures KQL queries and expected outputs are properly included.
    """

    def __init__(self):
        self.columns = ["Sr.No.", "Inputs Required", "INPUT details", "Instructions"]

    def generate_csv_template(
        self, rule_number: str, triaging_steps: list, rule_history: dict
    ) -> str:
        """Generate comprehensive CSV template with all investigation details"""
        output = StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

        # Header row
        writer.writerow(self.columns)

        # Rule description with historical context
        rule_desc = f"{rule_number}"
        historical_note = f"Based on {rule_history.get('total_incidents', 0)} past incidents ({rule_history.get('fp_rate', 0)}% FP, {rule_history.get('tp_rate', 0)}% TP)"
        writer.writerow(["", "", "", f"{rule_desc} - {historical_note}"])

        sr_no = 1

        # Add each investigation step with complete details
        for step in triaging_steps:
            step_row = self._create_step_row(sr_no, step, rule_history)
            writer.writerow(step_row)
            sr_no += 1

        # Add final assessment steps
        final_rows = self._create_final_assessment_rows(sr_no, rule_history)
        for row in final_rows:
            writer.writerow(row)
            sr_no += 1

        return output.getvalue()

    def _create_step_row(self, sr_no: int, step: dict, rule_history: dict) -> list:
        """Create a CONCISE, CLEAR step row"""
        step_name = step.get("step_name", f"Step {sr_no}")
        explanation = step.get("explanation", "")  # â­ Instructions
        input_required = step.get("input_required", "")
        expected_output = step.get("expected_output", "")
        kql_query = step.get("kql_query", "")

        clean_name = self._clean_text(step_name)

        # Build instructions (what to DO, not data)
        instructions = self._build_concise_instructions(
            explanation, expected_output, kql_query, rule_history
        )

        return [sr_no, clean_name, "", instructions]  # â­ INPUT details EMPTY

    def _build_concise_instructions(
        self, explanation: str, expected_output: str, kql_query: str, rule_history: dict
    ) -> str:
        """Build CONCISE instructions - focus on action and expected result"""
        parts = []

        # 1. Action (from explanation, first sentence only)
        if explanation:
            clean_exp = self._clean_text(explanation)
            sentences = clean_exp.split(". ")
            action = sentences[0]
            parts.append(action)

        # 2. Expected finding (SHORT version)
        if expected_output:
            clean_exp = self._clean_text(expected_output)
            # Extract just the key finding - FIXED to handle missing splits
            if "typically" in clean_exp.lower():
                split_parts = clean_exp.split("typically", 1)
                if len(split_parts) > 1:  # Check if split actually produced 2 parts
                    finding = split_parts[1]
                    finding = finding.split(".", 1)[0].strip(": ")
                    parts.append(f"Expected: {finding}")
                else:
                    # Fallback if split didn't work as expected
                    parts.append(f"Expected: {clean_exp}")

            parts.append(f"Expected: {clean_exp}")

        # 3. KQL (one-liner if present)
        if kql_query and kql_query.strip():
            clean_kql = self._clean_kql_for_csv(kql_query)
            if clean_kql:
                parts.append(f"Query: {clean_kql}")

        # 4. Historical context (ONE metric only)
        fp_rate = rule_history.get("fp_rate", 50)
        if fp_rate > 70:
            parts.append(f"[{fp_rate}% FP rate]")
        elif fp_rate < 30:
            parts.append(f"[{fp_rate}% FP - investigate carefully]")

        # Join with " | " separator (max 3 parts)
        return " | ".join(parts) if parts else "Investigate and document"

    def _clean_text(self, text: str) -> str:
        """Clean text - remove ALL formatting, keep content only"""
        if not text:
            return ""

        # Remove markdown
        text = re.sub(r"\*\*\*+", "", text)
        text = re.sub(r"\*\*", "", text)
        text = re.sub(r"\*", "", text)
        text = re.sub(r"#+\s*", "", text)
        text = re.sub(r"```[a-z]*", "", text)
        text = re.sub(r"`", "", text)

        # Remove step numbering and common prefixes
        text = re.sub(r"^(Step\s*\d+:?\s*|\d+\.\s*)", "", text, flags=re.IGNORECASE)
        text = re.sub(
            r"^(Explanation:|Expected:|Query:)\s*", "", text, flags=re.IGNORECASE
        )

        # Clean whitespace
        text = " ".join(text.split())

        return text.strip()

    def _clean_kql_for_csv(self, kql: str) -> str:
        """Clean and format KQL query for CSV (single line)"""
        if not kql or kql.strip().upper() in ["N/A", "NA", ""]:
            return ""

        # Remove code block markers
        kql = re.sub(r"```[a-z]*\s*", "", kql)
        kql = kql.strip()

        # Convert to single line for CSV
        kql = " ".join(kql.split())

        # Preserve pipe operators with spacing
        kql = kql.replace("|", " | ")
        kql = " ".join(kql.split())  # Clean up double spaces

        return kql if len(kql) > 15 else ""

    def _create_final_assessment_rows(
        self, start_sr_no: int, rule_history: dict
    ) -> list:
        """Create final assessment rows"""
        rows = []
        sr_no = start_sr_no

        # Final Classification
        fp_rate = rule_history.get("fp_rate", 0)
        tp_rate = rule_history.get("tp_rate", 0)

        rows.append(
            [
                sr_no,
                "Final Classification",
                "",
                f"Classify as True Positive, False Positive, or Benign Positive based on all investigation findings. [HISTORICAL BASELINE] {fp_rate}% FP, {tp_rate}% TP from {rule_history.get('total_incidents', 0)} past incidents",
            ]
        )
        sr_no += 1

        # Confidence Level
        rows.append(
            [
                sr_no,
                "Confidence Level",
                "",
                "Assess confidence: High (strong evidence from multiple sources), Medium (moderate evidence with some gaps), Low (limited or conflicting evidence)",
            ]
        )
        sr_no += 1

        # Justification
        rows.append(
            [
                sr_no,
                "Detailed Justification",
                "",
                "Provide comprehensive reasoning for classification. Reference specific findings from investigation steps above with step numbers and exact evidence",
            ]
        )
        sr_no += 1

        # Actions Taken
        rows.append(
            [
                sr_no,
                "Actions Taken",
                "",
                "Document all investigative actions: KQL queries executed, logs reviewed, threat intelligence checks performed, users/teams contacted, timeline of activities",
            ]
        )
        sr_no += 1

        # Escalation Decision
        rows.append(
            [
                sr_no,
                "Escalation Required?",
                "",
                "Yes/No - If yes, specify escalation path: L3 SOC (confirmed threats), IT Team (system issues), Security Manager (VIP/critical assets), Incident Response Team (active compromise)",
            ]
        )

        return rows


def generate_blank_triaging_template_csv(
    rule_number: str, triaging_steps: list, rule_history: dict
) -> str:
    """
    Main function to generate CSV template.
    This replaces the old function in utils.py
    """
    generator = CSVTemplateGenerator()
    return generator.generate_csv_template(rule_number, triaging_steps, rule_history)
