import pandas as pd
import re
from io import BytesIO
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

class TriagingTemplateGenerator:
    """
    Generates clean, structured triaging templates in Excel format
    No asterisks, proper formatting, comprehensive details
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
            "Remarks/Comments"
        ]
    
    def generate_structured_template(self, rule_number: str, triaging_steps: list, rule_history: dict) -> pd.DataFrame:
        """Generate structured template as DataFrame for Excel export"""
        template_rows = []
        
        # Add rule header row
        header_row = {
            "Step": "",
            "Name": f"Rule Analysis: {rule_number}",
            "Explanation": f"Comprehensive triaging plan based on {rule_history.get('total_incidents', 0)} historical incidents",
            "Input": f"Historical Context: {rule_history.get('fp_rate', 0)}% FP, {rule_history.get('tp_rate', 0)}% TP",
            "KQL Query": "",
            "Execute": "",
            "Output": "",
            "Remarks/Comments": f"Total incidents analyzed: {rule_history.get('total_incidents', 0)}"
        }
        template_rows.append(header_row)
        
        # Add investigation steps
        for i, step in enumerate(triaging_steps, 1):
            step_row = self._create_step_row(i, step, rule_history)
            template_rows.append(step_row)
        
        # Add final assessment steps
        final_steps = self._create_final_assessment_steps(len(triaging_steps) + 1, rule_history)
        template_rows.extend(final_steps)
        
        # Add historical reference section
        reference_rows = self._create_reference_section(rule_history)
        template_rows.extend(reference_rows)
        
        return pd.DataFrame(template_rows)
    
    def _create_step_row(self, step_num: int, step: dict, rule_history: dict) -> dict:
        """Create a single step row with clean formatting"""
        step_name = step.get("step_name", f"Investigation Step {step_num}")
        explanation = step.get("explanation", "")
        expected_output = step.get("expected_output", "")
        kql_query = step.get("kql_query", "")
        
        # Clean up the step name (remove markdown and asterisks)
        clean_name = re.sub(r'\*+|#+|Step \d+:?', '', step_name).strip()
        if clean_name.startswith(":"):
            clean_name = clean_name[1:].strip()
        
        # Clean up explanation (remove markdown formatting)
        clean_explanation = self._clean_text(explanation)
        
        # Extract input requirements
        input_required = self._extract_input_requirements(explanation, expected_output)
        
        # Clean KQL query
        clean_kql = self._clean_kql_query(kql_query)
        
        # Create remarks with expected output
        remarks = self._create_remarks(expected_output, rule_history)
        
        return {
            "Step": step_num,
            "Name": clean_name,
            "Explanation": clean_explanation,
            "Input": input_required,
            "KQL Query": clean_kql,
            "Execute": "",  # Empty for manual filling
            "Output": "",   # Empty for manual filling
            "Remarks/Comments": remarks
        }
    
    def _clean_text(self, text: str) -> str:
        """Clean text by removing markdown formatting and asterisks"""
        if not text:
            return ""
        
        # Remove markdown formatting
        clean_text = re.sub(r'\*+', '', text)  # Remove asterisks
        clean_text = re.sub(r'#+', '', clean_text)  # Remove hash symbols
        clean_text = re.sub(r'``````', '', clean_text)  # Remove code blocks
        clean_text = re.sub(r'`[^`]*`', '', clean_text)  # Remove inline code
        clean_text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', clean_text)  # Remove links
        
        # Clean up extra whitespace
        clean_text = ' '.join(clean_text.split())
        
        # Remove "Explanation:" prefix if present
        clean_text = re.sub(r'^Explanation:\s*', '', clean_text, flags=re.IGNORECASE)
        
        return clean_text.strip()
    
    def _extract_input_requirements(self, explanation: str, expected_output: str) -> str:
        """Extract what inputs/data are required for this step"""
        inputs = []
        
        # Common input patterns
        if "incident" in explanation.lower() or "consolidation" in explanation.lower():
            inputs.append("Incident ID/Number")
        
        if "ip" in explanation.lower() or "address" in explanation.lower():
            inputs.append("Source IP Address")
        
        if "user" in explanation.lower():
            inputs.append("Username/User Details")
        
        if "application" in explanation.lower() or "app" in explanation.lower():
            inputs.append("Application/Service Names")
        
        if "device" in explanation.lower():
            inputs.append("Device Information")
        
        if "logs" in explanation.lower():
            inputs.append("Log Files/Events")
        
        if "mfa" in explanation.lower() or "authentication" in explanation.lower():
            inputs.append("Authentication Details")
        
        # If no specific inputs identified, provide general guidance
        if not inputs:
            inputs.append("Incident details and relevant security data")
        
        return ", ".join(inputs)
    
    def _clean_kql_query(self, kql: str) -> str:
        """Clean and format KQL query for Excel display"""
        if not kql or kql.strip() == "":
            return ""
        
        # Remove markdown code block formatting
        clean_kql = re.sub(r'```', '', clean_kql)
        
        # Clean up whitespace but preserve query structure
        lines = [line.strip() for line in clean_kql.split('\n') if line.strip()]
        clean_kql = ' | '.join(lines) if len(lines) > 1 else clean_kql.strip()
        
        return clean_kql
    
    def _create_remarks(self, expected_output: str, rule_history: dict) -> str:
        """Create comprehensive remarks based on expected output and historical data"""
        remarks = []
        
        if expected_output:
            clean_expected = self._clean_text(expected_output)
            if clean_expected:
                remarks.append(f"Expected: {clean_expected}")
        
        # Add historical context
        fp_rate = rule_history.get('fp_rate', 0)
        tp_rate = rule_history.get('tp_rate', 0)
        
        if fp_rate > 80:
            remarks.append(f"High FP rate ({fp_rate}%) - likely legitimate activity")
        elif tp_rate > 50:
            remarks.append(f"Moderate TP rate ({tp_rate}%) - investigate thoroughly")
        
        return " | ".join(remarks) if remarks else "Document findings and analysis"
    
    def _create_final_assessment_steps(self, start_num: int, rule_history: dict) -> list:
        """Create standardized final assessment steps"""
        steps = []
        current_num = start_num
        
        # Final Classification
        steps.append({
            "Step": current_num,
            "Name": "Final Classification",
            "Explanation": "Classify the incident based on investigation findings and evidence collected",
            "Input": "All investigation findings from previous steps",
            "KQL Query": "",
            "Execute": "",
            "Output": "",
            "Remarks/Comments": f"Options: True Positive, False Positive, Benign Positive (Historical: {rule_history.get('fp_rate', 0)}% FP, {rule_history.get('tp_rate', 0)}% TP)"
        })
        current_num += 1
        
        # Confidence Assessment
        steps.append({
            "Step": current_num,
            "Name": "Confidence Assessment",
            "Explanation": "Assess confidence level based on strength and quality of evidence from investigation",
            "Input": "Evidence quality and completeness",
            "KQL Query": "",
            "Execute": "",
            "Output": "",
            "Remarks/Comments": "Scale: High (strong evidence), Medium (moderate evidence), Low (limited evidence)"
        })
        current_num += 1
        
        # Justification
        steps.append({
            "Step": current_num,
            "Name": "Detailed Justification",
            "Explanation": "Provide comprehensive reasoning for classification decision with specific evidence references",
            "Input": "Classification decision and supporting evidence",
            "KQL Query": "",
            "Execute": "",
            "Output": "",
            "Remarks/Comments": "Reference specific findings from investigation steps above"
        })
        current_num += 1
        
        # Actions Taken
        steps.append({
            "Step": current_num,
            "Name": "Actions Taken",
            "Explanation": "Document all investigative actions performed during triage process",
            "Input": "Investigation activities log",
            "KQL Query": "",
            "Execute": "",
            "Output": "",
            "Remarks/Comments": "Include: queries executed, logs reviewed, contacts made, tools used"
        })
        current_num += 1
        
        # Escalation Decision
        steps.append({
            "Step": current_num,
            "Name": "Escalation Decision",
            "Explanation": "Determine if incident requires escalation based on classification and organizational policy",
            "Input": "Final classification and escalation criteria",
            "KQL Query": "",
            "Execute": "",
            "Output": "",
            "Remarks/Comments": "Escalate to: L3 SOC / IT Team / Security Manager / Incident Response Team (if Yes)"
        })
        
        return steps
    
    def _create_reference_section(self, rule_history: dict) -> list:
        """Create historical reference section"""
        reference_rows = []
        
        # Add separator
        reference_rows.append({
            "Step": "",
            "Name": "HISTORICAL REFERENCE DATA",
            "Explanation": "Statistical analysis from past incidents for this rule",
            "Input": "",
            "KQL Query": "",
            "Execute": "",
            "Output": "",
            "Remarks/Comments": "Use this data to inform investigation approach"
        })
        
        # Total incidents
        reference_rows.append({
            "Step": "",
            "Name": "Total Historical Incidents",
            "Explanation": f"{rule_history.get('total_incidents', 0)}",
            "Input": "",
            "KQL Query": "",
            "Execute": "",
            "Output": "",
            "Remarks/Comments": "Complete historical dataset for pattern analysis"
        })
        
        # False Positive Rate
        reference_rows.append({
            "Step": "",
            "Name": "False Positive Rate",
            "Explanation": f"{rule_history.get('fp_rate', 0)}%",
            "Input": "",
            "KQL Query": "",
            "Execute": "",
            "Output": "",
            "Remarks/Comments": f"{rule_history.get('false_positives', 0)} of {rule_history.get('total_incidents', 0)} incidents were False Positives"
        })
        
        # True Positive Rate
        reference_rows.append({
            "Step": "",
            "Name": "True Positive Rate", 
            "Explanation": f"{rule_history.get('tp_rate', 0)}%",
            "Input": "",
            "KQL Query": "",
            "Execute": "",
            "Output": "",
            "Remarks/Comments": f"{rule_history.get('true_positives', 0)} of {rule_history.get('total_incidents', 0)} incidents were True Positives"
        })
        
        return reference_rows
    
    def export_to_excel(self, df: pd.DataFrame, rule_number: str) -> BytesIO:
        """Export DataFrame to Excel format for download"""
        output = BytesIO()
        
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Triaging_Template', index=False)
            
            # Get the workbook and worksheet
            workbook = writer.book
            worksheet = writer.sheets['Triaging_Template']
            
            # Format the worksheet
            self._format_excel_worksheet(worksheet, df)
        
        output.seek(0)
        return output
    
    def _format_excel_worksheet(self, worksheet, df):
        """Format the Excel worksheet for better readability"""
        # Header formatting
        header_font = Font(bold=True, color="FFFFFF")
        header_fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
        
        # Apply header formatting
        for col_num, column_title in enumerate(df.columns, 1):
            cell = worksheet.cell(row=1, column=col_num)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = Alignment(horizontal='center', vertical='center')
        
        # Adjust column widths
        column_widths = {
            'A': 8,   # Step
            'B': 25,  # Name  
            'C': 50,  # Explanation
            'D': 30,  # Input
            'E': 40,  # KQL Query
            'F': 12,  # Execute
            'G': 12,  # Output
            'H': 35   # Remarks/Comments
        }
        
        for col_letter, width in column_widths.items():
            worksheet.column_dimensions[col_letter].width = width
        
        # Add borders and alignment
        thin_border = Border(
            left=Side(style='thin'),
            right=Side(style='thin'), 
            top=Side(style='thin'),
            bottom=Side(style='thin')
        )
        
        for row in worksheet.iter_rows():
            for cell in row:
                cell.border = thin_border
                cell.alignment = Alignment(vertical='top', wrap_text=True)
        
        # Freeze the header row
        worksheet.freeze_panes = 'A2'
