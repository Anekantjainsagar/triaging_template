import os
from crewai import Crew, Process
from src.agents import TriagingAgents
from src.tasks import TriagingTasks
import json
import re


class TriagingCrew:
    def __init__(self):
        self.agents = TriagingAgents()
        self.tasks = TriagingTasks()

    def generate_excel_template(self, rule_number: str, consolidated_data: dict, template_content: str):
        """Generate clean Excel template using the new structured format"""
        try:
            # Run AI analysis to get triaging steps
            analysis_result = self.run_analysis_phase(consolidated_data, template_content, rule_number)
            
            triaging_steps = analysis_result.get('triaging_plan', [])
            rule_history = analysis_result.get('rule_history', {})
            
            # Initialize template generator
            from src.template_generator import TriagingTemplateGenerator
            template_gen = TriagingTemplateGenerator()
            
            # Generate structured DataFrame
            template_df = template_gen.generate_structured_template(
                rule_number, triaging_steps, rule_history
            )
            
            # Export to Excel
            excel_file = template_gen.export_to_excel(template_df, rule_number)
            
            return {
                'excel_file': excel_file,
                'template_df': template_df,
                'triaging_steps': triaging_steps,
                'rule_history': rule_history,
                'analysis_result': analysis_result
            }
            
        except Exception as e:
            print(f"Error generating Excel template: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    def run_analysis_phase(
        self, consolidated_data: dict, template_content: str, rule_number: str
    ):
        """
        Run the complete analysis phase using LLM to generate dynamic triaging plan.
        No hardcoded rules - learns from data and templates.
        """
        try:
            print("\n" + "=" * 80)
            print("Starting AI-Powered Dynamic Analysis...")
            print("=" * 80)

            # Get historical data for this rule (ALL INCIDENTS)
            from src.utils import read_all_tracker_sheets, consolidate_rule_data

            all_data = read_all_tracker_sheets("data")
            rule_history = consolidate_rule_data(all_data, rule_number)

            print(
                f"\nHistorical Context: {rule_history.get('total_incidents', 0)} past incidents"
            )
            print(f"True Positive Rate: {rule_history.get('tp_rate', 0)}%")
            print(f"False Positive Rate: {rule_history.get('fp_rate', 0)}%")

            # Create agents
            knowledge_agent = self.agents.knowledge_synthesis_agent()
            content_agent = self.agents.content_generation_agent()
            prediction_agent = self.agents.prediction_analysis_agent()

            # Convert consolidated data to string with FULL historical context
            data_summary = self._create_data_summary(consolidated_data)

            # Add COMPLETE historical analysis
            data_summary += f"""

    COMPLETE HISTORICAL PATTERN ANALYSIS FOR {rule_number}:
    Total Past Incidents: {rule_history.get('total_incidents', 0)}
    True Positive Count: {rule_history.get('true_positives', 0)}
    False Positive Count: {rule_history.get('false_positives', 0)}
    True Positive Rate: {rule_history.get('tp_rate', 0)}%
    False Positive Rate: {rule_history.get('fp_rate', 0)}%

    COMMON PATTERNS FROM ALL RESOLVER COMMENTS:
    {rule_history.get('all_resolver_comments', 'N/A')}

    COMMON JUSTIFICATIONS USED:
    {rule_history.get('common_justifications', 'N/A')}

    EXPECTED OUTPUTS BASED ON HISTORY:
    - For False Positives: {rule_history.get('fp_indicators', 'Clean IP, known devices, legitimate apps')}
    - For True Positives: {rule_history.get('tp_indicators', 'Malicious activity, unauthorized access')}
    """

            # Task 1: Learn from ALL historical data
            print("\n[1/3] Learning from ALL historical patterns...")
            synthesis_task = self.tasks.synthesize_knowledge_task(
                agent=knowledge_agent,
                consolidated_data=data_summary,
                template_content=template_content,
                rule_number=rule_number,
            )

            # Task 2: Generate dynamic plan with expected outputs
            print("\n[2/3] Generating plan with expected outputs...")
            plan_task = self.tasks.generate_triaging_plan_task(
                agent=content_agent,
                synthesis_output=synthesis_task,
                rule_number=rule_number,
            )

            # Task 3: Progressive prediction with cumulative analysis
            print("\n[3/3] Creating progressive prediction model...")
            prediction_task = self.tasks.predict_outcome_task(
                agent=prediction_agent,
                consolidated_data=consolidated_data,
                rule_number=rule_number,
            )

            # Create and run crew
            crew = Crew(
                agents=[knowledge_agent, content_agent, prediction_agent],
                tasks=[synthesis_task, plan_task, prediction_task],
                process=Process.sequential,
                verbose=True,
            )

            print("\n" + "=" * 80)
            print("Running CrewAI Workflow...")
            print("=" * 80 + "\n")

            result = crew.kickoff()

            print("\n" + "=" * 80)
            print("AI Analysis Complete!")
            print("=" * 80 + "\n")

            # Parse results with expected outputs
            triaging_plan = self._parse_triaging_plan_with_expectations(
                plan_task.output, rule_history
            )
            predictions = self._parse_predictions_dynamic(prediction_task.output)

            # Calculate progressive predictions for each step
            progressive_predictions = self._calculate_progressive_predictions(
                triaging_plan, rule_history
            )

            return {
                "triaging_plan": triaging_plan,
                "predictions": predictions,
                "progressive_predictions": progressive_predictions,
                "rule_history": rule_history,
            }

        except Exception as e:
            print(f"\nError in AI analysis: {str(e)}")
            import traceback

            traceback.print_exc()

            return {
                "triaging_plan": self._create_minimal_plan(
                    consolidated_data, template_content
                ),
                "predictions": self._create_minimal_prediction(consolidated_data),
                "progressive_predictions": {},
                "rule_history": {},
            }

    def _parse_triaging_plan_with_expectations(self, output, rule_history) -> list:
        """Parse plan and add expected outputs from historical data."""
        output_str = str(output)
        steps = []

        # Strategy 1: Structured format with EXPECTED_OUTPUT
        step_pattern = r"STEP:\s*(.+?)\s*EXPLANATION:\s*(.+?)\s*(?:KQL:\s*(.+?)\s*)?EXPECTED_OUTPUT:\s*(.+?)\s*INPUT_REQUIRED:\s*(.+?)(?=STEP:|---|\Z)"
        matches = re.findall(step_pattern, output_str, re.DOTALL | re.IGNORECASE)

        if matches:
            for match in matches:
                steps.append(
                    {
                        "step_name": match[0].strip(),
                        "explanation": match[1].strip(),
                        "kql_query": (
                            match[2].strip()
                            if len(match) > 2 and match[2].strip()
                            else ""
                        ),
                        "expected_output": (
                            match[3].strip()
                            if len(match) > 3
                            else self._generate_expected_output(match[0], rule_history)
                        ),
                        "user_input_required": (
                            "yes" in match[4].lower() if len(match) > 4 else True
                        ),
                    }
                )

        # Fallback: Add expected outputs from history
        if not steps:
            steps = self._extract_steps_from_text(output_str)
            for step in steps:
                step["expected_output"] = self._generate_expected_output(
                    step["step_name"], rule_history
                )

        return steps if steps else []

    def _generate_expected_output(self, step_name: str, rule_history: dict) -> str:
        """Generate expected output based on step name and historical patterns."""
        step_lower = step_name.lower()

        fp_rate = rule_history.get("fp_rate", 50)
        tp_rate = rule_history.get("tp_rate", 50)

        # Pattern-based expected outputs
        if "ip" in step_lower or "reputation" in step_lower:
            return f"Expected: ~{fp_rate}% chance IP is clean (False Positive). Look for: 'Clean IP', 'No malicious reputation', 'Known IP range'"

        elif "device" in step_lower or "registered" in step_lower:
            return f"Expected: ~{fp_rate}% chance device is registered. Look for: 'Known device', 'Registered device', 'Corporate device'"

        elif "mfa" in step_lower or "authentication" in step_lower:
            return f"Expected: ~{fp_rate}% chance MFA is satisfied. Look for: 'MFA successful', 'MFA enabled', 'Multi-factor authentication completed'"

        elif "user" in step_lower and "confirmation" in step_lower:
            return f"Expected: ~{fp_rate}% chance user confirms legitimate activity. Look for: 'User confirmed', 'Legitimate activity', 'Authorized by user'"

        elif "application" in step_lower or "app" in step_lower:
            return f"Expected: ~{fp_rate}% chance apps are known/legitimate. Look for: 'Known applications', 'Approved apps', 'Whitelisted applications'"

        else:
            return f"Based on {rule_history.get('total_incidents', 0)} past incidents: {fp_rate}% False Positive, {tp_rate}% True Positive"

    def _calculate_progressive_predictions(
        self, triaging_plan: list, rule_history: dict
    ) -> dict:
        """Calculate cumulative prediction percentages as steps are completed."""
        progressive = {}

        base_fp = rule_history.get("fp_rate", 50)
        base_tp = rule_history.get("tp_rate", 50)

        for i, step in enumerate(triaging_plan):
            step_name = step.get("step_name", f"Step {i+1}")

            # Adjust probabilities based on step completion
            # This is a simplified model - actual implementation would use historical correlations
            confidence_boost = (
                (i + 1) / len(triaging_plan) * 20
            )  # Max 20% confidence increase

            progressive[step_name] = {
                "false_positive_probability": min(
                    100, base_fp + confidence_boost if base_fp > base_tp else base_fp
                ),
                "true_positive_probability": min(
                    100, base_tp + confidence_boost if base_tp > base_fp else base_tp
                ),
                "confidence_level": f"{40 + (i + 1) / len(triaging_plan) * 60:.0f}%",  # Grows from 40% to 100%
            }

        return progressive

    def _create_data_summary(self, data: dict) -> str:
        """Create a structured summary for LLM processing."""
        summary = f"""
INCIDENT DATA:
Incident Number: {data.get('incident_no', 'N/A')}
Rule: {data.get('rule', 'N/A')}
Priority: {data.get('priority', 'N/A')}
Data Connector: {data.get('data_connector', 'N/A')}
Alert/Incident Type: {data.get('alert_incident', 'N/A')}
Date: {data.get('date', 'N/A')} {data.get('month', '')}
Shift: {data.get('shift', 'N/A')}
Engineer: {data.get('shift_engineer', 'N/A')}

TIMELINE METRICS:
Reported Time: {data.get('reported_time_stamp', 'N/A')}
Responded Time: {data.get('responded_time_stamp', 'N/A')}
Resolution Time: {data.get('resolution_time_stamp', 'N/A')}
MTTD (Mean Time To Detect): {data.get('mttd_mins', 'N/A')} minutes
MTTR (Mean Time To Resolve): {data.get('mttr_mins', 'N/A')} minutes

INVESTIGATION FINDINGS (RESOLVER COMMENTS):
{data.get('resolver_comments', 'N/A')}

HISTORICAL OUTCOME:
Classification: {data.get('false_true_positive', 'N/A')}
Why False Positive: {data.get('why_false_positive', 'N/A')}
Justification: {data.get('justification', 'N/A')}
Quality Audit: {data.get('quality_audit', 'N/A')}

ADDITIONAL CONTEXT:
Status: {data.get('status', 'N/A')}
VIP Users Involved: {data.get('vip_users', 'N/A')}
Service Owner: {data.get('service_owner', 'N/A')}
Remarks: {data.get('remarks_comments', 'N/A')}
"""
        return summary

    def _parse_triaging_plan_dynamic(self, output) -> list:
        """Parse triaging plan ensuring ALL details are captured."""
        output_str = str(output)
        steps = []

        print("\n" + "=" * 80)
        print("PARSING AI-GENERATED TRIAGING PLAN")
        print("=" * 80)

        # Strategy 1: Look for structured format with all fields
        step_pattern = r"---\s*STEP:\s*(.+?)\s*EXPLANATION:\s*(.+?)\s*(?:KQL:\s*(.+?)\s*)?(?:EXPECTED_OUTPUT:\s*(.+?)\s*)?INPUT_REQUIRED:\s*(.+?)\s*---"
        matches = re.findall(step_pattern, output_str, re.DOTALL | re.IGNORECASE)

        if matches:
            print(f"✅ Found {len(matches)} steps using structured format")
            for i, match in enumerate(matches, 1):
                kql = (
                    match[2].strip()
                    if len(match) > 2
                    and match[2].strip()
                    and match[2].strip().lower() != "n/a"
                    else ""
                )
                expected = (
                    match[3].strip()
                    if len(match) > 3
                    and match[3].strip()
                    and match[3].strip().lower() != "n/a"
                    else ""
                )

                step = {
                    "step_name": match[0].strip(),
                    "explanation": match[1].strip(),
                    "kql_query": kql,
                    "expected_output": expected,
                    "user_input_required": (
                        "yes" in match[4].lower() if len(match) > 4 else True
                    ),
                }
                steps.append(step)

                print(f"\n  Step {i}: {step['step_name']}")
                print(f"    - Explanation: {len(step['explanation'])} characters")
                print(f"    - KQL Query: {'Yes' if step['kql_query'] else 'No'}")
                print(
                    f"    - Expected Output: {'Yes' if step['expected_output'] else 'No'}"
                )

            print(f"\n{'='*80}\n")
            return steps

        # Strategy 2: Look for numbered/bulleted format with context
        print("⚠️  Structured format not found, trying numbered list parsing...")

        # Split by common delimiters
        sections = re.split(r"\n(?=\d+\.|#{2,3}\s|Step \d+:|\*\*Step)", output_str)

        for section in sections:
            section = section.strip()
            if len(section) < 30:  # Skip very short sections
                continue

            # Extract step name (first line)
            lines = section.split("\n")
            step_name = re.sub(
                r"^\d+\.\s*|\*\*|#{2,3}\s*|Step \d+:\s*", "", lines[0]
            ).strip()

            if not step_name or len(step_name) > 200:
                continue

            # Get full explanation (rest of the text)
            explanation = "\n".join(lines[1:]).strip() if len(lines) > 1 else section

            # Extract KQL if present
            kql = self._extract_kql_from_text(explanation)

            # Extract expected output if mentioned
            expected_match = re.search(
                r"(?:expected|look for|typically|should see):\s*(.{50,300})",
                explanation,
                re.IGNORECASE | re.DOTALL,
            )
            expected = expected_match.group(1).strip() if expected_match else ""

            steps.append(
                {
                    "step_name": step_name,
                    "explanation": explanation,
                    "kql_query": kql,
                    "expected_output": expected,
                    "user_input_required": True,
                }
            )

            if len(steps) >= 10:  # Safety limit
                break

        if steps:
            print(f"✅ Extracted {len(steps)} steps from unstructured format")
            for i, step in enumerate(steps, 1):
                print(f"\n  Step {i}: {step['step_name'][:60]}...")
        else:
            print("❌ Could not parse any steps from output")

        print(f"\n{'='*80}\n")
        return steps

    def _extract_kql_from_text(self, text: str) -> str:
        """Extract KQL query from text if present."""
        # Look for code blocks
        kql_pattern = r"```(?:kql|kusto|sql)?\s*\n(.+?)\n```"
        match = re.search(kql_pattern, text, re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(1).strip()

        # Look for SigninLogs queries
        if "SigninLogs" in text or "where" in text.lower():
            lines = text.split("\n")
            query_lines = []
            in_query = False
            for line in lines:
                if "SigninLogs" in line or "| where" in line:
                    in_query = True
                if in_query:
                    query_lines.append(line)
                    if not line.strip().startswith("|") and len(query_lines) > 1:
                        break
            if query_lines:
                return "\n".join(query_lines).strip()

        return ""

    def _parse_predictions_dynamic(self, output) -> list:
        """Dynamically parse predictions from LLM output."""
        output_str = str(output)

        # Try structured format first
        prediction_match = re.search(
            r"PREDICTION:\s*(.+?)(?:\n|$)", output_str, re.IGNORECASE
        )
        confidence_match = re.search(
            r"CONFIDENCE:\s*(.+?)(?:\n|$)", output_str, re.IGNORECASE
        )
        reasoning_match = re.search(
            r"REASONING:\s*(.+?)(?:\n\n|\Z)", output_str, re.IGNORECASE | re.DOTALL
        )

        if prediction_match:
            return [
                {
                    "step_name": "Overall Assessment",
                    "prediction": prediction_match.group(1).strip(),
                    "confidence_score": (
                        confidence_match.group(1).strip()
                        if confidence_match
                        else "Medium"
                    ),
                    "reasoning": (
                        reasoning_match.group(1).strip()
                        if reasoning_match
                        else output_str[:300]
                    ),
                }
            ]

        return []

    def _extract_steps_from_text(self, text: str) -> list:
        """Emergency extraction of any step-like structure from text."""
        steps = []

        # Split by double newlines or numbered points
        sections = re.split(r"\n\n+|\n(?=\d+\.)", text)

        for section in sections:
            section = section.strip()
            if len(section) > 20:  # Meaningful content
                # First line as name, rest as explanation
                lines = section.split("\n", 1)
                steps.append(
                    {
                        "step_name": lines[0].strip()[:150],
                        "explanation": lines[1].strip() if len(lines) > 1 else section,
                        "kql_query": "",
                        "user_input_required": True,
                    }
                )

                if len(steps) >= 8:  # Cap at reasonable number
                    break

        return steps

    def _extract_prediction_from_text(self, text: str) -> list:
        """Emergency extraction of prediction from any text."""
        # Look for positive/negative keywords
        text_lower = text.lower()

        if "true positive" in text_lower:
            prediction = "Likely True Positive"
        elif "false positive" in text_lower:
            prediction = "Likely False Positive"
        else:
            prediction = "Requires Investigation"

        return [
            {
                "step_name": "Overall Assessment",
                "prediction": prediction,
                "confidence_score": "Medium",
                "reasoning": text[:300],
            }
        ]

    def _create_minimal_plan(self, incident_data: dict, template: str) -> list:
        """Create minimal viable plan from template if LLM completely fails."""
        # Extract any structure from template
        if template and len(template) > 100:
            lines = template.split("\n")
            steps = []
            for line in lines:
                line = line.strip()
                if (
                    line.startswith("#")
                    or line.startswith("Step")
                    or line.endswith(":")
                ):
                    if len(steps) < 6:
                        steps.append(
                            {
                                "step_name": line.replace("#", "").strip(),
                                "explanation": "Please review this step based on the incident details.",
                                "kql_query": "",
                                "user_input_required": True,
                            }
                        )
            if steps:
                return steps

        # Absolute minimum fallback
        return [
            {
                "step_name": "1. Review Incident Details",
                "explanation": f'Review the incident: {incident_data.get("rule", "N/A")}. Check all provided information.',
                "kql_query": "",
                "user_input_required": True,
            },
            {
                "step_name": "2. Investigate Key Indicators",
                "explanation": "Based on resolver comments, investigate the key security indicators.",
                "kql_query": "",
                "user_input_required": True,
            },
            {
                "step_name": "3. Make Final Classification",
                "explanation": "Classify as True Positive, False Positive, or Benign Positive with justification.",
                "kql_query": "",
                "user_input_required": True,
            },
        ]

    def _create_minimal_prediction(self, incident_data: dict) -> list:
        """Create minimal prediction if LLM fails."""
        comments = str(incident_data.get("resolver_comments", "")).lower()

        # Simple keyword detection
        if any(
            word in comments for word in ["clean", "legitimate", "nothing suspicious"]
        ):
            prediction = "Likely False Positive"
        elif any(word in comments for word in ["escalat", "malicious", "compromise"]):
            prediction = "Likely True Positive"
        else:
            prediction = "Requires Investigation"

        return [
            {
                "step_name": "Overall Assessment",
                "prediction": prediction,
                "confidence_score": "Low",
                "reasoning": "Automated pattern detection from resolver comments.",
            }
        ]
