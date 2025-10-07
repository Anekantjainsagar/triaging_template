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

    def generate_excel_template(
        self, rule_number: str, consolidated_data: dict, template_content: str
    ):
        """Generate clean Excel template using the structured format"""
        try:
            # Run AI analysis to get triaging steps
            analysis_result = self.run_analysis_phase(
                consolidated_data, template_content, rule_number
            )

            triaging_steps = analysis_result.get("triaging_plan", [])
            rule_history = analysis_result.get("rule_history", {})

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
                "excel_file": excel_file,
                "template_df": template_df,
                "triaging_steps": triaging_steps,
                "rule_history": rule_history,
                "analysis_result": analysis_result,
            }

        except Exception as e:
            print(f"Error generating Excel template: {str(e)}")
            import traceback

            traceback.print_exc()
            return None

    def run_analysis_phase(
        self, consolidated_data: dict, template_content: str, rule_number: str
    ):
        """Run complete analysis phase with improved parsing"""
        try:
            print("\n" + "=" * 80)
            print("Starting AI-Powered Analysis...")
            print("=" * 80)

            # Get historical data
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

            # Convert consolidated data to string
            data_summary = self._create_data_summary(consolidated_data)

            # Add historical context
            data_summary += f"""

COMPLETE HISTORICAL PATTERN ANALYSIS FOR {rule_number}:
Total Past Incidents: {rule_history.get('total_incidents', 0)}
True Positive Count: {rule_history.get('true_positives', 0)}
False Positive Count: {rule_history.get('false_positives', 0)}
True Positive Rate: {rule_history.get('tp_rate', 0)}%
False Positive Rate: {rule_history.get('fp_rate', 0)}%

COMMON PATTERNS FROM RESOLVER COMMENTS:
{rule_history.get('all_resolver_comments', 'N/A')[:500]}
"""

            # Task 1: Synthesize knowledge
            print("\n[1/3] Synthesizing knowledge from historical data...")
            synthesis_task = self.tasks.synthesize_knowledge_task(
                agent=knowledge_agent,
                consolidated_data=data_summary,
                template_content=template_content,
                rule_number=rule_number,
                rule_history=rule_history,
            )

            # Task 2: Generate triaging plan
            print("\n[2/3] Generating triaging plan...")
            plan_task = self.tasks.generate_triaging_plan_task(
                agent=content_agent,
                synthesis_output=synthesis_task,
                rule_number=rule_number,
            )

            # Task 3: Predict outcome
            print("\n[3/3] Predicting outcome...")
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

            # Parse results with improved logic
            triaging_plan = self._parse_triaging_plan_robust(
                plan_task.output, rule_history
            )
            predictions = self._parse_predictions(prediction_task.output)
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

    def _parse_triaging_plan_robust(self, output, rule_history) -> list:
        """Robust parsing with multiple strategies to ensure ALL data is captured"""
        output_str = str(output)
        steps = []

        print("\n" + "=" * 80)
        print("PARSING TRIAGING PLAN")
        print("=" * 80)

        # Strategy 1: Look for structured format with markers
        pattern = r"---\s*STEP:\s*(.+?)\s+EXPLANATION:\s*(.+?)\s+(?:KQL:\s*(.+?)\s+)?(?:EXPECTED_OUTPUT:\s*(.+?)\s+)?INPUT_REQUIRED:\s*(.+?)\s*---"
        matches = re.findall(pattern, output_str, re.DOTALL | re.IGNORECASE)

        if matches:
            print(f"✓ Found {len(matches)} steps using structured format")
            for match in matches:
                kql = (
                    match[2].strip()
                    if len(match) > 2
                    and match[2].strip()
                    and match[2].strip().upper() != "N/A"
                    else ""
                )
                expected = (
                    match[3].strip()
                    if len(match) > 3
                    and match[3].strip()
                    and match[3].strip().upper() != "N/A"
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
            return steps

        # Strategy 2: Parse line by line for steps
        print("⚠ Structured format not found, using line-by-line parsing...")

        lines = output_str.split("\n")
        current_step = None
        current_field = None

        for line in lines:
            line = line.strip()

            # Detect step start
            if re.match(r"^(STEP|Step)\s*\d*:?\s*", line, re.IGNORECASE):
                if current_step:
                    steps.append(current_step)

                step_name = re.sub(
                    r"^(STEP|Step)\s*\d*:?\s*", "", line, flags=re.IGNORECASE
                ).strip()
                current_step = {
                    "step_name": step_name,
                    "explanation": "",
                    "kql_query": "",
                    "expected_output": "",
                    "user_input_required": True,
                }
                current_field = None

            elif current_step:
                # Detect field markers
                if line.upper().startswith("EXPLANATION:"):
                    current_field = "explanation"
                    current_step["explanation"] = (
                        line.replace("EXPLANATION:", "")
                        .replace("Explanation:", "")
                        .strip()
                    )
                elif line.upper().startswith("KQL:"):
                    current_field = "kql_query"
                    current_step["kql_query"] = (
                        line.replace("KQL:", "").replace("kql:", "").strip()
                    )
                elif line.upper().startswith("EXPECTED"):
                    current_field = "expected_output"
                    current_step["expected_output"] = (
                        line.replace("EXPECTED_OUTPUT:", "")
                        .replace("Expected Output:", "")
                        .strip()
                    )
                elif line.upper().startswith("INPUT_REQUIRED"):
                    current_field = None
                    current_step["user_input_required"] = "yes" in line.lower()
                elif current_field and line:
                    # Continue adding to current field
                    current_step[current_field] += " " + line

        # Add last step
        if current_step and current_step.get("step_name"):
            steps.append(current_step)

        # Strategy 3: If still no steps, extract from numbered/bulleted lists
        if not steps:
            print("⚠ Line parsing failed, trying numbered list extraction...")
            steps = self._extract_steps_from_text(output_str)

        # Enhance steps with expected outputs if missing
        for step in steps:
            if not step.get("expected_output") and step.get("step_name"):
                step["expected_output"] = self._generate_expected_output(
                    step["step_name"], rule_history
                )

            # Clean up text
            if step.get("explanation"):
                step["explanation"] = self._clean_text_for_display(step["explanation"])
            if step.get("kql_query"):
                step["kql_query"] = self._clean_kql(step["kql_query"])

        print(f"✓ Extracted {len(steps)} total steps")
        return steps if steps else self._create_fallback_steps()

    def _clean_text_for_display(self, text: str) -> str:
        """Clean text by removing markdown and extra whitespace"""
        if not text:
            return ""

        # Remove markdown
        text = re.sub(r"\*\*\*+", "", text)
        text = re.sub(r"\*\*", "", text)
        text = re.sub(r"\*", "", text)
        text = re.sub(r"#+\s*", "", text)

        # Clean whitespace
        text = " ".join(text.split())

        return text.strip()

    def _clean_kql(self, kql: str) -> str:
        """Clean KQL query"""
        if not kql or kql.strip().upper() in ["N/A", "NA", ""]:
            return ""

        # Remove code block markers
        kql = re.sub(r"```[a-z]*\s*", "", kql)
        kql = kql.strip()

        return kql if len(kql) > 10 else ""

    def _generate_expected_output(self, step_name: str, rule_history: dict) -> str:
        """Generate expected output based on step name and historical patterns"""
        step_lower = step_name.lower()
        fp_rate = rule_history.get("fp_rate", 50)
        tp_rate = rule_history.get("tp_rate", 50)

        # Pattern-based expected outputs
        if "ip" in step_lower or "reputation" in step_lower:
            return f"Based on {rule_history.get('total_incidents', 0)} past incidents ({fp_rate}% FP rate): Typically find 'Clean IP', 'No malicious reputation', 'Known IP range'. If found, indicates False Positive."

        elif "device" in step_lower or "registered" in step_lower:
            return f"Expected ({fp_rate}% FP historical rate): 'Known device', 'Registered device', 'Corporate device'. Finding these suggests False Positive."

        elif "mfa" in step_lower or "authentication" in step_lower:
            return f"Common finding ({fp_rate}% FP rate): 'MFA successful', 'MFA enabled', 'Multi-factor authentication completed'. Indicates legitimate access."

        elif "user" in step_lower and "confirm" in step_lower:
            return f"Typical outcome ({fp_rate}% FP rate): 'User confirmed activity', 'Legitimate action', 'Authorized by user'. Supports False Positive classification."

        elif "application" in step_lower or "app" in step_lower:
            return f"Expected result ({fp_rate}% FP rate): 'Known applications', 'Approved apps', 'Whitelisted applications'. Indicates normal activity."

        else:
            return f"Based on {rule_history.get('total_incidents', 0)} historical incidents: {fp_rate}% were False Positive, {tp_rate}% were True Positive. Investigate thoroughly."

    def _calculate_progressive_predictions(
        self, triaging_plan: list, rule_history: dict
    ) -> dict:
        """Calculate cumulative prediction percentages as steps are completed"""
        progressive = {}

        base_fp = rule_history.get("fp_rate", 50)
        base_tp = rule_history.get("tp_rate", 50)

        for i, step in enumerate(triaging_plan):
            step_name = step.get("step_name", f"Step {i+1}")

            # Confidence grows as more steps are completed
            confidence_boost = (i + 1) / len(triaging_plan) * 15

            progressive[step_name] = {
                "false_positive_probability": min(
                    100, base_fp + confidence_boost if base_fp > base_tp else base_fp
                ),
                "true_positive_probability": min(
                    100, base_tp + confidence_boost if base_tp > base_fp else base_tp
                ),
                "confidence_level": f"{40 + (i + 1) / len(triaging_plan) * 60:.0f}%",
            }

        return progressive

    def _create_data_summary(self, data: dict) -> str:
        """Create structured summary for LLM processing"""
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
MTTD: {data.get('mttd_mins', 'N/A')} minutes
MTTR: {data.get('mttr_mins', 'N/A')} minutes

INVESTIGATION FINDINGS:
{data.get('resolver_comments', 'N/A')}

HISTORICAL OUTCOME:
Classification: {data.get('false_true_positive', 'N/A')}
Why False Positive: {data.get('why_false_positive', 'N/A')}
Justification: {data.get('justification', 'N/A')}
"""
        return summary

    def _parse_predictions(self, output) -> list:
        """Parse predictions from LLM output"""
        output_str = str(output)

        # Try structured format
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

        # Fallback: keyword detection
        return self._extract_prediction_from_text(output_str)

    def _extract_steps_from_text(self, text: str) -> list:
        """Extract steps from unstructured text"""
        steps = []

        # Split by numbered points or headers
        sections = re.split(r"\n(?=\d+\.|#{2,3}\s|Step \d+:|\*\*Step)", text)

        for section in sections:
            section = section.strip()
            if len(section) < 30:
                continue

            lines = section.split("\n")
            step_name = re.sub(
                r"^\d+\.\s*|\*\*|#{2,3}\s*|Step \d+:\s*", "", lines[0]
            ).strip()

            if not step_name or len(step_name) > 200:
                continue

            explanation = "\n".join(lines[1:]).strip() if len(lines) > 1 else section

            steps.append(
                {
                    "step_name": step_name,
                    "explanation": explanation,
                    "kql_query": self._extract_kql_from_text(explanation),
                    "expected_output": "",
                    "user_input_required": True,
                }
            )

            if len(steps) >= 10:
                break

        return steps

    def _extract_kql_from_text(self, text: str) -> str:
        """Extract KQL query from text"""
        # Look for code blocks
        kql_pattern = r"```(?:kql|kusto|sql)?\s*\n(.+?)\n```"
        match = re.search(kql_pattern, text, re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(1).strip()

        # Look for SigninLogs queries
        if "SigninLogs" in text or "| where" in text:
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

    def _extract_prediction_from_text(self, text: str) -> list:
        """Extract prediction from any text"""
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

    def _parse_triaging_plan_robust(self, output, rule_history) -> list:
        """Parse triaging plan with focus on QUALITY and CLARITY"""
        output_str = str(output)
        steps = []

        print("\n" + "=" * 80)
        print("PARSING TRIAGING PLAN")
        print("=" * 80)

        # Strategy 1: Structured format with markers
        pattern = r"---\s*STEP:\s*(.+?)\s+EXPLANATION:\s*(.+?)\s+(?:KQL:\s*(.+?)\s+)?(?:EXPECTED_OUTPUT:\s*(.+?)\s+)?INPUT_REQUIRED:\s*(.+?)\s*---"
        matches = re.findall(pattern, output_str, re.DOTALL | re.IGNORECASE)

        if matches:
            print(f"✓ Found {len(matches)} structured steps")
            for match in matches:
                # Extract and clean data
                step_name = self._clean_step_name_parsing(match[0].strip())
                explanation = self._clean_explanation_parsing(match[1].strip())
                kql = self._extract_kql(match[2].strip() if len(match) > 2 else "")
                expected = self._clean_expected_output(
                    match[3].strip() if len(match) > 3 else ""
                )

                step = {
                    "step_name": step_name,
                    "explanation": explanation,
                    "kql_query": kql,
                    "expected_output": expected
                    or self._generate_expected_output(step_name, rule_history),
                    "user_input_required": (
                        "yes" in match[4].lower() if len(match) > 4 else True
                    ),
                }
                steps.append(step)

            # Quality check: limit to 8 steps max
            if len(steps) > 8:
                print(
                    f"⚠ Trimming from {len(steps)} to 8 steps (quality over quantity)"
                )
                steps = steps[:8]

            return steps

        # Strategy 2: Line-by-line parsing
        print("⚠ Using line-by-line parsing...")
        steps = self._parse_line_by_line(output_str, rule_history)

        if len(steps) > 8:
            steps = steps[:8]

        return steps if steps else self._create_fallback_steps()

    def _clean_step_name_parsing(self, name: str) -> str:
        """Clean step name during parsing - make it ACTION-FOCUSED"""
        # Remove markdown
        clean = re.sub(r"\*+", "", name)
        clean = re.sub(r"#+", "", clean)
        clean = re.sub(r"^Step\s*\d+:?\s*", "", clean, flags=re.IGNORECASE)
        clean = re.sub(r"^\d+\.\s*", "", clean)

        # Remove verbose phrases
        clean = re.sub(
            r"^(Please\s+)?(Perform\s+)?(Complete\s+)?(Verify\s+and\s+)?",
            "",
            clean,
            flags=re.IGNORECASE,
        )

        # Limit length (max 8 words)
        words = clean.split()
        if len(words) > 8:
            clean = " ".join(words[:8])

        clean = " ".join(clean.split())
        return clean if clean and len(clean) > 3 else "Investigation Step"

    def _clean_explanation_parsing(self, text: str) -> str:
        """Clean explanation - keep it CONCISE (2-3 sentences max)"""
        # Remove markdown
        text = re.sub(r"\*+", "", text)
        text = re.sub(r"#+", "", text)
        text = re.sub(r"`", "", text)

        # Split into sentences
        sentences = text.split(". ")

        # Keep only first 2-3 sentences
        if len(sentences) > 3:
            text = ". ".join(sentences[:3])
            if not text.endswith("."):
                text += "."

        # Remove common prefixes
        text = re.sub(
            r"^(Explanation:|EXPLANATION:|Instructions:)\s*",
            "",
            text,
            flags=re.IGNORECASE,
        )

        # Limit total length
        if len(text) > 300:
            text = text[:297] + "..."

        text = " ".join(text.split())
        return text.strip()

    def _clean_expected_output(self, text: str) -> str:
        """Clean expected output - ONE clear sentence"""
        if not text or text.upper() in ["N/A", "NA", ""]:
            return ""

        # Remove markdown
        text = re.sub(r"\*+", "", text)
        text = re.sub(
            r"^(Expected Output:|EXPECTED_OUTPUT:|Expected:)\s*",
            "",
            text,
            flags=re.IGNORECASE,
        )

        # Get first sentence only
        sentences = text.split(". ")
        text = sentences[0]
        if not text.endswith("."):
            text += "."

        # Limit length
        if len(text) > 150:
            text = text[:147] + "..."

        text = " ".join(text.split())
        return text.strip()

    def _create_fallback_steps(self) -> list:
        """Create CONCISE fallback steps"""
        return [
            {
                "step_name": "Review Incident Details",
                "explanation": "Review incident metadata including user, IP, and timestamp. Identify any obvious anomalies or patterns.",
                "kql_query": "",
                "expected_output": "Complete incident overview with key entities identified.",
                "user_input_required": True,
            },
            {
                "step_name": "Check Threat Intelligence",
                "explanation": "Query threat intelligence sources for IP reputation and known malicious indicators. Clean reputation indicates FP.",
                "kql_query": "",
                "expected_output": "Typically shows: Clean IP, No threats. If found → False Positive.",
                "user_input_required": True,
            },
            {
                "step_name": "Review User Activity",
                "explanation": "Check user sign-in history and behavior patterns. Consistent with normal activity indicates FP.",
                "kql_query": "",
                "expected_output": "Typically shows: Known devices, Normal patterns. If found → False Positive.",
                "user_input_required": True,
            },
            {
                "step_name": "Verify MFA Status",
                "explanation": "Confirm multi-factor authentication completion. Successful MFA indicates legitimate access.",
                "kql_query": "",
                "expected_output": "Typically shows: MFA successful. If found → False Positive.",
                "user_input_required": True,
            },
            {
                "step_name": "Final Classification",
                "explanation": "Classify as True Positive, False Positive, or Benign Positive based on all evidence. Document justification.",
                "kql_query": "",
                "expected_output": "Final determination with supporting evidence.",
                "user_input_required": True,
            },
        ]

    def _create_minimal_plan(self, incident_data: dict, template: str) -> list:
        """Create minimal viable plan if AI fails"""
        return self._create_fallback_steps()

    def run_real_time_prediction(
        self, 
        triaging_comments: dict, 
        rule_number: str, 
        template_content: str,
        consolidated_data: dict
    ) -> dict:
        """Run real-time prediction with robust fallback."""
        try:
            print("\n" + "=" * 80)
            print("RUNNING REAL-TIME PREDICTION...")
            print("=" * 80)
            
            # Get historical data
            from src.utils import read_all_tracker_sheets, consolidate_rule_data
            
            all_data = read_all_tracker_sheets("data")
            rule_history = consolidate_rule_data(all_data, rule_number)
            
            # Create prediction agent
            prediction_agent = self.agents.real_time_prediction_agent()
            
            # Create prediction task
            prediction_task = self.tasks.real_time_prediction_task(
                agent=prediction_agent,
                triaging_comments=triaging_comments,
                rule_number=rule_number,
                rule_history=rule_history,
                template_content=template_content
            )
            
            # Create and run crew
            crew = Crew(
                agents=[prediction_agent],
                tasks=[prediction_task],
                process=Process.sequential,
                verbose=True,
            )
            
            result = crew.kickoff()
            
            # Parse the prediction
            parsed_prediction = self._parse_real_time_prediction(str(result))
            
            # If parsing failed or returned None, use fallback
            if parsed_prediction is None:
                print("⚠️ AI prediction parsing failed. Using keyword-based fallback.")
                return self._create_fallback_prediction(triaging_comments, rule_history)
            
            print("\n" + "=" * 80)
            print("REAL-TIME PREDICTION COMPLETE!")
            print("=" * 80)
            
            return parsed_prediction
            
        except Exception as e:
            print(f"\n⚠️ Error in AI prediction: {str(e)}")
            print("Using keyword-based fallback prediction...")
            import traceback
            traceback.print_exc()
            
            # Return fallback prediction
            from src.utils import read_all_tracker_sheets, consolidate_rule_data
            all_data = read_all_tracker_sheets("data")
            rule_history = consolidate_rule_data(all_data, rule_number)
            return self._create_fallback_prediction(triaging_comments, rule_history)
    
    def _parse_real_time_prediction(self, output: str) -> dict:
        """Parse real-time prediction output - FIXED VERSION."""
        import re

        # Default to unknown
        prediction = {
            "prediction_type": "Requires Investigation",
            "false_positive_likelihood": 50,
            "true_positive_likelihood": 50,
            "benign_positive_likelihood": 0,
            "confidence_level": "Low",
            "key_factors": [],
            "historical_comparison": "",
            "reasoning": "",
            "web_research": "",
        }

        output_lower = output.lower()

        # Extract prediction type
        pred_type_match = re.search(
            r"PREDICTION_TYPE:\s*(.+?)(?:\n|$)", output, re.IGNORECASE
        )
        if pred_type_match:
            prediction["prediction_type"] = pred_type_match.group(1).strip()

        # Extract percentages - FIXED to handle multiple formats
        fp_match = re.search(
            r"False Positive[^:]*:\s*(\d+(?:\.\d+)?)%", output, re.IGNORECASE
        )
        tp_match = re.search(
            r"True Positive[^:]*:\s*(\d+(?:\.\d+)?)%", output, re.IGNORECASE
        )
        bp_match = re.search(
            r"Benign Positive[^:]*:\s*(\d+(?:\.\d+)?)%", output, re.IGNORECASE
        )

        if fp_match:
            prediction["false_positive_likelihood"] = int(float(fp_match.group(1)))
        if tp_match:
            prediction["true_positive_likelihood"] = int(float(tp_match.group(1)))
        if bp_match:
            prediction["benign_positive_likelihood"] = int(float(bp_match.group(1)))

        # VALIDATION: Check if percentages make sense
        total_pct = (
            prediction["false_positive_likelihood"]
            + prediction["true_positive_likelihood"]
            + prediction["benign_positive_likelihood"]
        )

        # If percentages don't add up to ~100, recalculate
        if total_pct < 90 or total_pct > 110:
            print(
                f"⚠️ Invalid percentages detected (total: {total_pct}%). Using fallback calculation."
            )
            return None  # Signal to use fallback

        # VALIDATION: Check if prediction_type matches the highest percentage
        highest_pct = max(
            prediction["false_positive_likelihood"],
            prediction["true_positive_likelihood"],
            prediction["benign_positive_likelihood"],
        )

        pred_type_lower = prediction["prediction_type"].lower()

        # Fix mismatched prediction type
        if highest_pct == prediction["false_positive_likelihood"]:
            if "false" not in pred_type_lower:
                print("⚠️ Prediction type mismatch! Correcting to False Positive")
                prediction["prediction_type"] = "False Positive"
        elif highest_pct == prediction["true_positive_likelihood"]:
            if "true" not in pred_type_lower or "false" in pred_type_lower:
                print("⚠️ Prediction type mismatch! Correcting to True Positive")
                prediction["prediction_type"] = "True Positive"

        # Extract confidence level
        conf_match = re.search(
            r"CONFIDENCE_LEVEL:\s*(.+?)(?:\n|$)", output, re.IGNORECASE
        )
        if conf_match:
            prediction["confidence_level"] = conf_match.group(1).strip()

        # Extract key factors
        factors_section = re.search(
            r"KEY_FACTORS:(.*?)(?:HISTORICAL_COMPARISON:|REASONING:|$)",
            output,
            re.DOTALL | re.IGNORECASE,
        )
        if factors_section:
            factors_text = factors_section.group(1)
            factors = re.findall(r"[\d]+\.\s*(.+?)(?:\n|$)", factors_text)
            prediction["key_factors"] = [
                f.strip() for f in factors[:5] if f.strip()
            ]  # Limit to 5

        # Extract historical comparison
        hist_match = re.search(
            r"HISTORICAL_COMPARISON:\s*(.+?)(?:REASONING:|WEB_RESEARCH_FINDINGS:|$)",
            output,
            re.DOTALL | re.IGNORECASE,
        )
        if hist_match:
            prediction["historical_comparison"] = hist_match.group(1).strip()[
                :500
            ]  # Limit length

        # Extract reasoning
        reasoning_match = re.search(
            r"REASONING:\s*(.+?)(?:WEB_RESEARCH_FINDINGS:|---|\Z)",
            output,
            re.DOTALL | re.IGNORECASE,
        )
        if reasoning_match:
            prediction["reasoning"] = reasoning_match.group(1).strip()[:500]

        # Extract web research
        web_match = re.search(
            r"WEB_RESEARCH_FINDINGS:\s*(.+?)(?:---|\Z)",
            output,
            re.DOTALL | re.IGNORECASE,
        )
        if web_match:
            prediction["web_research"] = web_match.group(1).strip()[:500]

        return prediction

    def _create_fallback_prediction(
        self, triaging_comments: dict, rule_history: dict
    ) -> dict:
        """Create SMART fallback prediction using keyword analysis."""

        # Combine all comments
        all_comments = " ".join(str(v) for v in triaging_comments.values()).lower()

        print("\n" + "=" * 80)
        print("RUNNING FALLBACK PREDICTION (Keyword-Based)")
        print("=" * 80)
        print(f"Analyzing comments: {all_comments[:200]}...")

        # Strong FP indicators (high confidence)
        strong_fp_keywords = {
            "clean ip": 15,
            "no malicious": 15,
            "known device": 15,
            "registered device": 15,
            "mfa success": 15,
            "legitimate": 12,
            "authorized": 12,
            "user confirmed": 12,
            "known app": 10,
            "vpn": 8,
            "nothing suspicious": 15,
            "normal behavior": 10,
            "corporate": 8,
            "approved": 8,
        }

        # Strong TP indicators (high confidence)
        strong_tp_keywords = {
            "malicious": 20,
            "threat detected": 20,
            "unauthorized": 18,
            "suspicious": 15,
            "compromised": 20,
            "bad reputation": 18,
            "unknown device": 12,
            "failed mfa": 15,
            "data exfiltration": 20,
            "escalated": 12,
            "anomalous": 15,
        }

        # Calculate scores
        fp_score = 0
        tp_score = 0

        fp_matches = []
        tp_matches = []

        for keyword, weight in strong_fp_keywords.items():
            if keyword in all_comments:
                fp_score += weight
                fp_matches.append(keyword)
                print(f"✅ Found FP indicator: '{keyword}' (weight: {weight})")

        for keyword, weight in strong_tp_keywords.items():
            if keyword in all_comments:
                tp_score += weight
                tp_matches.append(keyword)
                print(f"⚠️ Found TP indicator: '{keyword}' (weight: {weight})")

        print(f"\nScore - FP: {fp_score}, TP: {tp_score}")

        # Get historical baseline
        base_fp = rule_history.get("fp_rate", 50)
        base_tp = rule_history.get("tp_rate", 50)

        print(f"Historical baseline - FP: {base_fp}%, TP: {base_tp}%")

        # Calculate final percentages
        if fp_score == 0 and tp_score == 0:
            # No indicators found - use historical baseline
            fp_likelihood = base_fp
            tp_likelihood = base_tp
            confidence = "Low"
            reasoning = f"No clear indicators found. Using historical baseline: {base_fp}% FP, {base_tp}% TP."
        else:
            # Adjust baseline based on evidence
            total_score = fp_score + tp_score

            if total_score > 0:
                # Weight the scores
                fp_evidence_weight = (fp_score / total_score) * 100
                tp_evidence_weight = (tp_score / total_score) * 100

                # Combine with baseline (70% evidence, 30% baseline)
                fp_likelihood = int((fp_evidence_weight * 0.7) + (base_fp * 0.3))
                tp_likelihood = 100 - fp_likelihood

                # Determine confidence
                if abs(fp_score - tp_score) > 20:
                    confidence = "High"
                elif abs(fp_score - tp_score) > 10:
                    confidence = "Medium"
                else:
                    confidence = "Low"

                # Build reasoning
                if fp_score > tp_score:
                    reasoning = f"Strong False Positive indicators found ({len(fp_matches)} matches). "
                    reasoning += f"Evidence weight: {fp_evidence_weight:.0f}% FP vs {tp_evidence_weight:.0f}% TP. "
                    reasoning += (
                        f"Combined with historical baseline ({base_fp}% FP rate)."
                    )
                else:
                    reasoning = f"Strong True Positive indicators found ({len(tp_matches)} matches). "
                    reasoning += f"Evidence weight: {tp_evidence_weight:.0f}% TP vs {fp_evidence_weight:.0f}% FP. "
                    reasoning += (
                        f"Combined with historical baseline ({base_tp}% TP rate)."
                    )
            else:
                fp_likelihood = base_fp
                tp_likelihood = base_tp
                confidence = "Low"
                reasoning = f"Using historical baseline: {base_fp}% FP, {base_tp}% TP."

        # Determine prediction type
        if fp_likelihood > tp_likelihood:
            pred_type = "False Positive"
        elif tp_likelihood > fp_likelihood:
            pred_type = "True Positive"
        else:
            pred_type = "Requires Further Investigation"

        print(f"\n✅ FINAL PREDICTION: {pred_type}")
        print(f"   FP: {fp_likelihood}%, TP: {tp_likelihood}%")
        print(f"   Confidence: {confidence}")
        print("=" * 80 + "\n")

        return {
            "prediction_type": pred_type,
            "false_positive_likelihood": fp_likelihood,
            "true_positive_likelihood": tp_likelihood,
            "benign_positive_likelihood": 0,
            "confidence_level": confidence,
            "key_factors": [
                (
                    f"Found {len(fp_matches)} FP indicators: {', '.join(fp_matches[:5])}"
                    if fp_matches
                    else "No FP indicators"
                ),
                (
                    f"Found {len(tp_matches)} TP indicators: {', '.join(tp_matches[:5])}"
                    if tp_matches
                    else "No TP indicators"
                ),
                f"Historical pattern: {base_fp}% FP rate from {rule_history.get('total_incidents', 0)} past incidents",
            ],
            "historical_comparison": f"This case aligns with {base_fp}% of past incidents that were False Positive",
            "reasoning": reasoning,
            "web_research": "N/A (Fallback prediction)",
        }

    def _create_minimal_prediction(self, incident_data: dict) -> list:
        """Create minimal prediction if AI fails"""
        comments = str(incident_data.get("resolver_comments", "")).lower()

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
