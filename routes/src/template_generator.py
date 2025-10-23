import re
import pandas as pd
from io import BytesIO
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from crewai import LLM, Agent, Task, Crew
from crewai_tools import SerperDevTool
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
import time
import os
from dotenv import load_dotenv

# ✅ LOAD ENVIRONMENT VARIABLES
load_dotenv()

# ✅ IMPORT KQL GENERATOR
from routes.src.kql_generation import DynamicKQLGenerator


class OptimizedTemplateGenerator:
    """
    Fast, reliable template generator with parallel processing
    """

    def __init__(self):
        # ✅ USE MODEL FROM .ENV (qwen2.5:3b instead of 0.5b)
        ollama_model = os.getenv("OLLAMA_CHAT", "ollama/qwen2.5:3b")

        # Ensure proper format
        if not ollama_model.startswith("ollama/"):
            ollama_model = f"ollama/{ollama_model}"

        print(f"🤖 Using LLM: {ollama_model}")

        self.llm = LLM(
            model=ollama_model,
            base_url="http://localhost:11434",
            timeout=120,
        )

        # ✅ INITIALIZE KQL GENERATOR
        self.kql_generator = DynamicKQLGenerator()

        try:
            self.web_search = SerperDevTool()
            self.has_web = True
        except:
            self.web_search = None
            self.has_web = False

        self.template_columns = [
            "Step",
            "Name",
            "Explanation",
            "KQL Query",
            "KQL Explanation",
            "Execute",
            "Output",
            "Remarks/Comments",
        ]

    def generate_template(
        self, rule_number: str, original_steps: List[Dict], rule_context: str = ""
    ) -> pd.DataFrame:
        """Generate enhanced template with PARALLEL processing"""
        print(f"\n{'='*80}")
        print(f"🎯 PARALLEL TEMPLATE GENERATION FOR {rule_number}")
        print(f"{'='*80}\n")

        start_time = time.time()

        # Header row
        template_rows = []
        header_row = {col: "" for col in self.template_columns}
        header_row["Name"] = rule_number
        template_rows.append(header_row)

        # Process steps in PARALLEL
        enhanced_steps = self._process_steps_parallel(
            original_steps, rule_number, rule_context
        )

        template_rows.extend(enhanced_steps)

        elapsed = time.time() - start_time
        print(f"\n{'='*80}")
        print(f"✅ COMPLETED in {elapsed:.1f}s: {len(enhanced_steps)} steps")
        print(f"{'='*80}\n")

        return pd.DataFrame(template_rows)

    def _process_steps_parallel(
        self, original_steps: List[Dict], rule_number: str, rule_context: str
    ) -> List[Dict]:
        """Process multiple steps in parallel for speed"""

        enhanced_steps = [None] * len(original_steps)

        # Use ThreadPoolExecutor for parallel processing
        with ThreadPoolExecutor(max_workers=4) as executor:
            # Submit all tasks
            future_to_index = {
                executor.submit(
                    self._process_single_step_fast,
                    i + 1,
                    step,
                    rule_number,
                    rule_context,
                ): i
                for i, step in enumerate(original_steps)
            }

            # Collect results as they complete
            for future in as_completed(future_to_index):
                index = future_to_index[future]
                try:
                    result = future.result(timeout=150)
                    enhanced_steps[index] = result
                    print(f"✅ Step {index + 1} completed")
                except Exception as e:
                    print(f"⚠️ Step {index + 1} failed: {str(e)}")
                    # Use fallback
                    enhanced_steps[index] = self._fallback_step(
                        index + 1, original_steps[index]
                    )

        return enhanced_steps

    def _process_single_step_fast(
        self,
        step_num: int,
        original_step: Dict,
        rule_number: str,
        rule_context: str,
    ) -> Dict:
        """Process step with better error handling and faster prompts"""

        original_name = original_step.get("step_name", "")
        original_explanation = original_step.get("explanation", "")

        # 1. Generate step name - SHORT prompt
        step_name = self._generate_step_name_fast(
            original_name, original_explanation, step_num
        )

        # 2. Keep or enhance explanation
        if len(original_explanation) > 50 and not self._is_vague(original_explanation):
            explanation = self._enforce_explanation_length(original_explanation)
        else:
            explanation = self._enhance_explanation_fast(
                step_name, original_explanation
            )

        # 3. Generate KQL if needed
        kql_query, kql_explanation = self._generate_kql_dynamic(
            step_name, explanation, step_num
        )

        # 4. If no KQL, enhance explanation with manual steps
        if not kql_query and self._needs_investigation_guidance(step_name, explanation):
            explanation = self._add_manual_investigation_steps(explanation, step_name)

        return {
            "Step": step_num,
            "Name": step_name,
            "Explanation": explanation,
            "KQL Query": kql_query,
            "KQL Explanation": kql_explanation,
            "Execute": "",
            "Output": "",
            "Remarks/Comments": "",
        }

    def _enforce_explanation_length(
        self, explanation: str, max_sentences: int = 3
    ) -> str:
        """✅ REDUCED to 3 sentences max"""
        if not explanation:
            return explanation

        sentences = re.split(r"(?<=[.!?])\s+", explanation.strip())

        if len(sentences) > max_sentences:
            limited = " ".join(sentences[:max_sentences])
            return limited

        return explanation

    def _generate_kql_dynamic(
        self, step_name: str, explanation: str, step_num: int
    ) -> Tuple[str, str]:
        """Generate KQL using DynamicKQLGenerator (web + LLM)"""

        combined = f"{step_name} {explanation}".lower()

        # Check if needs KQL
        if not self._needs_kql(combined):
            return "", ""

        try:
            # ✅ USE DYNAMIC GENERATOR
            kql_query = self.kql_generator.generate_kql_query(
                step_name=step_name,
                explanation=explanation,
                context=f"Security investigation step {step_num}",
            )

            if kql_query and self._is_valid_kql(kql_query):
                # ✅ AGGRESSIVE KQL CLEANING
                kql_query = self._deep_clean_kql(kql_query)
                kql_explanation = self._get_kql_explanation_from_query(kql_query)
                return kql_query, kql_explanation

        except Exception as e:
            print(f"⚠️ KQL generation failed for step {step_num}: {str(e)}")

        return "", ""

    def _deep_clean_kql(self, kql: str) -> str:
        """✅ AGGRESSIVE KQL cleaning to remove all artifacts"""
        if not kql:
            return ""

        # Remove markdown
        kql = re.sub(r"```kql\s*", "", kql)
        kql = re.sub(r"```\s*", "", kql)

        # Remove explanations and comments
        lines = []
        for line in kql.split("\n"):
            line = line.strip()

            # Skip empty lines
            if not line:
                continue

            # Skip comment lines
            if line.startswith("//") or line.startswith("#"):
                continue

            # Remove inline comments
            if "//" in line:
                line = line.split("//")[0].strip()

            # Stop at explanation text
            if any(
                stop in line.lower()
                for stop in [
                    "this query",
                    "explanation:",
                    "note:",
                    "output:",
                    "the query",
                    "this kql",
                    "result:",
                ]
            ):
                break

            # ✅ REMOVE LLM ARTIFACTS
            if any(
                artifact in line.lower()
                for artifact in [
                    "i now can give",
                    "final answer",
                    "my job depends",
                    "i must use",
                    "current task",
                    "here is",
                    "here's",
                ]
            ):
                continue

            lines.append(line)

        kql = "\n".join(lines)

        # Replace hardcoded values with placeholders
        kql = re.sub(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "<USER_EMAIL>", kql
        )
        kql = re.sub(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "<IP_ADDRESS>", kql)
        kql = re.sub(r"ago\(\d+[dhm]\)", "ago(<TIMESPAN>)", kql)

        # Remove trailing/leading whitespace
        kql = kql.strip()

        return kql

    def _needs_investigation_guidance(self, step_name: str, explanation: str) -> bool:
        """Check if step needs investigation guidance"""
        combined = f"{step_name} {explanation}".lower()

        needs_guidance = [
            "verify",
            "check",
            "review",
            "analyze",
            "validate",
            "investigate",
            "examine",
            "assess",
            "inspect",
        ]

        skip = [
            "document",
            "close",
            "escalate",
            "inform",
            "notify",
            "report",
            "classify",
            "confirmation",
        ]

        if any(word in combined for word in skip):
            return False

        return any(word in combined for word in needs_guidance)

    def _add_manual_investigation_steps(self, explanation: str, step_name: str) -> str:
        """Add manual investigation steps when KQL isn't available"""

        step_lower = step_name.lower()

        manual_steps = ""

        if "ip" in step_lower and "reputation" in step_lower:
            manual_steps = " Manually check the IP address using VirusTotal, AbuseIPDB, or similar threat intelligence platforms. Document the reputation score and any malicious indicators found."

        elif "user" in step_lower and ("vip" in step_lower or "status" in step_lower):
            manual_steps = " Cross-reference the username against the organization's VIP user list. Verify user role, department, and access level in the identity management system."

        elif "device" in step_lower or "endpoint" in step_lower:
            manual_steps = " Check device compliance status in Endpoint Management console. Verify device registration, last check-in time, and compliance policy status."

        elif "mfa" in step_lower or "multi-factor" in step_lower:
            manual_steps = " Review user's MFA settings in Azure AD/Identity Provider. Verify enrolled authentication methods and recent MFA challenge results."

        elif "location" in step_lower or "geographic" in step_lower:
            manual_steps = " Analyze geographic location patterns from sign-in logs. Compare with user's known locations and identify any unusual or impossible travel scenarios."

        elif "role" in step_lower or "permission" in step_lower:
            manual_steps = " Review user's assigned roles and permissions in the identity management system. Verify role assignment history and check for any recent privilege escalations."

        else:
            manual_steps = " Review relevant logs and documentation. Gather evidence from available security tools and systems. Document all findings with timestamps and sources."

        if manual_steps and manual_steps.strip() not in explanation:
            combined = explanation + manual_steps
            return self._enforce_explanation_length(combined, max_sentences=3)

        return explanation

    def _get_kql_explanation_from_query(self, kql: str) -> str:
        """Generate concise explanation from KQL query structure"""

        kql_lower = kql.lower()

        if "signinlogs" in kql_lower:
            if "summarize" in kql_lower:
                return "Aggregates sign-in activity to identify patterns, unique locations, failed attempts, and risk indicators."
            else:
                return "Queries SigninLogs to retrieve user authentication activity, IP addresses, locations, and device details."

        elif "auditlogs" in kql_lower:
            if "role" in kql_lower:
                return "Queries AuditLogs to track role assignments, privilege escalations, and administrative actions."
            else:
                return "Queries AuditLogs to retrieve administrative actions, configuration changes, and security operations."

        elif "identityinfo" in kql_lower:
            return "Queries IdentityInfo to retrieve user profile data, organizational information, and VIP status."

        elif "threatintelligenceindicator" in kql_lower:
            return "Cross-references against threat intelligence feeds to identify known malicious indicators and IP reputations."

        elif "deviceinfo" in kql_lower:
            return "Queries device inventory to retrieve endpoint information and compliance status."

        else:
            return "Queries security logs to retrieve relevant data for investigation."

    def _generate_step_name_fast(
        self, original_name: str, explanation: str, step_num: int
    ) -> str:
        """Generate step name with AGGRESSIVE cleaning"""

        # If original is good, clean and use it
        if self._is_good_step_name(original_name):
            return self._clean_step_name(original_name)

        # ✅ EVEN SHORTER prompt
        prompt = f"""Generate 1 clear SOC step name.

Original: {original_name[:80]}

Rules:
- ONE verb only: Verify/Analyze/Review/Check
- 3-6 words
- No artifacts

Example: "Verify User VIP Status"

Name:"""

        try:
            result = self._quick_llm_call(prompt, max_tokens=30)
            step_name = self._ultra_clean_llm_output(result)

            # Validate
            if 5 <= len(step_name) <= 80 and self._is_clean_step_name(step_name):
                return step_name

        except:
            pass

        return self._clean_step_name(original_name) or f"Investigation Step {step_num}"

    def _enhance_explanation_fast(self, step_name: str, original: str) -> str:
        """Enhance explanation with length limit"""

        if len(original) > 50:
            return self._enforce_explanation_length(original)

        prompt = f"""Write SOC instruction for: {step_name}

Be specific:
- What to investigate
- Which tools/logs
- 2 sentences max

Instruction:"""

        try:
            result = self._quick_llm_call(prompt, max_tokens=80)
            explanation = self._ultra_clean_llm_output(result)
            explanation = self._enforce_explanation_length(explanation, max_sentences=2)

            return explanation if len(explanation) > 20 else original
        except:
            return original or "Complete investigation and document findings."

    def _is_valid_kql(self, kql: str) -> bool:
        """Validate KQL"""
        if not kql or len(kql) < 20:
            return False

        tables = [
            "SigninLogs",
            "AuditLogs",
            "IdentityInfo",
            "ThreatIntelligenceIndicator",
            "DeviceInfo",
        ]
        if not any(table in kql for table in tables):
            return False

        if not any(
            op in kql.lower() for op in ["where", "extend", "project", "summarize"]
        ):
            return False

        return True

    def _needs_kql(self, text: str) -> bool:
        """Check if step needs KQL"""

        skip_keywords = [
            "document",
            "close",
            "escalate",
            "inform",
            "notify",
            "report",
            "classify",
            "confirmation",
            "user confirms",
            "scenarios",
            "true positive",
            "false positive",
        ]

        if any(keyword in text for keyword in skip_keywords):
            return False

        kql_keywords = [
            "check",
            "verify",
            "review",
            "analyze",
            "query",
            "sign-in",
            "logs",
            "audit",
            "ip",
            "device",
            "user",
            "role",
        ]

        return any(keyword in text for keyword in kql_keywords)

    def _quick_llm_call(self, prompt: str, max_tokens: int = 100) -> str:
        """Make quick LLM call with timeout"""

        agent = Agent(
            role="SOC Analyst",
            goal="Generate concise output",
            backstory="Security expert",
            llm=self.llm,
            verbose=False,
        )

        task = Task(
            description=prompt,
            expected_output="Concise answer",
            agent=agent,
        )

        crew = Crew(agents=[agent], tasks=[task], verbose=False)
        result = crew.kickoff()

        return str(result)

    def _ultra_clean_llm_output(self, text: str) -> str:
        """✅ ULTRA AGGRESSIVE cleaning"""

        # Remove ALL common artifacts
        artifacts = [
            "I now can give a great answer",
            "FINAL ANSWER:",
            "Final Answer:",
            "I MUST use these formats",
            "my job depends on it",
            "Here is the",
            "Here's the",
            "Here is",
            "Here's",
            "The answer is:",
            "Answer:",
            "Step:",
            "Step Name:",
            "Name:",
            "Explanation:",
            "Query:",
            "Thought:",
            "User:",
            "Current Task:",
            "### User:",
            "Output:",
            "The task",
            "My final response",
            "ready for submission",
            "has been completed",
        ]

        text_lower = text.lower()
        for artifact in artifacts:
            if artifact.lower() in text_lower:
                parts = text.split(artifact, 1)
                text = parts[-1] if len(parts) > 1 else parts[0]
                text = text.replace(artifact, "")

        # Remove quotes, markdown, numbering
        text = re.sub(r'^["\'`\-\*\.]+', "", text.strip())
        text = re.sub(r'["\'`]+$', "", text.strip())
        text = re.sub(r"\*\*", "", text)
        text = re.sub(r"```[a-z]*\n?", "", text)
        text = re.sub(r"^\d+\.\s*", "", text)
        text = re.sub(r'^-\s*"?', "", text)
        text = re.sub(r"^:\s*", "", text)

        # Clean whitespace
        text = re.sub(r"\s+", " ", text)
        text = text.strip('" \n\r:.-')

        return text

    def _is_clean_step_name(self, name: str) -> bool:
        """Check if step name is clean (no artifacts)"""
        name_lower = name.lower()

        # Check for artifacts
        artifacts = [
            "i must",
            "job depends",
            "final answer",
            "task completed",
            "ready for submission",
            "my final response",
            "here is",
            "---",
            "the task",
            "successfully",
        ]

        if any(artifact in name_lower for artifact in artifacts):
            return False

        # Check for reasonable length
        if len(name) < 10 or len(name) > 80:
            return False

        return True

    def _is_good_step_name(self, name: str) -> bool:
        """Check if step name is good"""
        if not name or len(name) < 5:
            return False

        action_verbs = [
            "verify",
            "validate",
            "check",
            "review",
            "analyze",
            "examine",
            "investigate",
            "extract",
            "query",
            "assess",
        ]

        name_lower = name.lower()
        starts_with_verb = any(name_lower.startswith(verb) for verb in action_verbs)

        if len(name) > 80:
            return False

        if not self._is_clean_step_name(name):
            return False

        return starts_with_verb

    def _clean_step_name(self, name: str) -> str:
        """Clean step name"""
        name = re.sub(r"^\d+\.?\s*", "", name)
        name = re.sub(r"^Step\s*\d+:?\s*", "", name, flags=re.IGNORECASE)

        # Remove "---" artifacts
        name = re.sub(r"\s*---\s*\w+", "", name)

        if len(name) > 80:
            name = name[:77] + "..."

        return name.strip()

    def _is_vague(self, text: str) -> bool:
        """Check if text is vague"""
        if not text or len(text) < 30:
            return True

        vague = ["n/a", "tbd", "complete the step", "document findings"]
        return any(phrase in text.lower() for phrase in vague)

    def _fallback_step(self, step_num: int, original_step: Dict) -> Dict:
        """Create fallback step if processing fails"""
        return {
            "Step": step_num,
            "Name": self._clean_step_name(
                original_step.get("step_name", f"Step {step_num}")
            ),
            "Explanation": self._enforce_explanation_length(
                original_step.get("explanation", "Complete investigation step.")
            ),
            "KQL Query": "",
            "KQL Explanation": "",
            "Execute": "",
            "Output": "",
            "Remarks/Comments": "",
        }

    def export_to_excel(self, df: pd.DataFrame, rule_number: str) -> BytesIO:
        """Export to formatted Excel"""
        output = BytesIO()

        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            df.to_excel(writer, sheet_name="Triaging_Template", index=False)
            workbook = writer.book
            worksheet = writer.sheets["Triaging_Template"]
            self._format_worksheet(worksheet, df)

        output.seek(0)
        return output

    def _format_worksheet(self, worksheet, df):
        """Apply Excel formatting"""
        header_font = Font(bold=True, color="FFFFFF", size=11)
        header_fill = PatternFill(
            start_color="366092", end_color="366092", fill_type="solid"
        )
        header_alignment = Alignment(
            horizontal="center", vertical="center", wrap_text=True
        )

        for col_num, column_title in enumerate(df.columns, 1):
            cell = worksheet.cell(row=1, column=col_num)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = header_alignment

        column_widths = {
            "A": 8,
            "B": 30,
            "C": 45,
            "D": 60,
            "E": 35,
            "F": 12,
            "G": 25,
            "H": 30,
        }

        for col_letter, width in column_widths.items():
            worksheet.column_dimensions[col_letter].width = width

        thin_border = Border(
            left=Side(style="thin", color="CCCCCC"),
            right=Side(style="thin", color="CCCCCC"),
            top=Side(style="thin", color="CCCCCC"),
            bottom=Side(style="thin", color="CCCCCC"),
        )

        cell_alignment = Alignment(vertical="top", wrap_text=True, horizontal="left")

        for row_idx, row in enumerate(worksheet.iter_rows(min_row=2), start=2):
            for cell in row:
                cell.border = thin_border
                cell.alignment = cell_alignment

                if row_idx % 2 == 0:
                    cell.fill = PatternFill(
                        start_color="F9F9F9", end_color="F9F9F9", fill_type="solid"
                    )

        worksheet.freeze_panes = "A2"


# Compatibility wrapper
class EnhancedTemplateGenerator:
    def __init__(self):
        self.generator = OptimizedTemplateGenerator()
        self.template_columns = self.generator.template_columns

    def generate_clean_template(
        self, rule_number: str, enhanced_steps: List[Dict]
    ) -> pd.DataFrame:
        return self.generator.generate_template(
            rule_number=rule_number, original_steps=enhanced_steps, rule_context=""
        )

    def export_to_excel(self, df: pd.DataFrame, rule_number: str) -> BytesIO:
        return self.generator.export_to_excel(df, rule_number)
