import re
import os
import time
import pandas as pd
from io import BytesIO
from typing import List, Dict
from dotenv import load_dotenv
from crewai import LLM, Agent, Task, Crew
from routes.src.utils import extract_alert_name
from api_client.analyzer_api_client import get_analyzer_client
from concurrent.futures import ThreadPoolExecutor, as_completed
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

from routes.src.api_kql_generation import EnhancedKQLGenerator

load_dotenv()


class ImprovedTemplateGenerator:
    def __init__(self):
        # Initialize LLM for non-KQL tasks
        gemini_key = os.getenv("GOOGLE_API_KEY")
        if gemini_key:
            self.llm = LLM(
                model="gemini/gemini-1.5-flash", api_key=gemini_key, temperature=0.3
            )
            print("✅ Using Gemini for template generation")
        else:
            ollama_model = os.getenv("OLLAMA_CHAT", "ollama/qwen2.5:3b")
            if not ollama_model.startswith("ollama/"):
                ollama_model = f"ollama/{ollama_model}"
            self.llm = LLM(
                model=ollama_model, base_url="http://localhost:11434", temperature=0.3
            )
            print(f"✅ Using {ollama_model} for template generation")

        # Initialize enhanced KQL generator
        self.kql_generator = EnhancedKQLGenerator()

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

        # Initialize API Client for getting the Technical Overview
        try:
            self.analyzer_client = get_analyzer_client()
        except Exception as e:
            print(f"⚠️ Could not initialize Analyzer API Client: {e}")
            self.analyzer_client = None

    def _filter_investigative_steps(self, steps: List[Dict]) -> List[Dict]:
        """Filter non-investigative steps (remediation, closure, etc.)"""
        from routes.src.new_steps.step_merger import InvestigationStepMerger

        merger = InvestigationStepMerger()
        return merger._filter_investigative_steps(steps)

    def _process_merged_steps_with_kql(
        self, merged_steps: List[Dict], rule_number: str, profile: Dict
    ) -> List[Dict]:
        """
        Process merged steps and generate KQL for each
        Returns template rows ready for DataFrame
        """
        template_rows = []

        for idx, step in enumerate(merged_steps, 1):
            step_name = step.get("step_name", "")
            explanation = step.get("explanation", "")
            source = step.get("source", "unknown")
            priority = step.get("priority", "MEDIUM")
            confidence = step.get("confidence", "MEDIUM")

            print(f"\n   Step {idx}: {step_name}")
            print(
                f"      Source: {source} | Priority: {priority} | Confidence: {confidence}"
            )

            # Generate KQL if this step needs it
            kql_query = ""
            kql_explanation = ""

            if self._needs_kql(step_name, explanation):
                print(f"      🔍 Generating KQL...")
                kql_query, kql_explanation = self.kql_generator.generate_kql_query(
                    step_name=step_name,
                    explanation=explanation,
                    step_number=idx,
                    rule_context=profile.get("technical_overview", ""),
                )

                if kql_query:
                    print(f"      ✅ KQL generated ({len(kql_query)} chars)")
                else:
                    print(f"      ℹ️  No KQL needed for this step")
            else:
                print(f"      ℹ️  Step doesn't require KQL")

            # Build template row
            row = {
                "Step": idx,
                "Name": step_name,
                "Explanation": self._enforce_length(explanation, max_sentences=3),
                "KQL Query": kql_query,
                "KQL Explanation": kql_explanation,
                "Execute": "",
                "Output": "",
                "Remarks/Comments": f"[{source.upper()}] {priority}",  # Track source
            }

            template_rows.append(row)

        return template_rows

    def _needs_kql(self, step_name: str, explanation: str) -> bool:
        """Determine if step needs KQL query"""
        combined = f"{step_name} {explanation}".lower()

        # Skip for these
        skip_keywords = [
            "virustotal",
            "virus total",
            "abuseipdb",
            "document",
            "classification",
            "confirmation",
            "close",
            "remediate",
            "notify",
            "inform",
        ]

        if any(keyword in combined for keyword in skip_keywords):
            return False

        # Needs KQL for these
        needs_keywords = [
            "sign-in",
            "login",
            "verify",
            "check",
            "analyze",
            "audit",
            "query",
            "review",
            "count",
            "investigate",
        ]

        return any(keyword in combined for keyword in needs_keywords)

    def _enforce_length(self, text: str, max_sentences: int = 3) -> str:
        """Enforce maximum sentence length"""
        if not text:
            return text

        sentences = re.split(r"(?<=[.!?])\s+", text.strip())

        if len(sentences) > max_sentences:
            limited = " ".join(sentences[:max_sentences])
            return limited

        return text

    def generate_intelligent_template(
        self, rule_number: str, original_steps: List[Dict], rule_context: str = ""
    ) -> pd.DataFrame:
        print(f"\n{'='*80}")
        print(f"ðŸ§  INTELLIGENT TEMPLATE GENERATION FOR {rule_number}")
        print(f"{'='*80}\n")

        start_time = time.time()
        
        # ADD THIS DEBUG:
        print(f"DEBUG: rule_number = {rule_number}")
        print(f"DEBUG: original_steps count = {len(original_steps)}")
        print(f"DEBUG: First original step: {original_steps[0] if original_steps else 'NONE'}")

        # Header row
        template_rows = []
        header_row = {col: "" for col in self.template_columns}
        header_row["Name"] = rule_number
        template_rows.append(header_row)

        # STEP 1: BUILD INVESTIGATION PROFILE (No hardcoding)
        print(f"📊 PHASE 1: Building investigation profile...")
        from routes.src.new_steps.investigation_profile import (
            InvestigationProfileBuilder,
        )

        profile_builder = InvestigationProfileBuilder()
        profile = profile_builder.build_profile(rule_number, rule_context)

        print(f"   ✅ Profile complete:")
        print(f"      - MITRE Techniques: {len(profile['mitre_techniques'])}")
        print(f"      - Threat Actors: {len(profile['threat_actors'])}")
        print(f"      - Investigation Focus: {profile['investigation_focus']}")

        # STEP 2: GENERATE INVESTIGATION STEPS (Dynamic, LLM + Web Search)
        print(f"\n🤖 PHASE 2: Generating investigation steps...")
        from routes.src.new_steps.step_library import InvestigationStepLibrary

        step_library = InvestigationStepLibrary()
        generated_steps = step_library.generate_investigation_steps(profile)

        print(f"   ✅ Generated {len(generated_steps)} investigation steps")

        # STEP 3: FILTER & MERGE STEPS
        print(f"\n🔄 PHASE 3: Merging with original template...")

        # Filter non-investigative steps from original
        investigative_original = self._filter_investigative_steps(original_steps)
        print(f"   ✅ Original steps (investigative): {len(investigative_original)}")

        # Use merger to combine intelligently
        from routes.src.new_steps.step_merger import InvestigationStepMerger

        merger = InvestigationStepMerger()
        merged_steps, merge_report = merger.merge_steps(
            investigative_original, generated_steps, profile
        )

        # Print merge transparency report
        merger.print_merge_report(merge_report)

        # STEP 4: ADD KQL & CONVERT TO TEMPLATE ROWS
        print(f"\n⚙️  PHASE 4: Generating KQL queries and finalizing...")

        template_rows.extend(
            self._process_merged_steps_with_kql(merged_steps, rule_number, profile)
        )

        elapsed = time.time() - start_time
        print(f"\n{'='*80}")
        print(
            f"✅ COMPLETED in {elapsed:.1f}s: {len(template_rows)-1} investigation steps"
        )
        print(f"{'='*80}\n")

        return pd.DataFrame(template_rows)

    # --- NEW HELPER METHOD FOR FILTERING ---
    def _is_investigative_step(self, step: Dict) -> bool:
        """Filter out non-investigative/meta/remediation steps"""
        name = step.get("step_name", "").lower()
        explanation = step.get("explanation", "").lower()

        # Patterns for post-investigation, remediation, or final documentation
        non_investigative_patterns = [
            "reset the account",
            "revoke the mfa",
            "block the detected",
            "inform to it team",
            "track for the closer",
            "document the steps taken",
            "after all the investigation",
            "close it as:",
            "treat it as :",
            "if user confirms then close",
            "reach out to the network/edr",
            "final confirmation received",
        ]

        combined = f"{name} {explanation}"

        # If it is a step to confirm or finalize the incident, it is not investigative
        if any(p in combined for p in non_investigative_patterns):
            return False

        # If it contains core investigative verbs and is not caught by the above, keep it
        investigative_verbs = ["check", "verify", "analyze", "review", "run the kql"]
        if any(v in name for v in investigative_verbs):
            return True

        # Default to keeping if it's not explicitly filtered and not too short
        return len(name) > 10

    # --- NEW HELPER METHOD FOR TECHNICAL OVERVIEW ---
    def _get_alert_technical_overview(self, rule_number: str) -> str:
        """Fetch the Technical Overview from the AI Alert Analysis API"""
        if not self.analyzer_client:
            return ""

        try:
            # 1. Extract alert name from rule number (e.g., "Rule#297 - Unusual Login" -> "Unusual Login")
            alert_name = extract_alert_name(rule_number)

            # If the extraction fails, use a generic name
            if not alert_name or alert_name.lower() in ["n/a", rule_number.lower()]:
                return ""

            # 2. Call the analysis API
            result = self.analyzer_client.analyze_alert(alert_name)

            if result.get("success"):
                analysis_text = result.get("analysis", "")

                # 3. Extract only the Technical Overview section
                # Pattern to find '## TECHNICAL OVERVIEW' and everything until the next '##'
                match = re.search(
                    r"##\s*TECHNICAL\s*OVERVIEW\s*([\s\S]*?)(?=##|\Z)",
                    analysis_text,
                    re.IGNORECASE,
                )

                if match:
                    overview = match.group(1).strip()
                    # Further clean up any sub-headers or extra newlines
                    overview = re.sub(r"\n{2,}", " ", overview).strip()
                    return overview

            return ""

        except Exception as e:
            print(f"⚠️ Failed to get technical overview for {rule_number}: {e}")
            return ""

    def _extract_rule_context(self, rule_number: str, steps: List[Dict]) -> str:
        """Extract context from rule number and steps"""
        # Analyze step names to determine context
        all_text = " ".join(
            [s.get("step_name", "") + " " + s.get("explanation", "") for s in steps]
        ).lower()

        if "role" in all_text and ("assign" in all_text or "privilege" in all_text):
            return "Privileged role assignment and RBAC investigation"
        elif "sign-in" in all_text or "login" in all_text:
            return "User authentication and sign-in activity investigation"
        elif "ip" in all_text and "reputation" in all_text:
            return "IP reputation and network threat investigation"
        elif "device" in all_text or "endpoint" in all_text:
            return "Device compliance and endpoint security investigation"
        else:
            return "Security incident investigation and analysis"

    def _process_steps_parallel(
        self, original_steps: List[Dict], rule_number: str, rule_context: str
    ) -> List[Dict]:
        """Process multiple steps in parallel"""

        enhanced_steps = [None] * len(original_steps)

        # Use ThreadPoolExecutor for parallel processing
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_to_index = {
                executor.submit(
                    self._process_single_step,
                    i + 1,
                    step,
                    rule_number,
                    rule_context,
                ): i
                for i, step in enumerate(original_steps)
            }

            for future in as_completed(future_to_index):
                index = future_to_index[future]
                try:
                    # Longer timeout for web search and LLM calls
                    result = future.result(timeout=180)
                    enhanced_steps[index] = result
                    print(f"✅ Step {index + 1} completed")
                except Exception as e:
                    print(f"⚠️ Step {index + 1} failed: {str(e)}")
                    enhanced_steps[index] = self._fallback_step(
                        index + 1, original_steps[index]
                    )

        # Filter out any potential None if a step failed unexpectedly and fallback was missed
        return [step for step in enhanced_steps if step is not None]

    def _process_single_step(
        self,
        step_num: int,
        original_step: Dict,
        rule_number: str,
        rule_context: str,
    ) -> Dict:
        """Process single step with enhanced KQL generation"""

        original_name = original_step.get("step_name", "")
        original_explanation = original_step.get("explanation", "")

        # 1. Generate/improve step name
        step_name = self._enhance_step_name(
            original_name, original_explanation, step_num
        )

        # 2. Enhance explanation
        explanation = self._enhance_explanation(step_name, original_explanation)

        # 3. Generate KQL using enhanced generator
        print(f"\n📊 Processing Step {step_num}: {step_name}")
        kql_query, kql_explanation = self.kql_generator.generate_kql_query(
            step_name=step_name,
            explanation=explanation,
            step_number=step_num,
            rule_context=rule_context,  # Use the full_context passed from generate_intelligent_template
        )

        # 4. Add manual investigation steps if no KQL
        if not kql_query and self._needs_investigation_guidance(step_name, explanation):
            explanation = self._add_manual_investigation_steps(explanation, step_name)

        # Enforce length limits
        explanation = self._enforce_length(explanation, max_sentences=3)

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

    def _enhance_step_name(
        self, original_name: str, explanation: str, step_num: int
    ) -> str:
        """Enhance step name if needed"""

        # If original is good, clean and use it
        if self._is_good_step_name(original_name):
            return self._clean_step_name(original_name)

        # Generate improved name
        prompt = f"""Generate a clear SOC investigation step name.

Original name: {original_name[:100]}
Context: {explanation[:100]}

Requirements:
- Start with action verb: Verify, Analyze, Review, Check, Investigate
- Be specific and clear
- 4-8 words maximum
- No numbering or prefixes

Example: "Verify User Sign-in Activity"

Output ONLY the step name:"""

        try:
            result = self._quick_llm_call(prompt, max_tokens=30)
            step_name = self._aggressive_clean(result)

            if 5 <= len(step_name) <= 100 and self._is_clean_name(step_name):
                return step_name

        except Exception as e:
            print(f"   ⚠️ Name generation failed: {str(e)[:50]}")

        return self._clean_step_name(original_name) or f"Investigation Step {step_num}"

    def _enhance_explanation(self, step_name: str, original: str) -> str:
        """Enhance explanation if needed"""

        # If original is detailed enough, keep it
        if len(original) > 50 and not self._is_vague(original):
            return self._enforce_length(original, max_sentences=3)

        # Generate enhanced explanation
        prompt = f"""Write a concise SOC investigation instruction.

Step: {step_name}
Current: {original[:150]}

Include:
- What to investigate
- Which logs/tools to use
- What to look for
- Maximum 2-3 sentences

Output ONLY the instruction:"""

        try:
            result = self._quick_llm_call(prompt, max_tokens=100)
            explanation = self._aggressive_clean(result)

            if len(explanation) > 20:
                return self._enforce_length(explanation, max_sentences=3)

        except Exception as e:
            print(f"   ⚠️ Explanation generation failed: {str(e)[:50]}")

        return original or "Complete investigation and document findings."

    def _needs_investigation_guidance(self, step_name: str, explanation: str) -> bool:
        """Check if step needs manual investigation guidance"""
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
            return self._enforce_length(combined, max_sentences=4)

        return explanation

    def _enforce_length(self, text: str, max_sentences: int = 3) -> str:
        """Enforce maximum sentence length"""
        if not text:
            return text

        sentences = re.split(r"(?<=[.!?])\s+", text.strip())

        if len(sentences) > max_sentences:
            limited = " ".join(sentences[:max_sentences])
            return limited

        return text

    def _quick_llm_call(self, prompt: str, max_tokens: int = 100) -> str:
        """Make quick LLM call"""

        agent = Agent(
            role="SOC Analyst",
            goal="Generate concise security content",
            backstory="Expert security analyst",
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

    def _aggressive_clean(self, text: str) -> str:
        """Aggressively remove LLM artifacts"""

        artifacts = [
            "I now can give",
            "FINAL ANSWER:",
            "Final Answer:",
            "Here is",
            "Here's",
            "The answer is:",
            "Answer:",
            "Step:",
            "Name:",
            "Explanation:",
            "Output:",
            "Current Task:",
            "My final response",
            "successfully",
        ]

        text_lower = text.lower()
        for artifact in artifacts:
            if artifact.lower() in text_lower:
                parts = text.split(artifact, 1)
                text = parts[-1] if len(parts) > 1 else parts[0]

        # Remove quotes, markdown, numbering
        text = re.sub(r'^["\'`\-\*\.]+', "", text.strip())
        text = re.sub(r'["\'`]+', "", text.strip())
        text = re.sub(r"\*\*", "", text)
        text = re.sub(r"```[a-z]*\n?", "", text)
        text = re.sub(r"^\d+\.\s*", "", text)
        text = re.sub(r"^:\s*", "", text)

        # Clean whitespace
        text = re.sub(r"\s+", " ", text)
        text = text.strip('" \n\r:.-')

        return text

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

        if len(name) > 100 or not self._is_clean_name(name):
            return False

        return starts_with_verb

    def _is_clean_name(self, name: str) -> bool:
        """Check if name is clean"""
        name_lower = name.lower()

        artifacts = [
            "i must",
            "job depends",
            "final answer",
            "task completed",
            "ready for submission",
            "---",
            "successfully",
        ]

        return not any(artifact in name_lower for artifact in artifacts)

    def _clean_step_name(self, name: str) -> str:
        """Clean step name"""
        name = re.sub(r"^\d+\.?\s*", "", name)
        name = re.sub(r"^Step\s*\d+:?\s*", "", name, flags=re.IGNORECASE)
        name = re.sub(r"\s*---\s*\w+", "", name)

        if len(name) > 100:
            name = name[:97] + "..."

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
            "Explanation": self._enforce_length(
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
            "A": 8,  # Step
            "B": 30,  # Name
            "C": 50,  # Explanation
            "D": 70,  # KQL Query (wider for better readability)
            "E": 40,  # KQL Explanation
            "F": 12,  # Execute
            "G": 30,  # Output
            "H": 35,  # Remarks
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
        self.generator = ImprovedTemplateGenerator()
        self.template_columns = self.generator.template_columns

    def generate_clean_template(
        self, rule_number: str, enhanced_steps: List[Dict]
    ) -> pd.DataFrame:
        return self.generator.generate_intelligent_template(
            rule_number=rule_number, original_steps=enhanced_steps, rule_context=""
        )

    def export_to_excel(self, df: pd.DataFrame, rule_number: str) -> BytesIO:
        return self.generator.export_to_excel(df, rule_number)
