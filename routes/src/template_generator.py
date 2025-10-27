import re
import os
import time
import pandas as pd
from io import BytesIO
from typing import List, Dict
from dotenv import load_dotenv
from crewai import LLM, Agent, Task, Crew
from api_client.analyzer_api_client import get_analyzer_client
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

from difflib import SequenceMatcher
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
        ✅ KEEP all ORIGINAL steps (from template) regardless of KQL
        ✅ FILTER AI-GENERATED steps that don't have KQL
        Returns template rows ready for DataFrame
        """
        template_rows = []
        
        # Separate original and AI-generated steps
        original_steps = []
        ai_generated_steps = []
        
        for step in merged_steps:
            if step.get("source") == "original_template":
                original_steps.append(step)
            else:
                ai_generated_steps.append(step)
        
        print(f"   📊 Original steps: {len(original_steps)}")
        print(f"   🤖 AI-generated steps: {len(ai_generated_steps)}")
        
        # FIRST: Process ORIGINAL steps - keep ALL regardless of KQL
        print(f"\n   ✅ Processing ORIGINAL steps (keeping all)...")
        original_processed = 0
        for idx, step in enumerate(original_steps, 1):
            step_name = step.get("step_name", "")
            explanation = step.get("explanation", "")
            source = step.get("source", "unknown")
            priority = step.get("priority", "MEDIUM")
            confidence = step.get("confidence", "MEDIUM")

            print(f"\n      Step {idx}: {step_name}")
            print(f"         Source: {source} | Priority: {priority}")

            # Try to generate KQL for original steps too
            kql_query = ""
            kql_explanation = ""
            
            if self._needs_kql(step_name, explanation):
                print(f"         🔍 Generating KQL...")
                kql_query, kql_explanation = self.kql_generator.generate_kql_query(
                    step_name=step_name,
                    explanation=explanation,
                    step_number=idx,
                    rule_context=profile.get("technical_overview", ""),
                )
                
                if kql_query and len(kql_query.strip()) > 30:
                    print(f"         ✅ KQL generated ({len(kql_query)} chars)")
                else:
                    print(f"         ℹ️  No KQL for this step (external tool/manual)")
                    kql_query = ""
            else:
                print(f"         ℹ️  Step doesn't require KQL (external tool)")

            # Build template row - KEEP ORIGINAL EVEN IF NO KQL
            row = {
                "Step": str(idx),
                "Name": step_name,
                "Explanation": self._enhance_step_explanation(explanation),
                "KQL Query": kql_query,
                "KQL Explanation": kql_explanation,
                "Execute": "",
                "Output": "",
                "Remarks/Comments": f"[{source.upper()}] {priority}",
            }
            
            template_rows.append(row)
            original_processed += 1

        print(f"\n   ✅ Kept all {original_processed} ORIGINAL steps")

        # SECOND: Process AI-GENERATED steps - FILTER if no KQL
        print(f"\n   ✅ Processing AI-GENERATED steps (filtering if no KQL)...")
        ai_processed = 0
        ai_skipped = 0
        
        for idx, step in enumerate(ai_generated_steps, 1):
            step_name = step.get("step_name", "")
            explanation = step.get("explanation", "")
            source = step.get("source", "unknown")
            priority = step.get("priority", "MEDIUM")
            confidence = step.get("confidence", "MEDIUM")

            # ✅ FOR AI-GENERATED: Check if KQL is needed FIRST
            if not self._needs_kql(step_name, explanation):
                print(f"      ⏭️  Skipping AI step (no KQL needed): {step_name}")
                ai_skipped += 1
                continue

            print(f"\n      Step {original_processed + ai_processed + 1}: {step_name}")
            print(f"         Source: {source} | Priority: {priority}")
            print(f"         🔍 Generating KQL...")
            
            kql_query, kql_explanation = self.kql_generator.generate_kql_query(
                step_name=step_name,
                explanation=explanation,
                step_number=original_processed + ai_processed + 1,
                rule_context=profile.get("technical_overview", ""),
            )

            # ✅ FOR AI-GENERATED: Skip if KQL generation failed
            if not (kql_query and len(kql_query.strip()) > 30):
                print(f"         ⏭️  Skipping (KQL generation failed)")
                ai_skipped += 1
                continue

            print(f"         ✅ KQL generated ({len(kql_query)} chars)")
            print(f"         📝 Explanation: {kql_explanation[:80]}...")

            # Build template row for AI-generated step
            row = {
                "Step": str(original_processed + ai_processed + 1),
                "Name": step_name,
                "Explanation": self._enhance_step_explanation(explanation),
                "KQL Query": kql_query,
                "KQL Explanation": kql_explanation,
                "Execute": "",
                "Output": "",
                "Remarks/Comments": f"[{source.upper()}] {priority}",
            }

            template_rows.append(row)
            ai_processed += 1

        print(f"\n   ✅ Processed {ai_processed} AI-GENERATED steps")
        print(f"   ⏭️  Skipped {ai_skipped} AI-GENERATED steps (no KQL)")
        print(f"\n   📊 Final template: {len(template_rows)} total steps")
        print(f"      - {original_processed} from ORIGINAL")
        print(f"      - {ai_processed} from AI-GENERATED")
        
        return template_rows

    def _enhance_step_explanation(self, explanation: str) -> str:
        """Enhance step explanation - make it clear and concise"""
        if not explanation or len(explanation.strip()) == 0:
            return ""
        
        # If explanation is already reasonable, just enforce length
        if len(explanation) > 30 and not self._is_vague(explanation):
            return self._enforce_length(explanation, max_sentences=3)
        
        # If explanation is too vague or short, try to enhance it
        prompt = f"""Improve this SOC investigation instruction to be clear and actionable.

    Current: {explanation[:150]}

    Requirements:
    - Be specific and clear
    - Include what to investigate and what to look for
    - Maximum 2-3 sentences
    - Use imperative voice (e.g., "Check", "Review", "Verify")

    Output ONLY the improved instruction:"""
        
        try:
            result = self._quick_llm_call(prompt, max_tokens=100)
            enhanced = self._aggressive_clean(result)
            
            if len(enhanced) > 20:
                return self._enforce_length(enhanced, max_sentences=3)
        except Exception as e:
            print(f"   ⚠️ Explanation enhancement failed: {str(e)[:50]}")
        
        return self._enforce_length(explanation, max_sentences=3)

    def _needs_kql(self, step_name: str, explanation: str) -> bool:
        """Determine if step needs KQL query - MORE INCLUSIVE"""
        combined = f"{step_name} {explanation}".lower()

        # ❌ Skip only external tools
        skip_keywords = [
            "virustotal", "virus total", "abuseipdb", "abuse",
            "document", "close incident", "escalate", "inform", "notify"
        ]

        if any(keyword in combined for keyword in skip_keywords):
            return False

        # ✅ Include role/permission checks (they need AuditLogs)
        needs_keywords = [
            "sign-in", "signin", "login", "audit", "logs", "query",
            "check user", "verify user", "review", "analyze", "investigate",
            "count", "gather", "extract", "device", "endpoint",
            "role", "permission", "assignment", "group", "membership",  # ✅ ADDED
            "mfa", "authentication", "location", "oauth", "grant"  # ✅ ADDED
        ]

        return any(keyword in combined for keyword in needs_keywords)

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
        print(
            f"DEBUG: First original step: {original_steps[0] if original_steps else 'NONE'}"
        )

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
        
        profile["existing_step_names"] = [s.get("step_name", "") for s in original_steps]

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
        
        template_rows = self._deduplicate_kql_queries(template_rows)

        elapsed = time.time() - start_time
        print(f"\n{'='*80}")
        print(
            f"✅ COMPLETED in {elapsed:.1f}s: {len(template_rows)-1} investigation steps"
        )
        print(f"{'='*80}\n")

        return pd.DataFrame(template_rows)

    def _deduplicate_kql_queries(self, template_rows: List[Dict]) -> List[Dict]:
        """Remove steps with duplicate or nearly-identical KQL queries"""
        seen_queries = {}
        deduplicated = []

        for row in template_rows:
            kql = row.get("KQL Query", "").strip()

            # Always keep steps without KQL (header, manual steps)
            if not kql or len(kql) < 20:
                deduplicated.append(row)
                continue

            # Normalize KQL for comparison (remove whitespace, lowercase)
            normalized = re.sub(r"\s+", " ", kql.lower())

            # Check if we've seen this query before
            is_duplicate = False
            for seen_query in seen_queries.values():
                # If queries are 90%+ similar, consider duplicate
                similarity = SequenceMatcher(None, normalized, seen_query).ratio()
                if similarity > 0.9:
                    is_duplicate = True
                    break

            if not is_duplicate:
                seen_queries[row.get("Name", "")] = normalized
                deduplicated.append(row)
            else:
                print(f"   🗑️ Removed duplicate KQL step: {row.get('Name', '')}")

        return deduplicated

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

    def _is_vague(self, text: str) -> bool:
        """Check if text is vague"""
        if not text or len(text) < 30:
            return True

        vague = ["n/a", "tbd", "complete the step", "document findings"]
        return any(phrase in text.lower() for phrase in vague)

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

    def export_to_excel(self, df: pd.DataFrame, rule_number: str) -> BytesIO:
        return self.generator.export_to_excel(df, rule_number)
