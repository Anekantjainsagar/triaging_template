from crewai import Agent, Task, Crew, LLM
from crewai_tools import SerperDevTool
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


class WebLLMEnhancer:
    """
    ✅ FIXED VERSION:
    1. Keep ORIGINAL step names (no changes)
    2. Enhance explanations using web research + LLM refactoring
    3. Clean KQL queries (remove messy data)
    4. Use PARALLEL processing for speed
    """

    def __init__(self):
        self.llm = LLM(model="ollama/qwen2.5:0.5b", base_url="http://localhost:11434")

        try:
            self.web_search = SerperDevTool()
            print("✅ Web search (Serper) available")
        except:
            self.web_search = None
            print("⚠️ Web search unavailable. Using LLM-only enhancement.")

    def enhance_template_steps(self, rule_number: str, original_steps: list) -> list:
        """
        ✅ PARALLEL enhancement pipeline:
        - Keep original step names
        - Enhance explanations with web + LLM
        - Clean KQL queries
        """
        print(f"\n{'='*80}")
        print(f"🔍 WEB + LLM ENHANCEMENT FOR {rule_number}")
        print(f"{'='*80}")
        print(f"📥 Input: {len(original_steps)} original steps")
        print(f"⚡ Using PARALLEL processing for speed...")

        start_time = time.time()

        # ✅ PARALLEL PROCESSING with ThreadPoolExecutor
        enhanced_steps = []

        with ThreadPoolExecutor(max_workers=5) as executor:
            # Submit all tasks at once
            future_to_step = {
                executor.submit(self._enhance_single_step, step, i, rule_number): (
                    i,
                    step,
                )
                for i, step in enumerate(original_steps, 1)
            }

            # Collect results as they complete
            results = {}
            for future in as_completed(future_to_step):
                step_num, original_step = future_to_step[future]
                try:
                    enhanced_step = future.result()
                    results[step_num] = enhanced_step
                    print(f"✅ Completed step {step_num}/{len(original_steps)}")
                except Exception as e:
                    print(f"❌ Step {step_num} failed: {str(e)}")
                    # Use original as fallback
                    results[step_num] = original_step

            # Sort by step number to maintain order
            enhanced_steps = [results[i] for i in sorted(results.keys())]

        elapsed = time.time() - start_time
        print(f"\n{'='*80}")
        print(f"✅ ENHANCEMENT COMPLETE in {elapsed:.1f}s")
        print(f"   Original steps: {len(original_steps)}")
        print(f"   Enhanced steps: {len(enhanced_steps)}")
        print(
            f"   Steps with KQL: {len([s for s in enhanced_steps if s.get('kql_query')])}"
        )
        print(f"   Average time per step: {elapsed/len(original_steps):.1f}s")
        print(f"{'='*80}\n")

        return enhanced_steps

    def _enhance_single_step(self, step: dict, step_num: int, rule_number: str) -> dict:
        """
        ✅ Enhance a single step (called in parallel)
        """
        original_name = step.get("step_name", f"Step {step_num}")
        original_exp = step.get("explanation", "")
        original_kql = step.get("kql_query", "")

        # 1. ✅ KEEP ORIGINAL NAME (no changes!)
        final_name = original_name

        # 2. ✅ ENHANCE EXPLANATION (web research + LLM refactoring)
        enhanced_exp = self._enhance_explanation_with_web(
            final_name, original_exp, rule_number
        )

        # 3. ✅ CLEAN KQL QUERY (remove messy data)
        cleaned_kql = self._deep_clean_kql(original_kql)

        return {
            "step_name": final_name,
            "explanation": enhanced_exp,
            "input_required": step.get("input_required", ""),
            "kql_query": cleaned_kql,
        }

    def _enhance_explanation_with_web(
        self, step_name: str, original_exp: str, rule_number: str
    ) -> str:
        """
        ✅ ENHANCED: Use web research + LLM to refactor explanation
        """
        # If no original explanation, generate from step name
        if not original_exp or len(original_exp) < 10:
            return self._generate_explanation_from_name(step_name, rule_number)

        # Step 1: Web research for context (if available)
        web_context = ""
        if self.web_search:
            try:
                search_query = f"Microsoft Sentinel {rule_number} {step_name} investigation best practices"
                print(f"   🌐 Searching: {search_query[:60]}...")

                # Use Serper to search
                search_results = self.web_search._run(search_query)

                # Extract relevant snippets (first 300 chars)
                if search_results and len(str(search_results)) > 100:
                    web_context = str(search_results)[:300]
                    print(f"   ✅ Found web context: {len(web_context)} chars")
            except Exception as e:
                print(f"   ⚠️ Web search failed: {str(e)}")

        # Step 2: LLM refactoring with web context
        web_context_section = (
            f"WEB RESEARCH CONTEXT:\n{web_context}\n" if web_context else ""
        )

        prompt = f"""Refactor this security investigation step explanation to be clear, actionable, and professional.

    ORIGINAL EXPLANATION:
    {original_exp}

    STEP NAME: {step_name}
    RULE: {rule_number}

    {web_context_section}

    REQUIREMENTS:
    1. Keep it 25-40 words (concise but complete)
    2. Start with clear action verb
    3. Explain WHAT to investigate and WHY
    4. Mention expected outcome or decision point
    5. Be specific to security investigation
    6. Remove any formatting marks (**/##/etc)
    7. Professional tone

    EXAMPLES:
    - "Query Azure AD audit logs for privileged role assignments within the last 7 days. Identify high-risk roles like Global Admin or Security Admin. Document the assigned user, timestamp, and initiator for further validation."
    - "Verify IP address reputation using threat intelligence sources (VirusTotal, GreyNoise). Check for known malicious activity, geolocation anomalies, or previous incidents. Clean IPs indicate potential false positive."

    Generate refactored explanation (25-40 words):"""

        try:
            agent = Agent(
                role="Security Documentation Expert",
                goal="Create clear, actionable investigation steps",
                backstory="Expert in security operations and incident response documentation with 10+ years experience",
                llm=self.llm,
                verbose=False,
            )

            task = Task(
                description=prompt,
                expected_output="A 25-40 word professional explanation",
                agent=agent,
            )

            crew = Crew(agents=[agent], tasks=[task], verbose=False)
            result = crew.kickoff()

            enhanced_exp = str(result).strip()

            # Clean any remaining markdown
            enhanced_exp = re.sub(r"[*#_`]", "", enhanced_exp)
            enhanced_exp = " ".join(enhanced_exp.split())

            # Validate word count
            word_count = len(enhanced_exp.split())
            if 20 <= word_count <= 60 and len(enhanced_exp) > 50:
                return enhanced_exp

        except Exception as e:
            print(f"   ⚠️ LLM refactoring failed: {str(e)}")

        # Fallback: Clean and return original
        clean_original = re.sub(r"[*#_`]", "", original_exp)
        clean_original = " ".join(clean_original.split())
        return (
            clean_original
            if clean_original
            else f"Complete {step_name} investigation and document findings."
        )

    def _generate_explanation_from_name(self, step_name: str, rule_number: str) -> str:
        """Generate explanation when original is missing"""
        prompt = f"""Generate a clear 25-40 word explanation for this security investigation step.

STEP NAME: {step_name}
RULE: {rule_number}

Generate professional investigation instruction (25-40 words):"""

        try:
            agent = Agent(
                role="Security Documentation Expert",
                goal="Generate investigation instructions",
                backstory="Expert in security operations",
                llm=self.llm,
                verbose=False,
            )

            task = Task(
                description=prompt,
                expected_output="A 25-40 word explanation",
                agent=agent,
            )

            crew = Crew(agents=[agent], tasks=[task], verbose=False)
            result = crew.kickoff()

            return str(result).strip()

        except Exception as e:
            print(f"   ⚠️ Generation failed: {str(e)}")
            return f"Investigate {step_name}. Review relevant logs and security indicators. Document findings and determine if escalation is required."

    def _deep_clean_kql(self, kql: str) -> str:
        """
        ✅ DEEP CLEANING: Remove ALL messy data from KQL queries
        """
        if not kql or kql.strip().upper() in ["N/A", "NA", ""]:
            return ""

        # Remove markdown code blocks
        kql = re.sub(r"```[a-z]*\s*\n?", "", kql)
        kql = re.sub(r"\n?```", "", kql)

        # Remove comments that are too verbose (keep short ones)
        lines = kql.split("\n")
        cleaned_lines = []
        for line in lines:
            # Keep short comments (< 60 chars)
            if line.strip().startswith("//"):
                if len(line.strip()) < 60:
                    cleaned_lines.append(line)
            else:
                cleaned_lines.append(line)
        kql = "\n".join(cleaned_lines)

        # Replace hardcoded email addresses
        kql = re.sub(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "<USER_EMAIL>", kql
        )

        # Replace hardcoded IP addresses
        kql = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "<IP_ADDRESS>", kql)

        # Replace hardcoded device IDs/GUIDs
        kql = re.sub(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            "<DEVICE_ID>",
            kql,
        )

        # Replace hardcoded timestamps
        kql = re.sub(r"datetime\([\"'][\d\-:TZ]+[\"']\)", "ago(<TIMESPAN>)", kql)

        # Replace hardcoded time values
        kql = re.sub(r"ago\(\d+[dhm]\)", "ago(<TIMESPAN>)", kql)

        # Ensure TimeGenerated uses placeholder
        if "TimeGenerated" in kql and "ago(<TIMESPAN>)" not in kql:
            kql = re.sub(
                r"(TimeGenerated\s*[><=]+\s*)ago\([^)]+\)", r"\1ago(<TIMESPAN>)", kql
            )

        # Clean excessive whitespace but preserve structure
        lines = [line.rstrip() for line in kql.split("\n") if line.strip()]
        kql = "\n".join(lines)

        # Remove trailing/leading whitespace
        kql = kql.strip()

        # Validate it's still valid KQL
        if not any(
            keyword in kql
            for keyword in ["where", "extend", "project", "summarize", "|"]
        ):
            return ""  # Not valid KQL

        return kql if len(kql) > 20 else ""
