"""
Optimized Web LLM Enhancer - Uses model from .env
"""

from crewai import LLM, Agent, Task, Crew
from crewai_tools import SerperDevTool
import re
import os
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed

# ✅ LOAD ENVIRONMENT VARIABLES
load_dotenv()


class WebLLMEnhancer:
    """
    Fast, reliable enhancer with parallel processing
    """

    def __init__(self):
        # ✅ USE MODEL FROM .ENV
        ollama_model = os.getenv("OLLAMA_CHAT", "ollama/qwen2.5:3b")

        if not ollama_model.startswith("ollama/"):
            ollama_model = f"ollama/{ollama_model}"

        print(f"🤖 Enhancer using LLM: {ollama_model}")

        self.llm = LLM(
            model=ollama_model,
            base_url="http://localhost:11434",
            timeout=120,
        )

        try:
            self.web_search = SerperDevTool()
            self.has_web = True
            print("✅ Web search enabled")
        except:
            self.web_search = None
            self.has_web = False
            print("⚠️ Web search unavailable")

    def enhance_template_steps(self, rule_number: str, original_steps: list) -> list:
        """
        Enhanced with PARALLEL processing for speed
        """
        print(f"\n{'='*80}")
        print(f"🧠 FAST ENHANCEMENT FOR {rule_number}")
        print(f"{'='*80}\n")

        rule_context = self._get_rule_context_fast(rule_number)

        enhanced_steps = self._enhance_steps_parallel(
            original_steps, rule_number, rule_context
        )

        validation = self.validate_enhanced_steps(original_steps, enhanced_steps)
        self._print_validation_report(validation)

        return enhanced_steps

    def _get_rule_context_fast(self, rule_number: str) -> str:
        """Quick context - no web search needed"""
        if "016" in rule_number or "privileged" in rule_number.lower():
            return "Identity and privileged access monitoring"
        elif "role" in rule_number.lower():
            return "Role assignment and permission changes"
        else:
            return "Security alert investigation"

    def _enhance_steps_parallel(
        self, original_steps: list, rule_number: str, rule_context: str
    ) -> list:
        """Process steps in parallel"""

        enhanced_steps = [None] * len(original_steps)

        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_index = {
                executor.submit(
                    self._enhance_single_step_fast,
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
                    result = future.result(timeout=150)
                    enhanced_steps[index] = result
                    print(f"✅ Enhanced step {index + 1}")
                except Exception as e:
                    print(f"⚠️ Step {index + 1} failed: {str(e)[:50]}")
                    enhanced_steps[index] = original_steps[index]

        return enhanced_steps

    def _enhance_single_step_fast(
        self,
        step_num: int,
        original_step: dict,
        rule_number: str,
        rule_context: str,
    ) -> dict:
        """Enhance single step quickly"""

        original_name = original_step.get("step_name", "")
        original_explanation = original_step.get("explanation", "")

        # 1. Enhance step name if needed
        if self._is_good_step_name(original_name):
            enhanced_name = self._clean_step_name(original_name)
        else:
            enhanced_name = self._enhance_step_name_fast(
                original_name, original_explanation, step_num
            )

        # 2. Keep original explanation if good
        if len(original_explanation) > 50 and not self._is_vague(original_explanation):
            enhanced_explanation = original_explanation
        else:
            enhanced_explanation = self._enhance_explanation_fast(
                enhanced_name, original_explanation
            )

        return {
            "step_name": enhanced_name,
            "explanation": enhanced_explanation,
            "input_required": original_step.get("input_required", ""),
            "kql_query": self._clean_kql(original_step.get("kql_query", "")),
        }

    def _enhance_step_name_fast(
        self, original_name: str, explanation: str, step_num: int
    ) -> str:
        """Quick step name enhancement"""

        # SHORT prompt
        prompt = f"""Create SOC step name.

Current: {original_name[:80]}
Context: {explanation[:80]}

Rules:
- Start with verb: Verify/Analyze/Check/Review
- 4-8 words max
- Clear and specific

Output name only:"""

        try:
            result = self._quick_llm_call(prompt, max_tokens=30)
            name = self._aggressive_clean(result)

            if 5 <= len(name) <= 100 and self._is_clean_name(name):
                return name

        except:
            pass

        return self._clean_step_name(original_name) or f"Investigation Step {step_num}"

    def _enhance_explanation_fast(self, step_name: str, original: str) -> str:
        """Quick explanation enhancement"""

        if len(original) > 50:
            return original

        prompt = f"""Write SOC instruction for: {step_name}

Be concise:
- What to investigate
- Which logs/sources  
- What to check
- 2-3 sentences max

Output instruction only:"""

        try:
            result = self._quick_llm_call(prompt, max_tokens=80)
            explanation = self._aggressive_clean(result)
            return explanation if len(explanation) > 20 else original
        except:
            return original or "Complete investigation and document findings."

    def _quick_llm_call(self, prompt: str, max_tokens: int = 100) -> str:
        """Quick LLM call with timeout"""

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

    def _aggressive_clean(self, text: str) -> str:
        """Aggressively remove ALL LLM artifacts"""

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
            "successfully",
        ]

        text_lower = text.lower()
        for artifact in artifacts:
            if artifact.lower() in text_lower:
                parts = text.split(artifact, 1)
                text = parts[-1] if len(parts) > 1 else parts[0]

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

    def _clean_kql(self, kql: str) -> str:
        """Clean KQL query"""
        if not kql:
            return ""

        # Remove markdown
        kql = re.sub(r"```kql\s*", "", kql)
        kql = re.sub(r"```\s*", "", kql)

        # Extract only query part
        tables = [
            "SigninLogs",
            "AuditLogs",
            "IdentityInfo",
            "ThreatIntelligenceIndicator",
        ]
        for table in tables:
            if table in kql:
                start = kql.find(table)
                kql = kql[start:]
                break

        # Remove explanations
        lines = []
        for line in kql.split("\n"):
            line = line.strip()
            if not line:
                continue
            if any(stop in line for stop in ["This query", "Explanation:", "Note:"]):
                break
            lines.append(line)

        return "\n".join(lines).strip()

    def _is_clean_name(self, name: str) -> bool:
        """Check if name is clean (no artifacts)"""
        name_lower = name.lower()

        artifacts = [
            "i must",
            "job depends",
            "final answer",
            "task completed",
            "ready for submission",
            "my final response",
            "---",
            "successfully",
        ]

        return not any(artifact in name_lower for artifact in artifacts)

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
        ]

        name_lower = name.lower()
        starts_with_verb = any(name_lower.startswith(verb) for verb in action_verbs)

        # Reject if too long or has artifacts
        if len(name) > 80:
            return False

        if not self._is_clean_name(name):
            return False

        return starts_with_verb and len(name.split()) >= 2

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

        vague = [
            "n/a",
            "tbd",
            "complete the step",
            "document findings",
            "gather details",
        ]
        return any(phrase in text.lower() for phrase in vague)

    def validate_enhanced_steps(
        self, original_steps: list, enhanced_steps: list
    ) -> dict:
        """Validate enhancement quality"""

        report = {
            "total_original": len(original_steps),
            "total_enhanced": len(enhanced_steps),
            "names_improved": 0,
            "names_kept": 0,
            "explanations_enhanced": 0,
            "explanations_kept": 0,
            "kql_cleaned": 0,
            "kql_removed": 0,
            "issues": [],
        }

        for i, (orig, enh) in enumerate(zip(original_steps, enhanced_steps), 1):
            orig_name = orig.get("step_name", "")
            enh_name = enh.get("step_name", "")

            # Check name changes
            if orig_name != enh_name:
                if self._is_good_step_name(enh_name):
                    report["names_improved"] += 1
                else:
                    report["names_kept"] += 1
                    report["issues"].append(f"Step {i}: Name unchanged")
            else:
                report["names_kept"] += 1

            # Check explanations
            orig_exp = orig.get("explanation", "")
            enh_exp = enh.get("explanation", "")

            if orig_exp != enh_exp:
                report["explanations_enhanced"] += 1
            else:
                report["explanations_kept"] += 1

            # Check KQL
            orig_kql = orig.get("kql_query", "")
            enh_kql = enh.get("kql_query", "")

            if orig_kql and enh_kql:
                if len(enh_kql) < len(orig_kql):
                    report["kql_cleaned"] += 1

        return report

    def _print_validation_report(self, report: dict):
        """Print validation report"""
        print(f"\n{'='*80}")
        print(f"📊 VALIDATION REPORT")
        print(f"{'='*80}")
        print(f"✅ Names Improved: {report['names_improved']}")
        print(f"✅ Names Kept: {report['names_kept']}")
        print(f"📝 Explanations Enhanced: {report['explanations_enhanced']}")
        print(f"📝 Explanations Kept: {report['explanations_kept']}")
        print(f"🧹 KQL Cleaned: {report['kql_cleaned']}")

        if report["issues"]:
            print(f"\n⚠️ Issues: {len(report['issues'])}")
        else:
            print(f"\n✅ No Issues")

        print(f"{'='*80}\n")
