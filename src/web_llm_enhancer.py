from crewai import Agent, Task, Crew, LLM
from crewai_tools import SerperDevTool
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


class WebLLMEnhancer:
    """
    ✅ FIXED VERSION:
    1. DIRECTLY use original steps (no regeneration)
    2. Only enhance explanations (with prompt leak prevention)
    3. Validate KQL relevance to step
    """

    def __init__(self):
        self.llm = LLM(model="ollama/qwen2.5:0.5b", base_url="http://localhost:11434")

        try:
            self.web_search = SerperDevTool()
            print("✅ Web search available")
        except:
            self.web_search = None
            print("⚠️ Web search unavailable")

    def enhance_template_steps(self, rule_number: str, original_steps: list) -> list:
        """
        ✅ DIRECT enhancement - preserve ALL original data
        """
        print(f"\n{'='*80}")
        print(f"🔧 ENHANCING TEMPLATE FOR {rule_number}")
        print(f"{'='*80}")
        print(f"📥 Input: {len(original_steps)} original steps")

        start_time = time.time()
        enhanced_steps = []

        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_step = {
                executor.submit(self._enhance_single_step, step, i, rule_number): (
                    i,
                    step,
                )
                for i, step in enumerate(original_steps, 1)
            }

            results = {}
            for future in as_completed(future_to_step):
                step_num, original_step = future_to_step[future]
                try:
                    enhanced_step = future.result()
                    results[step_num] = enhanced_step
                    print(f"✅ Step {step_num}/{len(original_steps)}")
                except Exception as e:
                    print(f"⚠️ Step {step_num} enhancement failed, using original")
                    results[step_num] = original_step

            enhanced_steps = [results[i] for i in sorted(results.keys())]

        elapsed = time.time() - start_time
        print(f"\n✅ ENHANCED {len(enhanced_steps)} steps in {elapsed:.1f}s\n")

        return enhanced_steps

    def _enhance_single_step(self, step: dict, step_num: int, rule_number: str) -> dict:
        """
        ✅ FIXED: Preserve original, only enhance explanation + validate KQL
        """
        # ✅ PRESERVE EVERYTHING ORIGINAL
        original_name = step.get("step_name", f"Step {step_num}")
        original_exp = step.get("explanation", "")
        original_kql = step.get("kql_query", "")
        original_input = step.get("input_required", "")

        # 1. ✅ KEEP ORIGINAL NAME (NEVER CHANGE)
        final_name = original_name

        # 2. ✅ ENHANCE EXPLANATION ONLY IF TOO SHORT OR MESSY
        if len(original_exp) < 30 or self._has_prompt_artifacts(original_exp):
            enhanced_exp = self._safe_enhance_explanation(
                original_name, original_exp, rule_number
            )
        else:
            # Keep original if it's already good
            enhanced_exp = self._clean_prompt_leaks(original_exp)

        # 3. ✅ VALIDATE KQL RELEVANCE
        if original_kql:
            cleaned_kql = self._deep_clean_kql(original_kql)

            # Validate relevance
            if not self._is_kql_relevant(cleaned_kql, original_name, enhanced_exp):
                print(f"   ⚠️ Step {step_num}: KQL not relevant, removing")
                cleaned_kql = ""
        else:
            cleaned_kql = ""

        return {
            "step_name": final_name,  # ✅ ORIGINAL PRESERVED
            "explanation": enhanced_exp,  # ✅ ENHANCED OR CLEANED
            "input_required": original_input,  # ✅ ORIGINAL PRESERVED
            "kql_query": cleaned_kql,  # ✅ VALIDATED
        }

    def _has_prompt_artifacts(self, text: str) -> bool:
        """Check if text contains prompt leakage"""
        artifacts = [
            "generate",
            "create",
            "write",
            "provide",
            "give me",
            "you are",
            "your task",
            "instructions:",
            "prompt:",
            "###",
            "---",
            "step 1:",
            "step 2:",
            "final answer",
            "output format",
        ]
        text_lower = text.lower()
        return any(artifact in text_lower for artifact in artifacts)

    def _clean_prompt_leaks(self, text: str) -> str:
        """Remove prompt artifacts from text"""
        if not text:
            return text

        # Remove common prompt patterns
        text = re.sub(
            r"^(generate|create|write|provide).*?:", "", text, flags=re.IGNORECASE
        )
        text = re.sub(
            r"(you are|your task|instructions).*?\n", "", text, flags=re.IGNORECASE
        )
        text = re.sub(r"###.*?\n", "", text)
        text = re.sub(r"---+", "", text)
        text = re.sub(r"final answer:", "", text, flags=re.IGNORECASE)

        # Remove markdown artifacts
        text = re.sub(r"\*\*+", "", text)
        text = re.sub(r"#+\s*", "", text)
        text = re.sub(r"`+", "", text)

        # Clean whitespace
        text = " ".join(text.split())

        return text.strip()

    def _safe_enhance_explanation(
        self, step_name: str, original_exp: str, rule_number: str
    ) -> str:
        """
        ✅ SAFE enhancement with strict output validation
        """
        # If original is decent, just clean it
        if len(original_exp) > 40 and not self._has_prompt_artifacts(original_exp):
            return self._clean_prompt_leaks(original_exp)

        # Generate new explanation with strict constraints
        prompt = f"""Write ONE clear sentence (25-40 words) explaining this security investigation step.

STEP NAME: {step_name}
RULE: {rule_number}
ORIGINAL: {original_exp if original_exp else 'Not provided'}

STRICT RULES:
1. Write ONLY the explanation sentence
2. Start with action verb (Verify, Check, Review, Query, etc.)
3. Explain WHAT to investigate
4. No markdown, no formatting, no headers
5. 25-40 words maximum
6. Professional security investigation tone

EXAMPLE OUTPUT:
"Query Azure AD audit logs for privileged role assignments within last 7 days to identify high-risk roles like Global Admin and document assigned user, timestamp, and initiator."

YOUR OUTPUT (explanation only, no preamble):"""

        try:
            agent = Agent(
                role="Security Documentation Writer",
                goal="Write clear security investigation steps",
                backstory="Expert security analyst with 10+ years documentation experience",
                llm=self.llm,
                verbose=False,
            )

            task = Task(
                description=prompt,
                expected_output="A single 25-40 word explanation sentence",
                agent=agent,
            )

            crew = Crew(agents=[agent], tasks=[task], verbose=False)
            result = str(crew.kickoff()).strip()

            # ✅ AGGRESSIVE CLEANING
            cleaned = self._clean_prompt_leaks(result)

            # Validate output quality
            word_count = len(cleaned.split())

            # If output is garbage, use fallback
            if (
                word_count < 10
                or word_count > 60
                or self._has_prompt_artifacts(cleaned)
            ):
                return self._generate_fallback_explanation(step_name)

            return cleaned

        except Exception as e:
            print(f"   ⚠️ Enhancement failed: {str(e)}")
            return self._generate_fallback_explanation(step_name)

    def _generate_fallback_explanation(self, step_name: str) -> str:
        """Generate safe fallback explanation"""
        step_lower = step_name.lower()

        if "ip" in step_lower and "reputation" in step_lower:
            return "Verify IP address reputation using threat intelligence sources to identify malicious activity or geolocation anomalies."
        elif "user" in step_lower and "detail" in step_lower:
            return "Review user account details including job title, department, and VIP status to assess incident impact."
        elif "mfa" in step_lower:
            return "Check multi-factor authentication status and verify successful MFA completion for the sign-in attempt."
        elif "device" in step_lower:
            return "Validate device compliance status and verify if the device is registered and managed by the organization."
        elif "role" in step_lower:
            return "Query role assignments and permissions to identify high-risk privileged roles and recent changes."
        elif "log" in step_lower or "query" in step_lower:
            return "Execute KQL query against security logs to extract relevant incident data and identify patterns."
        elif "classification" in step_lower or "final" in step_lower:
            return "Classify incident as True Positive, False Positive, or Benign Positive based on investigation findings."
        else:
            return f"Complete {step_name} investigation by reviewing relevant data and documenting findings."

    def _is_kql_relevant(self, kql: str, step_name: str, explanation: str) -> bool:
        """
        ✅ NEW: Validate KQL query relevance to the step
        """
        if not kql or len(kql) < 20:
            return False

        # Extract key terms from step
        step_terms = set(re.findall(r"\b\w+\b", f"{step_name} {explanation}".lower()))

        # KQL relevance indicators
        kql_lower = kql.lower()

        # Map step types to required KQL elements
        relevance_checks = {
            "ip": ["ipaddress", "networkip", "sourceip"],
            "user": ["userprincipalname", "accountupn", "user"],
            "role": ["operationname", "role", "member", "auditlogs"],
            "sign": ["signinlogs", "authentication", "login"],
            "device": ["devicedetail", "deviceid", "compliant"],
            "mfa": ["mfa", "authenticationdetails", "authmethod"],
            "threat": ["threatintelligence", "indicator"],
            "location": ["locationdetails", "city", "country"],
        }

        # Check if KQL contains relevant terms for this step
        for term, kql_elements in relevance_checks.items():
            if term in step_terms:
                if any(element in kql_lower for element in kql_elements):
                    return True

        # If no specific match, check for generic query validity
        has_table = any(
            table in kql_lower
            for table in [
                "signinlogs",
                "auditlogs",
                "identityinfo",
                "threatintelligence",
            ]
        )
        has_operator = any(
            op in kql_lower for op in ["where", "extend", "project", "summarize"]
        )

        if has_table and has_operator:
            # Generic query is acceptable
            return True

        return False

    def validate_enhanced_steps(self, original_steps: list, enhanced_steps: list) -> dict:
        """
        ✅ Comprehensive validation report
        """
        report = {
            "total_original": len(original_steps),
            "total_enhanced": len(enhanced_steps),
            "names_preserved": 0,
            "explanations_improved": 0,
            "kql_relevant": 0,
            "kql_removed": 0,
            "prompt_leaks_found": 0,
            "issues": [],
        }

        for i, (orig, enh) in enumerate(zip(original_steps, enhanced_steps), 1):
            # Check name preservation
            if orig.get("step_name") == enh.get("step_name"):
                report["names_preserved"] += 1
            else:
                report["issues"].append(
                    f"Step {i}: Name changed from '{orig.get('step_name')}' to '{enh.get('step_name')}'"
                )

            # Check explanation improvement
            orig_exp_len = len(orig.get("explanation", ""))
            enh_exp_len = len(enh.get("explanation", ""))

            if enh_exp_len > orig_exp_len and not self._has_prompt_artifacts(
                enh.get("explanation", "")
            ):
                report["explanations_improved"] += 1
            elif self._has_prompt_artifacts(enh.get("explanation", "")):
                report["prompt_leaks_found"] += 1
                report["issues"].append(f"Step {i}: Prompt leak detected in explanation")

            # Check KQL relevance
            if enh.get("kql_query"):
                if self._is_kql_relevant(
                    enh.get("kql_query"), enh.get("step_name"), enh.get("explanation")
                ):
                    report["kql_relevant"] += 1
                else:
                    report["kql_removed"] += 1
                    report["issues"].append(
                        f"Step {i}: KQL not relevant, should be removed"
                    )

        return report


    def print_validation_report(self, report: dict):
        """Print formatted validation report"""
        print("\n" + "=" * 80)
        print("VALIDATION REPORT")
        print("=" * 80)
        print(f"Total Steps: {report['total_enhanced']}/{report['total_original']}")
        print(f"✅ Names Preserved: {report['names_preserved']}/{report['total_original']}")
        print(f"📝 Explanations Improved: {report['explanations_improved']}")
        print(f"🔍 KQL Queries Relevant: {report['kql_relevant']}")
        print(f"🗑️ KQL Queries Removed: {report['kql_removed']}")
        print(f"⚠️ Prompt Leaks Found: {report['prompt_leaks_found']}")

        if report["issues"]:
            print(f"\n⚠️ ISSUES FOUND ({len(report['issues'])}):")
            for issue in report["issues"][:5]:  # Show first 5
                print(f"  • {issue}")
            if len(report["issues"]) > 5:
                print(f"  ... and {len(report['issues']) - 5} more")
        else:
            print("\n✅ NO ISSUES FOUND")

        print("=" * 80 + "\n")

    def _deep_clean_kql(self, kql: str) -> str:
        """
        ✅ DEEP CLEANING: Remove ALL messy data
        """
        if not kql or kql.strip().upper() in ["N/A", "NA", ""]:
            return ""

        # Remove markdown
        kql = re.sub(r"```[a-z]*\s*\n?", "", kql)
        kql = re.sub(r"\n?```", "", kql)

        # Remove excessive comments
        lines = kql.split("\n")
        cleaned_lines = []
        for line in lines:
            if line.strip().startswith("//"):
                if len(line.strip()) < 60:
                    cleaned_lines.append(line)
            else:
                cleaned_lines.append(line)
        kql = "\n".join(cleaned_lines)

        # Replace hardcoded values with placeholders
        kql = re.sub(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "<USER_EMAIL>", kql
        )
        kql = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "<IP_ADDRESS>", kql)
        kql = re.sub(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            "<DEVICE_ID>",
            kql,
        )
        kql = re.sub(r"datetime\([\"'][\d\-:TZ]+[\"']\)", "ago(<TIMESPAN>)", kql)
        kql = re.sub(r"ago\(\d+[dhm]\)", "ago(<TIMESPAN>)", kql)

        # Clean whitespace
        lines = [line.rstrip() for line in kql.split("\n") if line.strip()]
        kql = "\n".join(lines)
        kql = kql.strip()

        # Final validation
        if not any(
            keyword in kql
            for keyword in ["where", "extend", "project", "summarize", "|"]
        ):
            return ""

        return kql if len(kql) > 20 else ""
