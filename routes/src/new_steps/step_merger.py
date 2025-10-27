import os
import re
from typing import List, Dict, Tuple
from difflib import SequenceMatcher
from crewai import LLM, Agent, Task, Crew
from dotenv import load_dotenv

load_dotenv()


class InvestigationStepMerger:
    """
    Merges original template steps with newly generated steps
    Provides transparency on what was kept, added, or modified
    """

    def __init__(self):
        print("✅ Investigation Step Merger initialized")

        # Initialize LLM for step classification
        self._init_llm()

        # Step categories for logical ordering
        self.step_categories = {
            "scope_verification": 1,  # How many affected
            "user_verification": 2,  # VIP status, role
            "authentication": 3,  # Sign-in analysis
            "threat_intelligence": 4,  # IP/domain reputation
            "network_analysis": 5,  # Network flow, VPN
            "device_analysis": 6,  # Device compliance
            "identity_access": 7,  # Roles, permissions
            "behavioral_analysis": 8,  # Patterns, anomalies
            "data_analysis": 9,  # Logs, events
            "correlation": 10,  # Cross-reference
            "classification": 11,  # TP/FP determination
        }

    def _init_llm(self):
        """Initialize LLM for intelligent step classification"""
        gemini_key = os.getenv("GOOGLE_API_KEY")
        if gemini_key:
            self.llm = LLM(
                model="gemini/gemini-2.0-flash-exp",
                api_key=gemini_key,
                temperature=0.2,  # Very low for classification
            )
        else:
            ollama_model = os.getenv("OLLAMA_CHAT", "ollama/qwen2.5:3b")
            if not ollama_model.startswith("ollama/"):
                ollama_model = f"ollama/{ollama_model}"
            self.llm = LLM(
                model=ollama_model, base_url="http://localhost:11434", temperature=0.2
            )

    def merge_steps(
        self, original_steps: List[Dict], generated_steps: List[Dict], profile: Dict
    ) -> Tuple[List[Dict], Dict]:
        print(f"\nMerging investigation steps...")

        # ADD THIS DEBUG:
        print(f"DEBUG: Original steps received: {len(original_steps)}")
        print(f"DEBUG: Generated steps received: {len(generated_steps)}")

        if len(generated_steps) == 0:
            print("❌ WARNING: No generated steps! Using only original.")

        # Step 1: Filter out non-investigative steps from original
        investigative_original = self._filter_investigative_steps(original_steps)
        print(f"   Investigative (original): {len(investigative_original)} steps")

        # Step 2: Identify duplicates between original and generated
        duplicates, unique_generated = self._identify_duplicates(
            investigative_original, generated_steps
        )
        print(f"   Duplicates found: {len(duplicates)}")
        print(f"   Unique new steps: {len(unique_generated)}")

        # Step 3: Merge and deduplicate
        merged_steps = self._perform_merge(
            investigative_original, unique_generated, duplicates
        )

        # Step 4: Sort by logical order
        merged_steps = self._sort_by_investigation_flow(merged_steps, profile)

        # Step 5: Generate merge report
        merge_report = self._generate_merge_report(
            original_steps,
            investigative_original,
            generated_steps,
            unique_generated,
            duplicates,
            merged_steps,
        )

        print(f"   ✅ Final merged steps: {len(merged_steps)}")

        return merged_steps, merge_report

    def _filter_investigative_steps(self, steps: List[Dict]) -> List[Dict]:
        """Filter out non-investigative steps with hardcoded patterns + LLM"""
        investigative_steps = []

        # HARDCODED DECISION/CLOSURE PATTERNS (fast filter)
        decision_patterns = [
            r"user\s+confirm",
            r"if\s+user\s+(says|confirms)",
            r"treat\s+it\s+as",
            r"true\s+positive",
            r"false\s+positive",
            r"close\s+(it|incident)",
            r"final\s+confirmation",
            r"mark\s+as",
            r"classify\s+as",
            r"escalate\s+to",
            r"inform\s+(it\s+)?team",
            r"notify\s+user",
            r"document\s+the\s+steps",
            r"after\s+all.*investigation",
            r"reset\s+the\s+account",
            r"revoke.*mfa",
            r"block.*detected",
        ]

        for step in steps:
            step_name = step.get("step_name", "").lower()
            explanation = step.get("explanation", "").lower()
            combined = f"{step_name} {explanation}"

            # Quick hardcoded filter
            if any(re.search(pattern, combined) for pattern in decision_patterns):
                print(f"   ⏭️ Filtered (hardcoded): {step.get('step_name', '')[:60]}")
                continue

            # Has tool = investigative
            tool = step.get("tool", "").lower()
            if tool and tool in ["virustotal", "abuseipdb"]:
                investigative_steps.append(step)
                continue

            # Has data source = investigative
            data_source = step.get("data_source", "").lower()
            if data_source and data_source not in ["manual", ""]:
                investigative_steps.append(step)
                continue

            # Use LLM for ambiguous cases only
            if len(combined) > 50 and not self._is_non_investigative_step(combined):
                investigative_steps.append(step)

        return investigative_steps

    def _is_non_investigative_step(self, text: str) -> bool:
        """
        Use LLM to determine if step is remediation/closure instead of hardcoded patterns
        """
        # Quick keyword check first (fast path)
        obvious_keywords = [
            "reset the account",
            "revoke the mfa",
            "block the detected",
            "inform to it team",
            "inform it team",
            "reach out to",
            "temporary disable",
            "close it as",
            "track for the closer",
            "closer confirmation",
            "final confirmation",
            "document the steps taken",
            "after all the investigation",
            "if user confirms",
            "escalate to",
            "notify the user",
        ]

        if any(keyword in text for keyword in obvious_keywords):
            return True

        # Use LLM for ambiguous cases
        return self._llm_classify_step_type(text)

    def _llm_classify_step_type(self, step_text: str) -> bool:
        """
        Use LLM to classify if step is investigative or remediation/closure
        Returns True if NON-investigative (should be filtered out)
        """
        try:
            prompt = f"""Classify this SOC step as either INVESTIGATIVE or NON-INVESTIGATIVE.

    Step: {step_text[:300]}

    INVESTIGATIVE steps:
    - Query logs/data sources
    - Check external tools (VirusTotal, AbuseIPDB)
    - Analyze patterns, anomalies
    - Extract specific data points
    - Verify user/device/IP information

    NON-INVESTIGATIVE steps (filter these out):
    - Remediation actions (reset, revoke, block, disable)
    - Notification/escalation (inform, notify, reach out)
    - Documentation (document findings, track closure)
    - Classification decisions (mark as TP/FP, close incident)
    - User confirmation requests

    Answer with ONLY one word: INVESTIGATIVE or NON-INVESTIGATIVE"""

            agent = Agent(
                role="SOC Step Classifier",
                goal="Classify step type accurately",
                backstory="Expert at distinguishing investigation from remediation",
                llm=self.llm,
                verbose=False,
            )

            task = Task(
                description=prompt,
                expected_output="Single word: INVESTIGATIVE or NON-INVESTIGATIVE",
                agent=agent,
            )

            crew = Crew(agents=[agent], tasks=[task], verbose=False)
            result = str(crew.kickoff()).strip().upper()

            return "NON-INVESTIGATIVE" in result

        except Exception as e:
            print(f"   ⚠️ LLM classification failed: {str(e)[:100]}")
            # Default to keeping if classification fails
            return False

    def _identify_duplicates(
        self, original_steps: List[Dict], generated_steps: List[Dict]
    ) -> Tuple[List[Dict], List[Dict]]:
        """
        Identify duplicate steps between original and generated

        Returns:
            Tuple of (duplicates, unique_generated)
        """
        duplicates = []
        unique_generated = []

        for gen_step in generated_steps:
            gen_name = gen_step.get("step_name", "").lower()
            gen_exp = gen_step.get("explanation", "").lower()

            is_duplicate = False

            for orig_step in original_steps:
                orig_name = orig_step.get("step_name", "").lower()
                orig_exp = orig_step.get("explanation", "").lower()

                # Check similarity
                name_similarity = self._calculate_similarity(gen_name, orig_name)
                exp_similarity = self._calculate_similarity(gen_exp, orig_exp)

                # If names are very similar (>70%) or explanations are similar (>60%)
                if name_similarity > 0.7 or exp_similarity > 0.6:
                    is_duplicate = True
                    duplicates.append(
                        {
                            "original": orig_step,
                            "generated": gen_step,
                            "similarity": max(name_similarity, exp_similarity),
                        }
                    )
                    break

            if not is_duplicate:
                unique_generated.append(gen_step)

        return duplicates, unique_generated

    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity between two text strings"""
        return SequenceMatcher(None, text1, text2).ratio()

    def _perform_merge(
        self,
        original_steps: List[Dict],
        unique_generated: List[Dict],
        duplicates: List[Dict],
    ) -> List[Dict]:
        """
        Perform the actual merge

        Strategy:
        1. Keep original steps (they have proven value)
        2. For duplicates, keep original but note that generated version exists
        3. Add unique generated steps
        """
        merged = []

        # Add all original investigative steps with source tag
        for step in original_steps:
            step_copy = step.copy()
            step_copy["source"] = "original_template"
            step_copy["confidence"] = "HIGH"
            merged.append(step_copy)

        # Add unique generated steps with source tag
        for step in unique_generated:
            step_copy = step.copy()
            step_copy["source"] = "ai_generated"
            step_copy["confidence"] = step.get("priority", "MEDIUM")
            merged.append(step_copy)

        # Store duplicates info for reporting
        for dup in duplicates:
            # Find the original step in merged list and add note
            orig_name = dup["original"].get("step_name", "")
            for step in merged:
                if step.get("step_name") == orig_name:
                    step["has_alternative"] = True
                    step["alternative_explanation"] = dup["generated"].get(
                        "explanation", ""
                    )
                    break

        return merged

    def _sort_by_investigation_flow(
        self, steps: List[Dict], profile: Dict
    ) -> List[Dict]:
        """Sort steps by logical investigation flow"""

        def get_step_category_priority(step: Dict) -> int:
            """Determine step category and priority"""
            step_name = step.get("step_name", "").lower()
            explanation = step.get("explanation", "").lower()
            combined = f"{step_name} {explanation}"

            # Scope verification (count users, systems)
            if any(
                k in combined
                for k in ["count", "how many", "total", "scope", "impacted"]
            ):
                return self.step_categories["scope_verification"]

            # User verification (VIP, role)
            if any(
                k in combined for k in ["vip", "user list", "verify user", "check user"]
            ):
                return self.step_categories["user_verification"]

            # Authentication analysis
            if any(
                k in combined
                for k in ["sign-in", "login", "authentication", "credential"]
            ):
                return self.step_categories["authentication"]

            # Threat intelligence
            if any(
                k in combined
                for k in ["ip reputation", "virustotal", "threat intel", "abuseipdb"]
            ):
                return self.step_categories["threat_intelligence"]

            # Network analysis
            if any(
                k in combined for k in ["network", "vpn", "remote access", "connection"]
            ):
                return self.step_categories["network_analysis"]

            # Device analysis
            if any(k in combined for k in ["device", "endpoint", "compliance"]):
                return self.step_categories["device_analysis"]

            # Identity/Access
            if any(
                k in combined
                for k in ["role", "permission", "privilege", "mfa", "group"]
            ):
                return self.step_categories["identity_access"]

            # Behavioral analysis
            if any(
                k in combined for k in ["pattern", "behavior", "anomaly", "unusual"]
            ):
                return self.step_categories["behavioral_analysis"]

            # Data/Log analysis
            if any(k in combined for k in ["log", "event", "audit", "query"]):
                return self.step_categories["data_analysis"]

            # Correlation
            if any(k in combined for k in ["correlate", "cross-reference", "timeline"]):
                return self.step_categories["correlation"]

            # Classification
            if any(
                k in combined
                for k in ["classify", "determine", "true positive", "false positive"]
            ):
                return self.step_categories["classification"]

            # Default to data analysis
            return self.step_categories["data_analysis"]

        # Sort by category priority
        sorted_steps = sorted(steps, key=get_step_category_priority)

        return sorted_steps

    def _generate_merge_report(
        self,
        original_steps: List[Dict],
        investigative_original: List[Dict],
        generated_steps: List[Dict],
        unique_generated: List[Dict],
        duplicates: List[Dict],
        merged_steps: List[Dict],
    ) -> Dict:
        """Generate comprehensive merge report"""

        filtered_out = len(original_steps) - len(investigative_original)

        # Identify which steps were added
        added_steps = []
        for step in merged_steps:
            if step.get("source") == "ai_generated":
                added_steps.append(
                    {
                        "name": step.get("step_name"),
                        "priority": step.get("priority", "MEDIUM"),
                        "reason": self._determine_addition_reason(step),
                    }
                )

        report = {
            "original_total": len(original_steps),
            "original_investigative": len(investigative_original),
            "filtered_out": filtered_out,
            "generated_total": len(generated_steps),
            "duplicates_found": len(duplicates),
            "unique_generated": len(unique_generated),
            "final_total": len(merged_steps),
            "added_steps": added_steps,
            "duplicate_details": [
                {
                    "original_name": d["original"].get("step_name"),
                    "generated_name": d["generated"].get("step_name"),
                    "similarity": f"{d['similarity']*100:.1f}%",
                }
                for d in duplicates
            ],
        }

        return report

    def _determine_addition_reason(self, step: Dict) -> str:
        """Determine why a step was added"""
        step_name = step.get("step_name", "").lower()
        explanation = step.get("explanation", "").lower()
        combined = f"{step_name} {explanation}"

        if "mitre" in combined or "att&ck" in combined:
            return "MITRE ATT&CK coverage"
        elif "threat actor" in combined or "ttp" in combined:
            return "Threat actor TTP coverage"
        elif any(k in combined for k in ["role", "permission", "privilege"]):
            return "Identity/Access analysis"
        elif "mfa" in combined:
            return "MFA verification"
        elif any(k in combined for k in ["vpn", "remote"]):
            return "Remote access analysis"
        elif any(k in combined for k in ["password", "credential"]):
            return "Credential security"
        elif "timeline" in combined or "correlate" in combined:
            return "Event correlation"
        else:
            return "Enhanced coverage"

    def print_merge_report(self, report: Dict):
        """Print formatted merge report"""
        print(f"\n{'='*80}")
        print(f"📊 TEMPLATE MERGE REPORT")
        print(f"{'='*80}")
        print(f"\n📋 ORIGINAL TEMPLATE:")
        print(f"   Total steps: {report['original_total']}")
        print(f"   Investigative steps: {report['original_investigative']}")
        print(f"   Filtered out: {report['filtered_out']} (remediation/closure steps)")

        print(f"\n🤖 AI GENERATED:")
        print(f"   Total generated: {report['generated_total']}")
        print(f"   Duplicates: {report['duplicates_found']}")
        print(f"   Unique new steps: {report['unique_generated']}")

        print(f"\n✅ FINAL MERGED TEMPLATE:")
        print(f"   Total investigation steps: {report['final_total']}")
        print(f"   From original: {report['original_investigative']}")
        print(f"   Newly added: {len(report['added_steps'])}")

        if report["added_steps"]:
            print(f"\n🆕 NEWLY ADDED STEPS:")
            for i, step in enumerate(report["added_steps"], 1):
                print(f"   {i}. {step['name']}")
                print(f"      Priority: {step['priority']} | Reason: {step['reason']}")

        if report["duplicate_details"]:
            print(f"\n🔄 DUPLICATE STEPS (Kept from original):")
            for dup in report["duplicate_details"][:5]:  # Show first 5
                print(f"   • Original: {dup['original_name']}")
                print(f"     Similar to: {dup['generated_name']} ({dup['similarity']})")

        print(f"\n{'='*80}\n")
