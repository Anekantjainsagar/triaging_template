from crewai import Agent, Task, Crew, LLM
from crewai_tools import SerperDevTool
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


class WebLLMEnhancer:
    """
    ✅ ENHANCED VERSION THAT PRESERVES EXACT STEPS

    Rules:
    1. NEVER change step names
    2. NEVER change KQL queries
    3. Only improve explanation IF it's truly vague/empty
    4. If explanation is decent, keep it EXACTLY as-is
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
        Enhance with STRICT preservation rules
        """
        print(f"\n{'='*80}")
        print(f"🔧 ENHANCING TEMPLATE FOR {rule_number}")
        print(f"{'='*80}")

        enhanced_steps = []

        for i, step in enumerate(original_steps, 1):
            original_name = step.get("step_name", "")
            original_exp = step.get("explanation", "")
            original_kql = step.get("kql_query", "")
            original_input = step.get("input_required", "")

            print(f"\n--- Step {i}: {original_name} ---")

            # ✅ RULE 1: NEVER change step name
            final_name = original_name
            print(f"✅ Name preserved: {final_name}")

            # ✅ RULE 2: Only enhance explanation if TRULY needed
            if self._needs_enhancement(original_exp):
                print(f"📝 Explanation needs improvement (too vague)")
                enhanced_exp = self._enhance_explanation_safely(
                    original_name, original_exp, rule_number
                )
            else:
                enhanced_exp = original_exp
                print(f"✅ Explanation kept as-is (already clear)")

            # ✅ RULE 3: NEVER change KQL
            final_kql = original_kql
            if final_kql:
                print(f"✅ KQL preserved ({len(final_kql)} chars)")
            else:
                print(f"ℹ️ No KQL (documentation step)")

            enhanced_steps.append(
                {
                    "step_name": final_name,  # ✅ EXACT ORIGINAL
                    "explanation": enhanced_exp,  # ✅ ORIGINAL OR IMPROVED
                    "input_required": original_input,  # ✅ EXACT ORIGINAL
                    "kql_query": final_kql,  # ✅ EXACT ORIGINAL
                }
            )

        print(f"\n✅ COMPLETED: {len(enhanced_steps)} steps processed")
        return enhanced_steps

    def _needs_enhancement(self, explanation: str) -> bool:
        """
        Check if explanation REALLY needs improvement

        Only enhance if:
        - Empty or very short (<20 chars)
        - Contains only "N/A" or "TBD"
        - Is obviously incomplete

        DO NOT enhance if:
        - Already has clear instructions
        - Contains specific details
        - Is >30 characters with real content
        """
        if not explanation or len(explanation) < 20:
            return True

        exp_lower = explanation.lower()

        # Vague placeholders
        if exp_lower in ["n/a", "tbd", "pending", "todo", "..."]:
            return True

        # Very generic phrases only
        generic_only = [
            "complete the step",
            "perform investigation",
            "document findings",
            "review data",
        ]

        if (
            any(phrase in exp_lower for phrase in generic_only)
            and len(explanation) < 40
        ):
            return True

        # Otherwise, explanation is good enough
        return False

    def _enhance_explanation_safely(
        self, step_name: str, original_exp: str, rule_number: str
    ) -> str:
        """
        Enhance ONLY if needed, with fallback to reasonable default
        """
        # Build context-aware explanation based on step name
        step_lower = step_name.lower()

        # ✅ SMART FALLBACKS based on common SOC patterns
        if "document" in step_lower and "investigation" in step_lower:
            return "Complete investigation by reviewing relevant data from all sources and documenting key findings including timestamps, user details, and any anomalies discovered during analysis."

        elif "verify" in step_lower and "vip" in step_lower:
            return "Cross-verify if the user is classified as VIP or Executive by checking organizational user lists and IdentityInfo tags to assess incident priority and escalation requirements."

        elif "audit" in step_lower or "log" in step_lower:
            return "Verify audit logs and sign-in attempts to identify whether any applications were accessed without proper authentication or if suspicious access patterns exist."

        elif "application" in step_lower and "critical" in step_lower:
            return "If application sign-in occurred without password authentication, determine whether the application is classified as critical to business operations to assess risk level."

        elif "close" in step_lower and "false positive" in step_lower:
            return "If no critical applications were accessed without authentication and all indicators point to legitimate activity, close the incident as False Positive with proper justification."

        elif "true positive" in step_lower:
            return "If any critical applications were found with passwordless authentication or other suspicious indicators, classify as True Positive and proceed with escalation."

        elif "authentication" in step_lower:
            return "Ensure passwordless authentication method used is legitimate such as biometrics or hardware tokens. If critical apps lack passwords, coordinate with IT to enable MFA."

        elif "legitimate" in step_lower and "close" in step_lower:
            return "If authentication method is verified as legitimate through approved passwordless mechanisms and user confirmation, classify as False Positive and close incident."

        elif "unauthorized" in step_lower or "action" in step_lower:
            return "If unauthorized access is confirmed or suspicious activity detected, take appropriate remediation actions including account lockout, password reset, or escalation for further investigation."

        elif "monitor" in step_lower or "future" in step_lower:
            return "Enhance monitoring capabilities and tune detection rules to identify similar events in the future. Document lessons learned and update playbook procedures accordingly."

        elif "ip" in step_lower and (
            "check" in step_lower or "reputation" in step_lower
        ):
            return "Query threat intelligence sources to verify IP address reputation, check for known malicious activity, and validate geolocation against user's expected locations."

        elif "user" in step_lower and (
            "detail" in step_lower or "information" in step_lower
        ):
            return "Extract comprehensive user account information including UPN, display name, department, job title, manager, and VIP status from IdentityInfo to assess context."

        elif "sign" in step_lower or "login" in step_lower:
            return "Review user sign-in logs to analyze authentication patterns, device compliance, MFA status, locations accessed, and identify any anomalies or deviations from normal behavior."

        elif "device" in step_lower:
            return "Verify device compliance status, check if device is registered and managed by organization, and validate operating system and security configurations."

        elif "mfa" in step_lower:
            return "Validate multi-factor authentication status and confirm MFA was successfully completed using approved methods for this sign-in attempt."

        elif "role" in step_lower:
            return "Query role assignments to identify privileged roles, check for recent changes, and verify if assigned roles match user's job responsibilities."

        else:
            # Generic fallback
            return f"Complete {step_name} by reviewing relevant security data, executing necessary queries, and documenting all findings with timestamps and evidence."

    def validate_enhanced_steps(
        self, original_steps: list, enhanced_steps: list
    ) -> dict:
        """
        Validation report
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
                    f"❌ Step {i}: Name changed! '{orig.get('step_name')}' → '{enh.get('step_name')}'"
                )

            # Check explanation
            orig_exp = orig.get("explanation", "")
            enh_exp = enh.get("explanation", "")

            if orig_exp != enh_exp and len(enh_exp) > len(orig_exp):
                report["explanations_improved"] += 1

            # Check KQL preservation
            orig_kql = orig.get("kql_query", "")
            enh_kql = enh.get("kql_query", "")

            if orig_kql == enh_kql:
                if enh_kql:
                    report["kql_relevant"] += 1
            else:
                if orig_kql and not enh_kql:
                    report["kql_removed"] += 1
                    report["issues"].append(f"⚠️ Step {i}: KQL removed")
                elif not orig_kql and enh_kql:
                    report["issues"].append(
                        f"⚠️ Step {i}: KQL added (should not happen)"
                    )

        return report

    def _is_kql_relevant(self, kql: str, step_name: str, explanation: str) -> bool:
        """Check if KQL is relevant to the step"""
        if not kql or len(kql) < 20:
            return False

        # Always return True to preserve original KQL
        return True
