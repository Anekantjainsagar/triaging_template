from crewai import Agent, Task, Crew, LLM
from crewai_tools import SerperDevTool
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


class WebLLMEnhancer:
    """
    âœ… ULTRA-STRICT ENHANCER - NEVER CHANGES STEP NAMES

    RULES:
    1. Step names are 100% PRESERVED from template - ZERO changes
    2. Only improve explanations if truly empty/vague
    3. CLEAN KQL queries - remove all explanations and junk
    """

    def __init__(self):
        self.llm = LLM(model="ollama/qwen2.5:0.5b", base_url="http://localhost:11434")

        try:
            self.web_search = SerperDevTool()
        except:
            self.web_search = None

    def enhance_template_steps(self, rule_number: str, original_steps: list) -> list:
        """
        âœ… PRESERVE EVERYTHING - Only enhance if absolutely needed
        """
        print(f"\n{'='*80}")
        print(f"ðŸ”§ PROCESSING TEMPLATE FOR {rule_number}")
        print(f"STRICT MODE: Preserving ALL original data")
        print(f"{'='*80}")

        enhanced_steps = []

        for i, step in enumerate(original_steps, 1):
            # âœ… GET ORIGINAL VALUES
            original_name = step.get("step_name", "")
            original_exp = step.get("explanation", "")
            original_kql = step.get("kql_query", "")
            original_input = step.get("input_required", "")

            print(f"\n{'='*60}")
            print(f"Step {i}/{len(original_steps)}")
            print(f"{'='*60}")
            print(f"Original Name: {original_name}")

            # âœ… RULE 1: NEVER CHANGE STEP NAME - 100% PRESERVED
            final_name = original_name

            # âœ… RULE 2: Keep explanation as-is OR improve only if empty
            if not original_exp or len(original_exp) < 15:
                print(f"ðŸ“ Explanation empty/too short, using smart fallback")
                enhanced_exp = self._get_smart_fallback(original_name)
            else:
                print(f"âœ… Explanation preserved (length: {len(original_exp)})")
                enhanced_exp = original_exp

            # âœ… RULE 3: CLEAN KQL - Remove explanations, keep only query
            if original_kql:
                final_kql = self._deep_clean_kql(original_kql)
                if final_kql:
                    print(
                        f"âœ… KQL cleaned ({len(original_kql)} â†’ {len(final_kql)} chars)"
                    )
                else:
                    print(f"âš ï¸ KQL removed (couldn't extract valid query)")
            else:
                final_kql = ""
                print(f"â„¹ï¸ No KQL (manual investigation step)")

            # âœ… STORE WITH ZERO MODIFICATIONS
            enhanced_steps.append(
                {
                    "step_name": final_name,  # âœ… 100% ORIGINAL
                    "explanation": enhanced_exp,  # âœ… ORIGINAL or smart fallback
                    "input_required": original_input,  # âœ… 100% ORIGINAL
                    "kql_query": final_kql,  # âœ… CLEANED
                }
            )

            print(f"âœ… Step {i} processed")

        print(f"\n{'='*80}")
        print(f"âœ… COMPLETED: {len(enhanced_steps)} steps")
        print(f"{'='*80}\n")

        return enhanced_steps

    def _deep_clean_kql(self, kql: str) -> str:
        """
        âœ… AGGRESSIVE KQL CLEANING - Extract ONLY the query

        Remove:
        - Explanations (e.g., "To generate...", "Here is...", "### Explanation")
        - Markdown formatting
        - Comments that are too long
        - Everything after "###" or "Explanation:" or "This query"
        """
        if not kql or kql.strip().upper() in ["N/A", "NA", ""]:
            return ""

        print(f"\n   ðŸ§¹ Cleaning KQL (original: {len(kql)} chars)...")

        # âœ… STEP 1: Remove everything BEFORE the actual query
        # Remove introductory text like "To generate a KQL query..."
        kql = re.sub(
            r"^.*?(SigninLogs|AuditLogs|IdentityInfo|ThreatIntelligenceIndicator|SecurityIncident|DeviceInfo)",
            r"\1",
            kql,
            flags=re.DOTALL | re.IGNORECASE,
        )

        # âœ… STEP 2: Remove everything AFTER the query
        # Stop at "###", "Explanation:", "This query", etc.
        stop_patterns = [
            r"###.*",
            r"Explanation:.*",
            r"This query.*",
            r"This KQL query.*",
            r"\*\*\* Explanation:.*",
            r"I now.*",
            r"The key elements.*",
            r"Since this is.*",
            r"You can adjust.*",
        ]

        for pattern in stop_patterns:
            kql = re.sub(pattern, "", kql, flags=re.DOTALL | re.IGNORECASE)

        # âœ… STEP 3: Remove markdown formatting
        kql = re.sub(r"```[a-z]*\s*\n?", "", kql)
        kql = re.sub(r"\n?```", "", kql)
        kql = re.sub(r"\*\*", "", kql)
        kql = re.sub(r"`", "", kql)

        # âœ… STEP 4: Remove long explanatory comments (keep short ones)
        lines = kql.split("\n")
        cleaned_lines = []

        for line in lines:
            stripped = line.strip()

            # Skip empty lines at start
            if not stripped and not cleaned_lines:
                continue

            # Keep KQL lines (contain |, where, extend, etc.)
            if any(
                keyword in stripped.lower()
                for keyword in ["|", "where", "extend", "project", "summarize", "join"]
            ):
                cleaned_lines.append(line)

            # Keep SHORT comments (< 60 chars)
            elif stripped.startswith("//") and len(stripped) < 60:
                cleaned_lines.append(line)

            # Keep lines that look like KQL operators
            elif stripped.startswith(
                (
                    "SigninLogs",
                    "AuditLogs",
                    "IdentityInfo",
                    "ThreatIntelligenceIndicator",
                    "SecurityIncident",
                    "DeviceInfo",
                )
            ):
                cleaned_lines.append(line)

        kql = "\n".join(cleaned_lines)

        # âœ… STEP 5: Remove trailing explanatory text
        # If there's a blank line followed by text, remove everything after
        parts = kql.split("\n\n")
        if len(parts) > 1:
            # Keep only the first part (the query)
            kql = parts[0]

        # âœ… STEP 6: Clean whitespace
        lines = [line.rstrip() for line in kql.split("\n") if line.strip()]
        kql = "\n".join(lines)
        kql = kql.strip()

        # âœ… STEP 7: Validate it's actually a KQL query
        if not any(
            keyword in kql
            for keyword in [
                "|",
                "where",
                "extend",
                "project",
                "summarize",
                "SigninLogs",
                "AuditLogs",
            ]
        ):
            print(f"   âš ï¸ Not a valid KQL query after cleaning")
            return ""

        # âœ… STEP 8: Final length check
        if len(kql) < 20:
            print(f"   âš ï¸ Query too short after cleaning")
            return ""

        print(f"   âœ… Cleaned to {len(kql)} chars")
        return kql

    def _get_smart_fallback(self, step_name: str) -> str:
        """
        Smart fallback explanations based on EXACT step name patterns
        """
        name_lower = step_name.lower()

        # âœ… EXACT MATCHES FIRST (from your template)
        if (
            "provide the username" in name_lower
            or "username which are involved" in name_lower
        ):
            return "Provide the username which are involved in the incident"

        elif "vip" in name_lower and "user" in name_lower:
            return "Cross verify if the user is VIP or not - with the list (Shared by Arcutis)"

        elif "run the kql" in name_lower or "run kql query" in name_lower:
            return "Verify the logs whether there is any Application without sign in attempts"

        elif (
            "collect the basic info" in name_lower
            or "username, app displayname" in name_lower
        ):
            return "If there is any application sign in without password check whether the application is critical or not"

        elif "user confirmation" in name_lower and "yes" in name_lower:
            return "If no critical applications close the incident as false positive"

        elif "user confirmation" in name_lower and "no" in name_lower:
            return "If any critical application found consider as True Positive"

        elif "ad logs" in name_lower or "sign in logs" in name_lower:
            return "Ensure that the passwordless authentication method used is legitimate (e.g., biometrics, hardware tokens). If there is critical applications without password then reach out IT team to set password by enabling MFA"

        elif "user account details" in name_lower:
            return "If the authentication is Legitimate then consider it as False Positive and close the incident"

        elif "inform to it team" in name_lower or "inform it team" in name_lower:
            return "If unauthorized, take appropriate action such as locking accounts, resetting passwords, or investigating further."

        elif "track" in name_lower and "closer" in name_lower:
            return "Enhance monitoring to detect similar events in the future"

        # âœ… GENERIC PATTERNS (if no exact match)
        elif "ip" in name_lower:
            return "Verify IP address reputation and check for known malicious activity using threat intelligence sources."

        elif "user" in name_lower and "detail" in name_lower:
            return "Extract comprehensive user account information including UPN, department, job title, and VIP status."

        elif "sign" in name_lower or "authentication" in name_lower:
            return "Review user sign-in logs to analyze authentication patterns, device compliance, and MFA status."

        elif "device" in name_lower:
            return "Verify device compliance status and check if device is registered and managed by organization."

        elif "mfa" in name_lower:
            return "Validate multi-factor authentication status and confirm MFA completion using approved methods."

        elif "role" in name_lower:
            return "Query role assignments to identify privileged roles and verify if roles match job responsibilities."

        else:
            # Last resort fallback
            return f"Complete {step_name} by reviewing relevant security data and documenting all findings."

    def validate_enhanced_steps(
        self, original_steps: list, enhanced_steps: list
    ) -> dict:
        """
        âœ… STRICT VALIDATION - Check for ANY changes
        """
        report = {
            "total_original": len(original_steps),
            "total_enhanced": len(enhanced_steps),
            "names_preserved": 0,
            "names_changed": 0,
            "explanations_kept": 0,
            "explanations_improved": 0,
            "kql_preserved": 0,
            "kql_cleaned": 0,
            "kql_removed": 0,
            "issues": [],
        }

        for i, (orig, enh) in enumerate(zip(original_steps, enhanced_steps), 1):
            # âœ… CHECK 1: Name preservation (MUST BE 100%)
            orig_name = orig.get("step_name", "")
            enh_name = enh.get("step_name", "")

            if orig_name == enh_name:
                report["names_preserved"] += 1
            else:
                report["names_changed"] += 1
                report["issues"].append(
                    f"âŒ Step {i}: Name CHANGED!\n"
                    f"   Original: '{orig_name}'\n"
                    f"   Enhanced: '{enh_name}'"
                )

            # âœ… CHECK 2: Explanation
            orig_exp = orig.get("explanation", "")
            enh_exp = enh.get("explanation", "")

            if orig_exp == enh_exp:
                report["explanations_kept"] += 1
            else:
                report["explanations_improved"] += 1

            # âœ… CHECK 3: KQL preservation/cleaning
            orig_kql = orig.get("kql_query", "")
            enh_kql = enh.get("kql_query", "")

            if orig_kql == enh_kql:
                report["kql_preserved"] += 1
            elif orig_kql and enh_kql:
                report["kql_cleaned"] += 1
            elif orig_kql and not enh_kql:
                report["kql_removed"] += 1

        return report

    def print_validation_report(self, report: dict):
        """Print detailed validation"""
        print("\n" + "=" * 80)
        print("VALIDATION REPORT")
        print("=" * 80)
        print(f"Total Steps: {report['total_enhanced']}/{report['total_original']}")
        print(f"\nðŸ“› STEP NAMES:")
        print(
            f"   âœ… Preserved: {report['names_preserved']}/{report['total_original']}"
        )
        print(f"   âŒ Changed: {report['names_changed']}/{report['total_original']}")

        print(f"\nðŸ“ EXPLANATIONS:")
        print(f"   âœ… Kept Original: {report['explanations_kept']}")
        print(f"   ðŸ“ Improved: {report['explanations_improved']}")

        print(f"\nðŸ“Š KQL QUERIES:")
        print(f"   âœ… Preserved: {report['kql_preserved']}")
        print(f"   ðŸ§¹ Cleaned: {report['kql_cleaned']}")
        print(f"   ðŸ—‘ï¸ Removed: {report['kql_removed']}")

        if report["issues"]:
            print(f"\n{'='*80}")
            print(f"âŒ CRITICAL ISSUES FOUND: {len(report['issues'])}")
            print(f"{'='*80}")
            for issue in report["issues"]:
                print(f"\n{issue}")
        else:
            print(f"\n{'='*80}")
            print("âœ… PERFECT - ALL STEP NAMES PRESERVED!")
            print(f"{'='*80}")

        print("\n")

    def _is_kql_relevant(self, kql: str, step_name: str, explanation: str) -> bool:
        """Always return True to preserve original KQL"""
        return True if kql else False
