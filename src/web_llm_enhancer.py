from crewai import Agent, Task, Crew, Process, LLM
from crewai_tools import SerperDevTool
from textwrap import dedent
import re


class WebLLMEnhancer:
    """
    Enhances triaging template steps using INTELLIGENT FALLBACK + Optional LLM.
    - Generates clean step names from raw input
    - Creates action-focused explanations
    - Finds/generates KQL queries
    - Ensures NO HARDCODED DATA
    """

    def __init__(self):
        self.llm = LLM(model="ollama/qwen2.5:0.5b", base_url="http://localhost:11434")
        try:
            self.web_search = SerperDevTool()
        except:
            self.web_search = None
            print("⚠️ Web search unavailable. Using pattern-based enhancement.")

    def enhance_template_steps(self, rule_number: str, original_steps: list) -> list:
        """
        Main enhancement pipeline - GUARANTEED TO RETURN VALID STEPS.

        Args:
            rule_number: Rule identifier (e.g., "Rule#183")
            original_steps: Steps parsed from CSV/Excel template

        Returns:
            Enhanced steps with improved KQL, explanations, and additional steps
        """
        print(f"\n{'='*80}")
        print(f"🌐 WEB + LLM ENHANCEMENT FOR {rule_number}")
        print(f"{'='*80}")
        print(f"📥 Input: {len(original_steps)} original steps")

        # ALWAYS run intelligent fallback first (guaranteed results)
        enhanced_steps = self._fallback_enhancement(original_steps)

        print(f"\n✅ Fallback enhancement complete: {len(enhanced_steps)} steps")

        # Optionally try LLM enhancement (experimental - may not work with small models)
        if (
            len(enhanced_steps) >= len(original_steps) * 0.8
        ):  # If fallback produced good results
            print(f"\n🤖 Attempting LLM enhancement for additional improvements...")
            try:
                # Create enhancement agent
                enhancement_agent = self._create_enhancement_agent()

                # Create enhancement task
                enhancement_task = self._create_enhancement_task(
                    enhancement_agent,
                    rule_number,
                    enhanced_steps,  # Use enhanced steps as input
                )

                # Run enhancement crew with timeout
                crew = Crew(
                    agents=[enhancement_agent],
                    tasks=[enhancement_task],
                    process=Process.sequential,
                    verbose=False,  # Reduce noise
                )

                result = crew.kickoff()
                llm_steps = self._parse_enhanced_output(str(result))

                # If LLM produced better results, use those
                if len(llm_steps) >= len(enhanced_steps):
                    print(f"✅ LLM enhancement successful: {len(llm_steps)} steps")
                    enhanced_steps = llm_steps
                else:
                    print(
                        f"⚠️ LLM produced {len(llm_steps)} steps (less than fallback). Using fallback."
                    )

            except Exception as e:
                print(f"⚠️ LLM enhancement failed: {str(e)}")
                print("   Using fallback results.")

        print(f"\n{'='*80}")
        print(f"✅ ENHANCEMENT COMPLETE")
        print(f"   Original steps: {len(original_steps)}")
        print(f"   Enhanced steps: {len(enhanced_steps)}")
        print(
            f"   Steps with KQL: {len([s for s in enhanced_steps if s.get('kql_query')])}"
        )
        print(f"{'='*80}\n")

        return enhanced_steps

    def _create_enhancement_agent(self) -> Agent:
        """Create web-powered enhancement agent"""
        tools = []
        if self.web_search:
            tools.append(self.web_search)

        return Agent(
            role="Security Template Enhancement Specialist",
            goal="Enhance triaging templates with web research, add missing KQL queries, and improve investigation steps.",
            backstory=(
                "You are an expert SOC analyst and Azure Sentinel specialist. "
                "You search the web for best practices, KQL queries, and investigation techniques. "
                "You NEVER hardcode user emails, IPs, or device names - always use placeholders. "
                "You enhance templates to be comprehensive, actionable, and parameterized."
            ),
            tools=tools,
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
        )

    def _create_enhancement_task(
        self, agent: Agent, rule_number: str, original_steps: list
    ) -> Task:
        """Create task for template enhancement"""

        # Format original steps for LLM
        steps_text = "\n\n".join(
            [
                f"STEP {i}: {step.get('step_name', 'Unknown')}\n"
                f"Explanation: {step.get('explanation', 'N/A')}\n"
                f"Input: {step.get('input_required', 'N/A')}\n"
                f"KQL: {step.get('kql_query', 'MISSING')}"
                for i, step in enumerate(original_steps, 1)
            ]
        )

        return Task(
            description=dedent(
                f"""
                Enhance the triaging template for {rule_number}.
                
                ===========================================================================
                ORIGINAL TEMPLATE STEPS:
                ===========================================================================
                {steps_text}
                
                ===========================================================================
                YOUR ENHANCEMENT TASKS:
                ===========================================================================
                
                **TASK 1: Find Missing KQL Queries** 🔍
                
                For EACH step that has "KQL: MISSING" or incomplete query:
                
                1. Search the web:
                   - "{rule_number} KQL query Azure Sentinel"
                   - "[step name] KQL query Microsoft Sentinel"
                   - "Azure AD sign-in logs KQL [specific check]"
                
                2. Extract the BEST query from search results
                
                3. CRITICAL: Replace ALL hardcoded values with placeholders:
                   - Email addresses → <USER_EMAIL>
                   - IP addresses → <IP_ADDRESS>
                   - Device IDs → <DEVICE_ID>
                   - Time ranges → ago(<TIMESPAN>) like ago(7d)
                
                Example search: "Check user sign-in logs KQL Azure"
                Example query found:
                ```
                SigninLogs
                | where UserPrincipalName == "john.doe@company.com"
                | where TimeGenerated > datetime(2024-01-01)
                ```
                
                YOUR PARAMETERIZED VERSION:
                ```
                SigninLogs
                | where UserPrincipalName == "<USER_EMAIL>"
                | where TimeGenerated > ago(7d)
                | project TimeGenerated, IPAddress, Location, AppDisplayName
                | order by TimeGenerated desc
                ```
                
                **TASK 2: Improve Explanations** 📝
                
                For EACH step:
                1. Make explanation ACTION-FOCUSED (what to DO, not what it is)
                2. Add WHY it's important (detection value)
                3. Keep it concise (2-3 sentences max)
                
                Example:
                BAD: "This step checks sign-in logs"
                GOOD: "Query Azure AD sign-in logs to identify authentication patterns and detect anomalous login behavior. Focus on IP reputation, device recognition, and MFA status. Legitimate activity typically shows known devices with successful MFA."
                
                **TASK 3: Add Missing Steps** ➕
                
                Search for "{rule_number} investigation best practices" and add steps if missing:
                
                Common missing steps:
                - IP reputation check (using threat intelligence)
                - Device enrollment verification
                - User behavior baseline comparison
                - Conditional Access policy review
                - Final classification & escalation decision
                
                **TASK 4: Define Clear Inputs** 📊
                
                For EACH step, specify EXACTLY what data is needed:
                
                Examples:
                - "User principal name (email address)"
                - "Source IP address"
                - "Time range (start and end)"
                - "Device ID or device name"
                - "Application display name"
                
                ===========================================================================
                OUTPUT FORMAT (MANDATORY):
                ===========================================================================
                
                For EACH step, output in this EXACT format:
                
                ---
                STEP_NUMBER: [1, 2, 3, ...]
                STEP_NAME: [Clean, action-focused name]
                EXPLANATION: [2-3 sentences: what to do, why important, what indicates FP/TP]
                INPUT_REQUIRED: [Specific data needed, comma-separated]
                KQL_QUERY: [Parameterized query OR empty if not applicable]
                ---
                
                EXAMPLE OUTPUT:
                
                ---
                STEP_NUMBER: 1
                STEP_NAME: Review Incident Alert Details
                EXPLANATION: Gather initial incident information including affected user, timestamp, and alert description. This provides context for subsequent investigation steps and helps identify priority level. Look for VIP users or unusual timing patterns.
                INPUT_REQUIRED: Incident number, Reported timestamp, User principal name
                KQL_QUERY: 
                ---
                
                ---
                STEP_NUMBER: 2
                STEP_NAME: Query User Sign-In Logs
                EXPLANATION: Retrieve recent sign-in activity for the affected user to establish behavior baseline. Analyze authentication methods, device types, and location patterns. Known devices with MFA indicate legitimate activity (FP).
                INPUT_REQUIRED: User principal name, Time range (typically last 7 days)
                KQL_QUERY: SigninLogs
                | where UserPrincipalName == "<USER_EMAIL>"
                | where TimeGenerated > ago(7d)
                | project TimeGenerated, IPAddress, Location, AppDisplayName, DeviceDetail, AuthenticationRequirement
                | order by TimeGenerated desc
                ---
                
                ---
                STEP_NUMBER: 3
                STEP_NAME: Check Source IP Reputation
                EXPLANATION: Verify IP address reputation using threat intelligence feeds and geolocation data. Clean IPs from known corporate ranges indicate legitimate access. Malicious IPs or TOR/VPN exit nodes require immediate escalation.
                INPUT_REQUIRED: Source IP address
                KQL_QUERY: SigninLogs
                | where UserPrincipalName == "<USER_EMAIL>"
                | where TimeGenerated > ago(7d)
                | distinct IPAddress
                | project IPAddress
                ---
                
                ===========================================================================
                QUALITY CHECKLIST:
                ===========================================================================
                
                Before submitting, verify:
                ✅ All KQL queries use placeholders (NO hardcoded emails/IPs)
                ✅ Each step has clear, actionable explanation
                ✅ Input requirements are specific and complete
                ✅ Steps are in logical investigation order
                ✅ At least 5-8 investigation steps (add if needed)
                ✅ Final step includes classification decision
                
                OUTPUT ALL STEPS NOW.
            """
            ),
            expected_output=dedent(
                """
                A complete list of enhanced steps in the specified format.
                Each step must have:
                - Step number
                - Clean step name
                - Actionable explanation (2-3 sentences)
                - Specific input requirements
                - Parameterized KQL query (or empty if N/A)
                
                All values must use placeholders:
                - <USER_EMAIL> for emails
                - <IP_ADDRESS> for IPs
                - <DEVICE_ID> for devices
                - ago(7d) for time ranges
                
                Minimum 5 steps, maximum 12 steps.
            """
            ),
            agent=agent,
        )

    def _parse_enhanced_output(self, output: str) -> list:
        """Parse LLM output into structured steps - ROBUST VERSION"""
        steps = []

        print(f"\n🔍 Parsing LLM output (length: {len(output)} chars)")

        # Try primary format first (---\nSTEP_NUMBER: X\n...)
        step_blocks = re.split(r"\n---+\n", output)

        for block in step_blocks:
            if not block.strip() or len(block.strip()) < 20:
                continue

            step = {}

            # Extract step number
            num_match = re.search(r"STEP_NUMBER:\s*(\d+)", block, re.IGNORECASE)
            if num_match:
                step["step_number"] = int(num_match.group(1))

            # Extract step name
            name_match = re.search(r"STEP_NAME:\s*(.+?)(?:\n|$)", block, re.IGNORECASE)
            if name_match:
                step["step_name"] = name_match.group(1).strip()

            # Extract explanation
            exp_match = re.search(
                r"EXPLANATION:\s*(.+?)(?:\nINPUT_REQUIRED:|\nKQL_QUERY:|\Z)",
                block,
                re.DOTALL | re.IGNORECASE,
            )
            if exp_match:
                step["explanation"] = exp_match.group(1).strip()

            # Extract input required
            input_match = re.search(
                r"INPUT_REQUIRED:\s*(.+?)(?:\nKQL_QUERY:|\n---|\Z)",
                block,
                re.DOTALL | re.IGNORECASE,
            )
            if input_match:
                step["input_required"] = input_match.group(1).strip()

            # Extract KQL query
            kql_match = re.search(
                r"KQL_QUERY:\s*(.+?)(?:\n---|\Z)", block, re.DOTALL | re.IGNORECASE
            )
            if kql_match:
                kql = kql_match.group(1).strip()
                step["kql_query"] = kql if len(kql) > 10 else ""

            # Only add if we have minimum required fields
            if step.get("step_name") and step.get("explanation"):
                steps.append(step)
                print(f"✅ Parsed step {len(steps)}: {step['step_name']}")

        # If parsing failed completely, show debug info
        if not steps:
            print(f"❌ No steps parsed! Output preview:")
            print(output[:500])
            print("\n... (truncated)")

        return steps

    def _fallback_enhancement(self, original_steps: list) -> list:
        """
        INTELLIGENT FALLBACK: Enhance steps using patterns and web search.
        This runs when LLM output parsing fails.
        """
        print(f"\n⚙️ Running INTELLIGENT fallback enhancement...")

        enhanced = []

        for i, step in enumerate(original_steps, 1):
            step_name = step.get("step_name", f"Step {i}")
            original_exp = step.get("explanation", "")

            # 🔧 FIX STEP NAME (remove numbers like "1.0", "2.0", etc.)
            clean_name = self._generate_clean_step_name(step_name, original_exp, i)

            # 🔧 ENHANCE EXPLANATION (make it actionable)
            enhanced_exp = self._enhance_explanation_with_patterns(
                clean_name, original_exp
            )

            # 🔧 FIND KQL QUERY (web search or pattern matching)
            kql_query = self._find_kql_for_step(clean_name, step.get("kql_query", ""))

            # 🔧 IMPROVE INPUT REQUIREMENTS
            input_required = self._improve_input_requirements(
                step.get("input_required", ""), clean_name
            )

            enhanced_step = {
                "step_name": clean_name,
                "explanation": enhanced_exp,
                "input_required": input_required,
                "kql_query": kql_query,
            }

            enhanced.append(enhanced_step)
            print(f"✅ Enhanced step {i}: {clean_name}")

        return enhanced

    def _generate_clean_step_name(
        self, raw_name: str, explanation: str, step_num: int
    ) -> str:
        """Generate clean, action-focused step name"""
        raw_lower = raw_name.lower().strip()
        exp_lower = explanation.lower() if explanation else ""

        # If step name is just a number (like "1.0", "2.0"), generate from explanation
        if re.match(r"^\d+\.?\d*$", raw_name.strip()):
            # Extract action from explanation
            if "vip" in exp_lower:
                return "Verify VIP User Status"
            elif "application" in exp_lower and "sign" in exp_lower:
                return "Check Passwordless Application Sign-Ins"
            elif "critical" in exp_lower and "application" in exp_lower:
                return "Assess Application Criticality"
            elif "close" in exp_lower and "false" in exp_lower:
                return "Close as False Positive"
            elif "true positive" in exp_lower:
                return "Escalate as True Positive"
            elif "legitimate" in exp_lower and "authentication" in exp_lower:
                return "Validate Authentication Method"
            elif "unauthorized" in exp_lower:
                return "Take Remediation Actions"
            elif "monitoring" in exp_lower or "enhance" in exp_lower:
                return "Enhance Future Monitoring"
            else:
                return f"Investigation Step {step_num}"

        # Otherwise, clean existing name
        clean = re.sub(r"^\d+\.?\d*\s*", "", raw_name)  # Remove leading numbers
        clean = re.sub(r"[*#_`]", "", clean)  # Remove markdown
        clean = clean.strip()

        return clean if len(clean) > 3 else f"Investigation Step {step_num}"

    def _enhance_explanation_with_patterns(
        self, step_name: str, original_exp: str
    ) -> str:
        """Enhance explanation to be action-focused and contextual"""
        step_lower = step_name.lower()

        # Pattern-based enhancements
        if "vip" in step_lower:
            return (
                "Cross-reference the affected user against the VIP user list to determine priority level. "
                "VIP users require expedited investigation and additional stakeholder notification. "
                "Document VIP status and adjust incident priority if necessary."
            )
        elif "passwordless" in step_lower and "application" in step_lower:
            return (
                "Query authentication logs to identify all applications accessed without password authentication. "
                "Filter for passwordless methods such as certificate-based auth, biometrics, or hardware tokens. "
                "Typical finding: Legitimate passwordless apps (Windows Hello, FIDO2) indicate FP."
            )
        elif "critical" in step_lower:
            return (
                "Evaluate whether identified passwordless applications are classified as critical or high-risk. "
                "Cross-reference against the approved passwordless application inventory. "
                "Critical apps without proper authorization require immediate escalation."
            )
        elif "false positive" in step_lower and "close" in step_lower:
            return (
                "If all checks confirm legitimate passwordless authentication (known apps, authorized methods, VIP user), "
                "classify as False Positive and close the incident. Document justification including VIP status, "
                "known applications, and approved authentication methods."
            )
        elif "true positive" in step_lower:
            return (
                "If unauthorized passwordless access to critical applications is confirmed, escalate as True Positive. "
                "Notify SOC lead and application owner immediately. Initiate containment procedures per IR playbook."
            )
        elif "legitimate" in step_lower or "validate" in step_lower:
            return (
                "Verify that the passwordless authentication method is legitimate and approved (e.g., FIDO2, Windows Hello, YubiKey). "
                "Contact IT team if critical apps lack MFA or proper authentication controls. "
                "Approved methods + known user = False Positive. Unauthorized methods = True Positive."
            )
        elif "unauthorized" in step_lower or "remediation" in step_lower:
            return (
                "If unauthorized access is confirmed, take immediate remediation actions: lock affected account, "
                "reset credentials, revoke active sessions, and isolate device if compromised. "
                "Escalate to IR team for forensic investigation."
            )
        elif "monitoring" in step_lower or "enhance" in step_lower:
            return (
                "Update detection rules and monitoring thresholds based on investigation findings. "
                "Add newly identified passwordless apps to whitelist or blacklist as appropriate. "
                "Document lessons learned for future incident response."
            )
        else:
            # Fallback: use original or generate generic
            if original_exp and len(original_exp) > 20:
                return original_exp
            else:
                return f"Complete {step_name} investigation step and document all findings thoroughly."

    def _find_kql_for_step(self, step_name: str, existing_kql: str) -> str:
        """Find or generate KQL query for the step"""
        step_lower = step_name.lower()

        # If KQL already exists and looks valid, clean and return it
        if existing_kql and len(existing_kql) > 20:
            return self._clean_kql_placeholders(existing_kql)

        # Otherwise, generate KQL based on step type
        if "passwordless" in step_lower or "application" in step_lower:
            return """SigninLogs
| where UserPrincipalName == "<USER_EMAIL>"
| where TimeGenerated > ago(7d)
| where AuthenticationRequirement == "singleFactorAuthentication"
| where isnotempty(AppDisplayName)
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location, DeviceDetail, AuthenticationRequirement, ResultType
| order by TimeGenerated desc"""

        elif "vip" in step_lower:
            return """// Query user details
let TargetUser = "<USER_EMAIL>";
IdentityInfo
| where AccountUPN == TargetUser
| project AccountUPN, JobTitle, Department, Manager"""

        elif "sign" in step_lower or "authentication" in step_lower:
            return """SigninLogs
| where UserPrincipalName == "<USER_EMAIL>"
| where TimeGenerated > ago(7d)
| summarize 
    TotalSignIns = count(),
    PasswordlessSignIns = countif(AuthenticationRequirement == "singleFactorAuthentication"),
    UniqueApps = dcount(AppDisplayName),
    UniqueIPs = dcount(IPAddress)
  by UserPrincipalName
| extend PasswordlessRatio = round(todouble(PasswordlessSignIns) / todouble(TotalSignIns) * 100, 2)"""

        else:
            return ""  # No KQL for decision/manual steps

    def _improve_input_requirements(self, original_input: str, step_name: str) -> str:
        """Improve input requirements to be more specific"""
        if (
            original_input
            and len(original_input) > 10
            and "previous steps" not in original_input.lower()
        ):
            return original_input

        step_lower = step_name.lower()

        if "vip" in step_lower:
            return "User principal name (email), VIP user list (from security team)"
        elif "application" in step_lower:
            return "User principal name (email), Time range (last 7 days), Application inventory"
        elif "sign" in step_lower or "authentication" in step_lower:
            return "User principal name (email), Time range (last 7-30 days)"
        elif "critical" in step_lower:
            return "Application name(s), Criticality classification list"
        elif "monitoring" in step_lower:
            return "Investigation summary, Detection rule repository"
        else:
            return "Findings from all previous investigation steps"

    def _clean_kql_placeholders(self, kql: str) -> str:
        """Ensure KQL uses placeholders instead of hardcoded values"""
        if not kql:
            return ""

        # Replace emails
        kql = re.sub(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "<USER_EMAIL>", kql
        )

        # Replace IPs
        kql = re.sub(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "<IP_ADDRESS>", kql)

        # Replace hardcoded dates with ago()
        kql = re.sub(r'datetime\(["\'][\d\-:TZ]+["\']\)', "ago(7d)", kql)

        return kql
