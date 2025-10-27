import os
import re
from typing import Dict, List
from crewai import LLM, Agent, Task, Crew
from crewai_tools import SerperDevTool
from dotenv import load_dotenv

load_dotenv()


class InvestigationStepLibrary:
    """
    Dynamically generates investigation steps using LLM + Web Search
    Based on alert analysis and threat intelligence
    """

    def __init__(self):
        self._init_llm()

        # Initialize web search if available
        try:
            self.web_search = SerperDevTool()
            self.has_web = True
            print("✅ Web search enabled for step generation")
        except:
            self.web_search = None
            self.has_web = False
            print("⚠️ Web search unavailable")

        print("✅ Dynamic Investigation Step Library initialized")

    def _init_llm(self):
        """Initialize LLM for step generation"""
        gemini_key = os.getenv("GOOGLE_API_KEY")
        if gemini_key:
            self.llm = LLM(
                model="gemini/gemini-2.5-flash", api_key=gemini_key, temperature=0.3
            )
            print("✅ Using Gemini for step generation")
        else:
            ollama_model = os.getenv("OLLAMA_CHAT", "ollama/qwen2.5:3b")
            if not ollama_model.startswith("ollama/"):
                ollama_model = f"ollama/{ollama_model}"
            self.llm = LLM(
                model=ollama_model, base_url="http://localhost:11434", temperature=0.3
            )
            print(f"✅ Using {ollama_model} for step generation")

    def generate_investigation_steps(self, profile: Dict) -> List[Dict]:
        print(f"\nGenerating investigation steps for {profile['alert_name']}")

        # ADD THIS DEBUG:
        print(f"DEBUG: Profile keys: {profile.keys()}")
        print(f"DEBUG: MITRE techniques: {profile.get('mitre_techniques', [])}")
        print(f"DEBUG: Threat actors: {profile.get('threat_actors', [])}")

        # ... rest of function
        print(f"\n🔬 Generating investigation steps for {profile['alert_name']}")

        # Step 1: Research best practices if web search available
        investigation_guidance = ""
        if self.has_web:
            investigation_guidance = self._research_investigation_practices(profile)

        # Step 2: Generate steps using LLM
        generated_steps = self._generate_steps_with_llm(profile, investigation_guidance)

        print(f"   ✅ Generated {len(generated_steps)} investigation steps")
        return generated_steps

    def _research_investigation_practices(self, profile: Dict) -> str:
        """Use web search to find investigation best practices"""
        print(f"   🌐 Researching investigation practices...")

        alert_name = profile.get("alert_name", "")
        mitre_techniques = profile.get("mitre_techniques", [])
        threat_actors = profile.get("threat_actors", [])

        # Build targeted search queries
        search_queries = []

        # Query 1: Alert-specific investigation
        if alert_name:
            search_queries.append(
                f"how to investigate {alert_name} SOC playbook incident response"
            )

        # Query 2: MITRE technique investigation
        if mitre_techniques:
            primary_technique = mitre_techniques[0]
            tech_name = profile.get("mitre_details", {}).get(primary_technique, "")
            search_queries.append(
                f"MITRE {primary_technique} {tech_name} detection investigation steps"
            )

        # Query 3: Threat actor TTPs
        if threat_actors:
            primary_actor = threat_actors[0]
            search_queries.append(
                f"{primary_actor} threat actor investigation detection methods"
            )

        # Perform searches (limit to 2 to save time)
        all_findings = []

        for query in search_queries[:2]:
            try:
                agent = Agent(
                    role="Security Research Analyst",
                    goal=f"Research investigation methodology for: {query}",
                    backstory="Expert at finding SOC investigation best practices and playbooks",
                    tools=[self.web_search],
                    llm=self.llm,
                    verbose=False,
                    max_iter=5,
                )

                task = Task(
                    description=f"""Search the web for: {query}

Find and extract:
1. Key investigation steps and procedures
2. Data sources and logs to check
3. Tools and techniques to use
4. Indicators to look for
5. Common artifacts and evidence

Return ONLY the actionable investigation steps as concise bullet points.
Focus on what a SOC analyst should DO, not just theory.""",
                    expected_output="Concise bullet point list of investigation steps",
                    agent=agent,
                )

                crew = Crew(agents=[agent], tasks=[task], verbose=False)
                result = crew.kickoff()

                findings = str(result).strip()
                if findings and len(findings) > 50:
                    all_findings.append(findings)
                    print(f"   ✅ Found guidance: {query[:60]}...")

            except Exception as e:
                print(f"   ⚠️ Search failed: {str(e)[:80]}")
                continue

        return "\n\n".join(all_findings) if all_findings else ""

    def _generate_steps_with_llm(self, profile: Dict, guidance: str) -> List[Dict]:
        """Generate investigation steps using LLM - FULLY DYNAMIC"""

        alert_name = profile.get("alert_name", "Unknown Alert")
        alert_type = profile.get("alert_type", "general_security")
        tech_overview = profile.get("technical_overview", "")
        mitre_techniques = profile.get("mitre_techniques", [])
        mitre_details = profile.get("mitre_details", {})
        threat_actors = profile.get("threat_actors", [])
        data_sources = profile.get("data_sources", [])
        business_impact = profile.get("business_impact", {})
        detection_mechanism = profile.get("detection_mechanism", [])

        # Build context strings
        mitre_context = "\n".join(
            [
                f"• {tid}: {mitre_details.get(tid, 'Unknown')}"
                for tid in mitre_techniques
            ]
        )

        separator = "=" * 80

        prompt = f"""You are a senior SOC analyst designing an investigation playbook.

    ALERT DETAILS:
    {separator}
    Alert Name: {alert_name}
    Alert Type: {alert_type}
    Risk Level: {business_impact.get('risk_level', 'UNKNOWN')}

    CRITICAL CONSTRAINTS:
    1. Generate ONLY data collection steps - NO remediation, NO closure, NO notifications
    2. Each step MUST query a log source OR use an external tool
    3. NO steps that say "inform", "notify", "reset", "revoke", "block", "disable", "escalate"
    4. NO steps that say "document", "track closure", "final confirmation", "close incident"
    5. NO duplicate or similar steps (check IP reputation only ONCE)
    6. Stay strictly within alert scope: {tech_overview[:200]}

    TECHNICAL OVERVIEW:
    {tech_overview[:600]}

    MITRE ATT&CK TECHNIQUES:
    {mitre_context if mitre_context else 'Not specified'}

    AVAILABLE DATA SOURCES:
    {', '.join(data_sources) if data_sources else 'SigninLogs, AuditLogs'}

    WEB RESEARCH FINDINGS:
    {guidance[:1500] if guidance else "No web research available"}

    STEP GENERATION RULES:
    ✅ GENERATE: Query/Check/Verify/Analyze/Extract/Review actions
    ✅ GENERATE: Steps with concrete data sources (SigninLogs, AuditLogs, etc.)
    ✅ GENERATE: Tool-based checks (VirusTotal, AbuseIPDB) - ONCE per type
    ❌ NEVER GENERATE: Remediation (reset/revoke/block/disable)
    ❌ NEVER GENERATE: Notifications (inform/notify/escalate/reach out)
    ❌ NEVER GENERATE: Documentation (document findings/track closure)
    ❌ NEVER GENERATE: Classification (TP/FP determination)
    ❌ NEVER GENERATE: Duplicate checks (don't repeat IP reputation)

    STEP SEQUENCE (8-12 unique steps):
    1. Scope Verification (count affected users/systems)
    2. User Context (VIP status, roles) - if user-related alert
    3. Authentication Analysis (sign-ins, MFA) - if auth-related
    4. Threat Intelligence (IP/domain reputation) - ONCE only
    5. Network Activity (connections, locations) - if network-related
    6. Device/Endpoint (compliance) - if device-related
    7. Identity/Access (roles, permissions) - if IAM-related
    8. MITRE-specific checks (based on techniques listed above)

    FORMAT (use EXACTLY this):
    STEP: [Action verb: Query/Check/Verify/Analyze/Extract]
    EXPLANATION: [What to investigate, Why it matters, What to look for - 2-3 sentences]
    NEEDS_KQL: [YES/NO]
    DATA_SOURCE: [SigninLogs/AuditLogs/DeviceInfo/IdentityInfo/CloudAppEvents OR "TOOL"]
    TOOL: [virustotal/abuseipdb/None]
    PRIORITY: [CRITICAL/HIGH/MEDIUM]

    EXAMPLES OF INVALID STEPS (DO NOT GENERATE):
    ❌ Correlate with Other Security Events
    ❌ Assess User Baseline Behavior
    ❌ Build Comprehensive Timeline
    ❌ Determine True/False Positive
    ❌ Investigate PowerShell Execution (unless alert is about PowerShell)

    Generate steps NOW. Be specific to THIS alert only."""

        try:
            agent = Agent(
                role="SOC Investigation Playbook Designer",
                goal="Generate executable investigation steps with concrete data sources",
                backstory="""You are a senior SOC analyst who creates precise, executable 
                investigation playbooks. Every step you design has a clear data source or tool.
                You never include manual analysis or abstract correlation steps.""",
                llm=self.llm,
                verbose=False,
            )

            task = Task(
                description=prompt,
                expected_output="8-12 structured investigation steps in specified format",
                agent=agent,
            )

            crew = Crew(agents=[agent], tasks=[task], verbose=False)
            result = str(crew.kickoff())

            # Parse LLM output
            steps = self._parse_llm_steps(result)

            # ✅ POST-PROCESSING: Filter out invalid steps
            valid_steps = []
            seen_types = set()
            for step in steps:
                step_name = step.get("step_name", "").lower()
                explanation = step.get("explanation", "")

                # Check for duplicates
                step_type = self._get_step_type(step_name)
                if step_type in seen_types:
                    print(f"   ❌ Filtered duplicate: {step_name}")
                    continue

                # Use LLM to validate
                if self._is_valid_investigation_step(step_name, explanation):
                    valid_steps.append(step)
                    seen_types.add(step_type)
                else:
                    print(f"   ❌ Filtered invalid: {step_name}")

            return valid_steps

        except Exception as e:
            print(f"   ❌ LLM generation failed: {str(e)[:100]}")
            return []

    def _get_step_type(self, step_name: str) -> str:
        """Determine step type to detect duplicates"""
        step_lower = step_name.lower()
        
        if "ip" in step_lower and "reputation" in step_lower:
            return "ip_reputation"
        elif "sign" in step_lower or "login" in step_lower or "auth" in step_lower:
            return "authentication"
        elif "device" in step_lower:
            return "device"
        elif "role" in step_lower or "permission" in step_lower:
            return "role_permission"
        elif "mfa" in step_lower:
            return "mfa"
        elif "vip" in step_lower or "user" in step_lower:
            return "user_context"
        else:
            return step_name[:20]  # Use first 20 chars as type

    def _is_valid_investigation_step(self, step_name: str, explanation: str) -> bool:
        """
        Use LLM to validate if step is a proper investigation step
        Returns True if valid, False if remediation/closure/duplicate
        """
        try:
            combined = f"{step_name} - {explanation}"
            
            prompt = f"""Is this a valid SOC INVESTIGATION step?

    Step: {combined[:300]}

    A valid investigation step:
    ✅ Queries a log source (SigninLogs, AuditLogs, etc.)
    ✅ Uses an external tool (VirusTotal, AbuseIPDB)
    ✅ Extracts/analyzes data
    ✅ Checks user/device/IP information
    
    An INVALID step (must be rejected):
    ❌ Remediation (reset, revoke, block, disable, temporary)
    ❌ Notification (inform, notify, reach out, escalate)
    ❌ Documentation (document, track, closure, confirmation)
    ❌ Classification (TP/FP, close incident, mark as)
    ❌ Generic/vague (assess baseline, correlate, timeline)

    Answer with ONLY: VALID or INVALID"""

            agent = Agent(
                role="SOC Step Validator",
                goal="Validate investigation step",
                backstory="Expert at identifying proper investigation steps",
                llm=self.llm,
                verbose=False,
            )

            task = Task(
                description=prompt,
                expected_output="Single word: VALID or INVALID",
                agent=agent,
            )
            crew = Crew(agents=[agent], tasks=[task], verbose=False)
            result = str(crew.kickoff()).strip().upper()

            return "VALID" in result

        except Exception as e:
            print(f"   ⚠️ Validation failed: {str(e)[:100]}")
            # If LLM fails, use strict keyword check
            invalid_keywords = [
                "reset", "revoke", "block", "disable", "inform", "notify",
                "escalate", "document", "track", "closure", "confirmation",
                "close incident", "mark as", "temporary", "reach out"
            ]
            combined_lower = f"{step_name} {explanation}".lower()
            return not any(keyword in combined_lower for keyword in invalid_keywords)

    def _parse_llm_steps(self, llm_output: str) -> List[Dict]:
        """Parse LLM output into structured step dictionaries"""

        steps = []

        # Split by step separators (--- or ━━━)
        step_blocks = re.split(r"\n[-━]{3,}\n", llm_output)

        for block in step_blocks:
            if not block.strip() or len(block) < 50:
                continue

            # Extract fields using flexible patterns
            step_match = re.search(r"STEP:\s*(.+?)(?:\n|$)", block, re.IGNORECASE)
            exp_match = re.search(
                r"EXPLANATION:\s*(.+?)(?=\n(?:NEEDS_KQL|DATA_SOURCE|TOOL|PRIORITY)|$)",
                block,
                re.IGNORECASE | re.DOTALL,
            )
            kql_match = re.search(r"NEEDS_KQL:\s*(YES|NO)", block, re.IGNORECASE)
            ds_match = re.search(r"DATA_SOURCE:\s*(.+?)(?:\n|$)", block, re.IGNORECASE)
            tool_match = re.search(r"TOOL:\s*(.+?)(?:\n|$)", block, re.IGNORECASE)
            priority_match = re.search(
                r"PRIORITY:\s*(CRITICAL|HIGH|MEDIUM|LOW)", block, re.IGNORECASE
            )

            if step_match and exp_match:
                step_name = step_match.group(1).strip()
                explanation = exp_match.group(1).strip()
                needs_kql = kql_match.group(1).upper() == "YES" if kql_match else True
                data_source = ds_match.group(1).strip() if ds_match else "SigninLogs"
                tool = tool_match.group(1).strip() if tool_match else "None"
                priority = (
                    priority_match.group(1).upper() if priority_match else "MEDIUM"
                )

                # Clean up
                step_name = self._clean_text(step_name)
                explanation = self._clean_text(explanation)

                # Validation
                if len(step_name) < 5 or len(explanation) < 20:
                    continue

                # Remove line breaks from explanation
                explanation = re.sub(r"\s+", " ", explanation)

                steps.append(
                    {
                        "step_name": step_name,
                        "explanation": explanation,
                        "kql_needed": needs_kql,
                        "data_source": data_source,
                        "tool": tool.lower() if tool.lower() != "none" else "",
                        "priority": priority,
                        "input_required": "",
                    }
                )

        return steps

    def _clean_text(self, text: str) -> str:
        """Clean text from artifacts"""

        # Remove quotes
        text = text.strip("\"'`")

        # Remove markdown
        text = re.sub(r"\*\*", "", text)
        text = re.sub(r"__", "", text)
        text = re.sub(r"^\*\s+", "", text)

        # Remove extra whitespace
        text = re.sub(r"\s+", " ", text)

        # Remove common artifacts
        text = re.sub(r"^(Step \d+:|STEP:)", "", text, flags=re.IGNORECASE)

        return text.strip()
