import os
import re
from typing import Dict, List
from dotenv import load_dotenv
from crewai_tools import SerperDevTool
from crewai import LLM, Agent, Task, Crew

load_dotenv()


class InvestigationStepLibrary:
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

    def _get_alert_impact_context(self, profile: Dict) -> str:
        """Generate context about why investigating this alert matters"""
        alert_type = profile.get("alert_type", "general_security")

        impact_map = {
            "authentication": "Compromised authentication can lead to unauthorized access, data breaches, and account takeovers. Attackers use stolen credentials to access sensitive data, deploy ransomware, or move laterally through your network.",
            "identity_access": "Privilege escalation allows attackers to gain admin rights, modify security settings, create backdoors, and access all company data. This is often the final step before a major breach.",
            "endpoint_security": "Compromised endpoints serve as entry points for malware, ransomware, and data exfiltration. Attackers use non-compliant devices to bypass security controls.",
            "network_activity": "Suspicious network activity indicates potential data exfiltration, command-and-control communication, or reconnaissance by attackers mapping your network for future attacks.",
            "data_security": "Data breaches expose sensitive customer information, intellectual property, and confidential business data, leading to regulatory fines, lawsuits, and reputation damage.",
            "threat_detection": "Active threats indicate ongoing attacks that could result in system compromise, data theft, ransomware deployment, or complete network takeover if not stopped immediately.",
        }

        return impact_map.get(
            alert_type,
            "This security alert indicates potential compromise that could lead to data breach, system damage, or unauthorized access to sensitive resources.",
        )

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
        """Generate investigation steps with STRICT anti-duplication"""

        existing_steps = profile.get("existing_step_names", [])
        existing_str = (
            "\n".join([f"- {s}" for s in existing_steps]) if existing_steps else "None"
        )

        prompt = f"""Generate NEW investigation steps that DON'T duplicate these existing ones:

    EXISTING STEPS (DO NOT REPEAT):
    {existing_str}

    ALERT: {profile.get('alert_name', '')}
    ALERT TYPE: {profile.get('alert_type', '')}
    TECHNICAL OVERVIEW: {profile.get('technical_overview', '')[:600]}

    WHY THIS MATTERS:
    {self._get_alert_impact_context(profile)}

    CRITICAL ANTI-DUPLICATION RULES:
    1. If "user count" or "impacted users" exists, DO NOT generate "Determine Total Number of Users"
    2. If "IP reputation" or "IP validation" exists, DO NOT generate IP reputation steps
    3. If "VIP users" exists, DO NOT generate user context steps
    4. Generate ONLY truly unique steps that investigate DIFFERENT aspects

    REQUIRED NEW STEPS (generate 3-4 UNIQUE ones that address gaps):
    Focus on aspects NOT covered by existing steps:
    - Advanced behavioral analysis (time patterns, impossible travel, unusual hours)
    - Credential usage analysis (password sprays, brute force attempts, account lockouts)
    - Session analysis (concurrent logins, session hijacking, session duration)
    - Application access patterns (risky apps, OAuth grants, sensitive data access)
    - Privilege escalation checks (role changes, permission grants, admin actions)
    - Conditional access policy violations (bypassed policies, risky sign-ins)

    Each step MUST:
    1. NOT duplicate existing steps
    2. Have specific, descriptive name (10-15 words explaining WHAT you're checking)
    3. Target a different data aspect than existing steps
    4. Require KQL query (SigninLogs/AuditLogs/DeviceInfo/CloudAppEvents)
    5. Explain in SIMPLE language WHY this matters for THIS alert

    FORMAT (follow exactly):
    STEP: [Descriptive name: "Check for X to detect Y behavior"]
    EXPLANATION: [3 parts in simple language:
    1. WHAT to check: "This step examines [specific data/logs]..."
    2. WHY it matters: "This is important because [how it relates to the alert]..."
    3. WHAT to look for: "Look for [specific indicators like X, Y, Z]..."]
    NEEDS_KQL: YES
    DATA_SOURCE: [SigninLogs/AuditLogs/DeviceInfo/CloudAppEvents]
    TOOL: None
    PRIORITY: [CRITICAL/HIGH/MEDIUM]
    RELEVANCE: [How this step specifically helps investigate THIS alert and what risk it mitigates]
    ---

    Example of GOOD step:
    STEP: Analyze Sign-in Patterns Across Multiple Time Zones to Detect Impossible Travel Scenarios
    EXPLANATION: This step examines the user's sign-in locations and timestamps from SigninLogs over the past 7 days. This is important because attackers who compromise credentials often sign in from different countries within impossible timeframes (e.g., USA then China within 1 hour). Look for sign-ins from geographically distant locations within short time periods, multiple countries in one day, or sign-ins from high-risk countries. This pattern strongly indicates credential theft rather than legitimate user activity.
    NEEDS_KQL: YES
    DATA_SOURCE: SigninLogs
    TOOL: None
    PRIORITY: HIGH
    RELEVANCE: For this {profile.get('alert_type', 'authentication')} alert, impossible travel indicates compromised credentials being used by attackers, which could lead to data breach, unauthorized access to sensitive systems, or lateral movement across the organization.
    ---

    Generate 3-4 UNIQUE, RELEVANT steps NOW:"""

        agent = Agent(
            role="SOC Investigation Playbook Designer",
            goal="Generate 3-4 unique investigation steps that don't duplicate existing ones",
            backstory="Expert at identifying gaps in investigation coverage and avoiding duplicates",
            llm=self.llm,
            verbose=False,
        )

        task = Task(
            description=prompt,
            expected_output="3-4 unique investigation steps",
            agent=agent,
        )
        crew = Crew(agents=[agent], tasks=[task], verbose=False)
        result = str(crew.kickoff())

        steps = self._parse_llm_steps(result)

        # Post-filter against existing
        unique_steps = []
        for step in steps:
            if not self._is_duplicate_of_existing(step, existing_steps):
                unique_steps.append(step)
            else:
                print(f"   ⏭️ Filtered duplicate: {step.get('step_name', '')[:60]}")

        return unique_steps

    def _is_duplicate_of_existing(self, step: Dict, existing_names: List[str]) -> bool:
        """Check if step duplicates existing steps"""
        step_name = step.get("step_name", "").lower()

        # Semantic similarity check
        from difflib import SequenceMatcher

        for existing in existing_names:
            existing_lower = existing.lower()
            similarity = SequenceMatcher(None, step_name, existing_lower).ratio()

            if similarity > 0.6:  # 60% similar = duplicate
                return True

            # Keyword overlap check
            step_keywords = set(step_name.split())
            existing_keywords = set(existing_lower.split())
            common = step_keywords & existing_keywords

            if len(common) >= 3:  # 3+ common words = likely duplicate
                return True

        return False

    def _parse_llm_steps(self, llm_output: str) -> List[Dict]:
        """Parse LLM output into structured step dictionaries"""
        steps = []
        step_blocks = re.split(r"\n[-─]{3,}\n", llm_output)

        for block in step_blocks:
            if not block.strip() or len(block) < 50:
                continue

            # Extract fields using flexible patterns
            step_match = re.search(r"STEP:\s*(.+?)(?:\n|$)", block, re.IGNORECASE)
            exp_match = re.search(
                r"EXPLANATION:\s*(.+?)(?=\n(?:NEEDS_KQL|DATA_SOURCE|TOOL|PRIORITY|RELEVANCE)|$)",
                block,
                re.IGNORECASE | re.DOTALL,
            )
            kql_match = re.search(r"NEEDS_KQL:\s*(YES|NO)", block, re.IGNORECASE)
            ds_match = re.search(r"DATA_SOURCE:\s*(.+?)(?:\n|$)", block, re.IGNORECASE)
            tool_match = re.search(r"TOOL:\s*(.+?)(?:\n|$)", block, re.IGNORECASE)
            priority_match = re.search(
                r"PRIORITY:\s*(CRITICAL|HIGH|MEDIUM|LOW)", block, re.IGNORECASE
            )
            # ✅ NEW: Extract relevance
            relevance_match = re.search(
                r"RELEVANCE:\s*(.+?)(?=\n(?:STEP|---)|$)",
                block,
                re.IGNORECASE | re.DOTALL
            )

            if step_match and exp_match:
                step_name = step_match.group(1).strip()
                explanation = exp_match.group(1).strip()
                needs_kql = kql_match.group(1).upper() == "YES" if kql_match else True
                data_source = ds_match.group(1).strip() if ds_match else "SigninLogs"
                tool = tool_match.group(1).strip() if tool_match else "None"
                priority = priority_match.group(1).upper() if priority_match else "MEDIUM"
                relevance = relevance_match.group(1).strip() if relevance_match else ""

                # Clean up
                step_name = self._clean_text(step_name)
                explanation = self._clean_text(explanation)
                relevance = self._clean_text(relevance)

                # Validation
                if len(step_name) < 5 or len(explanation) < 20:
                    continue

                # Remove line breaks from explanation and relevance
                explanation = re.sub(r"\s+", " ", explanation)
                relevance = re.sub(r"\s+", " ", relevance)

                steps.append({
                    "step_name": step_name,
                    "explanation": explanation,
                    "relevance": relevance,  # ✅ NEW FIELD
                    "kql_needed": needs_kql,
                    "data_source": data_source,
                    "tool": tool.lower() if tool.lower() != "none" else "",
                    "priority": priority,
                    "input_required": "",
                })

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
