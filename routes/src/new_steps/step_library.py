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
        """Generate investigation steps with STRICT anti-duplication"""
        
        # Get existing step names from profile
        existing_steps = profile.get("existing_step_names", [])
        existing_str = "\n".join([f"- {s}" for s in existing_steps]) if existing_steps else "None"

        prompt = f"""Generate NEW investigation steps that DON'T duplicate these existing ones:

    EXISTING STEPS (DO NOT REPEAT):
    {existing_str}

    ALERT: {profile.get('alert_name', '')}
    TECHNICAL OVERVIEW: {profile.get('technical_overview', '')[:600]}

    CRITICAL ANTI-DUPLICATION RULES:
    1. If "user count" or "impacted users" exists, DO NOT generate "Determine Total Number of Users"
    2. If "IP reputation" or "IP validation" exists, DO NOT generate IP reputation steps
    3. If "VIP users" exists, DO NOT generate user context steps
    4. Generate ONLY truly unique steps that investigate DIFFERENT aspects

    REQUIRED NEW STEPS (generate 3-4 UNIQUE ones):
    - Advanced behavioral analysis (time patterns, impossible travel)
    - Credential usage analysis (password sprays, brute force)
    - Session analysis (concurrent logins, session hijacking)
    - Application access patterns (risky apps, OAuth grants)
    - Privilege escalation checks (role changes, permission grants)
    - Conditional access policy violations

    Each step MUST:
    1. NOT duplicate existing steps
    2. Have specific, descriptive name (8-12 words)
    3. Target different data aspect
    4. Need KQL query (SigninLogs/AuditLogs/DeviceInfo)

    FORMAT:
    STEP: [Unique descriptive name that's clearly different from existing]
    EXPLANATION: [What to investigate and why - 2-3 sentences]
    NEEDS_KQL: YES
    DATA_SOURCE: [SigninLogs/AuditLogs/DeviceInfo/CloudAppEvents]
    TOOL: None
    PRIORITY: [CRITICAL/HIGH/MEDIUM]
    ---

    Generate 3-4 UNIQUE steps NOW:"""

        # Rest of LLM call...
        agent = Agent(
            role="SOC Investigation Playbook Designer",
            goal="Generate 3-4 unique investigation steps that don't duplicate existing ones",
            backstory="Expert at identifying gaps in investigation coverage and avoiding duplicates",
            llm=self.llm,
            verbose=False,
        )

        task = Task(description=prompt, expected_output="3-4 unique investigation steps", agent=agent)
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

    def _is_generic_name(self, step_name: str) -> bool:
        """Check if step name is too generic"""
        step_lower = step_name.lower().strip()
        
        # Single word or very short names are too generic
        if len(step_name.split()) <= 2:
            return True
        
        # Generic standalone verbs
        generic_verbs = [
            "query", "check", "verify", "analyze", "review", 
            "investigate", "examine", "assess"
        ]
        
        if step_lower in generic_verbs:
            return True
        
        # Check if it's just a verb + generic noun
        generic_patterns = [
            r"^(query|check|verify|analyze|review)\s+(data|logs|activity|information)$",
            r"^(investigate|examine|assess)\s+(issue|problem|alert)$"
        ]
        
        return any(re.match(pattern, step_lower) for pattern in generic_patterns)

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
