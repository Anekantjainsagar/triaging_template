"""
Investigation Step Library - FULLY DYNAMIC
Uses LLM + Web Search to generate investigation steps
NO HARDCODING - Everything generated based on threat intelligence
"""

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
                model="gemini/gemini-2.5-flash",
                api_key=gemini_key,
                temperature=0.4
            )
            print("✅ Using Gemini for step generation")
        else:
            ollama_model = os.getenv("OLLAMA_CHAT", "ollama/qwen2.5:3b")
            if not ollama_model.startswith("ollama/"):
                ollama_model = f"ollama/{ollama_model}"
            self.llm = LLM(
                model=ollama_model,
                base_url="http://localhost:11434",
                temperature=0.4
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
            search_queries.append(f"how to investigate {alert_name} SOC playbook incident response")

        # Query 2: MITRE technique investigation
        if mitre_techniques:
            primary_technique = mitre_techniques[0]
            tech_name = profile.get("mitre_details", {}).get(primary_technique, "")
            search_queries.append(f"MITRE {primary_technique} {tech_name} detection investigation steps")

        # Query 3: Threat actor TTPs
        if threat_actors:
            primary_actor = threat_actors[0]
            search_queries.append(f"{primary_actor} threat actor investigation detection methods")

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
        threat_actor_ttps = profile.get("threat_actor_ttps", {})
        data_sources = profile.get("data_sources", [])
        investigation_focus = profile.get("investigation_focus", [])
        required_checks = profile.get("required_checks", [])
        business_impact = profile.get("business_impact", {})
        detection_mechanism = profile.get("detection_mechanism", [])

        # Build context strings first (outside f-string)
        mitre_context = "\n".join([
            f"• {tid}: {mitre_details.get(tid, 'Unknown')}" 
            for tid in mitre_techniques
        ])

        actor_context = "\n".join([
            f"• {actor}: {threat_actor_ttps.get(actor, 'Unknown TTPs')}" 
            for actor in threat_actors
        ])

        separator = "=" * 80

        prompt = f"""You are a senior SOC analyst designing an investigation playbook.

ALERT DETAILS:
{separator}
Alert Name: {alert_name}
Alert Type: {alert_type}
Risk Level: {business_impact.get('risk_level', 'UNKNOWN')}
Data at Risk: {business_impact.get('data_at_risk', 'Unknown')}

TECHNICAL OVERVIEW:
{tech_overview[:600]}

DETECTION MECHANISM:
{', '.join(detection_mechanism) if detection_mechanism else 'Standard logs'}

MITRE ATT&CK TECHNIQUES:
{mitre_context if mitre_context else 'Not specified'}

THREAT ACTORS:
{actor_context if actor_context else 'Not specified'}

AVAILABLE DATA SOURCES:
{', '.join(data_sources) if data_sources else 'SigninLogs, AuditLogs'}

INVESTIGATION FOCUS AREAS:
{', '.join(investigation_focus) if investigation_focus else 'User activity, Network analysis'}

REQUIRED CHECKS:
{', '.join(required_checks) if required_checks else 'User verification, IP reputation'}

WEB RESEARCH FINDINGS
{guidance[:1500] if guidance else "No web research findings available"}
{separator}

TASK:
Generate a comprehensive investigation workflow with 10-15 steps that a SOC analyst should perform.

STEP GENERATION RULES:
1. Start with SCOPE VERIFICATION (how many users/systems affected)
2. Add USER/ENTITY VERIFICATION (VIP status, role, department)
3. Include DATA COLLECTION from relevant logs (SigninLogs, AuditLogs, etc.)
4. Add THREAT INTELLIGENCE checks (IP reputation, domain reputation)
5. Include BEHAVIORAL ANALYSIS (patterns, anomalies, timeline)
6. Add DEVICE/ENDPOINT checks if relevant
7. Include IDENTITY/ACCESS verification (roles, permissions, MFA)
8. Add CORRELATION steps (cross-reference multiple sources)
9. Include specific checks for EACH MITRE technique identified
10. Add specific checks for threat actor TTPs if identified
11. End with CLASSIFICATION (True Positive vs False Positive determination)

For EACH step, use this EXACT format:

STEP: [Clear action-oriented name starting with a verb like: Verify, Analyze, Check, Review, Investigate, Extract, Query, Assess, Validate, Cross-reference]
EXPLANATION: [2-4 sentences explaining: What to investigate, Why it matters for this specific alert, What specific things to look for, How it helps determine True/False positive]
NEEDS_KQL: [YES if requires querying logs/data sources, NO if manual/tool-based]
DATA_SOURCE: [Exact name: SigninLogs, AuditLogs, DeviceInfo, IdentityInfo, SecurityEvent, CloudAppEvents, or MANUAL for tool-based]
TOOL: [VirusTotal, AbuseIPDB, Manual, None - specify if external tool needed]
PRIORITY: [CRITICAL/HIGH/MEDIUM/LOW - based on investigation importance]
---

Generate ALL steps now. Be specific and thorough:"""

        try:
            agent = Agent(
                role="Senior SOC Investigation Architect",
                goal="Design comprehensive, actionable investigation workflows",
                backstory="""You are an expert SOC analyst with 15+ years of experience. 
                You design thorough investigation playbooks that help analysts quickly determine 
                if an alert is a True Positive requiring escalation or a False Positive that can be closed.
                Your playbooks are detailed, logical, and cover all aspects of the investigation.""",
                llm=self.llm,
                verbose=False,
            )

            task = Task(
                description=prompt,
                expected_output="Structured investigation steps in specified format",
                agent=agent,
            )

            crew = Crew(agents=[agent], tasks=[task], verbose=False)
            result = str(crew.kickoff())

            # Parse LLM output into structured steps
            steps = self._parse_llm_steps(result)

            if len(steps) < 5:
                print(f"   ⚠️ Only {len(steps)} steps generated, trying fallback parser...")
                steps = self._parse_fallback(result)

            return steps

        except Exception as e:
            print(f"   ❌ LLM generation failed: {str(e)[:100]}")
            return []

    def _parse_llm_steps(self, llm_output: str) -> List[Dict]:
        """Parse LLM output into structured step dictionaries"""

        steps = []

        # Split by step separators (--- or ━━━)
        step_blocks = re.split(r'\n[-━]{3,}\n', llm_output)

        for block in step_blocks:
            if not block.strip() or len(block) < 50:
                continue

            # Extract fields using flexible patterns
            step_match = re.search(r'STEP:\s*(.+?)(?:\n|$)', block, re.IGNORECASE)
            exp_match = re.search(
                r'EXPLANATION:\s*(.+?)(?=\n(?:NEEDS_KQL|DATA_SOURCE|TOOL|PRIORITY)|$)', 
                block, 
                re.IGNORECASE | re.DOTALL
            )
            kql_match = re.search(r'NEEDS_KQL:\s*(YES|NO)', block, re.IGNORECASE)
            ds_match = re.search(r'DATA_SOURCE:\s*(.+?)(?:\n|$)', block, re.IGNORECASE)
            tool_match = re.search(r'TOOL:\s*(.+?)(?:\n|$)', block, re.IGNORECASE)
            priority_match = re.search(r'PRIORITY:\s*(CRITICAL|HIGH|MEDIUM|LOW)', block, re.IGNORECASE)

            if step_match and exp_match:
                step_name = step_match.group(1).strip()
                explanation = exp_match.group(1).strip()
                needs_kql = kql_match.group(1).upper() == "YES" if kql_match else True
                data_source = ds_match.group(1).strip() if ds_match else "SigninLogs"
                tool = tool_match.group(1).strip() if tool_match else "None"
                priority = priority_match.group(1).upper() if priority_match else "MEDIUM"

                # Clean up
                step_name = self._clean_text(step_name)
                explanation = self._clean_text(explanation)

                # Validation
                if len(step_name) < 5 or len(explanation) < 20:
                    continue

                # Remove line breaks from explanation
                explanation = re.sub(r'\s+', ' ', explanation)

                steps.append({
                    "step_name": step_name,
                    "explanation": explanation,
                    "kql_needed": needs_kql,
                    "data_source": data_source,
                    "tool": tool.lower() if tool.lower() != "none" else "",
                    "priority": priority,
                    "input_required": "",
                })

        return steps

    def _parse_fallback(self, text: str) -> List[Dict]:
        """Fallback parser if structured format fails"""

        steps = []
        lines = text.split('\n')
        current_step = None
        current_explanation = []

        for line in lines:
            line = line.strip()

            # Check if it's a step header (numbered or keyword-based)
            if re.match(r'^\d+[\.\)]\s+.+|^Step \d+:|^STEP:', line, re.IGNORECASE):
                # Save previous step
                if current_step:
                    explanation_text = ' '.join(current_explanation)
                    if len(explanation_text) > 20:
                        steps.append({
                            "step_name": current_step,
                            "explanation": explanation_text,
                            "kql_needed": True,
                            "data_source": "SigninLogs",
                            "tool": "",
                            "priority": "MEDIUM",
                            "input_required": "",
                        })

                # Start new step
                current_step = re.sub(
                    r'^\d+[\.\)]\s+|^Step \d+:|^STEP:', 
                    '', 
                    line, 
                    flags=re.IGNORECASE
                ).strip()
                current_explanation = []

            elif current_step and line and not line.startswith(('---', '━━━', 'NEEDS_KQL', 'DATA_SOURCE', 'TOOL', 'PRIORITY')):
                current_explanation.append(line)

        # Add last step
        if current_step:
            explanation_text = ' '.join(current_explanation)
            if len(explanation_text) > 20:
                steps.append({
                    "step_name": current_step,
                    "explanation": explanation_text,
                    "kql_needed": True,
                    "data_source": "SigninLogs",
                    "tool": "",
                    "priority": "MEDIUM",
                    "input_required": "",
                })

        return steps

    def _clean_text(self, text: str) -> str:
        """Clean text from artifacts"""

        # Remove quotes
        text = text.strip('"\'`')

        # Remove markdown
        text = re.sub(r'\*\*', '', text)
        text = re.sub(r'__', '', text)
        text = re.sub(r'^\*\s+', '', text)

        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text)

        # Remove common artifacts
        text = re.sub(r'^(Step \d+:|STEP:)', '', text, flags=re.IGNORECASE)

        return text.strip()
