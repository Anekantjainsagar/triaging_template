import os
import re
from typing import Dict
from crewai_tools import SerperDevTool
from crewai import Agent, Task, Crew, Process, LLM

# Configuration
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
SERPER_API_KEY = os.getenv("SERPER_API_KEY")
USE_OLLAMA = os.getenv("USE_OLLAMA", "false").lower() == "true"
OLLAMA_CHAT = os.getenv("OLLAMA_CHAT", "qwen2.5:0.5b")


class SecurityAlertAnalyzerCrew:
    """Backend service for security alert analysis using CrewAI with Google Gemini or Ollama"""

    def __init__(self):
        # Initialize LLM based on configuration
        
        if USE_OLLAMA:
            # Use Ollama
            print("Using OLLAMA", OLLAMA_CHAT)
            self.llm = LLM(
                model=f"ollama/{OLLAMA_CHAT}", base_url="http://localhost:11434"
            )
        else:
            # Use Google Gemini
            print("Using GEMINI")
            if not GOOGLE_API_KEY:
                raise ValueError("GOOGLE_API_KEY environment variable must be set")
            self.llm = LLM(
                model="gemini/gemini-2.5-flash", temperature=0.7, api_key=GOOGLE_API_KEY
            )

        print(self.llm, USE_OLLAMA)
        self.search_tool = (
            SerperDevTool(api_key=SERPER_API_KEY) if SERPER_API_KEY else None
        )

    def _clean_output(self, text: str) -> str:
        """Clean and deduplicate the LLM output"""
        patterns_to_remove = [
            r"Final Answer[\s\S]*?(?=##|$)",
            r"Action Input:[\s\S]*?(?=##|$)",
            r"Observation:[\s\S]*?(?=##|$)",
            r"Thought:[\s\S]*?(?=##|$)",
            r"Action:[\s\S]*?(?=##|$)",
            r'\{[\s\S]*?"Tool Name"[\s\S]*?\}',
            r"Search the internet with Serper",
        ]

        cleaned = text
        for pattern in patterns_to_remove:
            cleaned = re.sub(pattern, "", cleaned, flags=re.IGNORECASE)

        cleaned = re.sub(
            r"#+\s*Immediate Actions[\s\S]*?(?=##|\Z)", "", cleaned, flags=re.IGNORECASE
        )

        sections = re.split(r"(## .+)", cleaned)
        seen_sections = {}
        result_parts = []

        for i, part in enumerate(sections):
            if part.strip():
                if part.startswith("##"):
                    section_name = part.strip().lower()
                    if section_name not in seen_sections:
                        seen_sections[section_name] = True
                        result_parts.append(part)
                        if i + 1 < len(sections):
                            result_parts.append(sections[i + 1])
                else:
                    if i > 0 and sections[i - 1].startswith("##"):
                        continue
                    elif i == 0:
                        result_parts.append(part)

        cleaned = "".join(result_parts)
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
        return cleaned.strip()

    def _create_agents(self) -> Dict[str, Agent]:
        """Create specialized agents for different analysis aspects"""
        threat_intel_agent = Agent(
            role="Senior SOC Analyst",
            goal="Deliver concise, actionable security analysis focused on what matters",
            backstory="""You are a senior SOC analyst who excels at cutting through noise 
            to deliver clear, actionable intelligence. You focus only on essential information 
            that security teams need to respond effectively.
            
            CORE PRINCIPLES:
            - Brevity is key - remove all fluff
            - Focus on actionable intelligence only
            - NO placeholder text ever
            - Use web search for threat actor data
            - Remove all meta-text""",
            tools=([self.search_tool] if self.search_tool else []),
            llm=self.llm,
            verbose=True,
            allow_delegation=False,
            max_iter=12,
        )
        return {"threat_intel": threat_intel_agent}

    def _create_tasks(self, alert_name: str, agents: Dict[str, Agent]):
        """Create focused task for security alert analysis"""
        threat_intel_task = Task(
            description=f"""Analyze: {alert_name}

REQUIREMENTS:
- NO placeholders
- Use web search for threat actors
- Keep sections brief
- NO meta-text

═══════════════════════════════════════════════════════════════

## TECHNICAL OVERVIEW

Write 2-3 sentences covering:
- What this alert detects
- Key detection mechanism (event IDs, protocols)
- Normal vs suspicious behavior

═══════════════════════════════════════════════════════════════

## MITRE ATT&CK TECHNIQUES

**What is MITRE ATT&CK?**
MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. It provides a common language for describing cyber threats and helps security teams understand attacker behavior patterns.

**Why It Matters:**
Understanding the MITRE ATT&CK techniques associated with this alert enables security teams to anticipate attacker next steps, identify gaps in defenses, and prioritize detection and response efforts based on proven attack patterns used by threat actors worldwide.

Provide EXACTLY 3 most relevant techniques:

### T[ID] - [Name]

**Overview:** (2 sentences on the attack method)

**Relevance:** (1-2 sentences on connection to this alert)

**Indicators:**
- Key indicator 1
- Key indicator 2

═══════════════════════════════════════════════════════════════

## THREAT ACTORS

**What are Threat Actors?**
Threat actors are individuals, groups, or nation-states that conduct malicious cyber activities. They range from sophisticated state-sponsored APT groups to organized cybercrime syndicates, each with distinct motivations, capabilities, and targeting patterns.

**Why It Matters:**
Identifying threat actors associated with this alert helps organizations understand attacker motivations, predict future tactics, assess risk severity, and implement targeted defenses. Knowing who might use these techniques enables proactive threat hunting and informed security investment decisions.


Provide 2-3 most relevant actors. USE WEB SEARCH.

### [Name] ([Main Alias])

**Profile:** [Nation/Type] | Active since [Year] | Targets: [Sectors]

**Key TTPs:** T[ID], T[ID], T[ID]

**Notable Attack:** [One major campaign with year and impact]

**Why it is Relevant:** (1 sentence on why this alert matters for this actor)

═══════════════════════════════════════════════════════════════

## BUSINESS IMPACT

### Risk Assessment

**Data at Risk:** [Types: PII, PHI, financial, IP]

**Compliance:**
- GDPR: Up to €20M or 4%
- HIPAA: $100-$50K per violation
- PCI-DSS: Fines + audits

**Reputation Impact:** [Expected customer/market impact]

### Overall Risk: [CRITICAL/HIGH/MEDIUM/LOW]

**Rationale:** (2-3 sentences justifying the rating based on likelihood and impact)

═══════════════════════════════════════════════════════════════

FINAL CHECK:
✅ No placeholders?
✅ Concise and scannable?
✅ Searched for threat actors?
✅ All sections under 5 sentences?""",
            agent=agents["threat_intel"],
            expected_output="""Brief, actionable analysis with all sections complete. 
            Total output should be readable in under 2 minutes.""",
        )
        return [threat_intel_task]

    def analyze_alert(self, alert_name: str) -> str:
        try:
            agents = self._create_agents()
            tasks = self._create_tasks(alert_name, agents)

            crew = Crew(
                agents=list(agents.values()),
                tasks=tasks,
                process=Process.sequential,
                verbose=True,
            )

            result = crew.kickoff()

            if hasattr(result, "raw"):
                analysis_text = str(result.raw)
            elif hasattr(result, "output"):
                analysis_text = str(result.output)
            elif hasattr(result, "__str__"):
                analysis_text = str(result)
            else:
                analysis_text = repr(result)

            analysis_text = self._clean_output(analysis_text)

            if not analysis_text.startswith("#"):
                analysis_text = f"## Security Alert Analysis\n\n{analysis_text}"

            return analysis_text

        except Exception as e:
            raise Exception(str(e))
