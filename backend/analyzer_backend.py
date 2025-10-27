import os
import re
import time
from typing import Dict
from crewai_tools import SerperDevTool
from crewai import Agent, Task, Crew, Process, LLM

# Configuration
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
SERPER_API_KEY = os.getenv("SERPER_API_KEY")
USE_OLLAMA = os.getenv("USE_OLLAMA", "false").lower() == "true"
OLLAMA_CHAT = os.getenv("OLLAMA_CHAT", "qwen2.5:3b")


class SecurityAlertAnalyzerCrew:
    """Backend service for security alert analysis using CrewAI with Google Gemini or Ollama"""

    def __init__(self):
        # Initialize LLM based on configuration
        if USE_OLLAMA:
            print("Using OLLAMA", OLLAMA_CHAT)
            self.llm = LLM(
                model=f"ollama/{OLLAMA_CHAT}", base_url="http://localhost:11434"
            )
        else:
            print("Using GEMINI")
            if not GOOGLE_API_KEY:
                raise ValueError("GOOGLE_API_KEY environment variable must be set")
            # Add rate limit handling to LiteLLM config
            self.llm = LLM(
                model="gemini/gemini-2.5-flash",
                temperature=0.7,
                api_key=GOOGLE_API_KEY,
                timeout=60,
                max_retries=3,  # Enable retries
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
            verbose=False,
            allow_delegation=False,
            max_iter=5,  # Reduced iterations to reduce API calls
        )
        return {"threat_intel": threat_intel_agent}

    def _create_tasks(self, alert_name: str, agents: Dict[str, Agent]):
        """Create focused task for security alert analysis"""
        threat_intel_task = Task(
            description=f"""Analyze the security alert: {alert_name}

Provide analysis in the following sections:

1. TECHNICAL OVERVIEW (2-3 sentences)
- What this alert detects
- Key detection mechanism
- Normal vs suspicious behavior

2. MITRE ATT&CK TECHNIQUES (3 techniques max)
For each: ID, Name, Overview, Relevance, Key Indicators

3. THREAT ACTORS (2-3 actors, use web search)
For each: Name, Profile, TTPs, Notable Attack, Relevance

4. BUSINESS IMPACT
- Data at Risk
- Compliance implications
- Reputation Impact
- Risk Level: CRITICAL/HIGH/MEDIUM/LOW with rationale

Keep all sections brief and actionable. No placeholder text.""",
            agent=agents["threat_intel"],
            expected_output="""Complete security analysis with all four sections. 
            Actionable and readable in under 2 minutes.""",
        )
        return [threat_intel_task]

    def analyze_alert(self, alert_name: str, max_retries: int = 3) -> str:
        """
        Analyze alert with retry logic for rate limiting

        Args:
            alert_name: Name of the alert to analyze
            max_retries: Maximum number of retry attempts (default: 3)

        Returns:
            Analysis text

        Raises:
            Exception: If analysis fails after all retries
        """
        last_error = None

        for attempt in range(max_retries):
            try:
                print(
                    f"Analyzing alert: {alert_name} (Attempt {attempt + 1}/{max_retries})"
                )

                agents = self._create_agents()
                tasks = self._create_tasks(alert_name, agents)

                crew = Crew(
                    agents=list(agents.values()),
                    tasks=tasks,
                    process=Process.sequential,
                    verbose=False,
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
                last_error = e
                error_str = str(e).lower()

                # Check if it's a rate limit error
                if (
                    "429" in str(e)
                    or "rate limit" in error_str
                    or "too many requests" in error_str
                ):
                    wait_time = min(
                        2**attempt * 5, 60
                    )  # Exponential backoff: 5s, 10s, 20s, 60s max
                    print(
                        f"Rate limit hit. Waiting {wait_time} seconds before retry..."
                    )
                    time.sleep(wait_time)
                    continue
                else:
                    # Not a rate limit error, re-raise immediately
                    raise

        # All retries failed
        raise Exception(
            f"Failed to analyze alert after {max_retries} attempts. Last error: {str(last_error)}"
        )
