import os
import re
import time
import logging
from typing import Dict, Optional, Tuple
from crewai_tools import SerperDevTool
from crewai import Agent, Task, Crew, Process, LLM

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
SERPER_API_KEY = os.getenv("SERPER_API_KEY")
USE_OLLAMA = os.getenv("USE_OLLAMA", "false").lower() == "true"
OLLAMA_CHAT = os.getenv("OLLAMA_CHAT", "qwen2.5:3b")
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "2"))
RETRY_DELAY = int(os.getenv("RETRY_DELAY", "3"))
ENABLE_FALLBACK = os.getenv("ENABLE_FALLBACK", "true").lower() == "true"


class SecurityAlertAnalyzerCrew:
    """Backend service for security alert analysis with Gemini -> Ollama fallback"""

    def __init__(self):
        """Initialize with resilient LLM configuration"""
        self.primary_llm = None
        self.fallback_llm = None
        self.search_tool = None
        self.current_provider = None
        self._initialize_llms()

    def _initialize_llms(self):
        """Initialize both Gemini and Ollama LLMs"""
        try:
            if USE_OLLAMA:
                logger.info("Primary: Ollama (as configured)")
                self.primary_llm = self._create_ollama_llm()
                self.current_provider = "ollama"
                self.fallback_llm = None
            else:
                logger.info("Primary: Gemini, Fallback: Ollama")
                self.primary_llm = self._create_gemini_llm()
                self.current_provider = "gemini"

                if ENABLE_FALLBACK:
                    try:
                        self.fallback_llm = self._create_ollama_llm()
                        logger.info("✅ Fallback Ollama LLM initialized")
                    except Exception as e:
                        logger.warning(f"⚠️ Fallback Ollama not available: {str(e)}")
                        self.fallback_llm = None

            if SERPER_API_KEY:
                self.search_tool = SerperDevTool(api_key=SERPER_API_KEY)
                logger.info("Search tool initialized")

        except Exception as e:
            logger.error(f"Failed to initialize LLMs: {str(e)}")
            raise

    def _create_gemini_llm(self) -> LLM:
        """Create Gemini LLM instance"""
        if not GOOGLE_API_KEY:
            raise ValueError("GOOGLE_API_KEY environment variable not set")

        return LLM(
            model="gemini/gemini-2.5-flash",
            temperature=0.7,
            api_key=GOOGLE_API_KEY,
            timeout=90,
            max_retries=1,
        )

    def _create_ollama_llm(self) -> LLM:
        """Create Ollama LLM instance"""
        return LLM(
            model=f"ollama/{OLLAMA_CHAT}",
            base_url="http://localhost:11434",
            temperature=0.7,
        )

    def _is_gemini_error(self, error: Exception) -> bool:
        """Detect if error is from Gemini API"""
        error_str = str(error).lower()
        gemini_indicators = [
            "503",
            "service unavailable",
            "overloaded",
            "vertex",
            "gemini",
            "generativelanguage",
            "quota exceeded",
            "rate limit",
            "429",
        ]
        return any(indicator in error_str for indicator in gemini_indicators)

    def _should_fallback(self, error: Exception, attempt: int) -> bool:
        """Determine if we should fallback to Ollama"""
        if not ENABLE_FALLBACK or self.fallback_llm is None:
            return False

        if self._is_gemini_error(error) and attempt >= 1:
            return True

        return False

    def _calculate_backoff(self, attempt: int) -> int:
        """Calculate exponential backoff with jitter"""
        base_delay = RETRY_DELAY
        max_delay = 60
        delay = min(base_delay * (2**attempt) + attempt, max_delay)
        return delay

    def _clean_output(self, text: str) -> str:
        """Clean LLM output - simplified to preserve content"""

        # Extract just the analysis content
        # Look for patterns like "Final Answer:" followed by actual content
        if "Final Answer:" in text:
            # Split at Final Answer and take everything after
            parts = text.split("Final Answer:", 1)
            if len(parts) > 1:
                text = parts[1]

        # Remove common LLM metadata patterns
        patterns_to_remove = [
            r"^Thought:.*?(?=\n[A-Z]|\n##|\n\d+\.)",  # Remove "Thought:" lines
            r"Action:.*?(?=\n)",  # Remove action lines
            r"Action Input:.*?(?=\n)",
            r"Observation:.*?(?=\n)",
            r"Tool Args:.*?(?=\n)",
            r"Using Tool:.*?(?=\n)",
        ]

        for pattern in patterns_to_remove:
            text = re.sub(pattern, "", text, flags=re.IGNORECASE | re.DOTALL)

        # Clean up excessive whitespace
        text = re.sub(r"\n{3,}", "\n\n", text)
        text = text.strip()

        # Ensure proper markdown headers for main sections
        # Add ## before numbered sections if not present
        text = re.sub(r"\n(\d+\.\s+[A-Z][A-Z\s]+)\n", r"\n## \1\n", text)

        # Fix list formatting
        text = re.sub(r"\n-\s+", "\n- ", text)
        text = re.sub(r"\n\*\s+", "\n- ", text)

        return text.strip()

    def _create_agents(self, llm: LLM) -> Dict[str, Agent]:
        """Create specialized agents for analysis with specified LLM"""
        threat_intel_agent = Agent(
            role="Senior SOC Analyst",
            goal="Deliver concise, actionable security analysis with tactical and strategic insights",
            backstory="""You are an experienced Senior Security Operations Center (SOC) analyst 
            with 10+ years of expertise in threat intelligence, incident response, and security 
            architecture. Your specialty is distilling complex security events into clear, 
            actionable intelligence that enables security teams to respond swiftly and effectively.
            
            YOUR EXPERTISE INCLUDES:
            - MITRE ATT&CK framework mapping and tactical analysis
            - Threat actor profiling and attribution
            - Vulnerability assessment and exploit analysis
            - Security incident triage and risk prioritization
            - Compliance and regulatory impact evaluation
            
            CORE PRINCIPLES FOR ANALYSIS:
            - Brevity is essential: remove all unnecessary information and filler
            - Focus exclusively on actionable intelligence that drives response decisions
            - NEVER include placeholder text, meta-commentary, or internal reasoning
            - Remove all tool outputs, reasoning traces, and technical scaffolding
            - Be direct, clear, and professionally authoritative
            - Provide context that helps security teams understand threat implications
            - Prioritize high-impact information first""",
            tools=([self.search_tool] if self.search_tool else []),
            llm=llm,
            verbose=True,
            allow_delegation=False,
            max_iter=3,
        )
        return {"threat_intel": threat_intel_agent}

    def _create_tasks(self, alert_name: str, agents: Dict[str, Agent]):
        """Create focused task for security alert analysis"""
        threat_intel_task = Task(
            description=f"""Analyze the security alert: '{alert_name}'

You are analyzing a critical security alert that requires comprehensive threat intelligence 
assessment. Provide a structured analysis using the following sections:

1. TECHNICAL OVERVIEW (2-3 sentences maximum)
   - Clearly explain what specific security threat or vulnerability this alert detects
   - Describe the primary detection mechanism or the technical indicator being monitored
   - Include relevant technical context (e.g., protocol, service, or component affected)

2. MITRE ATT&CK TECHNIQUES (2-3 most relevant techniques)
   Format each as: [Technique ID] Technique Name - Brief explanation of relevance
   - Select techniques that directly correspond to the alert's detection criteria
   - Explain why each technique is relevant to this alert
   - Consider the entire attack chain if applicable

3. THREAT ACTORS (2 known threat actors or groups)
   Format each as: Actor Name - Primary TTPs (Tactics/Techniques) - Relevance to alert
   - Research and identify threat groups known to use techniques detected by this alert
   - Describe their typical tactics, techniques, and procedures (TTPs)
   - Explain how this alert might indicate their activity
   - Use search capabilities if available to find current threat intelligence

4. BUSINESS IMPACT ASSESSMENT
   - Data at Risk: Specify types of data and systems potentially compromised
   - Compliance Implications: Reference relevant standards (GDPR, HIPAA, PCI-DSS, etc.)
   - Risk Level: Assign CRITICAL, HIGH, MEDIUM, or LOW with justification
   - Business Context: Explain potential operational and financial impact

CRITICAL GUIDELINES:
- Keep all sections brief and focused on actionable insights
- Exclude any meta-text, internal reasoning, or tool usage descriptions
- Do not include preliminary analysis or working notes
- Provide only the final, polished analysis
- Use professional security terminology appropriately
- Ensure all sections are complete and provide value to a security team""",
            agent=agents["threat_intel"],
            expected_output="Complete, professional security analysis covering all four sections with clear, actionable intelligence",
        )
        return [threat_intel_task]

    def _analyze_with_llm(
        self, alert_name: str, llm: LLM, provider_name: str
    ) -> Tuple[bool, Optional[str], Optional[Exception]]:
        """
        Execute analysis with specified LLM

        Returns:
            Tuple of (success, result, error)
        """
        try:
            logger.info(f"Analyzing with {provider_name}...")

            agents = self._create_agents(llm)
            tasks = self._create_tasks(alert_name, agents)

            crew = Crew(
                agents=list(agents.values()),
                tasks=tasks,
                process=Process.sequential,
                verbose=True,
                memory=False,
            )

            result = crew.kickoff()

            if hasattr(result, "raw"):
                analysis_text = str(result.raw)
            elif hasattr(result, "output"):
                analysis_text = str(result.output)
            else:
                analysis_text = str(result)

            analysis_text = self._clean_output(analysis_text)

            if not analysis_text.startswith("#"):
                analysis_text = (
                    f"## Security Alert Analysis: {alert_name}\n\n{analysis_text}"
                )

            return True, analysis_text, None

        except Exception as e:
            return False, None, e

    def analyze_alert(self, alert_name: str) -> str:
        """
        Analyze alert with automatic Gemini -> Ollama fallback

        Args:
            alert_name: Name of the alert to analyze

        Returns:
            Analysis text

        Raises:
            Exception: If all attempts (including fallback) fail
        """
        if not alert_name or not alert_name.strip():
            raise ValueError("Alert name cannot be empty")

        last_error = None
        used_fallback = False

        for attempt in range(MAX_RETRIES):
            try:
                logger.info(
                    f"🔍 Analyzing '{alert_name}' with {self.current_provider.upper()} "
                    f"(Attempt {attempt + 1}/{MAX_RETRIES})"
                )

                success, result, error = self._analyze_with_llm(
                    alert_name, self.primary_llm, self.current_provider
                )

                if success:
                    logger.info(
                        f"✅ Analysis completed with {self.current_provider.upper()}"
                    )
                    return result

                last_error = error

                if self._should_fallback(error, attempt):
                    logger.warning(
                        f"⚠️ {self.current_provider.upper()} failed: {str(error)}"
                    )
                    logger.info("🔄 Attempting fallback to Ollama...")
                    break

                if attempt < MAX_RETRIES - 1:
                    backoff_time = self._calculate_backoff(attempt)
                    logger.info(f"⏳ Waiting {backoff_time}s before retry...")
                    time.sleep(backoff_time)

            except Exception as e:
                last_error = e
                logger.error(f"Attempt {attempt + 1} failed: {str(e)}")

                if self._should_fallback(e, attempt):
                    logger.info("🔄 Triggering fallback to Ollama...")
                    break

                if attempt < MAX_RETRIES - 1:
                    time.sleep(self._calculate_backoff(attempt))

        if self.fallback_llm and not used_fallback:
            logger.info("🔄 Falling back to Ollama...")

            try:
                success, result, error = self._analyze_with_llm(
                    alert_name, self.fallback_llm, "ollama"
                )

                if success:
                    logger.info("✅ Analysis completed with Ollama (fallback)")
                    result = (
                        f"{result}\n\n"
                        f"*Note: This analysis was generated using Ollama "
                        f"due to temporary unavailability of the primary AI service.*"
                    )
                    return result
                else:
                    last_error = error
                    logger.error(f"❌ Ollama fallback also failed: {str(error)}")

            except Exception as e:
                last_error = e
                logger.error(f"❌ Ollama fallback failed: {str(e)}")

        error_detail = str(last_error) if last_error else "Unknown error"
        logger.error(f"❌ Failed to analyze alert after all attempts: {error_detail}")

        if self.fallback_llm is None and self.current_provider == "gemini":
            error_msg = (
                f"Analysis failed after {MAX_RETRIES} attempts. "
                f"Gemini API is overloaded/unavailable. "
                f"To enable Ollama fallback, ensure Ollama is running locally. "
                f"Error: {error_detail}"
            )
        else:
            error_msg = (
                f"Analysis failed after {MAX_RETRIES} attempts (including fallback). "
                f"Both Gemini and Ollama are unavailable. "
                f"Error: {error_detail}"
            )

        raise Exception(error_msg)
