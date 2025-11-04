import os
import re
import time
import logging
from crewai_tools import SerperDevTool
from typing import Dict, Optional, Tuple
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
    """Backend service for security alert analysis with robust output cleaning"""

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
        """Calculate exponential backoff"""
        base_delay = RETRY_DELAY
        max_delay = 60
        delay = min(base_delay * (2**attempt) + attempt, max_delay)
        return delay

    def _normalize_final_output(self, text: str) -> str:
        """Final normalization pass to ensure perfect formatting"""
        # Remove any remaining prefixes
        text = re.sub(r"^.*?(?=##|\d+\.)", "", text, flags=re.DOTALL).strip()

        # Ensure consistent header format
        lines = []
        for line in text.split("\n"):
            # Convert numbered sections to headers if not already
            if re.match(
                r"^\s*\d+\.\s+[A-Z][A-Z\s&/()-]+", line
            ) and not line.startswith("##"):
                line = "## " + line.strip()
            lines.append(line)

        return "\n".join(lines).strip()

    def _clean_output(self, text: str) -> str:
        """
        Aggressively clean LLM output to ensure consistent structure
        """
        if not text or not text.strip():
            return ""

        original_text = text

        # STEP 1: Find LAST occurrence of structured content
        sections_pattern = r"((?:^|\n)\s*1\.\s+TECHNICAL OVERVIEW.*?)(?=\n\s*(?:Thought:|Action:|I now|Based on|$))"
        matches = list(re.finditer(sections_pattern, text, re.IGNORECASE | re.DOTALL))

        if matches:
            text = matches[-1].group(1)
            logger.info("✅ Extracted final structured content")
        else:
            logger.warning("⚠️ Using fallback extraction")
            text = self._extract_structured_content(original_text)

        # STEP 2: Remove ALL agent metadata
        metadata_patterns = [
            r"Thought:.*?(?=\n|\Z)",
            r"Action:.*?(?=\n|\Z)",
            r"Action Input:.*?(?=\n|\Z)",
            r"Observation:.*?(?=\n|\Z)",
            r"Tool Args:.*?(?=\n|\Z)",
            r"Using Tool:.*?(?=\n|\Z)",
            r"Final Answer:",
            r"I now (?:can give|have).*?(?=\n|\Z)",
            r"Based on.*?(?=\n|\Z)",
            r"Let me.*?(?=\n|\Z)",
            r"I will.*?(?=\n|\Z)",
            r"I have.*?(?=\n|\Z)",
            r"\[.*?\]:\s*",
            r"Security Alert\s*Now\s*",
        ]

        for pattern in metadata_patterns:
            text = re.sub(pattern, "", text, flags=re.IGNORECASE | re.MULTILINE)

        # STEP 3: Format section headers
        text = re.sub(
            r"(?:^|\n)\s*(\d+)\.\s+(TECHNICAL OVERVIEW|MITRE ATT&CK TECHNIQUES?|THREAT ACTORS?|BUSINESS IMPACT ASSESSMENT)\s*:?\s*\n",
            r"\n## \1. \2\n\n",
            text,
            flags=re.IGNORECASE | re.MULTILINE,
        )

        # STEP 4: Standardize bullets
        text = re.sub(r"\n\s*[•●◦▪▫]\s+", "\n- ", text)
        text = re.sub(r"\n\s*[-*]\s+", "\n- ", text)

        # STEP 5: Clean bold formatting
        text = re.sub(r"\n\s*\*\*([^*]+)\*\*\s*:\s*", r"\n**\1:** ", text)

        # STEP 6: Remove duplicate lines
        lines = text.split("\n")
        seen = set()
        unique_lines = []

        for line in lines:
            if line.startswith("##") or not line.strip():
                unique_lines.append(line)
            else:
                line_norm = re.sub(r"\s+", " ", line.strip().lower())
                if line_norm not in seen or len(line_norm) < 20:
                    seen.add(line_norm)
                    unique_lines.append(line)

        text = "\n".join(unique_lines)

        # STEP 7: Clean whitespace
        text = re.sub(r"\n{3,}", "\n\n", text)
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n\s+\n", "\n\n", text)

        # STEP 8: Spacing after headers
        text = re.sub(r"(##[^\n]+)\n([^\n#])", r"\1\n\n\2", text)

        # STEP 9: Final normalization
        text = text.strip()
        text = self._normalize_final_output(text)

        # STEP 10: Validation
        if not self._validate_output_structure(text):
            logger.error("❌ Validation failed, using fallback")
            text = self._extract_structured_content(original_text)
            text = self._normalize_final_output(text)

        return text

    def _extract_structured_content(self, text: str) -> str:
        """Emergency fallback extraction"""
        sections = []

        section_markers = [
            (r"1\.\s+TECHNICAL OVERVIEW", "## 1. TECHNICAL OVERVIEW"),
            (r"2\.\s+MITRE ATT&CK TECHNIQUES?", "## 2. MITRE ATT&CK TECHNIQUES"),
            (r"3\.\s+THREAT ACTORS?", "## 3. THREAT ACTORS"),
            (r"4\.\s+BUSINESS IMPACT ASSESSMENT", "## 4. BUSINESS IMPACT ASSESSMENT"),
        ]

        for i, (pattern, header) in enumerate(section_markers):
            start_match = re.search(pattern, text, re.IGNORECASE)
            if not start_match:
                continue

            start_pos = start_match.end()

            if i < len(section_markers) - 1:
                next_pattern = section_markers[i + 1][0]
                end_match = re.search(next_pattern, text[start_pos:], re.IGNORECASE)
                end_pos = start_pos + end_match.start() if end_match else len(text)
            else:
                end_match = re.search(
                    r"\n(?:Thought:|Action:|I now|Based on)",
                    text[start_pos:],
                    re.IGNORECASE,
                )
                end_pos = start_pos + end_match.start() if end_match else len(text)

            section_content = text[start_pos:end_pos].strip()

            # Clean metadata from section
            section_content = re.sub(
                r"Thought:.*?(?=\n|\Z)",
                "",
                section_content,
                flags=re.IGNORECASE | re.MULTILINE,
            )
            section_content = re.sub(
                r"Action:.*?(?=\n|\Z)",
                "",
                section_content,
                flags=re.IGNORECASE | re.MULTILINE,
            )
            section_content = re.sub(
                r"(?:I now|Based on|Let me).*?(?=\n|\Z)",
                "",
                section_content,
                flags=re.IGNORECASE | re.MULTILINE,
            )
            section_content = section_content.strip()

            if section_content and len(section_content) > 20:
                sections.append(f"{header}\n\n{section_content}")

        if sections:
            return "\n\n".join(sections)

        # Ultimate fallback
        cleaned = re.sub(
            r"(?:Thought|Action|Observation):.*?(?=\n|\Z)",
            "",
            text,
            flags=re.IGNORECASE | re.MULTILINE,
        )
        return cleaned.strip()

    def _validate_output_structure(self, text: str) -> bool:
        """Strict validation"""
        if not text or len(text.strip()) < 200:
            logger.warning("⚠️ Output too short")
            return False

        required_headers = [
            r"##\s*1\.\s*TECHNICAL OVERVIEW",
            r"##\s*2\.\s*MITRE ATT&CK",
            r"##\s*3\.\s*THREAT ACTOR",
            r"##\s*4\.\s*BUSINESS IMPACT",
        ]

        found_count = sum(
            1 for h in required_headers if re.search(h, text, re.IGNORECASE)
        )

        # Check for metadata
        if re.search(r"(?:Thought|Action|Observation):", text, re.IGNORECASE):
            logger.warning("⚠️ Agent metadata still present")
            return False

        is_valid = found_count >= 3
        if not is_valid:
            logger.warning(f"⚠️ Only {found_count}/4 sections found")

        return is_valid

    def _create_agents(self, llm: LLM) -> Dict[str, Agent]:
        """Create agents"""
        threat_intel_agent = Agent(
            role="Senior SOC Analyst",
            goal="Deliver structured security analysis in exact format specified",
            backstory="""Expert SOC analyst specializing in MITRE ATT&CK mapping, 
            threat actor profiling, and business impact assessment. You provide 
            clear, structured analysis without any meta-commentary or reasoning traces.""",
            tools=([self.search_tool] if self.search_tool else []),
            llm=llm,
            verbose=False,  # Reduce output noise
            allow_delegation=False,
            max_iter=3,
        )
        return {"threat_intel": threat_intel_agent}

    def _create_tasks(self, alert_name: str, agents: Dict[str, Agent]):
        """Create task with strict template"""
        threat_intel_task = Task(
            description=f"""Analyze: '{alert_name}'

STRICT FORMAT - Follow EXACTLY:

1. TECHNICAL OVERVIEW
[2-3 sentences about the threat, detection mechanism, and affected systems]

2. MITRE ATT&CK TECHNIQUES
- [T####] Technique Name - Why it's relevant to this alert
- [T####] Another Technique - Why it's relevant
- [T####] Third Technique - Why it's relevant

3. THREAT ACTORS
- Actor Name - Primary TTPs - How this alert relates to their activity
- Another Actor - Primary TTPs - How this alert relates to their activity

4. BUSINESS IMPACT ASSESSMENT
- **Data at Risk:** Specific data and systems
- **Compliance Implications:** Relevant regulations (GDPR, HIPAA, etc.)
- **Risk Level:** CRITICAL/HIGH/MEDIUM/LOW - Brief justification
- **Business Context:** Operational and financial impact

RULES:
- NO "Thought:", "Action:", or meta-commentary
- NO reasoning process or internal notes
- ONLY provide the structured analysis above
- Use exact section numbering and names""",
            agent=agents["threat_intel"],
            expected_output="Structured 4-section analysis with headers: 1. TECHNICAL OVERVIEW, 2. MITRE ATT&CK TECHNIQUES, 3. THREAT ACTORS, 4. BUSINESS IMPACT ASSESSMENT",
        )
        return [threat_intel_task]

    def _analyze_with_llm(
        self, alert_name: str, llm: LLM, provider_name: str
    ) -> Tuple[bool, Optional[str], Optional[Exception]]:
        """Execute analysis"""
        try:
            logger.info(f"Analyzing with {provider_name}...")

            agents = self._create_agents(llm)
            tasks = self._create_tasks(alert_name, agents)

            crew = Crew(
                agents=list(agents.values()),
                tasks=tasks,
                process=Process.sequential,
                verbose=False,  # Disable verbose
                memory=False,
            )

            result = crew.kickoff()

            # Extract output
            if hasattr(result, "raw"):
                analysis_text = str(result.raw)
            elif hasattr(result, "output"):
                analysis_text = str(result.output)
            else:
                analysis_text = str(result)

            logger.info(f"📝 Raw: {len(analysis_text)} chars")

            # Clean
            analysis_text = self._clean_output(analysis_text)

            logger.info(f"✨ Cleaned: {len(analysis_text)} chars")

            # Add title
            if not analysis_text.startswith("#"):
                analysis_text = (
                    f"## Security Alert Analysis: {alert_name}\n\n{analysis_text}"
                )

            return True, analysis_text, None

        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            return False, None, e

    def analyze_alert(self, alert_name: str) -> str:
        """Main analysis method with fallback"""
        if not alert_name or not alert_name.strip():
            raise ValueError("Alert name cannot be empty")

        last_error = None

        for attempt in range(MAX_RETRIES):
            try:
                logger.info(
                    f"🔍 Analyzing '{alert_name}' with {self.current_provider.upper()} "
                    f"(Attempt {attempt + 1}/{MAX_RETRIES})"
                )

                success, result, error = self._analyze_with_llm(
                    alert_name, self.primary_llm, self.current_provider
                )

                if success and self._validate_output_structure(result):
                    logger.info(f"✅ Success with {self.current_provider.upper()}")
                    return result

                if success:
                    logger.warning("⚠️ Output validation failed, retrying...")
                    last_error = Exception("Output validation failed")
                else:
                    last_error = error

                if self._should_fallback(error if error else last_error, attempt):
                    logger.info("🔄 Triggering fallback...")
                    break

                if attempt < MAX_RETRIES - 1:
                    backoff = self._calculate_backoff(attempt)
                    logger.info(f"⏳ Waiting {backoff}s...")
                    time.sleep(backoff)

            except Exception as e:
                last_error = e
                logger.error(f"Attempt {attempt + 1} failed: {str(e)}")

                if self._should_fallback(e, attempt):
                    break

                if attempt < MAX_RETRIES - 1:
                    time.sleep(self._calculate_backoff(attempt))

        # Fallback to Ollama
        if self.fallback_llm:
            logger.info("🔄 Falling back to Ollama...")
            try:
                success, result, error = self._analyze_with_llm(
                    alert_name, self.fallback_llm, "ollama"
                )

                if success and self._validate_output_structure(result):
                    logger.info("✅ Success with Ollama (fallback)")
                    result = f"{result}\n\n*Note: Generated using Ollama fallback.*"
                    return result

                last_error = error or Exception("Ollama validation failed")

            except Exception as e:
                last_error = e
                logger.error(f"❌ Ollama fallback failed: {str(e)}")

        # All attempts failed
        error_detail = str(last_error) if last_error else "Unknown error"
        logger.error(f"❌ All attempts failed: {error_detail}")

        raise Exception(f"Analysis failed after {MAX_RETRIES} attempts: {error_detail}")
