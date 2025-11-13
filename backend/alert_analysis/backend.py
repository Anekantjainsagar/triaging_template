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
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
SERPER_API_KEY = os.getenv("SERPER_API_KEY")
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "2"))  # Reduced since we have fallback
RETRY_DELAY = int(os.getenv("RETRY_DELAY", "5"))


class SecurityAlertAnalyzerCrew:
    """Backend service for security alert analysis using Gemini only"""

    def __init__(self):
        """Initialize with Gemini primary and Groq fallback"""
        self.primary_llm = None
        self.fallback_llm = None
        self.search_tool = None
        self._initialize_llms()

    def _initialize_llms(self):
        """Initialize Gemini primary and Groq fallback"""
        try:
            logger.info("Initializing Primary: Gemini, Fallback: Groq")
            self.primary_llm = self._create_gemini_llm()
            
            if GROQ_API_KEY:
                self.fallback_llm = self._create_groq_llm()
                logger.info("✅ Groq fallback initialized")
            else:
                logger.warning("⚠️ No Groq API key - no fallback available")

            if SERPER_API_KEY:
                self.search_tool = SerperDevTool(api_key=SERPER_API_KEY)
                logger.info("Search tool initialized")

        except Exception as e:
            logger.error(f"Failed to initialize LLM: {str(e)}")
            raise

    def _create_gemini_llm(self) -> LLM:
        """Create Gemini LLM instance"""
        if not GOOGLE_API_KEY:
            raise ValueError("GOOGLE_API_KEY environment variable not set")

        return LLM(
            model="gemini/gemini-2.5-flash",
            temperature=0.7,
            api_key=GOOGLE_API_KEY,
            timeout=60,
            max_retries=1,
        )
    
    def _create_groq_llm(self) -> LLM:
        """Create Groq LLM instance as fallback"""
        if not GROQ_API_KEY:
            raise ValueError("GROQ_API_KEY environment variable not set")

        return LLM(
            model="groq/llama-3.1-8b-instant",
            temperature=0.7,
            api_key=GROQ_API_KEY,
            timeout=60,
            max_retries=1,
        )

    def _calculate_backoff(self, attempt: int) -> int:
        """Calculate exponential backoff with jitter"""
        import random

        base_delay = RETRY_DELAY
        max_delay = 120  # Increased max delay
        delay = min(base_delay * (2**attempt) + random.uniform(1, 5), max_delay)
        return int(delay)

    def _normalize_final_output(self, text: str) -> str:
        """Final normalization pass to ensure perfect formatting"""
        text = re.sub(r"^.*?(?=##|\d+\.)", "", text, flags=re.DOTALL).strip()

        lines = []
        for line in text.split("\n"):
            if re.match(
                r"^\s*\d+\.\s+[A-Z][A-Z\s&/()-]+", line
            ) and not line.startswith("##"):
                line = "## " + line.strip()
            lines.append(line)

        return "\n".join(lines).strip()

    def _clean_output(self, text: str) -> str:
        """Aggressively clean LLM output to ensure consistent structure"""
        if not text or not text.strip():
            return ""

        original_text = text

        # Find structured content
        sections_pattern = r"((?:^|\n)\s*1\.\s+TECHNICAL OVERVIEW.*?)(?=\n\s*(?:Thought:|Action:|I now|Based on|$))"
        matches = list(re.finditer(sections_pattern, text, re.IGNORECASE | re.DOTALL))

        if matches:
            text = matches[-1].group(1)
            logger.info("✅ Extracted final structured content")
        else:
            logger.warning("⚠️ Using fallback extraction")
            text = self._extract_structured_content(original_text)

        # Remove agent metadata
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

        # Format section headers
        text = re.sub(
            r"(?:^|\n)\s*(\d+)\.\s+(TECHNICAL OVERVIEW|MITRE ATT&CK TECHNIQUES?|THREAT ACTORS?|BUSINESS IMPACT ASSESSMENT)\s*:?\s*\n",
            r"\n## \1. \2\n\n",
            text,
            flags=re.IGNORECASE | re.MULTILINE,
        )

        # Clean formatting
        text = re.sub(r"\n\s*[•●◦▪▫]\s+", "\n- ", text)
        text = re.sub(r"\n\s*[-*]\s+", "\n- ", text)
        text = re.sub(r"\n\s*\*\*([^*]+)\*\*\s*:\s*", r"\n**\1:** ", text)

        # Remove duplicates and clean whitespace
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
        text = re.sub(r"\n{3,}", "\n\n", text)
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"(##[^\n]+)\n([^\n#])", r"\1\n\n\2", text)

        text = text.strip()
        text = self._normalize_final_output(text)

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
            for clean_pattern in [
                r"Thought:.*?(?=\n|\Z)",
                r"Action:.*?(?=\n|\Z)",
                r"(?:I now|Based on|Let me).*?(?=\n|\Z)",
            ]:
                section_content = re.sub(
                    clean_pattern,
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
            verbose=False,
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
        self, alert_name: str, llm: LLM
    ) -> Tuple[bool, Optional[str], Optional[Exception]]:
        """Execute analysis with specified LLM"""
        try:
            model_name = "Gemini" if "gemini" in str(llm.model).lower() else "Groq"
            logger.info(f"Analyzing with {model_name}...")

            agents = self._create_agents(llm)
            tasks = self._create_tasks(alert_name, agents)

            crew = Crew(
                agents=list(agents.values()),
                tasks=tasks,
                process=Process.sequential,
                verbose=False,
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
        """Main analysis method with Groq fallback"""
        if not alert_name or not alert_name.strip():
            raise ValueError("Alert name cannot be empty")

        # Try Gemini first
        for attempt in range(MAX_RETRIES):
            try:
                logger.info(
                    f"🔍 Analyzing '{alert_name}' with GEMINI "
                    f"(Attempt {attempt + 1}/{MAX_RETRIES})"
                )

                success, result, error = self._analyze_with_llm(
                    alert_name, self.primary_llm
                )

                if success and self._validate_output_structure(result):
                    logger.info("✅ Success with GEMINI")
                    return result

                if attempt < MAX_RETRIES - 1:
                    backoff = self._calculate_backoff(attempt)
                    logger.info(f"⏳ Waiting {backoff}s before retry...")
                    time.sleep(backoff)

            except Exception as e:
                logger.error(f"Gemini attempt {attempt + 1} failed: {str(e)}")
                if attempt < MAX_RETRIES - 1:
                    time.sleep(2)

        # Fallback to Groq if Gemini fails
        if self.fallback_llm:
            logger.info("🔄 Falling back to GROQ...")
            try:
                success, result, error = self._analyze_with_llm(
                    alert_name, self.fallback_llm
                )
                
                if success and self._validate_output_structure(result):
                    logger.info("✅ Success with GROQ fallback")
                    return result
                else:
                    logger.error(f"Groq fallback failed: {error}")
            except Exception as e:
                logger.error(f"Groq fallback error: {str(e)}")

        # All methods failed
        logger.error("❌ Both Gemini and Groq failed")
        raise Exception(f"Analysis failed with both Gemini and Groq after {MAX_RETRIES} attempts")
