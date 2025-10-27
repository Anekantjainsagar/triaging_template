import os
import re
from typing import Dict, List, Optional
from api_client.analyzer_api_client import get_analyzer_client
from routes.src.utils import extract_alert_name
from crewai import LLM, Agent, Task, Crew
from dotenv import load_dotenv

load_dotenv()


class InvestigationProfileBuilder:
    def __init__(self):
        self._init_llm()

        self.analyzer_client = None
        try:
            self.analyzer_client = get_analyzer_client()
            print("✅ Investigation Profile Builder initialized")
        except Exception as e:
            print(f"⚠️ Analyzer client unavailable: {e}")

    def _init_llm(self):
        """Initialize LLM for dynamic analysis with retry logic"""
        gemini_key = os.getenv("GOOGLE_API_KEY")
        if gemini_key:
            self.llm = LLM(
                model="gemini/gemini-2.0-flash-exp",
                api_key=gemini_key,
                temperature=0.2,
                timeout=180,  # 3 minute timeout
                max_retries=3,
                rpm=10,  # Rate limit to 10 requests per minute
            )
        else:
            ollama_model = os.getenv("OLLAMA_CHAT", "ollama/qwen2.5:3b")
            if not ollama_model.startswith("ollama/"):
                ollama_model = f"ollama/{ollama_model}"
            self.llm = LLM(
                model=ollama_model, base_url="http://localhost:11434", temperature=0.2
            )

    def build_profile(self, rule_number: str, rule_context: str = "") -> Dict:
        """
        Build comprehensive investigation profile

        Args:
            rule_number: Rule number (e.g., "Rule#297")
            rule_context: Additional context

        Returns:
            Investigation profile dictionary
        """
        print(f"\n Building Investigation Profile for {rule_number}")

        # Initialize profile with defaults
        profile = {
            "rule_number": rule_number,
            "alert_name": "",
            "alert_type": self._classify_alert_type(rule_number, rule_context),
            "technical_overview": "",
            "mitre_techniques": [],
            "mitre_details": {},
            "threat_actors": [],
            "threat_actor_ttps": {},
            "data_sources": [],
            "investigation_focus": [],
            "required_checks": [],
            "business_impact": {},
            "detection_mechanism": [],
        }

        # Try to get AI analysis with retry logic
        if self.analyzer_client:
            try:
                alert_name = extract_alert_name(rule_number)
                profile["alert_name"] = alert_name

                print(f"   Fetching AI analysis for: {alert_name}")

                # Implement retry logic for rate limiting
                result = self._get_analysis_with_retry(alert_name, max_retries=2)

                if result.get("success"):
                    analysis_text = result.get("analysis", "")
                    self._parse_analysis(analysis_text, profile)
                    print(f"   âœ… Parsed AI analysis successfully")
                else:
                    error_msg = result.get("error", "Unknown error")
                    if "429" in error_msg or "rate limit" in error_msg.lower():
                        print(f"   âš ï¸ Rate limit hit - using fallback profile")
                    else:
                        print(f"   âš ï¸ AI analysis failed: {error_msg[:100]}")
                    # Continue with empty profile - fallback will handle it

            except Exception as e:
                error_str = str(e)
                print(f"   âš ï¸ Error getting AI analysis: {error_str[:100]}")

        # Enhance with rule context
        if rule_context:
            self._enhance_from_context(rule_context, profile)

        # Determine investigation requirements (uses fallback if no AI analysis)
        self._determine_investigation_requirements(profile)

        print(
            f"   âœ… Profile: {len(profile['mitre_techniques'])} MITRE, "
            f"{len(profile['threat_actors'])} actors, {len(profile['investigation_focus'])} focus areas"
        )

        return profile

    def _get_analysis_with_retry(self, alert_name: str, max_retries: int = 2) -> Dict:
        """
        Get AI analysis with retry logic for rate limiting

        Args:
            alert_name: Alert name to analyze
            max_retries: Number of retries (default: 2)

        Returns:
            Analysis result dictionary
        """
        import time

        last_error = None

        for attempt in range(max_retries):
            try:
                result = self.analyzer_client.analyze_alert(alert_name)
                if result.get("success"):
                    return result

                error_msg = result.get("error", "")
                if "429" in error_msg or "rate limit" in error_msg.lower():
                    wait_time = min(2**attempt * 3, 30)
                    print(f"   ⏳ Rate limited. Waiting {wait_time}s before retry...")
                    time.sleep(wait_time)
                    last_error = result
                    continue
                else:
                    return result

            except Exception as e:
                last_error = e
                error_str = str(e).lower()

                if (
                    "429" in str(e)
                    or "rate limit" in error_str
                    or "too many" in error_str
                ):
                    wait_time = min(2**attempt * 3, 30)
                    print(
                        f"   ⏳ Rate limited (attempt {attempt + 1}/{max_retries}). Waiting {wait_time}s..."
                    )
                    time.sleep(wait_time)
                    continue
                else:
                    # Not rate limit, return error
                    return {"success": False, "error": str(e)}

        # All retries exhausted
        return {
            "success": False,
            "error": f"Rate limit exceeded after {max_retries} attempts",
        }

    def _classify_alert_type(self, rule_number: str, context: str) -> str:
        """Classify alert into broad category"""
        combined = f"{rule_number} {context}".lower()

        if any(k in combined for k in ["login", "sign-in", "auth", "credential"]):
            return "authentication"
        elif any(k in combined for k in ["role", "permission", "privilege", "rbac"]):
            return "identity_access"
        elif any(k in combined for k in ["device", "endpoint", "compliance"]):
            return "endpoint_security"
        elif any(k in combined for k in ["network", "ip", "connection"]):
            return "network_activity"
        elif any(k in combined for k in ["data", "exfiltration", "download"]):
            return "data_security"
        elif any(k in combined for k in ["malware", "threat", "suspicious"]):
            return "threat_detection"
        else:
            return "general_security"

    def _parse_analysis(self, analysis_text: str, profile: Dict):
        """Parse AI analysis text and extract structured data"""

        # Extract Technical Overview
        tech_match = re.search(
            r"##\s*TECHNICAL\s*OVERVIEW\s*(.*?)(?=##|\Z)",
            analysis_text,
            re.IGNORECASE | re.DOTALL,
        )
        if tech_match:
            overview = tech_match.group(1).strip()
            overview = re.sub(r"\n{2,}", " ", overview).strip()
            profile["technical_overview"] = overview
            profile["detection_mechanism"] = self._extract_detection_mechanisms(
                overview
            )

        # Extract MITRE ATT&CK Techniques with details
        mitre_section = re.search(
            r"##\s*MITRE\s*ATT&CK.*?(?=##|\Z)", analysis_text, re.IGNORECASE | re.DOTALL
        )
        if mitre_section:
            mitre_text = mitre_section.group(0)
            techniques = re.findall(r"(T\d{4}(?:\.\d{3})?)\s*-\s*([^\n]+)", mitre_text)

            for tech_id, tech_name in techniques[:5]:
                profile["mitre_techniques"].append(tech_id)
                profile["mitre_details"][tech_id] = tech_name.strip()

        # Extract Threat Actors with TTPs
        actor_section = re.search(
            r"##\s*THREAT\s*ACTORS.*?(?=##|\Z)",
            analysis_text,
            re.IGNORECASE | re.DOTALL,
        )
        if actor_section:
            actor_text = actor_section.group(0)

            # Extract actor names
            actors = re.findall(r"###\s*([^\(\n]+?)(?:\s*\([^\)]+\))?", actor_text)
            profile["threat_actors"] = [a.strip() for a in actors[:3]]

            # Extract TTPs for each actor
            for actor in profile["threat_actors"]:
                ttps_match = re.search(
                    rf"###\s*{re.escape(actor)}.*?Key TTPs:\s*([^\n]+)",
                    actor_text,
                    re.IGNORECASE | re.DOTALL,
                )
                if ttps_match:
                    profile["threat_actor_ttps"][actor] = ttps_match.group(1).strip()

        # Extract Business Impact
        impact_section = re.search(
            r"##\s*BUSINESS\s*IMPACT.*?(?=##|\Z)",
            analysis_text,
            re.IGNORECASE | re.DOTALL,
        )
        if impact_section:
            impact_text = impact_section.group(0)

            data_match = re.search(
                r"Data at Risk[:\s]+(.*?)(?:\n|$)", impact_text, re.IGNORECASE
            )
            if data_match:
                profile["business_impact"]["data_at_risk"] = data_match.group(1).strip()

            risk_match = re.search(
                r"Overall Risk[:\s]+(CRITICAL|HIGH|MEDIUM|LOW)",
                impact_text,
                re.IGNORECASE,
            )
            if risk_match:
                profile["business_impact"]["risk_level"] = risk_match.group(1).upper()

    def _extract_detection_mechanisms(self, text: str) -> List[str]:
        """Extract detection mechanisms from technical overview"""
        mechanisms = []

        patterns = [
            r"Event ID (\d+)",
            r"(SigninLogs|AuditLogs|SecurityEvent|DeviceEvents|CloudAppEvents|IdentityInfo)",
            r"(Windows Event|Sysmon|Azure AD|Okta|Sentinel)",
        ]

        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            mechanisms.extend(matches)

        return list(set(mechanisms))

    def _enhance_from_context(self, context: str, profile: Dict):
        """Enhance profile from additional context"""
        context_lower = context.lower()

        if "signin" in context_lower or "login" in context_lower:
            if "SigninLogs" not in profile["data_sources"]:
                profile["data_sources"].append("SigninLogs")

        if "audit" in context_lower:
            if "AuditLogs" not in profile["data_sources"]:
                profile["data_sources"].append("AuditLogs")

        if "device" in context_lower:
            if "DeviceInfo" not in profile["data_sources"]:
                profile["data_sources"].append("DeviceInfo")

    def _determine_investigation_requirements(self, profile: Dict):
        """Determine what investigation checks are needed - FULLY DYNAMIC using LLM"""
        tech_overview = profile["technical_overview"]

        if not tech_overview:
            # Better fallback with more focus areas
            profile["investigation_focus"] = [
                "user_activity",
                "authentication_analysis",
                "ip_reputation",
                "device_compliance",
                "behavioral_patterns",
            ]
            profile["required_checks"] = [
                "user_verification",
                "signin_analysis",
                "ip_reputation",
                "mfa_verification",
                "device_check",
            ]
            profile["data_sources"] = ["SigninLogs", "AuditLogs", "DeviceInfo"]
            return

        # Use LLM with minimum 4-5 focus areas requirement
        focus_areas, required_checks, data_sources = self._llm_analyze_requirements(
            tech_overview
        )

        # Ensure minimum coverage
        if len(focus_areas) < 4:
            base_focus = [
                "user_activity",
                "authentication_analysis",
                "ip_reputation",
                "device_compliance",
            ]
            focus_areas.extend([f for f in base_focus if f not in focus_areas])

        if len(required_checks) < 4:
            base_checks = [
                "user_verification",
                "signin_analysis",
                "ip_reputation",
                "mfa_verification",
            ]
            required_checks.extend([c for c in base_checks if c not in required_checks])

        profile["investigation_focus"] = focus_areas[:5]  # Max 5
        profile["required_checks"] = required_checks[:5]
        profile["data_sources"] = (
            data_sources if data_sources else ["SigninLogs", "AuditLogs"]
        )

    def _llm_analyze_requirements(self, tech_overview: str) -> tuple:
        """
        Use LLM to analyze technical overview and determine investigation requirements
        Returns: (focus_areas, required_checks, data_sources)
        """
        try:
            prompt = f"""Analyze this security alert and determine investigation requirements.

    TECHNICAL OVERVIEW:
    {tech_overview[:800]}

    Extract and list:

    1. FOCUS AREAS (what to investigate):
    Examples: network_analysis, authentication_analysis, device_compliance, privilege_analysis

    2. REQUIRED CHECKS (specific verifications needed):
    Examples: ip_reputation, user_verification, mfa_verification, role_verification

    3. DATA SOURCES (Azure/M365 log sources to query):
    Examples: SigninLogs, AuditLogs, DeviceInfo, IdentityInfo, CloudAppEvents

    Format your response as:
    FOCUS: area1, area2, area3
    CHECKS: check1, check2, check3
    SOURCES: source1, source2, source3

    Be specific and concise."""

            agent = Agent(
                role="SOC Requirements Analyst",
                goal="Determine investigation requirements from alert analysis",
                backstory="Expert at translating threat analysis into investigation steps",
                llm=self.llm,
                verbose=False,
            )

            task = Task(
                description=prompt,
                expected_output="Structured list of focus areas, checks, and data sources",
                agent=agent,
            )

            crew = Crew(agents=[agent], tasks=[task], verbose=False)
            result = str(crew.kickoff())

            # Parse LLM output
            focus_areas = []
            required_checks = []
            data_sources = []

            for line in result.split("\n"):
                line = line.strip()
                if line.startswith("FOCUS:"):
                    focus_areas = [
                        x.strip() for x in line.replace("FOCUS:", "").split(",")
                    ]
                elif line.startswith("CHECKS:"):
                    required_checks = [
                        x.strip() for x in line.replace("CHECKS:", "").split(",")
                    ]
                elif line.startswith("SOURCES:"):
                    data_sources = [
                        x.strip() for x in line.replace("SOURCES:", "").split(",")
                    ]

            return focus_areas, required_checks, data_sources

        except Exception as e:
            print(f"   ⚠️ LLM requirements analysis failed: {str(e)[:100]}")
            # Fallback to basic parsing
            return self._fallback_requirements_parsing(tech_overview)

    def _fallback_requirements_parsing(self, tech_overview: str) -> tuple:
        """Fallback parsing if LLM fails"""
        focus_areas = set()
        required_checks = set()
        data_sources = set()

        tech_lower = tech_overview.lower()

        # Simple keyword matching as fallback
        if "ip" in tech_lower or "address" in tech_lower:
            required_checks.add("ip_reputation")
            focus_areas.add("network_analysis")

        if "user" in tech_lower or "account" in tech_lower:
            required_checks.add("user_verification")
            focus_areas.add("user_activity")
            data_sources.add("SigninLogs")

        if "device" in tech_lower or "endpoint" in tech_lower:
            required_checks.add("device_verification")
            focus_areas.add("device_compliance")
            data_sources.add("DeviceInfo")

        if "role" in tech_lower or "permission" in tech_lower:
            required_checks.add("role_verification")
            data_sources.add("AuditLogs")

        return list(focus_areas), list(required_checks), list(data_sources)
