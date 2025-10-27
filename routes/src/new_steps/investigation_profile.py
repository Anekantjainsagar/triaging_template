"""
Investigation Profile Builder
Extracts intelligence from AI Threat Analysis to guide investigation step generation
"""

import re
from typing import Dict, List, Optional
from api_client.analyzer_api_client import get_analyzer_client
from routes.src.utils import extract_alert_name


class InvestigationProfileBuilder:
    """
    Builds structured investigation profile from AI threat analysis
    This guides intelligent step generation
    """

    def __init__(self):
        self.analyzer_client = None
        try:
            self.analyzer_client = get_analyzer_client()
            print("✅ Investigation Profile Builder initialized")
        except Exception as e:
            print(f"⚠️ Analyzer client unavailable: {e}")

    def build_profile(self, rule_number: str, rule_context: str = "") -> Dict:
        """
        Build comprehensive investigation profile

        Args:
            rule_number: Rule number (e.g., "Rule#297")
            rule_context: Additional context

        Returns:
            Investigation profile dictionary
        """
        print(f"\n🔍 Building Investigation Profile for {rule_number}")

        # Initialize profile with defaults
        profile = {
            "rule_number": rule_number,
            "alert_name": "",
            "alert_type": self._classify_alert_type(rule_number, rule_context),
            "technical_overview": "",
            "mitre_techniques": [],
            "mitre_details": {},  # ✅ NEW: Store technique details
            "threat_actors": [],
            "threat_actor_ttps": {},  # ✅ NEW: Store actor TTPs
            "data_sources": [],
            "investigation_focus": [],
            "required_checks": [],
            "business_impact": {},
            "detection_mechanism": [],
        }

        # Get AI analysis if available
        if self.analyzer_client:
            try:
                alert_name = extract_alert_name(rule_number)
                profile["alert_name"] = alert_name

                print(f"   📡 Fetching AI analysis for: {alert_name}")
                result = self.analyzer_client.analyze_alert(alert_name)

                if result.get("success"):
                    analysis_text = result.get("analysis", "")
                    self._parse_analysis(analysis_text, profile)
                    print(f"   ✅ Parsed AI analysis successfully")
                else:
                    print(f"   ⚠️ AI analysis failed: {result.get('error')}")

            except Exception as e:
                print(f"   ⚠️ Error getting AI analysis: {str(e)[:100]}")

        # Enhance with rule context
        if rule_context:
            self._enhance_from_context(rule_context, profile)

        # Determine investigation requirements
        self._determine_investigation_requirements(profile)

        print(
            f"   ✅ Profile: {len(profile['mitre_techniques'])} MITRE, "
            f"{len(profile['threat_actors'])} actors, {len(profile['investigation_focus'])} focus areas"
        )

        return profile

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
            # Fallback to basic requirements
            profile["investigation_focus"] = ["user_activity", "authentication_analysis"]
            profile["required_checks"] = ["user_verification", "signin_analysis"]
            profile["data_sources"] = ["SigninLogs"]
            return

        # Use LLM to analyze technical overview
        focus_areas, required_checks, data_sources = self._llm_analyze_requirements(tech_overview)
        
        profile["investigation_focus"] = focus_areas
        profile["required_checks"] = required_checks
        profile["data_sources"] = data_sources if data_sources else ["SigninLogs"]

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

            for line in result.split('\n'):
                line = line.strip()
                if line.startswith('FOCUS:'):
                    focus_areas = [x.strip() for x in line.replace('FOCUS:', '').split(',')]
                elif line.startswith('CHECKS:'):
                    required_checks = [x.strip() for x in line.replace('CHECKS:', '').split(',')]
                elif line.startswith('SOURCES:'):
                    data_sources = [x.strip() for x in line.replace('SOURCES:', '').split(',')]

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