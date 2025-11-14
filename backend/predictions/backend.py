import re
import json
import logging
from datetime import datetime
import google.generativeai as genai
from typing import Dict, List, Any, Optional
from routes.src.utils import _strip_step_number_prefix

logger = logging.getLogger(__name__)


def clean_json_response(content: str) -> str:
    """
    Aggressively clean JSON response from LLM to fix parsing errors
    """
    # Remove any BOM or invisible characters at start
    content = content.lstrip("\ufeff\u200b\u200c\u200d\u2060\ufeff")

    # Remove all control characters except newline/tab (we'll handle those separately)
    content = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", content)

    # Replace non-breaking spaces and other problematic Unicode spaces
    content = content.replace("\xa0", " ")
    content = content.replace("\u202f", " ")
    content = content.replace("\u2009", " ")

    # Strip leading/trailing whitespace
    content = content.strip()

    # Handle literal newlines and tabs in string values (not in structure)
    # This regex finds content between quotes and escapes unescaped newlines
    def escape_in_strings(match):
        s = match.group(0)
        # Only escape if not already escaped
        s = re.sub(r"(?<!\\)\n", r"\\n", s)
        s = re.sub(r"(?<!\\)\t", r"\\t", s)
        s = re.sub(r"(?<!\\)\r", r"\\r", s)
        return s

    # Apply to content between double quotes
    content = re.sub(r'"[^"]*"', escape_in_strings, content, flags=re.DOTALL)

    return content


class MITREAttackAnalyzer:
    def __init__(self, api_key: str):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel("gemini-2.5-flash")

        # High-risk countries for geolocation analysis
        self.high_risk_countries = [
            "russia",
            "china",
            "north korea",
            "iran",
            "syria",
            "belarus",
            "venezuela",
            "cuba",
            "afghanistan",
        ]

        # Load MITRE ATT&CK techniques
        self.mitre_data = self._load_mitre_data()

    def _load_mitre_data(self) -> Dict[str, Any]:
        """Load MITRE ATT&CK framework data"""
        from data.utils.mitre_data import mitre_structure

        return mitre_structure

    def extract_geolocation_risk(
        self, investigation_steps: List[Dict]
    ) -> Dict[str, Any]:
        """Extract and analyze geolocation risk from investigation data"""
        geo_risks = {
            "has_high_risk_country": False,
            "high_risk_locations": [],
            "suspicious_ips": [],
        }

        for step in investigation_steps:
            output = str(step.get("output", ""))

            # Check for high-risk countries
            for country in self.high_risk_countries:
                if country in output.lower():
                    geo_risks["has_high_risk_country"] = True

                    # Extract IP addresses
                    ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
                    ips = re.findall(ip_pattern, output)

                    geo_risks["high_risk_locations"].append(
                        {
                            "country": country.title(),
                            "step": _strip_step_number_prefix(step.get("step_name", "")),
                            "context": output[:200],
                        }
                    )

                    if ips:
                        geo_risks["suspicious_ips"].extend(ips)

        geo_risks["suspicious_ips"] = list(set(geo_risks["suspicious_ips"]))
        return geo_risks

    def build_mitre_techniques_reference(self) -> str:
        """Build comprehensive MITRE techniques reference"""
        reference = "\n## COMPLETE MITRE ATT&CK TECHNIQUES REFERENCE:\n\n"

        for tactic, techniques in self.mitre_data.items():
            reference += f"\n### {tactic}\n"
            for technique, sub_techniques in techniques.items():
                reference += f"- **{technique}**"
                if sub_techniques:
                    reference += f"\n  Sub-techniques: {', '.join(sub_techniques)}"
                reference += "\n"

        return reference

    def analyze_mitre_attack_chain(
        self,
        username: str,
        classification: str,
        investigation_summary: Dict[str, Any],
        investigation_steps: List[Dict],
    ) -> Optional[Dict[str, Any]]:
        """Generate comprehensive MITRE ATT&CK analysis"""
        try:
            geo_risk_data = self.extract_geolocation_risk(investigation_steps)

            # Build prompt (using existing method from your code)
            prompt = self.build_mitre_analysis_prompt(
                username,
                classification,
                investigation_summary,
                geo_risk_data,
                investigation_steps,
            )

            response = self.model.generate_content(prompt)
            content = response.text.strip()

            # Remove code blocks
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]

            # CRITICAL FIX: Use the aggressive JSON cleaner
            content = clean_json_response(content)

            logger.info(f"Cleaned MITRE response length: {len(content)}")
            logger.info(f"First 20 chars: {content[:20]}")

            # Parse JSON
            mitre_analysis = json.loads(content)

            # Add geo-risk metadata
            mitre_analysis["geographic_risk_assessment"] = geo_risk_data

            # Validate sub-technique coverage
            self._validate_subtechnique_coverage(mitre_analysis)

            return mitre_analysis

        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing error in MITRE analysis: {str(e)}")
            logger.error(f"Content causing error: {content[:500]}")
            return None
        except Exception as e:
            logger.error(f"Error in MITRE analysis: {str(e)}")
            return None

    def build_mitre_analysis_prompt(
        self,
        username: str,
        classification: str,
        investigation_summary: Dict[str, Any],
        geo_risk_data: Dict[str, Any],
        investigation_steps: List[Dict],
    ) -> str:
        """Build prompt for MITRE ATT&CK mapping with attack chain analysis"""

        # Format investigation context
        investigation_context = ""
        for step in investigation_steps:
            # ✅ Include remarks if they exist
            remarks_info = ""
            if step.get("remarks") and len(step.get("remarks", "")) > 0:
                remarks_info = f"""
        **Analyst Notes**: {step['remarks']}
        """

            investigation_context += f"""
        ### {step['step_name']}
        Output: {str(step['output'])}
        **Analyst Remarks/Comments**: {step.get('remarks', 'None')}
        {remarks_info}
        ---
        """

        geo_risk_context = ""
        if geo_risk_data["has_high_risk_country"]:
            geo_risk_context = f"""
    **HIGH-RISK GEOLOCATION DETECTED:**
    - High-risk countries: {', '.join([loc['country'] for loc in geo_risk_data['high_risk_locations']])}
    - Suspicious IPs: {', '.join(geo_risk_data['suspicious_ips'])}
    This significantly increases the TRUE POSITIVE likelihood and threat severity.
    """

        # Get MITRE techniques reference
        mitre_reference = self.build_mitre_techniques_reference()

        # FIXED: Changed the timeline example to avoid f-string format issues
        prompt = f"""You are an elite threat intelligence analyst specializing in MITRE ATT&CK framework mapping and cyber attack chain reconstruction.

    # INVESTIGATION CONTEXT
    **User:** {username}
    **Classification:** {classification}
    **Risk Level:** {investigation_summary.get('risk_level', 'UNKNOWN')}
    **Confidence:** {investigation_summary.get('confidence_score', 0)}%

    {geo_risk_context}

    # INVESTIGATION DATA SUMMARY
    {investigation_context}

    # KEY FINDINGS
    {json.dumps(investigation_summary.get('key_findings', []), indent=2)}

    # RISK INDICATORS
    {json.dumps(investigation_summary.get('risk_indicators', []), indent=2)}

    {mitre_reference}

    ---

    # YOUR MISSION: MITRE ATT&CK MAPPING & ATTACK CHAIN RECONSTRUCTION

    You must provide a comprehensive MITRE ATT&CK analysis including:

    1. **Complete Attack Chain Mapping** - Map observed TTPs to MITRE ATT&CK framework
    2. **Attack Progression Timeline** - Reconstruct the attack sequence
    3. **Threat Actor Profiling** - Identify likely threat actor characteristics
    4. **Predicted Next Steps** - Forecast attacker's probable next moves
    5. **Visual Attack Path** - Color-coded technique mapping (Green/Amber/Red)


    ---

    ## ATTACK TIMELINE GENERATION REQUIREMENTS:

    **Create a detailed chronological attack timeline with the following:**

    1. **Chronological Ordering**: Arrange all attack events in time sequence based on actual timestamps from investigation data
    2. **Stage Numbering**: Number each stage sequentially (1, 2, 3, etc.) to show attack progression
    3. **Complete Context**: For each timeline entry include:
    - Exact timestamp from investigation data
    - MITRE tactic and technique (with sub-technique)
    - Clear description of what happened in business terms
    - Specific evidence from investigation outputs
    - Severity assessment (RED/AMBER/GREEN)
    - Impact statement explaining the security implications
    - List of indicators observed at that stage

    4. **Narrative Flow**: Timeline should tell a story - connect each stage to show how the attack progressed
    5. **Evidence-Based**: Every timeline entry must reference specific data from investigation steps
    6. **Business Language**: Describe technical events in terms business stakeholders can understand

    **Timeline Entry Format:**
    - Stage 1 at [timestamp]: Initial Access via compromised credentials
    - Stage 2 at [timestamp]: Privilege escalation through role manipulation  
    - Stage 3 at [timestamp]: Reconnaissance of cloud resources
    - Stage 4 at [timestamp]: Lateral movement to sensitive systems
    - Stage 5 at [timestamp]: Data exfiltration or impact activities

    **Example Timeline Entry Structure:**
    Stage 1: Initial cloud account compromise at 2025-10-08 11:54:20
    Tactic: Initial Access
    Technique: Valid Accounts with Cloud Accounts sub-technique (T1078.004)
    Description: Attacker accessed cloud account using stolen credentials from suspicious location
    Evidence: Authentication log showing sign-in from unknown IP address
    Severity: AMBER
    Impact: Attacker gained foothold in cloud environment with user privileges
    Indicators: Impossible travel, unknown device, high-risk geographic region

    ---

    ## MITRE ATT&CK TACTICS (All 14):
    1. Reconnaissance (TA0043)
    2. Resource Development (TA0042)
    3. Initial Access (TA0001)
    4. Execution (TA0002)
    5. Persistence (TA0003)
    6. Privilege Escalation (TA0004)
    7. Defense Evasion (TA0005)
    8. Credential Access (TA0006)
    9. Discovery (TA0007)
    10. Lateral Movement (TA0008)
    11. Collection (TA0009)
    12. Command and Control (TA0011)
    13. Exfiltration (TA0010)
    14. Impact (TA0040)

    ---

    ## CRITICAL INSTRUCTIONS FOR SUB-TECHNIQUES:

    **ALWAYS include sub-techniques when mapping MITRE techniques:**
    - Use the complete reference provided above to identify appropriate sub-techniques
    - Every technique that has sub-techniques MUST include at least one relevant sub-technique
    - Sub-technique selection must be evidence-based from investigation data
    - Format: "Technique" > "Sub-technique"
    - Example: "Valid Accounts" > "Cloud Accounts" (T1078.004)

    **DO NOT use generic techniques when specific sub-techniques exist**
    - Wrong: "Valid Accounts (T1078)" without sub-technique
    - Correct: "Valid Accounts: Cloud Accounts (T1078.004)"

    ---


    ## CRITICAL INSTRUCTIONS FOR PROCEDURES (TTP Details):

    **ALWAYS include detailed procedures for each technique:**
    - The "procedure" field must explain HOW the attacker executed the technique
    - Include specific tools, methods, commands, or techniques used
    - Reference actual evidence from the investigation data
    - Describe the attack flow step-by-step
    - Make it actionable for defenders to understand the attack methodology

    **Procedure Example Format:**
    "The attacker used stolen credentials (username: john.doe@abc.com) to authenticate from IP 203.0.113.45 located in an unknown geographic region. The authentication occurred at 14:34:34, shortly after a Global Administrator role was assigned to the account. The attacker leveraged the cloud account access to bypass traditional perimeter defenses, utilizing valid authentication tokens to avoid detection by signature-based security tools."

    **DO NOT use generic procedures** - Every procedure must be specific to THIS investigation's evidence.

    ---

    ## ANALYSIS REQUIREMENTS:

    ### For TRUE POSITIVE Cases:
    - Map ALL observed techniques to MITRE ATT&CK framework WITH sub-techniques
    - Identify the current attack stage
    - Predict 3-5 most likely next attacker moves WITH specific sub-techniques
    - Provide detailed kill chain reconstruction
    - Assign severity colors: RED (confirmed), AMBER (likely), GREEN (possible future)
    - Include specific technique IDs and sub-technique IDs (e.g., T1078.004 - Valid Accounts: Cloud Accounts)

    ### For FALSE POSITIVE Cases:
    - Map potential misinterpreted behaviors to MITRE techniques WITH sub-techniques
    - Explain why behaviors appeared suspicious but are benign
    - Provide "what-if" attack scenarios for learning
    - Suggest detection improvements to reduce false positives
    - Color code hypothetical attack paths

    ### For Both Cases:
    - Generate comprehensive attack narrative
    - Include MITRE Navigator layer data with sub-techniques
    - Provide defensive recommendations mapped to MITRE techniques and sub-techniques
    - Identify detection gaps

    ---

    # OUTPUT FORMAT (STRICT JSON):

    {{
        "mitre_attack_analysis": {{
            "overall_assessment": {{
                "attack_stage": "Initial Access | Persistence Established | Privilege Escalation | Lateral Movement | Exfiltration | Impact",
                "attack_stage_explanation": "Detailed 2-3 sentence explanation of what this stage means, why the attacker is at this stage, and what evidence supports this assessment",
                "threat_sophistication": "Low | Medium | High | Advanced Persistent Threat",
                "sophistication_explanation": "Explain the attacker's skill level based on observed techniques, tools used, and operational security practices. Include specific examples from the investigation",
                "attack_confidence": 95,
                "confidence_explanation": "Explain why this confidence level was assigned, what evidence strongly supports the assessment, and what gaps exist",
                "primary_objective": "Credential theft | Data exfiltration | Ransomware | Espionage | Financial fraud",
                "objective_explanation": "Explain what the attacker is trying to achieve based on observed behavior and targeted systems",
                "estimated_dwell_time": "< 1 hour | 1-24 hours | 1-7 days | > 7 days",
                "dwell_time_explanation": "Explain how long the attacker has been in the environment, what evidence suggests this timeframe, and what this means for the investigation",
                "geographic_threat_indicator": "High-risk country detected" or "Standard geographic profile"
            }},
            
            "attack_chain_narrative": "Detailed 5-7 paragraph narrative that tells the complete attack story chronologically. Start with initial compromise, explain each stage of the attack progression, describe the attacker's objectives and methods at each phase, reference specific timestamps and evidence, explain the business impact at each stage, and conclude with the current threat status. Include all sub-techniques observed.",
            
            "mitre_techniques_observed": [
                {{
                    "tactic": "Initial Access",
                    "tactic_id": "TA0001",
                    "technique": "Valid Accounts",
                    "technique_id": "T1078",
                    "sub_technique": "Cloud Accounts",
                    "sub_technique_id": "T1078.004",
                    "severity": "RED | AMBER | GREEN",
                    "confidence": 95,
                    "evidence": "Specific evidence from investigation showing this technique and sub-technique",
                    "timestamp": "2025-10-09 09:54:20",
                    "indicators": ["Impossible travel", "Suspicious IP: 203.0.113.45"],
                    "sub_technique_justification": "Why this specific sub-technique applies",
                    "procedure": "DETAILED step-by-step description of HOW the attacker executed this specific technique. Must include: (1) What credentials/access was used, (2) What systems/accounts were targeted, (3) What tools or methods were employed, (4) What evasion techniques were used if any, (5) What the attacker achieved through this action, (6) Specific evidence from logs/investigation that proves this procedure. Example: The attacker leveraged stolen credentials for user john.doe@abc.com obtained through a prior phishing campaign. At 14:34:34 UTC, they authenticated to the Microsoft 365 tenant from IP address 203.0.113.45 originating from Moscow, Russia. The authentication used valid username and password combination, bypassing initial access controls. The attacker's session presented as a new device with generic browser fingerprint, triggering impossible travel alerts as the legitimate user had authenticated from New York just 30 minutes prior. The cloud account access provided the attacker with initial foothold in the corporate environment, granting access to email, SharePoint, and other cloud resources associated with the compromised account. Evidence includes authentication logs showing successful sign-in with MFA push notification approved, geolocation data indicating high-risk country, and device fingerprint showing previously unknown device characteristics."
                }}
            ],
            
            "attack_timeline": [
                {{
                    "stage": 1,
                    "timestamp": "2025-10-08 11:54:20",
                    "tactic": "Initial Access",
                    "technique": "Valid Accounts: Cloud Accounts (T1078.004)",
                    "description": "Detailed narrative description of what happened at this stage. Explain the attacker's actions, the systems involved, and the security implications. Make it understandable for non-technical stakeholders.",
                    "evidence": "Specific evidence from investigation logs or data that proves this event occurred",
                    "severity": "AMBER",
                    "sub_technique_details": "Explain exactly which sub-technique was used and why it fits this classification",
                    "impact": "Explain the business and security impact of this event. What access did the attacker gain? What risks does this create?",
                    "indicators_observed": ["Impossible travel detected", "Unknown device used", "Geographic anomaly from high-risk region", "Temporal anomaly - access outside business hours"]
                }}
            ],
            
            "predicted_next_steps": [
                {{
                    "sequence": 1,
                    "likelihood": "High | Medium | Low",
                    "tactic": "[Tactic from MITRE framework]",
                    "technique": "[Technique name]",
                    "technique_id": "[T####]",
                    "sub_technique": "[Sub-technique if applicable]",
                    "sub_technique_id": "[T####.###]",
                    "description": "ONLY predict next steps that are LOGICAL based on the ACTUAL investigation data. DO NOT mention cloud storage, AWS, Azure, Google Drive, DropBox, or any specific cloud services UNLESS the investigation explicitly shows the organization uses these services. Base predictions ONLY on what was observed: if you saw role assignments, predict abuse of those roles. If you saw unknown locations, predict lateral movement. DO NOT fabricate scenarios.",
                    "rationale": "Explain WHY this is the predicted next step based on current attack stage, attacker's demonstrated capabilities, and common attack patterns",
                    "indicators_to_watch": ["Specific log entries", "System behaviors", "Network activities to monitor"],
                    "recommended_preventive_action": "Specific actionable steps to prevent this predicted activity",
                    "detection_method": "How to detect if this activity occurs",
                    "business_impact_if_occurs": "What would happen to the business if this predicted step succeeds"
                }}
            ],
            
            "threat_actor_profile": {{
                "sophistication_level": "Low | Medium | High | APT",
                "sophistication_details": "Detailed analysis of attacker capabilities based on observed techniques, tools used, and operational security practices. Include specific examples from the investigation",
                "likely_motivation": "Financial | Espionage | Sabotage | Hacktivism",
                "motivation_details": "Why we believe this is the attacker's motivation based on targets, methods, and objectives",
                "probable_attribution": "Individual | Cybercriminal Group | Nation State | Insider",
                "attribution_details": "Evidence supporting this attribution including geographic indicators, TTP patterns, and known threat actor behaviors",
                "geographic_indicators": ["Russia", "China"] or ["No specific indicators"],
                "tactics_signature": "Matches known APT group patterns" or "Generic attack methodology",
                "similar_campaigns": ["Campaign names or TTPs matching known threats"],
                "preferred_sub_techniques": ["List of commonly used sub-techniques by this threat actor"]
            }},
            
            "mitre_navigator_layer": {{
                "name": "Attack Chain - {username}",
                "description": "MITRE ATT&CK Navigator layer for visualized attack path with sub-techniques",
                "domain": "enterprise-attack",
                "versions": {{
                    "attack": "14",
                    "navigator": "4.9"
                }},
                "techniques": [
                    {{
                        "techniqueID": "T1078",
                        "tactic": "initial-access",
                        "color": "#ff0000",
                        "comment": "Observed - Valid Accounts: Cloud Accounts (T1078.004)",
                        "enabled": true,
                        "score": 100,
                        "showSubtechniques": true
                    }},
                    {{
                        "techniqueID": "T1078.004",
                        "tactic": "initial-access",
                        "color": "#ff0000",
                        "comment": "Observed - Cloud Accounts sub-technique",
                        "enabled": true,
                        "score": 100
                    }}
                ],
                "gradient": {{
                    "colors": ["#00ff00", "#ffff00", "#ff0000"],
                    "minValue": 0,
                    "maxValue": 100
                }}
            }},
            
            "attack_path_visualization": {{
                "paths": [
                    {{
                        "path_id": 1,
                        "path_name": "Primary Attack Path",
                        "color_code": "RED",
                        "stages": [
                            {{
                                "stage": "Initial Access",
                                "techniques": ["T1078.004 - Valid Accounts: Cloud Accounts"],
                                "status": "CONFIRMED",
                                "color": "RED",
                                "sub_technique_details": "Cloud account compromise through credential theft"
                            }}
                        ]
                    }}
                ]
            }},
            
            "defensive_recommendations": [
                {{
                    "priority": "CRITICAL | HIGH | MEDIUM | LOW",
                    "mitre_mitigation": "M1027 - Password Policies",
                    "recommendation": "Implement mandatory MFA for all cloud accounts with hardware tokens",
                    "mapped_techniques": ["T1078", "T1078.004"],
                    "mapped_sub_techniques": ["Cloud Accounts (T1078.004)"],
                    "implementation_complexity": "Low | Medium | High",
                    "estimated_effectiveness": "80%"
                }}
            ],
            
            "detection_gaps": [
                {{
                    "gap_description": "No geo-blocking for executive cloud accounts",
                    "affected_techniques": ["T1078.004"],
                    "affected_sub_techniques": ["Cloud Accounts"],
                    "risk_level": "HIGH",
                    "recommended_detection": "Implement conditional access policies based on geolocation for cloud accounts",
                    "mitre_data_source": "DS0028 - Logon Session"
                }}
            ],
            
            "sub_technique_coverage": {{
                "total_techniques_mapped": 0,
                "techniques_with_sub_techniques": 0,
                "sub_technique_percentage": "0%",
                "techniques_requiring_sub_techniques": []
            }}
        }},
        
        "executive_summary": {{
            "one_line_summary": "Account compromise via credential theft from high-risk country with impossible travel pattern",
            "attack_sophistication": "Medium sophistication attack using compromised valid credentials with cloud account access",
            "business_impact": "Critical - CFO account compromised, potential financial data exposure",
            "immediate_actions": ["Disable account", "Reset credentials", "Review access logs", "Enable MFA"],
            "investigation_priority": "P1 - Critical",
            "key_sub_techniques_observed": ["Cloud Accounts (T1078.004)"]
        }}
    }}

    ---

    # CRITICAL REQUIREMENTS:

    1. **Evidence-Based**: Every MITRE technique AND sub-technique must be supported by specific evidence from investigation
    2. **NO FABRICATION IN PREDICTIONS**: When predicting next attacker moves:
    - Base predictions ONLY on techniques that logically follow from observed activity
    - DO NOT mention specific cloud services (AWS, Azure, GCP, DropBox, etc.) unless investigation data explicitly mentions them
    - DO NOT assume "cloud storage" exists unless investigation shows cloud environment
    - DO NOT predict "exfiltration to cloud storage" unless investigation shows cloud infrastructure
    - ONLY predict generic follow-up actions based on observed patterns
    - Example: If you saw "Global Administrator assigned" → predict "Discovery of resources" NOT "Discovery of AWS S3 buckets"
    3. **Sub-Technique Mandatory**: ALWAYS include sub-techniques when they exist for a technique
    4. **Prediction Quality**: Next steps must include specific sub-techniques and be realistic based on observed attacker behavior
    5. **Remarks Priority**: Analyst Remarks/Comments (from the investigation data) MUST be given the highest priority for classification and narrative reconstruction. If remarks contradict auto-detected severity, the remarks should generally prevail.
    6. **Detailed Procedures**: Every technique must have a comprehensive procedure describing the exact attack method
    7. **Comprehensive Timeline**: Attack timeline must include ALL stages with detailed narratives for each event
    8. **Explanations**: All assessment fields (attack_stage, sophistication, confidence, dwell_time) must include detailed explanations
    9. **Color Coding**: 
    - RED = Confirmed observed technique/sub-technique
    - AMBER = Highly likely technique/sub-technique in progress
    - GREEN = Predicted future technique/sub-technique
    10. **Completeness**: Map ALL relevant MITRE tactics (1-14) with appropriate sub-techniques
    11. **Specificity**: Use exact MITRE ATT&CK technique IDs and sub-technique IDs (e.g., T1078.004)
    12. **Actionability**: Recommendations must be specific, prioritized, and implementable
    13. **Timeline Accuracy**: Correlate MITRE techniques with actual timestamps from investigation
    14. **Prediction Quality**: Next steps must include specific sub-techniques and be realistic based on observed attacker behavior
    15. **Geographic Context**: If high-risk countries detected, emphasize in threat profiling
    16. **Sub-Technique Justification**: Explain WHY each specific sub-technique was selected based on evidence
    17. **Navigator Compatibility**: Include both parent techniques and sub-techniques in MITRE Navigator layer
    18. **Coverage Tracking**: Track sub-technique coverage percentage in analysis

    **Sub-Technique Selection Rules**:
    - If evidence shows "cloud account" access → Use T1078.004 (Cloud Accounts)
    - If evidence shows "domain account" access → Use T1078.002 (Domain Accounts)
    - If evidence shows "local account" access → Use T1078.003 (Local Accounts)
    - Always match the most specific sub-technique to the evidence
    - If multiple sub-techniques apply, include all relevant ones

    **Geographic Risk Enhancement**: If investigation involves Russia, China, or other high-risk countries, automatically increase threat severity and include nation-state TTPs with specific sub-techniques in analysis.

    ---

    Now analyze the investigation data and provide comprehensive MITRE ATT&CK mapping with detailed sub-techniques, comprehensive procedures, and detailed explanations in VALID JSON format only."""

        return prompt

    def _validate_subtechnique_coverage(self, mitre_analysis: Dict[str, Any]):
        """Validate and enhance sub-technique coverage in analysis"""
        if "mitre_attack_analysis" in mitre_analysis:
            analysis = mitre_analysis["mitre_attack_analysis"]

            # Calculate sub-technique coverage
            techniques_observed = analysis.get("mitre_techniques_observed", [])
            total_techniques = len(techniques_observed)
            techniques_with_subtechniques = sum(
                1
                for t in techniques_observed
                if t.get("sub_technique")
                and t.get("sub_technique") != "N/A"
                and t.get("sub_technique").strip()
            )

            coverage = {
                "total_techniques_mapped": total_techniques,
                "techniques_with_sub_techniques": techniques_with_subtechniques,
                "sub_technique_percentage": f"{(techniques_with_subtechniques/total_techniques*100) if total_techniques > 0 else 0:.1f}%",
                "techniques_requiring_sub_techniques": [],
                "quality_score": (
                    "Excellent"
                    if techniques_with_subtechniques / total_techniques >= 0.8
                    else (
                        "Good"
                        if techniques_with_subtechniques / total_techniques >= 0.6
                        else "Needs Improvement"
                    )
                ),
            }

            # Identify techniques that should have sub-techniques
            for technique in techniques_observed:
                technique_name = technique.get("technique", "")
                tactic = technique.get("tactic", "")

                # Check if this technique has available sub-techniques in our data
                if (
                    tactic in self.mitre_data
                    and technique_name in self.mitre_data[tactic]
                ):
                    available_subtechniques = self.mitre_data[tactic][technique_name]
                    if available_subtechniques and (
                        not technique.get("sub_technique")
                        or technique.get("sub_technique") == "N/A"
                    ):
                        coverage["techniques_requiring_sub_techniques"].append(
                            {
                                "technique": technique_name,
                                "technique_id": technique.get("technique_id"),
                                "tactic": tactic,
                                "available_sub_techniques": available_subtechniques[
                                    :3
                                ],  # Show only first 3
                            }
                        )

            analysis["sub_technique_coverage"] = coverage


class InvestigationAnalyzer:
    def __init__(self, api_key: str):
        self.api_key = api_key

        try:
            logger.info("Configuring Gemini API...")
            genai.configure(api_key=api_key)
            logger.info("Initializing GenerativeModel...")
            self.model = genai.GenerativeModel("gemini-2.5-flash")
            logger.info("✅ Investigation Analyzer initialized")

            self.mitre_analyzer = MITREAttackAnalyzer(api_key)
        except Exception as e:
            logger.error(f"FATAL: InvestigationAnalyzer init failed: {str(e)}")
            raise

    def perform_initial_analysis(
        self, username: str, investigation_steps: List[Dict]
    ) -> Optional[Dict[str, Any]]:
        """
        Perform initial investigation analysis with UNIQUE findings enforcement
        """
        try:
            steps_with_output = [s for s in investigation_steps if s.get("output")]

            logger.info(f"Initial analysis for {username}")
            logger.info(f"Total steps: {len(investigation_steps)}")
            logger.info(f"Steps with output: {len(steps_with_output)}")

            if len(steps_with_output) < 2:
                logger.warning(f"Insufficient data - using fallback")
                return self._fallback_analysis(username, investigation_steps)

            # Build investigation context with step numbers for uniqueness
            investigation_context = ""
            for step in investigation_steps:
                if step.get("output") or step.get("explanation"):
                    output_text = str(step.get("output", "No output data"))
                    remarks_text = str(step.get("remarks", "None"))

                    investigation_context += f"""
    ### Step {step['step_number']}: {step['step_name']}
    Explanation: {step.get('explanation', 'N/A')}
    Output: {output_text}
    Remarks: {remarks_text}
    ---
    """

            # ENHANCED PROMPT with specific findings generation
            prompt = f"""You are an elite cybersecurity analyst specializing in SOC investigations. Analyze this investigation for user: {username}

    INVESTIGATION DATA:
    {investigation_context}

    Your task is to provide a comprehensive security assessment with HIGHLY SPECIFIC and ACTIONABLE findings.

    CLASSIFICATION RULES:
    - TRUE POSITIVE: Clear malicious activity, security violations, compromise indicators, policy violations
    - FALSE POSITIVE: Normal business activity, legitimate user behavior, expected patterns

    CRITICAL REQUIREMENTS FOR FINDINGS:
    
    1. **EXTRACT SPECIFIC DATA POINTS**: 
       - IP addresses with exact reputation scores
       - Geographic locations with specific countries/cities
       - Timestamps with exact times and dates
       - Authentication counts (failed/successful attempts)
       - Device information (managed/unmanaged status)
       - Risk scores and percentages
    
    2. **CREATE UNIQUE, SPECIFIC CATEGORIES**:
       - "Impossible Travel Detection" (not "Geographic Anomaly")
       - "Malicious IP Reputation" (not "IP Issue")
       - "Brute Force Attack Pattern" (not "Authentication Issue")
       - "Unmanaged Device Access" (not "Device Problem")
       - "High-Risk Geographic Access" (not "Location Issue")
    
    3. **PROVIDE ACTIONABLE EVIDENCE**:
       - Include exact numbers, percentages, and metrics
       - Reference specific investigation step outputs
       - Mention specific security tools and their results
       - Include risk assessment scores where available
    
    4. **BUSINESS IMPACT FOCUS**:
       - Explain what this means for the organization
       - Identify potential data at risk
       - Assess compliance implications
       - Suggest immediate containment actions

    EXAMPLES OF EXCELLENT FINDINGS:
    
    ✅ EXCELLENT (Specific, actionable):
    - Category: "Impossible Travel Detection"
      Details: "User authenticated from Mumbai, India at 14:30 UTC, then from London, UK at 14:45 UTC - physically impossible 15-minute travel across 4,200 miles"
      Evidence: "SigninLogs show successful authentication from IP 116.75.193.147 (Mumbai) followed by IP 203.0.113.45 (London) with 15-minute gap"
      Impact: "Indicates credential compromise - attacker using stolen credentials from multiple geographic locations simultaneously"
    
    - Category: "Malicious IP Reputation Confirmed"
      Details: "Source IP 116.75.193.147 flagged as malicious by 8 out of 95 security vendors on VirusTotal with 85% confidence score"
      Evidence: "VirusTotal analysis: 8/95 detections, AbuseIPDB confidence: 85%, associated with botnet activity"
      Impact: "High probability of compromised infrastructure - potential data exfiltration or command & control communication"
    
    - Category: "Brute Force Attack Pattern"
      Details: "47 failed authentication attempts within 2-hour window, followed by successful login using same credentials"
      Evidence: "AuditLogs: FailedLogons=47, TimeWindow=120min, FinalSuccess=True, SourceIP=116.75.193.147"
      Impact: "Successful credential compromise after systematic password attack - immediate account lockdown required"

    MANDATORY ANALYSIS DEPTH:
    - Extract ALL numerical data from investigation outputs
    - Identify ALL IP addresses and their reputation status
    - Note ALL geographic locations and travel patterns
    - Count ALL authentication events (success/failure)
    - Assess ALL device compliance and management status
    - Evaluate ALL risk scores and confidence levels
    - Reference ALL security tool outputs (VirusTotal, AbuseIPDB, etc.)

    Respond ONLY with valid JSON:
    {{
        "classification": "TRUE POSITIVE" or "FALSE POSITIVE",
        "risk_level": "Critical" or "High" or "Medium" or "Low",
        "confidence_score": 0-100,
        "key_findings": [
            {{
                "step_reference": "Exact step name from investigation",
                "category": "Highly specific category (e.g., 'Impossible Travel Detection', 'Malicious IP Reputation', 'Brute Force Attack Pattern')",
                "severity": "Critical/High/Medium/Low",
                "details": "Extremely specific finding with EXACT data points - include all numbers, IPs, locations, timestamps, counts, percentages, and metrics from the investigation",
                "evidence": "Concrete technical evidence with precise measurements (e.g., 'IP: 116.75.193.147, VirusTotal: 8/95 detections, Distance: 4,200 miles, Time: 15 minutes, Confidence: 85%')",
                "impact": "Clear business and security impact with specific risks and recommended immediate actions"
            }}
        ],
        "risk_indicators": [
            {{
                "indicator": "Specific measurable risk indicator with exact values",
                "severity": "Critical/High/Medium/Low",
                "evidence": "Quantified evidence with numbers and metrics"
            }}
        ]
    }}"""

            logger.info("Sending prompt to Gemini...")
            
            # Retry mechanism for API quota issues
            max_retries = 3
            base_delay = 5
            
            for attempt in range(max_retries):
                try:
                    response = self.model.generate_content(prompt)
                    content = response.text.strip()
                    break  # Success, exit retry loop
                except Exception as api_error:
                    error_str = str(api_error)
                    if "429" in error_str or "quota" in error_str.lower():
                        if attempt < max_retries - 1:
                            delay = base_delay * (2 ** attempt)  # Exponential backoff
                            logger.warning(f"API quota exceeded, retrying in {delay}s (attempt {attempt + 1}/{max_retries})")
                            import time
                            time.sleep(delay)
                            continue
                        else:
                            logger.error("API quota exceeded, max retries reached")
                            raise
                    else:
                        raise  # Re-raise non-quota errors immediately

            logger.info(f"Gemini response length: {len(content)}")

            # Clean response
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]

            # CRITICAL FIX: Use aggressive JSON cleaner
            content = clean_json_response(content)

            logger.info(f"Cleaned response preview: {content[:200]}")

            try:
                analysis_result = json.loads(content)
                logger.info(f"✅ JSON parsed: {analysis_result.get('classification')}")

                # ✅ NEW: DEDUPLICATE FINDINGS
                if "key_findings" in analysis_result:
                    original_count = len(analysis_result["key_findings"])
                    analysis_result["key_findings"] = deduplicate_findings(
                        analysis_result["key_findings"]
                    )
                    deduplicated_count = len(analysis_result["key_findings"])

                    if original_count != deduplicated_count:
                        logger.warning(
                            f"⚠️ Deduplicated findings: {original_count} → {deduplicated_count}"
                        )

                # Existing VirusTotal validation logic (keep as is)
                virustotal_malicious_count = 0
                has_virustotal_check = False

                for step in investigation_steps:
                    output = str(step.get("output", "")).lower()

                    if "virustotal" in output:
                        has_virustotal_check = True
                        import re

                        malicious_patterns = [
                            r"malicious[:\s]+(\d+)/(\d+)",
                            r"•\s*malicious[:\s]+(\d+)/(\d+)",
                        ]

                        for pattern in malicious_patterns:
                            match = re.search(pattern, output, re.IGNORECASE)
                            if match:
                                malicious_count = int(match.group(1))
                                total_count = int(match.group(2))

                                if total_count > 0:
                                    malicious_percentage = (
                                        malicious_count / total_count
                                    ) * 100
                                    virustotal_malicious_count = malicious_count

                                    logger.info(
                                        f"VirusTotal detection: {malicious_count}/{total_count} ({malicious_percentage:.1f}%)"
                                    )

                                    if malicious_count > 0:
                                        logger.warning(
                                            f"⚠️ IP flagged as malicious by {malicious_count} vendor(s)"
                                        )
                                break

                # Apply intelligent override logic (keep existing logic)
                if has_virustotal_check:
                    if virustotal_malicious_count == 0:
                        if analysis_result.get("classification") == "TRUE POSITIVE":
                            other_indicators = False
                            for finding in analysis_result.get("key_findings", []):
                                if finding.get("severity") in ["High", "Critical"]:
                                    other_indicators = True
                                    break

                            if not other_indicators:
                                logger.warning(
                                    "Overriding to FALSE POSITIVE: VirusTotal clean + no other high-severity indicators"
                                )
                                analysis_result["classification"] = "FALSE POSITIVE"
                                analysis_result["risk_level"] = "Low"
                                analysis_result["confidence_score"] = 60

                    elif virustotal_malicious_count >= 1:
                        logger.info(
                            f"⚠️ VirusTotal detected malicious IP - maintaining TRUE POSITIVE classification"
                        )

                        if analysis_result.get("classification") == "FALSE POSITIVE":
                            logger.warning(
                                "Overriding to TRUE POSITIVE: VirusTotal detected malicious IP"
                            )
                            analysis_result["classification"] = "TRUE POSITIVE"
                            analysis_result["risk_level"] = "High"
                            analysis_result["confidence_score"] = max(
                                analysis_result.get("confidence_score", 70), 80
                            )

                            malicious_ip_finding = {
                                "step_reference": "Verify IP Reputation Using VirusTotal",
                                "category": "Malicious IP Detected",
                                "severity": "High",
                                "details": f"IP address flagged as malicious by {virustotal_malicious_count} VirusTotal vendor(s)",
                                "evidence": f"VirusTotal detection ratio: {virustotal_malicious_count}/95",
                                "impact": "Potential compromise, data exfiltration risk, or botnet activity",
                            }

                            findings = analysis_result.get("key_findings", [])
                            ip_finding_exists = False
                            for i, finding in enumerate(findings):
                                if "IP" in finding.get(
                                    "category", ""
                                ) or "VirusTotal" in finding.get("step_reference", ""):
                                    findings[i] = malicious_ip_finding
                                    ip_finding_exists = True
                                    break

                            if not ip_finding_exists:
                                findings.append(malicious_ip_finding)

                            analysis_result["key_findings"] = findings

                logger.info(
                    f"Final classification: {analysis_result.get('classification')}"
                )

                return analysis_result

            except json.JSONDecodeError as je:
                logger.error(f"JSON parse error: {str(je)}")
                logger.error(f"Raw content: {content[:500]}")
                return self._fallback_analysis(username, investigation_steps)

        except Exception as e:
            error_str = str(e)
            if "429" in error_str or "quota" in error_str.lower() or "rate limit" in error_str.lower():
                logger.warning(f"API quota exceeded after retries, using fallback analysis")
            else:
                logger.exception(f"Error in initial analysis: {error_str}")
            return self._fallback_analysis(username, investigation_steps)

    def _fallback_analysis(
        self, username: str, investigation_steps: List[Dict]
    ) -> Dict[str, Any]:
        """
        FIXED: Fallback analysis with deduplication
        """
        import re  # Ensure re is available in this scope
        
        logger.info("Using fallback analysis")

        risk_score = 0
        findings = []
        has_virustotal_malicious = False
        malicious_ip_count = 0

        # Enhanced fallback logic with specific findings extraction
        for step in investigation_steps:
            output = str(step.get("output", ""))
            output_lower = output.lower()
            step_name = step.get("step_name", "Unknown Step")

            # Extract IP addresses for analysis
            ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
            ips_found = re.findall(ip_pattern, output)

            # VirusTotal analysis with specific details
            if "virustotal" in output_lower:
                # Look for malicious detection patterns
                malicious_patterns = [
                    r"malicious[:\s]+(\d+)/(\d+)",
                    r"•\s*malicious[:\s]+(\d+)/(\d+)",
                    r"detections?[:\s]+(\d+)\s*out\s*of\s*(\d+)",
                    r"flagged[:\s]+(\d+)/(\d+)"
                ]

                for pattern in malicious_patterns:
                    match = re.search(pattern, output, re.IGNORECASE)
                    if match:
                        malicious_count = int(match.group(1))
                        total_count = int(match.group(2))
                        detection_percentage = (malicious_count / total_count * 100) if total_count > 0 else 0

                        if malicious_count > 0:
                            has_virustotal_malicious = True
                            malicious_ip_count = malicious_count
                            risk_score += 40

                            # Extract specific IP if available
                            ip_detail = f" (IP: {ips_found[0]})" if ips_found else ""
                            
                            findings.append({
                                "step_reference": step_name,
                                "category": "Malicious IP Reputation Confirmed",
                                "severity": "Critical" if malicious_count >= 5 else "High",
                                "details": f"IP address{ip_detail} flagged as malicious by {malicious_count} out of {total_count} VirusTotal security vendors ({detection_percentage:.1f}% detection rate)",
                                "evidence": f"VirusTotal analysis: {malicious_count}/{total_count} detections, Detection rate: {detection_percentage:.1f}%{ip_detail}",
                                "impact": f"High-confidence malicious infrastructure detected - immediate blocking required. Risk of data exfiltration, command & control communication, or botnet activity",
                            })
                        elif malicious_count == 0:
                            risk_score -= 10
                        break

            # Geographic anomaly analysis with specific details
            if any(keyword in output_lower for keyword in ["impossible travel", "geographic", "location", "country"]):
                risk_score += 25
                
                # Extract specific geographic details
                countries = re.findall(r"\b(?:United States|India|China|Russia|Germany|France|United Kingdom|Canada|Australia|Japan|Brazil|Mexico)\b", output, re.IGNORECASE)
                
                # Check for impossible travel indicators
                if "impossible travel" in output_lower:
                    category = "Impossible Travel Detection"
                    severity = "Critical"
                    details = f"Impossible travel pattern detected between geographic locations"
                    if countries and len(countries) >= 2:
                        details += f" - access from {countries[0]} and {countries[1]}"
                    impact = "Strong indicator of credential compromise - user cannot physically travel between locations in observed timeframe"
                else:
                    category = "Geographic Access Anomaly"
                    severity = "Medium"
                    details = f"Unusual geographic access patterns detected"
                    if countries:
                        details += f" - access from {', '.join(set(countries))}"
                    if ips_found:
                        details += f" via IP addresses: {', '.join(ips_found[:3])}"
                    impact = "Potential account compromise or unauthorized access from unexpected geographic locations"
                
                findings.append({
                    "step_reference": step_name,
                    "category": category,
                    "severity": severity,
                    "details": details,
                    "evidence": f"Geographic indicators: Countries={countries}, IPs={ips_found[:2]}",
                    "impact": impact,
                })

            # Authentication failure analysis with specific counts
            if "failed" in output_lower:
                # Look for specific failure counts
                failed_patterns = [
                    r"failed[^:]*:\s*(\d+)",
                    r"failures?[^:]*:\s*(\d+)",
                    r"unsuccessful[^:]*:\s*(\d+)",
                    r"(\d+)\s*failed"
                ]
                
                failed_count = 0
                for pattern in failed_patterns:
                    failed_match = re.search(pattern, output, re.IGNORECASE)
                    if failed_match:
                        failed_count = int(failed_match.group(1))
                        break
                
                if failed_count > 0:
                    if failed_count >= 20:
                        risk_score += 35
                        severity = "Critical"
                        category = "Brute Force Attack Pattern"
                        impact = "High-volume brute force attack detected - immediate account lockdown required"
                    elif failed_count >= 10:
                        risk_score += 25
                        severity = "High"
                        category = "Credential Stuffing Attack"
                        impact = "Systematic credential attack detected - password reset and MFA enforcement recommended"
                    elif failed_count >= 5:
                        risk_score += 15
                        severity = "Medium"
                        category = "Multiple Authentication Failures"
                        impact = "Repeated authentication failures may indicate attack or user account issues"
                    else:
                        risk_score += 5
                        severity = "Low"
                        category = "Authentication Anomaly"
                        impact = "Minor authentication issues detected - monitoring recommended"
                    
                    findings.append({
                        "step_reference": step_name,
                        "category": category,
                        "severity": severity,
                        "details": f"{failed_count} authentication failures detected",
                        "evidence": f"Failed authentication count: {failed_count}",
                        "impact": impact,
                    })
                else:
                    risk_score += 10

            # Suspicious activity indicators
            if "suspicious" in output_lower:
                risk_score += 20

            # Privilege escalation indicators
            if any(keyword in output_lower for keyword in ["admin", "privilege", "escalation", "role", "global administrator"]):
                risk_score += 15

        # ✅ DEDUPLICATE FINDINGS
        findings = deduplicate_findings(findings)

        # Existing classification logic (keep as is)
        if has_virustotal_malicious:
            classification = "TRUE POSITIVE"
            risk_level = "High"
            confidence = min(75 + (malicious_ip_count * 5), 95)
        elif risk_score >= 50:
            classification = "TRUE POSITIVE"
            risk_level = "High" if risk_score >= 70 else "Medium"
            confidence = min(risk_score, 90)
        elif risk_score >= 30:
            classification = "TRUE POSITIVE"
            risk_level = "Medium"
            confidence = 70
        else:
            classification = "FALSE POSITIVE"
            risk_level = "Low"
            confidence = 60

        logger.info(f"Fallback result: {classification} (risk_score={risk_score})")

        return {
            "classification": classification,
            "risk_level": risk_level,
            "confidence_score": confidence,
            "key_findings": (
                findings
                if findings
                else [
                    {
                        "step_reference": "Overall Assessment",
                        "category": "General Analysis",
                        "severity": "Low",
                        "details": "Limited investigation data available for analysis",
                        "evidence": f"Analyzed {len(investigation_steps)} investigation steps",
                        "impact": "Manual review recommended",
                    }
                ]
            ),
            "risk_indicators": [
                {
                    "indicator": "Investigation completeness",
                    "severity": "Medium" if has_virustotal_malicious else "Low",
                    "evidence": f"{len([s for s in investigation_steps if s.get('output')])} steps with data",
                }
            ],
        }

    def perform_complete_analysis(
        self, username: str, investigation_steps: List[Dict]
    ) -> Dict[str, Any]:
        """Perform complete analysis with all components"""
        try:
            # Initial analysis
            initial_analysis = self.perform_initial_analysis(
                username, investigation_steps
            )

            if not initial_analysis:
                return {
                    "status": "error",
                    "error": "Initial analysis failed",
                    "analysis_timestamp": datetime.now().isoformat(),
                }

            # MITRE analysis
            mitre_analysis = self.mitre_analyzer.analyze_mitre_attack_chain(
                username,
                initial_analysis["classification"],
                initial_analysis,
                investigation_steps,
            )

            # Geographic risk
            geo_risk = self.mitre_analyzer.extract_geolocation_risk(investigation_steps)

            # Executive summary
            executive_summary = self._create_executive_summary(
                username, initial_analysis, mitre_analysis, geo_risk
            )

            return {
                "status": "success",
                "analysis_timestamp": datetime.now().isoformat(),
                "initial_analysis": initial_analysis,
                "mitre_attack_analysis": (
                    mitre_analysis.get("mitre_attack_analysis", {})
                    if mitre_analysis
                    else {}
                ),
                "executive_summary": executive_summary,
                "geographic_risk": geo_risk,
                "investigation_steps_analyzed": len(investigation_steps),
            }

        except Exception as e:
            logger.exception(f"Error in complete analysis: {str(e)}")
            return {
                "status": "error",
                "error": str(e),
                "analysis_timestamp": datetime.now().isoformat(),
            }

    def _create_executive_summary(
        self,
        username: str,
        initial_analysis: Dict,
        mitre_analysis: Dict,
        geo_risk: Dict,
    ) -> Dict[str, Any]:
        """Create executive summary"""
        classification = initial_analysis.get("classification", "UNKNOWN")
        risk_level = initial_analysis.get("risk_level", "UNKNOWN")

        key_sub_techniques = []
        if mitre_analysis and "mitre_attack_analysis" in mitre_analysis:
            techniques = mitre_analysis["mitre_attack_analysis"].get(
                "mitre_techniques_observed", []
            )
            for tech in techniques[:5]:
                if tech.get("sub_technique"):
                    key_sub_techniques.append(
                        f"{tech.get('technique')} > {tech.get('sub_technique')}"
                    )

        return {
            "one_line_summary": f"{classification} - {risk_level} risk investigation for {username}",
            "attack_sophistication": "Medium" if "TRUE" in classification else "Low",
            "business_impact": "High" if "TRUE" in classification else "Low",
            "immediate_actions": [
                "Review authentication logs",
                "Check for suspicious IP addresses",
                "Verify user account status",
                "Implement MFA if not enabled",
            ],
            "investigation_priority": "P1" if "TRUE" in classification else "P3",
            "key_sub_techniques_observed": key_sub_techniques,
        }


def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate findings to ensure each finding is unique and specific

    Removes duplicate findings based on category and severity,
    keeping only the most detailed version
    """
    if not findings:
        return findings

    # Group by category
    category_map = {}

    for finding in findings:
        category = finding.get("category", "Unknown")
        severity = finding.get("severity", "Low")

        # Create unique key
        key = f"{category}_{severity}"

        # Keep the finding with more detailed evidence
        if key not in category_map:
            category_map[key] = finding
        else:
            # Compare evidence length and keep the more detailed one
            existing_evidence = category_map[key].get("evidence", "")
            new_evidence = finding.get("evidence", "")

            if len(new_evidence) > len(existing_evidence):
                category_map[key] = finding

    # Return deduplicated findings
    return list(category_map.values())

