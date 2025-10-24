import re
import json
import pandas as pd
from datetime import datetime
import google.generativeai as genai
from typing import Dict, List, Any, Optional

import logging

logger = logging.getLogger(__name__)


class MITREAttackAnalyzer:
    def __init__(self, api_key: str):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel("gemini-2.0-flash-exp")

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

        # Load MITRE ATT&CK techniques and sub-techniques from document
        self.mitre_data = self._load_mitre_data()

    def _load_mitre_data(self) -> Dict[str, Any]:
        """Load MITRE ATT&CK framework data from the document"""
        # This will be populated from the MITRE ATT&CK document provided
        # Structure: {tactic: {technique: [sub-techniques]}}
        from backend.mitre_data import mitre_structure

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

                    # Extract IP addresses from output
                    ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
                    ips = re.findall(ip_pattern, output)

                    geo_risks["high_risk_locations"].append(
                        {
                            "country": country.title(),
                            "step": step.get("step_name", "Unknown"),
                            "context": output[:200],
                        }
                    )

                    if ips:
                        geo_risks["suspicious_ips"].extend(ips)

        geo_risks["suspicious_ips"] = list(set(geo_risks["suspicious_ips"]))
        return geo_risks

    def build_mitre_techniques_reference(self) -> str:
        """Build comprehensive MITRE techniques reference for the AI prompt"""
        reference = "\n## COMPLETE MITRE ATT&CK TECHNIQUES REFERENCE:\n\n"

        for tactic, techniques in self.mitre_data.items():
            reference += f"\n### {tactic}\n"
            for technique, sub_techniques in techniques.items():
                reference += f"- **{technique}**"
                if sub_techniques:
                    reference += f"\n  Sub-techniques: {', '.join(sub_techniques)}"
                reference += "\n"

        return reference

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
                }},
                {{
                    "stage": 2,
                    "timestamp": "2025-10-08 15:34:34",
                    "tactic": "Privilege Escalation",
                    "technique": "Account Manipulation: Additional Cloud Roles (T1098.003)",
                    "description": "Detailed description of privilege escalation activity",
                    "evidence": "Role assignment logs showing Global Administrator role granted",
                    "severity": "RED",
                    "sub_technique_details": "Specific cloud role manipulation technique used",
                    "impact": "Attacker gained full administrative control over cloud environment",
                    "indicators_observed": ["Privilege escalation", "Administrative role assignment", "Unauthorized permission changes"]
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
                "sophistication_details": "Detailed analysis of attacker capabilities based on observed techniques, operational security, and tool usage",
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
                            }},
                            {{
                                "stage": "Defense Evasion", 
                                "techniques": ["T1550.004 - Use Alternate Authentication Material: Web Session Cookie"],
                                "status": "LIKELY",
                                "color": "AMBER",
                                "sub_technique_details": "Session hijacking using stolen cookies"
                            }},
                            {{
                                "stage": "Exfiltration",
                                "techniques": ["T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage"],
                                "status": "PREDICTED",
                                "color": "GREEN",
                                "sub_technique_details": "Data exfiltration to attacker-controlled cloud storage"
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
            "key_sub_techniques_observed": ["Cloud Accounts (T1078.004)", "Additional sub-techniques as observed"]
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
    4. **Detailed Procedures**: Every technique must have a comprehensive procedure describing the exact attack method
    5. **Comprehensive Timeline**: Attack timeline must include ALL stages with detailed narratives for each event
    6. **Explanations**: All assessment fields (attack_stage, sophistication, confidence, dwell_time) must include detailed explanations
    7. **Color Coding**: 
    - RED = Confirmed observed technique/sub-technique
    - AMBER = Highly likely technique/sub-technique in progress
    - GREEN = Predicted future technique/sub-technique
    8. **Completeness**: Map ALL relevant MITRE tactics (1-14) with appropriate sub-techniques
    9. **Specificity**: Use exact MITRE ATT&CK technique IDs and sub-technique IDs (e.g., T1078.004)
    10. **Actionability**: Recommendations must be specific, prioritized, and implementable
    11. **Timeline Accuracy**: Correlate MITRE techniques with actual timestamps from investigation
    12. **Prediction Quality**: Next steps must include specific sub-techniques and be realistic based on observed attacker behavior
    13. **Geographic Context**: If high-risk countries detected, emphasize in threat profiling
    14. **Sub-Technique Justification**: Explain WHY each specific sub-technique was selected based on evidence
    15. **Navigator Compatibility**: Include both parent techniques and sub-techniques in MITRE Navigator layer
    16. **Coverage Tracking**: Track sub-technique coverage percentage in analysis

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

    def analyze_mitre_attack_chain(
        self,
        username: str,
        classification: str,
        investigation_summary: Dict[str, Any],
        investigation_steps: List[Dict],
    ) -> Optional[Dict[str, Any]]:
        """Generate comprehensive MITRE ATT&CK analysis with sub-techniques"""

        try:
            # Extract geolocation risks
            geo_risk_data = self.extract_geolocation_risk(investigation_steps)

            # Force TRUE POSITIVE if high-risk country detected
            if (
                geo_risk_data["has_high_risk_country"]
                and "FALSE" in classification.upper()
            ):
                classification = "TRUE POSITIVE"
                investigation_summary["classification"] = "TRUE POSITIVE"
                investigation_summary["risk_level"] = "CRITICAL"
                investigation_summary["confidence_score"] = max(
                    investigation_summary.get("confidence_score", 0), 90
                )

                # Add geo-risk to key findings
                if "key_findings" not in investigation_summary:
                    investigation_summary["key_findings"] = []

                investigation_summary["key_findings"].insert(
                    0,
                    {
                        "step_reference": "Geolocation Analysis",
                        "category": "Geographic Anomaly",
                        "severity": "Critical",
                        "details": f"Access from high-risk country: {', '.join([loc['country'] for loc in geo_risk_data['high_risk_locations']])}",
                        "evidence": f"Suspicious IPs: {', '.join(geo_risk_data['suspicious_ips'])}",
                        "impact": "High-risk geographic location significantly increases likelihood of malicious activity",
                    },
                )

            # Build and execute MITRE analysis prompt
            prompt = self.build_mitre_analysis_prompt(
                username,
                classification,
                investigation_summary,
                geo_risk_data,
                investigation_steps,
            )

            response = self.model.generate_content(prompt)
            content = response.text.strip()

            # Clean response
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]

            content = content.strip()
            
            content_safe = re.sub(r'(?<!\\)\n', r'\\n', content)
            content_safe = re.sub(r'(?<!\\)\t', r'\\t', content_safe)

            # Parse JSON
            mitre_analysis = json.loads(content_safe)

            # Add geo-risk metadata
            mitre_analysis["geographic_risk_assessment"] = geo_risk_data

            # Validate sub-technique coverage
            self._validate_subtechnique_coverage(mitre_analysis)

            return mitre_analysis

        except json.JSONDecodeError as e:
            print(f"JSON parsing error in MITRE analysis: {str(e)}")
            return None
        except Exception as e:
            print(f"Error in MITRE analysis: {str(e)}")
            return None

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
            # 💡 Log before configuration
            logger.info("Attempting to configure Gemini API...")
            genai.configure(api_key=api_key)
            logger.info("Gemini API configured.")

            # 💡 Log before model initialization
            logger.info("Attempting to initialize GenerativeModel...")
            self.model = genai.GenerativeModel("gemini-2.0-flash-exp")
            logger.info("GenerativeModel initialized.")

            self.mitre_analyzer = MITREAttackAnalyzer(api_key)
        except Exception as e:
            # 🚨 If this block is hit, the initialization failed.
            logger.error(f"FATAL ERROR during InvestigationAnalyzer init: {str(e)}")
            raise  # Re-raise to be caught by predictions_router

    def extract_investigation_steps(self, df, username: str) -> List[Dict]:
        """Extract investigation steps with their outputs AND remarks for the specific user - FIXED"""
        investigation_steps = []

        for idx, row in df.iterrows():
            # ✅ SKIP HEADER ROW - Check if Step column is NULL/NaN
            step_value = row.get("Step", None)
            if pd.isna(step_value) or step_value is None:
                # This is likely the header row with rule number in "Name" column
                print(f"⏭️  Skipping header row at index {idx}")
                continue

            # ✅ SKIP ROWS WITH NO STEP NUMBER
            try:
                step_num = int(step_value)
                if step_num < 1:
                    print(f"⏭️  Skipping invalid step number: {step_value}")
                    continue
            except (ValueError, TypeError):
                print(f"⏭️  Skipping non-numeric step: {step_value}")
                continue

            # Extract ALL relevant columns
            output_value = row.get("Output", "")
            remarks_value = row.get("Remarks/Comments", "")
            step_name = row.get("Name", "Unknown Step")
            explanation = row.get("Explanation", "")
            kql_query = row.get("KQL Query", "")

            # ✅ Clean up values - handle None/NULL properly
            output_str = ""
            if output_value is not None and pd.notna(output_value):
                output_clean = str(output_value).strip()
                if output_clean.lower() not in ["nan", "none", "null", ""]:
                    output_str = output_clean

            remarks_str = ""
            if remarks_value is not None and pd.notna(remarks_value):
                remarks_clean = str(remarks_value).strip()
                if remarks_clean.lower() not in ["nan", "none", "null", ""]:
                    remarks_str = remarks_clean

            step_data = {
                "step_number": step_num,
                "step_name": str(step_name) if pd.notna(step_name) else "Unknown Step",
                "explanation": str(explanation) if pd.notna(explanation) else "",
                "kql_query": (
                    str(kql_query)
                    if pd.notna(kql_query)
                    and str(kql_query).strip().lower()
                    not in ["nan", "none", "null", ""]
                    else ""
                ),
                "output": output_str,  # ✅ Query output
                "remarks": remarks_str,  # ✅ Analyst remarks
                "analyst_notes": remarks_str,  # ✅ Additional field for context
            }

            # ✅ Include step if it has meaningful data
            # Since username might not be in every step, we include all steps with data
            has_meaningful_data = (
                output_str or remarks_str or step_data.get("explanation")
            )

            if has_meaningful_data:
                investigation_steps.append(step_data)

        # ✅ Debug logging
        print(f"📊 Extracted {len(investigation_steps)} valid steps")
        if investigation_steps:
            for step in investigation_steps[:3]:  # Show first 3 steps
                print(f"  - Step {step['step_number']}: {step['step_name']}")
                print(f"    Output length: {len(step['output'])} chars")
                print(f"    Remarks length: {len(step['remarks'])} chars")
        else:
            print(f"⚠️  No valid investigation steps found!")
            print(f"   Total rows in dataframe: {len(df)}")
            print(f"   DataFrame columns: {df.columns.tolist()}")
            if len(df) > 0:
                print(f"   First row 'Step' value: {df.iloc[0].get('Step')}")
                print(f"   First row 'Name' value: {df.iloc[0].get('Name')}")

        return investigation_steps

    def _calculate_risk_score(self, investigation_steps: List[Dict]) -> int:
        """Calculate risk score based on investigation data to bias toward true positive"""
        risk_score = 0

        for step in investigation_steps:
            output = str(step.get("output", "")).lower()
            remarks = str(step.get("remarks", "")).lower()

            # High-risk indicators
            if any(
                country in output
                for country in ["russia", "china", "north korea", "iran"]
            ):
                risk_score += 30
            if "unknown" in output or "unknown" in remarks:
                risk_score += 20
            if "suspicious" in output or "suspicious" in remarks:
                risk_score += 25
            if "global admin" in output or "privilege" in output:
                risk_score += 15
            if "impossible" in output or "travel" in output:
                risk_score += 20
            if any(ip in output for ip in ["ip", "address", "location"]):
                risk_score += 10

        return min(risk_score, 100)

    def _should_classify_true_positive(self, investigation_steps: List[Dict]) -> bool:
        """Determine if classification should be TRUE POSITIVE based on risk indicators"""
        risk_score = self._calculate_risk_score(investigation_steps)

        # Bias toward true positive: threshold lowered to 40
        return risk_score >= 40

    def build_initial_analysis_prompt(
        self, username: str, investigation_steps: List[Dict]
    ) -> str:
        """Build prompt for initial investigation analysis with true positive bias"""
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
        {remarks_info}
        ---
        """

        prompt = f"""You are a cybersecurity analyst analyzing investigation data for potential account compromise.

    # INVESTIGATION DATA FOR USER: {username}

    {investigation_context}

    # ANALYSIS REQUIREMENTS:

    1. **Classification**: Classify as TRUE POSITIVE or FALSE POSITIVE
    2. **Risk Level**: Critical, High, Medium, Low
    3. **Confidence Score**: 0-100% based on evidence quality
    4. **Key Findings**: List specific suspicious indicators
    5. **Risk Indicators**: Technical risk factors observed

    # CLASSIFICATION GUIDELINES:

    **TRUE POSITIVE Indicators (Prioritize these):**
    - Access from unknown locations or devices
    - Impossible travel patterns
    - Suspicious IP addresses or geolocations
    - Privilege escalation attempts
    - Unusual account activity patterns
    - High-risk country connections (Russia, China, etc.)
    - Analyst remarks indicating suspicion
    - Multiple risk factors present

    **FALSE POSITIVE Indicators:**
    - Only normal business activity
    - Expected user behavior patterns
    - No concrete suspicious indicators
    - Legitimate business travel
    - Authorized administrative actions

    # IMPORTANT: 
    - When multiple indicators exist, lean toward TRUE POSITIVE
    - High-risk countries automatically increase suspicion
    - Unknown devices/locations are strong TRUE POSITIVE indicators
    - Analyst remarks should be heavily weighted

    # OUTPUT FORMAT (JSON only):

    {{
        "classification": "TRUE POSITIVE" or "FALSE POSITIVE",
        "risk_level": "Critical" or "High" or "Medium" or "Low",
        "confidence_score": 85,
        "key_findings": [
            {{
                "step_reference": "Step name or reference",
                "category": "Geographic Anomaly | Privilege Escalation | Suspicious Activity",
                "severity": "Critical | High | Medium | Low",
                "details": "Specific finding description",
                "evidence": "Supporting evidence from investigation",
                "impact": "Potential security impact"
            }}
        ],
        "risk_indicators": [
            {{
                "indicator": "Unknown device access",
                "severity": "High",
                "evidence": "Device not recognized in user's history"
            }}
        ]
    }}

    Now analyze the investigation data and provide your assessment in JSON format:"""

        return prompt

    def perform_initial_analysis(
        self, username: str, investigation_steps: List[Dict]
    ) -> Optional[Dict[str, Any]]:
        """Perform initial investigation analysis with better error handling"""
        try:
            # ✅ VALIDATE we have enough data
            steps_with_output = [s for s in investigation_steps if s.get("output")]

            logger.info(f"Initial analysis for {username}")
            logger.info(f"Total steps: {len(investigation_steps)}")
            logger.info(f"Steps with output: {len(steps_with_output)}")

            if len(steps_with_output) < 2:
                logger.warning(
                    f"Only {len(steps_with_output)} steps with output - using fallback analysis"
                )
                return self._fallback_analysis(username, investigation_steps)

            # Build simplified context
            investigation_context = ""
            for step in investigation_steps:
                if step.get("output") or step.get("explanation"):
                    investigation_context += f"""
    ### Step {step['step_number']}: {step['step_name']}
    Explanation: {step.get('explanation', 'N/A')}
    Output: {step.get('output', 'No output data')}
    Remarks: {step.get('remarks', 'None')}
    ---
    """

            # ✅ SIMPLIFIED PROMPT - Less strict requirements
            prompt = f"""You are a cybersecurity analyst. Analyze this investigation for user: {username}

    INVESTIGATION DATA:
    {investigation_context}

    Classify as TRUE POSITIVE or FALSE POSITIVE based on available evidence.

    GUIDELINES:
    - TRUE POSITIVE: Suspicious activity, unusual patterns, high-risk indicators
    - FALSE POSITIVE: Normal business activity, no concrete threats

    Respond ONLY with valid JSON:
    {{
        "classification": "TRUE POSITIVE" or "FALSE POSITIVE",
        "risk_level": "Critical" or "High" or "Medium" or "Low",
        "confidence_score": 0-100,
        "key_findings": [
            {{
                "step_reference": "Step name",
                "category": "Category",
                "severity": "High/Medium/Low",
                "details": "Finding description",
                "evidence": "Supporting evidence",
                "impact": "Security impact"
            }}
        ],
        "risk_indicators": [
            {{
                "indicator": "Risk indicator",
                "severity": "High/Medium/Low",
                "evidence": "Evidence"
            }}
        ]
    }}"""

            logger.info("Sending prompt to Gemini API...")
            response = self.model.generate_content(prompt)
            content = response.text.strip()

            logger.info(f"Gemini response length: {len(content)}")

            # Clean response
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]

            content = content.strip()
            
            content_safe = re.sub(r'(?<!\\)\n', r'\\n', content)
            content_safe = re.sub(r'(?<!\\)\t', r'\\t', content_safe)

            # ✅ LOG RAW RESPONSE for debugging
            logger.info(f"Cleaned response preview: {content_safe[:200]}")

            try:
                analysis_result = json.loads(content_safe)
                logger.info(
                    f"✅ JSON parsed successfully: {analysis_result.get('classification')}"
                )
                return analysis_result
            except json.JSONDecodeError as je:
                logger.error(f"JSON parse error: {str(je)}")
                logger.error(f"Raw content: {content}")
                return self._fallback_analysis(username, investigation_steps)

        except Exception as e:
            logger.exception(f"Error in initial analysis: {str(e)}")
            return self._fallback_analysis(username, investigation_steps)

    def _fallback_analysis(
        self, username: str, investigation_steps: List[Dict]
    ) -> Dict[str, Any]:
        """Fallback analysis when LLM fails"""
        logger.info("Using fallback analysis")

        # Simple heuristic analysis
        risk_score = 0
        findings = []

        for step in investigation_steps:
            output = str(step.get("output", "")).lower()
            if "failed" in output or "suspicious" in output:
                risk_score += 30
                findings.append(
                    {
                        "step_reference": step["step_name"],
                        "category": "Suspicious Activity",
                        "severity": "High",
                        "details": "Failed attempts or suspicious indicators detected",
                        "evidence": output[:200],
                        "impact": "Potential security concern",
                    }
                )
            elif "unknown" in output:
                risk_score += 20

        classification = "TRUE POSITIVE" if risk_score >= 40 else "FALSE POSITIVE"
        risk_level = (
            "High" if risk_score >= 60 else ("Medium" if risk_score >= 40 else "Low")
        )

        return {
            "classification": classification,
            "risk_level": risk_level,
            "confidence_score": min(risk_score, 95),
            "key_findings": (
                findings
                if findings
                else [
                    {
                        "step_reference": "Overall Assessment",
                        "category": "General",
                        "severity": "Low",
                        "details": "Limited investigation data available",
                        "evidence": f"Analysis based on {len(investigation_steps)} steps",
                        "impact": "Requires manual review",
                    }
                ]
            ),
            "risk_indicators": [
                {
                    "indicator": "Investigation completeness",
                    "severity": "Low",
                    "evidence": f"Only {len([s for s in investigation_steps if s.get('output')])} steps have output data",
                }
            ],
        }

    def analyze_investigation(
        self, df: pd.DataFrame, username: str
    ) -> Optional[Dict[str, Any]]:
        """Main analysis function - unchanged interface"""
        try:
            # Extract investigation steps
            investigation_steps = self.extract_investigation_steps(df, username)

            if not investigation_steps:
                print(f"No investigation steps found for user: {username}")
                return None

            # Perform initial analysis
            initial_analysis = self.perform_initial_analysis(
                username, investigation_steps
            )

            if not initial_analysis:
                print("Initial analysis failed")
                return None

            # Generate MITRE ATT&CK analysis
            mitre_analysis = self.mitre_analyzer.analyze_mitre_attack_chain(
                username,
                initial_analysis["classification"],
                initial_analysis,
                investigation_steps,
            )

            # Combine results
            combined_results = {
                "user_analysis": initial_analysis,
                "mitre_attack_analysis": mitre_analysis,
                "investigation_steps_analyzed": len(investigation_steps),
                "analysis_timestamp": datetime.now().isoformat(),
            }

            return combined_results

        except Exception as e:
            print(f"Error in investigation analysis: {str(e)}")
            return None

    def perform_complete_analysis(
        self, username: str, investigation_steps: List[Dict]
    ) -> Dict[str, Any]:
        """
        Perform complete analysis including initial classification and MITRE ATT&CK mapping
        """
        try:
            # Perform initial analysis
            initial_analysis = self.perform_initial_analysis(
                username, investigation_steps
            )

            if not initial_analysis:
                return {
                    "status": "error",
                    "error": "Initial analysis failed",
                    "analysis_timestamp": datetime.now().isoformat(),
                }

            # Generate MITRE ATT&CK analysis
            mitre_analysis = self.mitre_analyzer.analyze_mitre_attack_chain(
                username,
                initial_analysis["classification"],
                initial_analysis,
                investigation_steps,
            )

            # Extract geographic risk
            geo_risk = self.mitre_analyzer.extract_geolocation_risk(investigation_steps)

            # Create executive summary
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
            print(f"Error in complete analysis: {str(e)}")
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
        """Create executive summary from analysis results"""

        classification = initial_analysis.get("classification", "UNKNOWN")
        risk_level = initial_analysis.get("risk_level", "UNKNOWN")

        # Extract key sub-techniques from MITRE analysis
        key_sub_techniques = []
        if mitre_analysis and "mitre_attack_analysis" in mitre_analysis:
            techniques = mitre_analysis["mitre_attack_analysis"].get(
                "mitre_techniques_observed", []
            )
            for tech in techniques:
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
            "key_sub_techniques_observed": key_sub_techniques[:5],  # Top 5 only
        }
