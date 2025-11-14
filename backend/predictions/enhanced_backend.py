"""
Enhanced backend for predictions with better investigation specificity and MITRE mapping
"""
import json
import re
from typing import Dict, List, Any, Optional
from datetime import datetime


class EnhancedInvestigationAnalyzer:
    """Enhanced analyzer for more specific investigation details"""
    
    def __init__(self):
        self.investigation_patterns = {
            "geographic_anomaly": {
                "keywords": ["geographic", "location", "country", "ip", "travel", "impossible"],
                "severity_mapping": {
                    "impossible_travel": "CRITICAL",
                    "high_risk_country": "HIGH", 
                    "unusual_location": "MEDIUM",
                    "multiple_locations": "LOW"
                }
            },
            "authentication_failure": {
                "keywords": ["authentication", "login", "signin", "failure", "failed", "password"],
                "severity_mapping": {
                    "brute_force": "CRITICAL",
                    "multiple_failures": "HIGH",
                    "credential_stuffing": "HIGH",
                    "single_failure": "LOW"
                }
            },
            "privilege_escalation": {
                "keywords": ["privilege", "escalation", "admin", "elevated", "permissions"],
                "severity_mapping": {
                    "admin_access": "CRITICAL",
                    "role_change": "HIGH",
                    "permission_change": "MEDIUM"
                }
            },
            "device_anomaly": {
                "keywords": ["device", "endpoint", "compliance", "managed", "trust"],
                "severity_mapping": {
                    "unmanaged_device": "HIGH",
                    "non_compliant": "MEDIUM",
                    "new_device": "LOW"
                }
            }
        }
    
    def enhance_findings(self, raw_findings: List[Dict]) -> List[Dict]:
        """Enhance findings with more specific details and better categorization"""
        enhanced_findings = []
        
        for finding in raw_findings:
            enhanced_finding = self._enhance_single_finding(finding)
            enhanced_findings.append(enhanced_finding)
        
        return enhanced_findings
    
    def _enhance_single_finding(self, finding: Dict) -> Dict:
        """Enhance a single finding with specific details"""
        enhanced = finding.copy()
        
        # Extract more specific details from evidence
        evidence = finding.get("evidence", "").lower()
        details = finding.get("details", "").lower()
        combined_text = f"{evidence} {details}"
        
        # Enhance category specificity
        enhanced["category"] = self._determine_specific_category(combined_text, finding.get("category", ""))
        
        # Enhance severity based on specific indicators
        enhanced["severity"] = self._determine_enhanced_severity(combined_text, finding.get("severity", "MEDIUM"))
        
        # Add specific indicators
        enhanced["specific_indicators"] = self._extract_specific_indicators(combined_text)
        
        # Add remediation steps
        enhanced["remediation_steps"] = self._generate_remediation_steps(enhanced["category"], enhanced["severity"])
        
        # Add timeline context
        enhanced["timeline_context"] = self._add_timeline_context(finding)
        
        return enhanced
    
    def _determine_specific_category(self, text: str, original_category: str) -> str:
        """Determine more specific category based on text analysis"""
        
        # Geographic anomalies
        if any(keyword in text for keyword in ["impossible travel", "geographic", "location"]):
            if "impossible travel" in text or "< 1 hour" in text:
                return "Impossible Travel Detection"
            elif any(country in text for country in ["russia", "china", "north korea", "iran"]):
                return "High-Risk Geographic Location"
            elif "multiple locations" in text or "different countries" in text:
                return "Geographic Anomaly"
            else:
                return "Location-Based Suspicious Activity"
        
        # Authentication issues
        elif any(keyword in text for keyword in ["authentication", "login", "signin", "password"]):
            if "brute force" in text or "multiple failed" in text:
                return "Brute Force Attack"
            elif "credential stuffing" in text:
                return "Credential Stuffing Attack"
            elif "mfa" in text or "multi-factor" in text:
                return "MFA Bypass Attempt"
            else:
                return "Authentication Anomaly"
        
        # Device/Endpoint issues
        elif any(keyword in text for keyword in ["device", "endpoint", "compliance"]):
            if "unmanaged" in text or "not managed" in text:
                return "Unmanaged Device Access"
            elif "non-compliant" in text or "compliance" in text:
                return "Non-Compliant Device"
            else:
                return "Device Trust Issue"
        
        # Privilege escalation
        elif any(keyword in text for keyword in ["privilege", "admin", "elevated"]):
            if "admin" in text or "administrator" in text:
                return "Administrative Privilege Escalation"
            elif "role change" in text:
                return "Role-Based Access Change"
            else:
                return "Privilege Escalation Attempt"
        
        return original_category or "Security Anomaly"
    
    def _determine_enhanced_severity(self, text: str, original_severity: str) -> str:
        """Determine enhanced severity based on specific indicators"""
        
        # Critical indicators
        critical_indicators = [
            "impossible travel", "admin access", "brute force", "high-risk country",
            "russia", "china", "north korea", "iran", "credential stuffing"
        ]
        
        # High indicators  
        high_indicators = [
            "multiple failures", "unmanaged device", "privilege escalation",
            "mfa bypass", "role change", "suspicious location"
        ]
        
        # Medium indicators
        medium_indicators = [
            "geographic anomaly", "authentication failure", "device compliance",
            "unusual activity", "multiple locations"
        ]
        
        if any(indicator in text for indicator in critical_indicators):
            return "CRITICAL"
        elif any(indicator in text for indicator in high_indicators):
            return "HIGH"
        elif any(indicator in text for indicator in medium_indicators):
            return "MEDIUM"
        else:
            return original_severity or "LOW"
    
    def _extract_specific_indicators(self, text: str) -> List[str]:
        """Extract specific indicators from the text"""
        indicators = []
        
        # IP addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, text)
        indicators.extend([f"IP: {ip}" for ip in ips])
        
        # Countries
        countries = ["russia", "china", "north korea", "iran", "india", "united states"]
        found_countries = [country.title() for country in countries if country in text]
        indicators.extend([f"Country: {country}" for country in found_countries])
        
        # Time indicators
        time_patterns = ["< 1 hour", "< 3 hours", "< 6 hours", "impossible travel"]
        found_times = [pattern for pattern in time_patterns if pattern in text]
        indicators.extend([f"Timing: {time}" for time in found_times])
        
        # Device indicators
        device_patterns = ["unmanaged", "non-compliant", "new device", "unknown device"]
        found_devices = [pattern for pattern in device_patterns if pattern in text]
        indicators.extend([f"Device: {device}" for device in found_devices])
        
        return indicators
    
    def _generate_remediation_steps(self, category: str, severity: str) -> List[str]:
        """Generate specific remediation steps based on category and severity"""
        
        base_steps = {
            "Impossible Travel Detection": [
                "Immediately disable user account",
                "Force password reset",
                "Review all active sessions",
                "Check for data exfiltration",
                "Implement conditional access policies"
            ],
            "High-Risk Geographic Location": [
                "Block access from high-risk countries",
                "Enable geo-blocking policies", 
                "Review user's legitimate travel patterns",
                "Implement additional MFA requirements"
            ],
            "Brute Force Attack": [
                "Lock user account temporarily",
                "Implement account lockout policies",
                "Enable CAPTCHA for failed logins",
                "Monitor for distributed attacks"
            ],
            "Unmanaged Device Access": [
                "Block unmanaged device access",
                "Require device enrollment",
                "Implement device compliance policies",
                "Review device management settings"
            ],
            "Administrative Privilege Escalation": [
                "Review admin role assignments",
                "Audit privileged access logs",
                "Implement just-in-time access",
                "Enable privileged access monitoring"
            ]
        }
        
        steps = base_steps.get(category, [
            "Review security logs",
            "Implement additional monitoring",
            "Update security policies",
            "Conduct user training"
        ])
        
        # Add severity-specific steps
        if severity == "CRITICAL":
            steps.insert(0, "IMMEDIATE ACTION REQUIRED")
            steps.insert(1, "Escalate to security team")
        elif severity == "HIGH":
            steps.insert(0, "Prioritize investigation")
        
        return steps
    
    def _add_timeline_context(self, finding: Dict) -> Dict:
        """Add timeline context to findings"""
        return {
            "detection_time": datetime.now().isoformat(),
            "urgency": "Immediate" if finding.get("severity") == "CRITICAL" else "Standard",
            "investigation_window": "24 hours" if finding.get("severity") in ["CRITICAL", "HIGH"] else "72 hours"
        }


class EnhancedMITREMapper:
    """Enhanced MITRE ATT&CK mapper with better technique specificity"""
    
    def __init__(self):
        self.technique_mappings = {
            # Initial Access
            "geographic_anomaly": {
                "tactic": "Initial Access",
                "technique": "Valid Accounts",
                "technique_id": "T1078",
                "sub_technique": "Cloud Accounts",
                "sub_technique_id": "T1078.004"
            },
            "authentication_failure": {
                "tactic": "Credential Access", 
                "technique": "Brute Force",
                "technique_id": "T1110",
                "sub_technique": "Password Guessing",
                "sub_technique_id": "T1110.001"
            },
            "impossible_travel": {
                "tactic": "Initial Access",
                "technique": "Valid Accounts", 
                "technique_id": "T1078",
                "sub_technique": "Cloud Accounts",
                "sub_technique_id": "T1078.004"
            },
            "privilege_escalation": {
                "tactic": "Privilege Escalation",
                "technique": "Account Manipulation",
                "technique_id": "T1098",
                "sub_technique": "Additional Cloud Roles", 
                "sub_technique_id": "T1098.003"
            },
            "device_anomaly": {
                "tactic": "Defense Evasion",
                "technique": "Impair Defenses",
                "technique_id": "T1562",
                "sub_technique": "Disable or Modify Tools",
                "sub_technique_id": "T1562.001"
            }
        }
        
        self.predicted_sequences = {
            "initial_access": [
                {
                    "tactic": "Execution",
                    "technique": "Command and Scripting Interpreter",
                    "technique_id": "T1059",
                    "likelihood": "High",
                    "rationale": "Attackers typically execute commands after gaining access"
                },
                {
                    "tactic": "Persistence", 
                    "technique": "Create Account",
                    "technique_id": "T1136",
                    "likelihood": "Medium",
                    "rationale": "Creating backdoor accounts for persistent access"
                }
            ],
            "credential_access": [
                {
                    "tactic": "Discovery",
                    "technique": "Account Discovery", 
                    "technique_id": "T1087",
                    "likelihood": "High",
                    "rationale": "Enumerate additional accounts after credential compromise"
                },
                {
                    "tactic": "Lateral Movement",
                    "technique": "Remote Services",
                    "technique_id": "T1021", 
                    "likelihood": "Medium",
                    "rationale": "Use compromised credentials for lateral movement"
                }
            ]
        }
    
    def enhance_mitre_mapping(self, findings: List[Dict]) -> Dict:
        """Enhanced MITRE mapping with better technique specificity"""
        
        mapped_techniques = []
        predicted_steps = []
        
        for finding in findings:
            # Map finding to MITRE technique
            technique_data = self._map_finding_to_technique(finding)
            if technique_data:
                mapped_techniques.append(technique_data)
                
                # Add predicted next steps
                predictions = self._get_predicted_next_steps(technique_data)
                predicted_steps.extend(predictions)
        
        return {
            "mitre_techniques_observed": mapped_techniques,
            "predicted_next_steps": predicted_steps,
            "attack_chain_narrative": self._generate_attack_narrative(mapped_techniques),
            "overall_assessment": self._generate_overall_assessment(mapped_techniques, findings)
        }
    
    def _map_finding_to_technique(self, finding: Dict) -> Optional[Dict]:
        """Map a finding to specific MITRE technique"""
        
        category = finding.get("category", "").lower()
        evidence = finding.get("evidence", "").lower()
        
        # Determine mapping key
        mapping_key = None
        if "impossible travel" in category or "impossible travel" in evidence:
            mapping_key = "impossible_travel"
        elif "geographic" in category or "location" in category:
            mapping_key = "geographic_anomaly"
        elif "authentication" in category or "brute force" in category:
            mapping_key = "authentication_failure"
        elif "privilege" in category or "escalation" in category:
            mapping_key = "privilege_escalation"
        elif "device" in category or "compliance" in category:
            mapping_key = "device_anomaly"
        
        if not mapping_key or mapping_key not in self.technique_mappings:
            return None
        
        base_mapping = self.technique_mappings[mapping_key].copy()
        
        # Enhance with finding-specific data
        base_mapping.update({
            "severity": finding.get("severity", "MEDIUM"),
            "confidence": self._calculate_confidence(finding),
            "evidence": finding.get("evidence", ""),
            "timestamp": finding.get("timeline_context", {}).get("detection_time", ""),
            "indicators": finding.get("specific_indicators", []),
            "procedure": self._generate_procedure_description(finding, base_mapping),
            "sub_technique_justification": self._generate_sub_technique_justification(finding, base_mapping)
        })
        
        return base_mapping
    
    def _calculate_confidence(self, finding: Dict) -> int:
        """Calculate confidence score based on finding quality"""
        base_confidence = 70
        
        # Increase confidence for specific indicators
        if finding.get("specific_indicators"):
            base_confidence += len(finding["specific_indicators"]) * 5
        
        # Increase confidence for high severity
        severity = finding.get("severity", "MEDIUM")
        if severity == "CRITICAL":
            base_confidence += 20
        elif severity == "HIGH":
            base_confidence += 10
        
        # Cap at 95%
        return min(base_confidence, 95)
    
    def _generate_procedure_description(self, finding: Dict, technique: Dict) -> str:
        """Generate specific procedure description"""
        
        category = finding.get("category", "")
        evidence = finding.get("evidence", "")
        
        if "impossible travel" in category.lower():
            return f"Attacker used compromised credentials to access cloud services from geographically impossible locations. {evidence}"
        elif "brute force" in category.lower():
            return f"Systematic password guessing attack against user account. {evidence}"
        elif "privilege escalation" in category.lower():
            return f"Unauthorized elevation of user privileges or role assignments. {evidence}"
        else:
            return f"Security anomaly detected in user behavior patterns. {evidence}"
    
    def _generate_sub_technique_justification(self, finding: Dict, technique: Dict) -> str:
        """Generate justification for sub-technique selection"""
        
        sub_technique = technique.get("sub_technique", "")
        category = finding.get("category", "")
        
        if "Cloud Accounts" in sub_technique:
            return "Activity involves cloud-based authentication and access, indicating cloud account compromise"
        elif "Password Guessing" in sub_technique:
            return "Multiple failed authentication attempts suggest systematic password guessing"
        elif "Additional Cloud Roles" in sub_technique:
            return "Evidence of unauthorized role or permission changes in cloud environment"
        else:
            return f"Sub-technique selected based on {category} indicators and evidence patterns"
    
    def _get_predicted_next_steps(self, technique: Dict) -> List[Dict]:
        """Get predicted next steps based on observed technique"""
        
        tactic = technique.get("tactic", "").lower()
        
        if "initial access" in tactic:
            return self.predicted_sequences.get("initial_access", [])
        elif "credential access" in tactic:
            return self.predicted_sequences.get("credential_access", [])
        else:
            return []
    
    def _generate_attack_narrative(self, techniques: List[Dict]) -> str:
        """Generate coherent attack chain narrative"""
        
        if not techniques:
            return "No clear attack pattern identified from available evidence."
        
        narrative_parts = []
        
        # Sort techniques by tactic order
        tactic_order = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", 
                       "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
                       "Collection", "Command and Control", "Exfiltration", "Impact"]
        
        sorted_techniques = sorted(techniques, key=lambda x: tactic_order.index(x.get("tactic", "")) if x.get("tactic") in tactic_order else 999)
        
        for i, technique in enumerate(sorted_techniques, 1):
            tactic = technique.get("tactic", "Unknown")
            tech_name = technique.get("technique", "Unknown")
            evidence = technique.get("evidence", "")
            
            narrative_parts.append(
                f"Stage {i} ({tactic}): The attacker employed {tech_name} technique. "
                f"Evidence suggests {evidence[:100]}..."
            )
        
        return " ".join(narrative_parts)
    
    def _generate_overall_assessment(self, techniques: List[Dict], findings: List[Dict]) -> Dict:
        """Generate overall assessment of the attack"""
        
        # Determine attack stage
        tactics_observed = [t.get("tactic", "") for t in techniques]
        
        if "Impact" in tactics_observed:
            attack_stage = "Impact/Damage"
        elif "Exfiltration" in tactics_observed:
            attack_stage = "Data Exfiltration"
        elif "Lateral Movement" in tactics_observed:
            attack_stage = "Network Propagation"
        elif "Persistence" in tactics_observed:
            attack_stage = "Foothold Establishment"
        else:
            attack_stage = "Initial Compromise"
        
        # Determine sophistication
        critical_findings = [f for f in findings if f.get("severity") == "CRITICAL"]
        if len(critical_findings) > 2:
            sophistication = "High"
        elif len(critical_findings) > 0:
            sophistication = "Medium"
        else:
            sophistication = "Low"
        
        # Calculate confidence
        avg_confidence = sum(t.get("confidence", 0) for t in techniques) / len(techniques) if techniques else 0
        
        return {
            "attack_stage": attack_stage,
            "threat_sophistication": sophistication,
            "attack_confidence": int(avg_confidence),
            "estimated_dwell_time": "< 24 hours" if attack_stage == "Initial Compromise" else "1-7 days"
        }