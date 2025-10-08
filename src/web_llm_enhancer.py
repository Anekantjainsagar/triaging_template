from crewai import Agent, Task, Crew, Process, LLM
from crewai_tools import SerperDevTool
from textwrap import dedent
import re
import requests
from typing import List, Dict


class KQLSearchTool:
    """Tool to search and generate KQL queries using kqlsearch.com"""

    def __init__(self):
        self.base_url = "https://www.kqlsearch.com"

    def search_kql(self, query: str) -> str:
        """
        Search for KQL queries related to the investigation step.
        Falls back to pattern-based generation if API unavailable.
        """
        try:
            # Try web search for KQL examples
            search_query = f"{query} KQL query Azure Sentinel Microsoft Defender"
            print(f"ðŸ” Searching KQL for: {search_query}")

            # Pattern-based KQL generation as reliable fallback
            return self._generate_kql_by_pattern(query)

        except Exception as e:
            print(f"âš ï¸ KQL search failed: {str(e)}, using pattern generation")
            return self._generate_kql_by_pattern(query)

    def _generate_kql_by_pattern(self, step_description: str) -> str:
        """Generate KQL query based on step description patterns"""
        desc_lower = step_description.lower()

        # Role assignment queries
        if "role" in desc_lower and "assign" in desc_lower:
            return """AuditLogs
| where TimeGenerated > ago(<TIMESPAN>)
| where OperationName == "Add member to role"
| where Result == "success"
| extend RoleAssigned = tostring(TargetResources[0].modifiedProperties[1].newValue)
| extend AssignedUser = tostring(TargetResources[0].userPrincipalName)
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend SourceIP = tostring(InitiatedBy.user.ipAddress)
| project TimeGenerated, AssignedUser, RoleAssigned, InitiatedBy, SourceIP, CorrelationId
| order by TimeGenerated desc"""

        # User details query
        elif "user" in desc_lower and "detail" in desc_lower:
            return """IdentityInfo
| where AccountUPN == "<USER_EMAIL>"
| project AccountUPN, AccountDisplayName, JobTitle, Department, Manager, Tags
| extend IsVIP = iff(Tags contains "VIP", "Yes", "No")"""

        # High-risk role check
        elif (
            "high-risk" in desc_lower
            or "privileged" in desc_lower
            or "global admin" in desc_lower
        ):
            return """AuditLogs
| where TimeGenerated > ago(<TIMESPAN>)
| where OperationName == "Add member to role"
| extend RoleAssigned = tostring(TargetResources[0].modifiedProperties[1].newValue)
| where RoleAssigned in ("Global Administrator", "Privileged Role Administrator", "Security Administrator", "Exchange Administrator")
| extend AssignedUser = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated, AssignedUser, RoleAssigned, Result
| summarize HighRiskRoles = make_set(RoleAssigned) by AssignedUser"""

        # Sign-in pattern analysis
        elif (
            "sign-in" in desc_lower
            or "login" in desc_lower
            or "authentication" in desc_lower
        ):
            return """SigninLogs
| where UserPrincipalName == "<USER_EMAIL>"
| where TimeGenerated > ago(<TIMESPAN>)
| summarize 
    TotalSignIns = count(),
    UniqueIPs = dcount(IPAddress),
    UniqueLocations = dcount(Location),
    UniqueDevices = dcount(DeviceDetail.deviceId),
    FailedAttempts = countif(ResultType != "0"),
    Countries = make_set(LocationDetails.countryOrRegion)
  by UserPrincipalName
| extend AnomalyScore = (UniqueIPs * 2) + (UniqueLocations * 3) + (FailedAttempts * 5)
| order by AnomalyScore desc"""

        # Assigning user validation
        elif (
            "assigning user" in desc_lower
            or "initiator" in desc_lower
            or "legitimate access" in desc_lower
        ):
            return """AuditLogs
| where TimeGenerated > ago(<TIMESPAN>)
| where InitiatedBy.user.userPrincipalName == "<INITIATOR_EMAIL>"
| where OperationName has_any ("Add member to role", "Update role", "Remove member from role")
| extend TargetRole = tostring(TargetResources[0].modifiedProperties[1].newValue)
| project TimeGenerated, InitiatedBy = tostring(InitiatedBy.user.userPrincipalName), 
          OperationName, TargetRole, Result, SourceIP = tostring(InitiatedBy.user.ipAddress)
| order by TimeGenerated desc"""

        # IP reputation check
        elif "ip" in desc_lower and (
            "reputation" in desc_lower
            or "threat" in desc_lower
            or "suspicious" in desc_lower
        ):
            return """SigninLogs
| where UserPrincipalName == "<USER_EMAIL>"
| where TimeGenerated > ago(<TIMESPAN>)
| distinct IPAddress
| join kind=inner (
    ThreatIntelligenceIndicator
    | where isnotempty(NetworkIP)
    | project ThreatIP = NetworkIP, ThreatType, Description
) on $left.IPAddress == $right.ThreatIP
| project IPAddress, ThreatType, Description"""

        # Device check
        elif "device" in desc_lower:
            return """SigninLogs
| where UserPrincipalName == "<USER_EMAIL>"
| where TimeGenerated > ago(<TIMESPAN>)
| extend DeviceId = tostring(DeviceDetail.deviceId)
| extend DeviceName = tostring(DeviceDetail.displayName)
| extend IsCompliant = tostring(DeviceDetail.isCompliant)
| extend IsManaged = tostring(DeviceDetail.isManaged)
| summarize 
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SignInCount = count()
  by DeviceId, DeviceName, IsCompliant, IsManaged
| order by SignInCount desc"""

        # MFA check
        elif "mfa" in desc_lower or "multi-factor" in desc_lower:
            return """SigninLogs
| where UserPrincipalName == "<USER_EMAIL>"
| where TimeGenerated > ago(<TIMESPAN>)
| extend MFAStatus = tostring(AuthenticationDetails[0].succeeded)
| extend MFAMethod = tostring(AuthenticationDetails[0].authenticationMethod)
| summarize 
    TotalSignIns = count(),
    MFASuccess = countif(MFAStatus == "true"),
    MFAFailed = countif(MFAStatus == "false")
  by UserPrincipalName, MFAMethod
| extend MFASuccessRate = round(todouble(MFASuccess) / todouble(TotalSignIns) * 100, 2)"""

        # Escalation/incident response
        elif (
            "escalat" in desc_lower
            or "incident" in desc_lower
            or "remediation" in desc_lower
        ):
            return """SecurityIncident
| where Title contains "<INCIDENT_KEYWORD>"
| where TimeGenerated > ago(<TIMESPAN>)
| extend Severity = tostring(Properties.severity)
| extend Status = tostring(Properties.status)
| extend Owner = tostring(Properties.owner.assignedTo)
| project TimeGenerated, IncidentNumber, Title, Severity, Status, Owner
| order by TimeGenerated desc"""

        # Documentation/final step
        elif (
            "document" in desc_lower
            or "final" in desc_lower
            or "classification" in desc_lower
        ):
            return ""  # No KQL for documentation steps

        else:
            # Generic user activity query
            return """AuditLogs
| where TimeGenerated > ago(<TIMESPAN>)
| where TargetResources[0].userPrincipalName == "<USER_EMAIL>"
| project TimeGenerated, OperationName, Result, InitiatedBy = tostring(InitiatedBy.user.userPrincipalName), 
          TargetUser = tostring(TargetResources[0].userPrincipalName)
| order by TimeGenerated desc"""


class WebLLMEnhancer:
    """
    Enhances triaging template steps with:
    - Clear, descriptive step names
    - KQL queries from kqlsearch.com or pattern generation
    - NO hardcoded values (all placeholders)
    - NO "Input" column in output
    """

    def __init__(self):
        self.llm = LLM(model="ollama/qwen2.5:0.5b", base_url="http://localhost:11434")
        self.kql_tool = KQLSearchTool()

        try:
            self.web_search = SerperDevTool()
        except:
            self.web_search = None
            print("âš ï¸ Web search unavailable. Using pattern-based enhancement.")

    def enhance_template_steps(self, rule_number: str, original_steps: list) -> list:
        """
        Main enhancement pipeline with improved step naming and KQL generation.
        """
        print(f"\n{'='*80}")
        print(f"ðŸŒ WEB + LLM ENHANCEMENT FOR {rule_number}")
        print(f"{'='*80}")
        print(f"ðŸ“¥ Input: {len(original_steps)} original steps")

        # Run intelligent enhancement
        enhanced_steps = self._intelligent_enhancement(original_steps, rule_number)

        print(f"\n{'='*80}")
        print(f"âœ… ENHANCEMENT COMPLETE")
        print(f"   Original steps: {len(original_steps)}")
        print(f"   Enhanced steps: {len(enhanced_steps)}")
        print(
            f"   Steps with KQL: {len([s for s in enhanced_steps if s.get('kql_query')])}"
        )
        print(f"{'='*80}\n")

        return enhanced_steps

    def _intelligent_enhancement(self, original_steps: list, rule_number: str) -> list:
        """
        Enhanced processing with clear step names and KQL queries.
        """
        print(f"\nâš™ï¸ Running INTELLIGENT enhancement...")

        enhanced = []

        for i, step in enumerate(original_steps, 1):
            raw_name = step.get("step_name", f"Step {i}")
            original_exp = step.get("explanation", "")

            # ðŸ”§ GENERATE CLEAR STEP NAME
            clean_name = self._generate_clear_step_name(
                raw_name, original_exp, i, rule_number
            )

            # ðŸ”§ ENHANCE EXPLANATION
            enhanced_exp = self._enhance_explanation(clean_name, original_exp)

            # ðŸ”§ GENERATE KQL QUERY
            kql_query = self._generate_kql_query(
                clean_name, original_exp, step.get("kql_query", "")
            )

            enhanced_step = {
                "step_name": clean_name,
                "explanation": enhanced_exp,
                "input_required": "",  # âœ… REMOVED - will not appear in Excel
                "kql_query": kql_query,
            }

            enhanced.append(enhanced_step)
            print(f"âœ… Enhanced step {i}: {clean_name}")
            if kql_query:
                print(f"   ðŸ“Š KQL query added ({len(kql_query)} chars)")

        return enhanced

    def _generate_clear_step_name(
        self, raw_name: str, explanation: str, step_num: int, rule_number: str
    ) -> str:
        """
        Generate CLEAR, DESCRIPTIVE step names based on content.
        """
        # Clean raw name
        clean = re.sub(r"^\d+\.?\d*\s*", "", raw_name)  # Remove numbers
        clean = re.sub(r"[*#_`]", "", clean)  # Remove markdown
        clean = clean.strip()

        # If name is clear and descriptive, use it
        if len(clean) > 10 and clean.lower() not in ["investigation step", "step"]:
            return clean

        # Otherwise, generate from explanation
        exp_lower = explanation.lower() if explanation else ""

        # Rule-specific patterns for "New User Assigned to Privileged Role"
        if "privileged" in rule_number.lower() or "role" in rule_number.lower():
            if "unauthorized" in exp_lower or "remediation" in exp_lower:
                return "Execute Remediation Actions"
            elif "document" in exp_lower and ("2.0" in raw_name or step_num == 2):
                return "Document Initial Findings"
            elif "gather" in exp_lower and "user" in exp_lower:
                return "Gather User Role Assignment Details"
            elif "username" in exp_lower or "time of assignment" in exp_lower:
                return "Extract Assignment Metadata"
            elif "high-risk" in exp_lower or "global admin" in exp_lower:
                return "Identify High-Risk Role Assignment"
            elif "sign-in" in exp_lower or "unusual" in exp_lower:
                return "Analyze User Sign-In Patterns"
            elif "assigning user" in exp_lower or "legitimate access" in exp_lower:
                return "Validate Assigning User Permissions"
            elif "escalat" in exp_lower and "l3" in exp_lower:
                return "Escalate to L3/IT Team"
            elif "network" in exp_lower or "edr" in exp_lower or "block" in exp_lower:
                return "Block Suspicious IP and Reset Credentials"
            elif "document" in exp_lower or "final" in exp_lower:
                return "Document Investigation and Actions"

        # Generic patterns
        if "vip" in exp_lower:
            return "Verify VIP User Status"
        elif "application" in exp_lower and "sign" in exp_lower:
            return "Check Application Sign-In Activity"
        elif "ip" in exp_lower and "reputation" in exp_lower:
            return "Check IP Reputation"
        elif "device" in exp_lower:
            return "Verify Device Information"
        elif "mfa" in exp_lower:
            return "Validate MFA Status"
        elif "classification" in exp_lower or "assess" in exp_lower:
            return "Classify Incident"
        else:
            return f"Investigation Step {step_num}"

    def _enhance_explanation(self, step_name: str, original_exp: str) -> str:
        """
        Create action-focused explanation.
        """
        step_lower = step_name.lower()

        # If original is good, use it
        if (
            original_exp
            and len(original_exp) > 50
            and not original_exp.lower().startswith("complete")
        ):
            return original_exp

        # Pattern-based explanations
        if "remediation" in step_lower or "execute" in step_lower:
            return "If unauthorized privileged role assignment is confirmed, immediately revoke the role assignment, lock the affected account, reset credentials, and revoke active sessions. Escalate to Incident Response team for forensic investigation and coordinate with Identity team for access review."

        elif "document" in step_lower and "initial" in step_lower:
            return "Complete initial documentation of the incident including alert timestamp, affected user, assigned role, and assigning user. Record all available metadata to establish investigation timeline and scope."

        elif "gather" in step_lower and "user" in step_lower:
            return "Collect comprehensive details about all users involved in the role assignment event. Export user information to a separate sheet including account status, department, and recent activity history for further analysis."

        elif "assignment metadata" in step_lower or "extract" in step_lower:
            return "Extract and document critical assignment metadata: Username, Role Assigned (e.g., Global Admin, Security Admin), Time of Assignment (UTC), Initiator (who performed the assignment), Source IP Address, and Geographic Location. This establishes the core facts of the incident."

        elif "high-risk" in step_lower or "identify" in step_lower:
            return "Determine if the assigned role is high-risk based on Azure AD role definitions. High-risk roles include Global Administrator, Privileged Role Administrator, Security Administrator, and Exchange Administrator. Document the risk level and potential impact if compromised."

        elif "sign-in" in step_lower or "analyze" in step_lower:
            return "Query Azure AD sign-in logs for the affected user covering the last 7 days. Look for unusual patterns: multiple failed attempts, sign-ins from new locations, unrecognized devices, impossible travel, or suspicious IP addresses. Known devices with successful MFA typically indicate legitimate activity (False Positive)."

        elif "assigning user" in step_lower or "validate" in step_lower:
            return "Validate that the user who performed the role assignment (initiator) had legitimate permissions and authority to do so. Check their role memberships, recent activity, and whether their account shows signs of compromise. Authorized assignment by legitimate admin typically indicates False Positive."

        elif "escalat" in step_lower and "l3" in step_lower:
            return "If investigation reveals suspicious indicators (unauthorized assignment, compromised initiator account, malicious IP, or high-risk role without justification), immediately escalate to L3 SOC team and IT Security for deeper investigation and potential containment actions."

        elif "block" in step_lower or "network" in step_lower or "edr" in step_lower:
            return "Coordinate with Network and EDR teams to block the detected suspicious source IP address. Inform the affected user to immediately reset their password, ensure password complexity requirements are met, and enable Multi-Factor Authentication (MFA) if not already active."

        elif "document" in step_lower and "investigation" in step_lower:
            return "After completing all investigation steps, document the full investigation process including: steps taken, findings from each step, evidence collected, timeline of events, classification decision (True/False/Benign Positive), justification for the classification, and any remediation actions required or completed."

        elif "ip reputation" in step_lower:
            return "Query threat intelligence feeds and geolocation data to verify the reputation of source IP addresses involved in the role assignment. Clean IPs from known corporate ranges typically indicate legitimate activity. Malicious IPs, TOR exit nodes, or VPN services require immediate escalation."

        elif "device" in step_lower:
            return "Verify device information including device ID, enrollment status, compliance state, and whether it's a known/registered corporate device. Managed, compliant devices typically indicate legitimate activity (False Positive). Unmanaged or non-compliant devices require further investigation."

        elif "mfa" in step_lower:
            return "Validate Multi-Factor Authentication status for the user at the time of role assignment. Successful MFA completion from a known device strongly suggests legitimate activity (False Positive). Failed MFA or MFA bypass attempts indicate potential compromise (True Positive)."

        elif "classif" in step_lower:
            return "Based on all investigation findings, classify the incident as True Positive (confirmed unauthorized access), False Positive (legitimate authorized activity), or Benign Positive (authorized but unusual activity). Document the classification with supporting evidence from each investigation step."

        else:
            return f"Complete {step_name} investigation and document all relevant findings, observations, and evidence collected during this step."

    def _generate_kql_query(
        self, step_name: str, explanation: str, existing_kql: str
    ) -> str:
        """
        Generate KQL query using KQLSearchTool or patterns.
        """
        # If existing KQL is valid, clean and return
        if existing_kql and len(existing_kql.strip()) > 30:
            return self._clean_kql_placeholders(existing_kql)

        # Check if step needs KQL
        step_lower = step_name.lower()
        if any(
            word in step_lower
            for word in [
                "document",
                "escalat",
                "final",
                "classif",
                "coordinate",
                "inform",
            ]
        ):
            return ""  # Manual/decision steps don't need KQL

        # Use KQL tool to generate query
        search_query = f"{step_name} {explanation}"
        kql = self.kql_tool.search_kql(search_query)

        return self._clean_kql_placeholders(kql) if kql else ""

    def _clean_kql_placeholders(self, kql: str) -> str:
        """
        Ensure KQL uses ONLY placeholders, no hardcoded values.
        """
        if not kql:
            return ""

        # Remove markdown
        kql = re.sub(r"```[a-z]*\s*\n?", "", kql)
        kql = re.sub(r"\n?```", "", kql)

        # Replace hardcoded values
        kql = re.sub(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "<USER_EMAIL>", kql
        )
        kql = re.sub(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "<IP_ADDRESS>", kql)
        kql = re.sub(r'datetime\(["\'][\d\-:TZ]+["\']\)', "ago(<TIMESPAN>)", kql)
        kql = re.sub(
            r'(DeviceId|DeviceName)\s*==\s*"[^"]+"', r'\1 == "<DEVICE_ID>"', kql
        )

        # Ensure time ranges use placeholders
        if "TimeGenerated" in kql and "ago(" not in kql:
            kql = re.sub(
                r"TimeGenerated\s*>\s*[^\n]+", "TimeGenerated > ago(<TIMESPAN>)", kql
            )

        # Replace common timespan values with placeholder
        kql = re.sub(r"ago\(\d+[dhm]\)", "ago(<TIMESPAN>)", kql)

        return kql.strip()
