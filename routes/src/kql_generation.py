import re
from crewai import LLM, Agent, Task, Crew
from typing import Optional
from crewai_tools import SerperDevTool
import os
from dotenv import load_dotenv

# ✅ LOAD ENVIRONMENT VARIABLES
load_dotenv()


class DynamicKQLGenerator:
    def __init__(self):
        # ✅ USE MODEL FROM .ENV
        ollama_model = os.getenv("OLLAMA_CHAT", "ollama/qwen2.5:3b")

        if not ollama_model.startswith("ollama/"):
            ollama_model = f"ollama/{ollama_model}"

        print(f"🤖 KQL Generator using LLM: {ollama_model}")

        self.llm = LLM(model=ollama_model, base_url="http://localhost:11434")

        try:
            self.web_search = SerperDevTool()
        except:
            self.web_search = None
            print("⚠️ Web search unavailable")

        # KQL Query Templates - Microsoft Sentinel/Defender
        self.kql_templates = {
            "role_assignment": """AuditLogs
| where TimeGenerated > ago(<TIMESPAN>)
| where OperationName == "Add member to role"
| where Result == "success"
| extend RoleName = tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[1].newValue)
| extend AssignedUser = tostring(TargetResources[0].userPrincipalName)
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend SourceIP = tostring(InitiatedBy.user.ipAddress)
| project TimeGenerated, AssignedUser, RoleName, InitiatedBy, SourceIP, CorrelationId""",
            "high_risk_roles": """AuditLogs
| where TimeGenerated > ago(<TIMESPAN>)
| where OperationName has_any ("Add member to role", "Update role")
| extend RoleName = tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[1].newValue)
| where RoleName has_any ("Global Administrator", "Privileged Role Administrator", "Security Administrator", "Exchange Administrator", "SharePoint Administrator")
| extend AssignedUser = tostring(TargetResources[0].userPrincipalName)
| extend Initiator = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, AssignedUser, RoleName, Initiator, Result""",
            "user_signin_analysis": """SigninLogs
| where UserPrincipalName == "<USER_EMAIL>"
| where TimeGenerated > ago(<TIMESPAN>)
| extend Location = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion)
| extend DeviceName = tostring(DeviceDetail.displayName)
| extend DeviceCompliant = tostring(DeviceDetail.isCompliant)
| extend MFAResult = tostring(AuthenticationDetails[0].succeeded)
| summarize 
    SignInCount = count(),
    UniqueIPs = dcount(IPAddress),
    UniqueLocations = dcount(Location),
    FailedSignIns = countif(ResultType != "0"),
    Locations = make_set(Location),
    IPs = make_set(IPAddress)
  by UserPrincipalName
| extend RiskScore = (UniqueIPs * 2) + (UniqueLocations * 3) + (FailedSignIns * 5)""",
            "initiator_validation": """AuditLogs
| where TimeGenerated > ago(<TIMESPAN>)
| where InitiatedBy.user.userPrincipalName == "<INITIATOR_EMAIL>"
| where OperationName has_any ("Add member to role", "Update role", "Remove member from role")
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend Role = tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[1].newValue)
| extend SourceIP = tostring(InitiatedBy.user.ipAddress)
| project TimeGenerated, InitiatedBy = tostring(InitiatedBy.user.userPrincipalName), OperationName, TargetUser, Role, SourceIP, Result""",
            "ip_reputation": """SigninLogs
| where IPAddress == "<IP_ADDRESS>"
| where TimeGenerated > ago(<TIMESPAN>)
| summarize 
    SignInAttempts = count(),
    UniqueUsers = dcount(UserPrincipalName),
    FailedAttempts = countif(ResultType != "0"),
    Users = make_set(UserPrincipalName),
    Locations = make_set(strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion))
  by IPAddress
| join kind=leftouter (
    ThreatIntelligenceIndicator
    | where NetworkIP == "<IP_ADDRESS>"
    | project ThreatIP = NetworkIP, ThreatType, Description, ConfidenceScore
) on $left.IPAddress == $right.ThreatIP""",
            "device_compliance": """SigninLogs
| where UserPrincipalName == "<USER_EMAIL>"
| where TimeGenerated > ago(<TIMESPAN>)
| extend DeviceId = tostring(DeviceDetail.deviceId)
| extend DeviceName = tostring(DeviceDetail.displayName)
| extend IsCompliant = tostring(DeviceDetail.isCompliant)
| extend IsManaged = tostring(DeviceDetail.isManaged)
| extend OS = tostring(DeviceDetail.operatingSystem)
| summarize 
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SignInCount = count()
  by DeviceId, DeviceName, IsCompliant, IsManaged, OS""",
            "mfa_status": """SigninLogs
| where UserPrincipalName == "<USER_EMAIL>"
| where TimeGenerated > ago(<TIMESPAN>)
| extend MFARequired = tostring(ConditionalAccessStatus)
| extend MFAResult = tostring(AuthenticationDetails[0].succeeded)
| extend AuthMethod = tostring(AuthenticationDetails[0].authenticationMethod)
| summarize 
    TotalSignIns = count(),
    MFASuccess = countif(MFAResult == "true"),
    MFAFailures = countif(MFAResult == "false"),
    Methods = make_set(AuthMethod)
  by UserPrincipalName
| extend MFASuccessRate = round((todouble(MFASuccess) / todouble(TotalSignIns)) * 100, 2)""",
            "user_details": """IdentityInfo
| where AccountUPN == "<USER_EMAIL>"
| project AccountUPN, AccountDisplayName, JobTitle, Department, Manager, City, Country
| extend IsVIP = iff(Tags contains "VIP" or Tags contains "Executive", "Yes", "No")""",
            "unusual_locations": """SigninLogs
| where UserPrincipalName == "<USER_EMAIL>"
| where TimeGenerated > ago(<TIMESPAN>)
| extend Location = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion)
| summarize LocationCount = count() by Location, IPAddress
| order by LocationCount asc
| where LocationCount <= 2""",
            # ✅ NEW: Count impacted users
            "count_impacted_users": """SigninLogs
| where TimeGenerated > ago(<TIMESPAN>)
| summarize UniqueUsers = dcount(UserPrincipalName), SignInAttempts = count() by bin(TimeGenerated, 1h)
| project TimeGenerated, UniqueUsers, SignInAttempts
| order by TimeGenerated desc""",
        }

    def generate_kql_query(
        self, step_name: str, explanation: str, context: str = ""
    ) -> str:
        """
        Generate KQL query using multiple strategies

        Args:
            step_name: Name of the investigation step
            explanation: Detailed explanation of what to investigate
            context: Additional context (rule name, etc.)

        Returns:
            Formatted KQL query with placeholders
        """
        print(f"\n🔎 Generating KQL for: {step_name}")

        # Strategy 1: Pattern matching for common scenarios
        kql = self._match_pattern(step_name, explanation)
        if kql:
            print("✅ Generated from pattern matching")
            return self._clean_and_format_kql(kql)

        # Strategy 2: Web research for specific cases (if available)
        if self.web_search:
            kql = self._web_research_kql(step_name, explanation, context)
            if kql:
                print("✅ Generated from web research")
                return self._clean_and_format_kql(kql)

        # Strategy 3: LLM generation for complex cases
        kql = self._llm_generate_kql(step_name, explanation, context)
        if kql:
            print("✅ Generated using LLM")
            return self._clean_and_format_kql(kql)

        print("⚠️ No KQL query generated")
        return ""

    def _match_pattern(self, step_name: str, explanation: str) -> Optional[str]:
        """Match step to predefined KQL patterns"""
        combined = f"{step_name} {explanation}".lower()

        # ✅ Count impacted users
        if any(
            word in combined
            for word in [
                "how many users",
                "count users",
                "users impacted",
                "number of users",
            ]
        ):
            return self.kql_templates["count_impacted_users"]

        # Role assignment queries
        if any(
            word in combined
            for word in ["role assign", "privileged role", "add member"]
        ):
            if (
                "high-risk" in combined
                or "global admin" in combined
                or "privileged" in combined
            ):
                return self.kql_templates["high_risk_roles"]
            return self.kql_templates["role_assignment"]

        # User analysis
        if "sign-in" in combined or "login" in combined or "authentication" in combined:
            if "unusual" in combined or "pattern" in combined:
                return self.kql_templates["user_signin_analysis"]
            return self.kql_templates["user_signin_analysis"]

        # Initiator validation
        if (
            "assigning user" in combined
            or "initiator" in combined
            or "legitimate access" in combined
        ):
            return self.kql_templates["initiator_validation"]

        # IP reputation
        if "ip" in combined and ("reputation" in combined or "threat" in combined):
            return self.kql_templates["ip_reputation"]

        # Device compliance
        if "device" in combined and ("complian" in combined or "managed" in combined):
            return self.kql_templates["device_compliance"]

        # MFA validation
        if (
            "mfa" in combined
            or "multi-factor" in combined
            or "authentication method" in combined
        ):
            return self.kql_templates["mfa_status"]

        # User details
        if (
            "user detail" in combined
            or "user information" in combined
            or "vip" in combined
        ):
            return self.kql_templates["user_details"]

        # Location analysis
        if "location" in combined and ("unusual" in combined or "travel" in combined):
            return self.kql_templates["unusual_locations"]

        return None

    def _web_research_kql(
        self, step_name: str, explanation: str, context: str
    ) -> Optional[str]:
        """Research KQL queries using web search"""
        try:
            search_query = f"Microsoft Sentinel KQL query {step_name} {context}"
            print(f"🔍 Searching: {search_query}")

            # This would use SerperDevTool to search
            # For now, return pattern-based as fallback
            return None

        except Exception as e:
            print(f"⚠️ Web research failed: {str(e)}")
            return None

    def _llm_generate_kql(
        self, step_name: str, explanation: str, context: str
    ) -> Optional[str]:
        """Generate KQL using LLM with strict guidelines"""

        prompt = f"""Generate a Microsoft Sentinel KQL query for this investigation step.

STEP NAME: {step_name}
EXPLANATION: {explanation}
CONTEXT: {context}

REQUIREMENTS:
1. Use ONLY these table names: SigninLogs, AuditLogs, IdentityInfo, ThreatIntelligenceIndicator, SecurityIncident, DeviceInfo
2. Use placeholders: <USER_EMAIL>, <IP_ADDRESS>, <DEVICE_ID>, <TIMESPAN>
3. Include proper KQL operators: where, extend, project, summarize, join
4. Focus on security investigation data
5. Return ONLY the KQL query, no explanations or artifacts

EXAMPLES:
- SigninLogs | where UserPrincipalName == "<USER_EMAIL>" | where TimeGenerated > ago(<TIMESPAN>)
- AuditLogs | where OperationName == "Add member to role" | extend RoleName = tostring(TargetResources[0].modifiedProperties)

Generate KQL query:"""

        try:
            kql_agent = Agent(
                role="KQL Query Expert",
                goal="Generate accurate Microsoft Sentinel KQL queries",
                backstory="Expert in KQL syntax and security investigation queries",
                llm=self.llm,
                verbose=False,
            )

            kql_task = Task(
                description=prompt,
                expected_output="A valid KQL query with placeholders",
                agent=kql_agent,
            )

            crew = Crew(agents=[kql_agent], tasks=[kql_task], verbose=False)
            result = crew.kickoff()

            # Extract KQL from result
            kql = str(result).strip()

            # Validate it looks like KQL
            if any(
                keyword in kql
                for keyword in ["where", "extend", "project", "summarize"]
            ):
                return kql

        except Exception as e:
            print(f"⚠️ LLM generation failed: {str(e)}")

        return None

    def _clean_and_format_kql(self, kql: str) -> str:
        """✅ AGGRESSIVE KQL cleaning"""
        if not kql:
            return ""

        # Remove markdown code blocks
        kql = re.sub(r"```[a-z]*\s*", "", kql)
        kql = re.sub(r"```", "", kql)

        # Remove LLM artifacts
        artifacts = [
            "I now can give",
            "FINAL ANSWER",
            "Final Answer",
            "Here is",
            "Here's",
            "The query",
            "This query",
            "Explanation:",
            "Output:",
            "Result:",
        ]

        for artifact in artifacts:
            if artifact in kql:
                parts = kql.split(artifact, 1)
                kql = parts[0] if len(parts) > 1 else parts[0]

        # Remove comment lines and inline comments
        lines = []
        for line in kql.split("\n"):
            line = line.strip()

            # Skip empty lines
            if not line:
                continue

            # Skip comment lines
            if line.startswith("//") or line.startswith("#"):
                continue

            # Remove inline comments
            if "//" in line:
                line = line.split("//")[0].strip()

            # Stop at explanation text
            if any(
                stop in line.lower()
                for stop in [
                    "this query",
                    "explanation:",
                    "note:",
                    "output:",
                    "the query",
                    "this kql",
                    "result:",
                    "aggregates",
                    "queries signinlogs",
                    "queries auditlogs",
                ]
            ):
                break

            # Skip lines with artifacts
            if any(
                artifact.lower() in line.lower()
                for artifact in [
                    "i must",
                    "job depends",
                    "final answer",
                    "my final",
                    "task completed",
                    "ready for submission",
                ]
            ):
                continue

            lines.append(line)

        kql = "\n".join(lines)

        # Replace any hardcoded values with placeholders
        kql = re.sub(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "<USER_EMAIL>", kql
        )
        kql = re.sub(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "<IP_ADDRESS>", kql)
        kql = re.sub(r"ago\(\d+[dhm]\)", "ago(<TIMESPAN>)", kql)

        # Clean whitespace but preserve structure
        lines = [line.strip() for line in kql.split("\n") if line.strip()]
        kql = "\n".join(lines)

        return kql.strip()
