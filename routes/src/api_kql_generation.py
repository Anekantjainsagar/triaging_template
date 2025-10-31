"""
Enhanced KQL Query Generator with Specific, Unique Queries
"""

import re
import os
from typing import Optional, Tuple, Dict, List
from crewai import LLM, Agent, Task, Crew
from crewai_tools import SerperDevTool
from dotenv import load_dotenv
import json
import requests

load_dotenv()


class SchemaValidator:
    """Validates KQL queries against actual Azure table schemas"""

    def __init__(self):
        self.SIGNINLOGS_COLUMNS = {
            "TimeGenerated",
            "UserPrincipalName",
            "IPAddress",
            "AppDisplayName",
            "ResultType",
            "ResultSignature",
            "ResultDescription",
            "Location",
            "DeviceDetail",
            "LocationDetails",
            "ConditionalAccessStatus",
            "AuthenticationDetails",
            "AuthenticationRequirement",
            "ClientAppUsed",
            "IsInteractive",
            "IsRisky",
            "RiskDetail",
            "RiskEventTypes",
            "RiskLevelAggregated",
            "RiskLevelDuringSignIn",
            "RiskState",
            "ResourceDisplayName",
            "Status",
            "UserDisplayName",
            "UserId",
            "UserAgent",
            "MfaDetail",
            "NetworkLocationDetails",
            "CorrelationId",
            "AuthenticationMethodsUsed",
            "AuthenticationProcessingDetails",
            "ConditionalAccessPolicies",
            "CreatedDateTime",
            "DurationMs",
            "OriginalRequestId",
            "ProcessingTimeInMilliseconds",
            "SessionId",
        }

        self.AUDITLOGS_COLUMNS = {
            "TimeGenerated",
            "OperationName",
            "TargetResources",
            "InitiatedBy",
            "ActivityDateTime",
            "Category",
            "CorrelationId",
            "Result",
            "ResultReason",
            "AADTenantId",
            "Identity",
            "Level",
            "ResourceId",
            "ResourceGroup",
        }

        self.IDENTITYINFO_COLUMNS = {
            "TimeGenerated",
            "AccountUPN",
            "AccountName",
            "Department",
            "JobTitle",
            "Manager",
            "Office",
            "Country",
            "State",
            "City",
            "StreetAddress",
            "UsageLocation",
        }

        self.table_schemas = {
            "SigninLogs": self.SIGNINLOGS_COLUMNS,
            "AuditLogs": self.AUDITLOGS_COLUMNS,
            "IdentityInfo": self.IDENTITYINFO_COLUMNS,
        }

    def validate_query(self, kql: str) -> Tuple[bool, List[str]]:
        """Validate KQL query against actual schemas"""
        errors = []

        table_match = re.search(r"(SigninLogs|AuditLogs|IdentityInfo)", kql)
        if not table_match:
            return True, []

        table_name = table_match.group(1)
        valid_columns = self.table_schemas.get(table_name, set())

        # Extract column references
        column_pattern = (
            r"\b([A-Z][a-zA-Z0-9]*)\b\s*(?:==|!=|>|<|>=|<=|\bin\b|contains|startswith)"
        )
        columns_used = re.findall(column_pattern, kql)

        # Check project/extend/summarize
        project_match = re.search(r"\|\s*project\s+([^\|]+)", kql)
        if project_match:
            project_cols = re.findall(
                r"\b([A-Z][a-zA-Z0-9]*)\b", project_match.group(1)
            )
            columns_used.extend(project_cols)

        # Check for invalid columns
        allowed_functions = {
            "TimeGenerated",
            "ago",
            "tostring",
            "bin",
            "count",
            "dcount",
            "countif",
            "make_set",
            "summarize",
            "project",
            "extend",
            "where",
            "order",
            "datetime",
            "in",
        }

        for col in set(columns_used):
            if col not in valid_columns and col not in allowed_functions:
                errors.append(f"Invalid column '{col}' for table {table_name}")

        return len(errors) == 0, errors

    def fix_query(self, kql: str) -> str:
        """Fix common schema errors"""
        # Remove non-existent columns
        kql = re.sub(r"\|\s*where\s+AlertName\s*==\s*[^\|]+", "", kql)

        # Fix MFA references
        kql = re.sub(r"\bMfaResult\b", "tostring(MfaDetail.authMethod)", kql)

        # Fix authentication method references
        kql = re.sub(r"\bAuthenticationMethod\b", "AuthenticationMethodsUsed", kql)

        # Fix VIP/Admin checks
        kql = re.sub(
            r"\bIsVIP\b",
            '(JobTitle contains "VP" or JobTitle contains "Chief" or JobTitle contains "Director")',
            kql,
        )

        # Fix DeviceDetail access
        if "DeviceDetail ==" in kql:
            kql = re.sub(
                r"DeviceDetail\s*==", "tostring(DeviceDetail.deviceId) ==", kql
            )

        # Fix Location references
        if "| where Location ==" in kql:
            kql = re.sub(
                r"\|\s*where\s+Location\s*==",
                "| where tostring(LocationDetails.countryOrRegion) ==",
                kql,
            )

        # Clean up empty where clauses
        kql = re.sub(r"\|\s*where\s*\|", "|", kql)

        return kql.strip()


class UniqueKQLGenerator:
    """Generates specific, unique KQL queries based on step context"""

    def __init__(self):
        self.validator = SchemaValidator()
        self.generated_queries = set()  # Track generated queries for uniqueness

    def generate_unique_query(self, step_context: Dict) -> Optional[str]:
        """Generate a unique, specific KQL query"""
        intent = step_context.get("intent", "")
        focus = step_context.get("focus", "")
        step_name = step_context.get("step_name", "")
        step_number = step_context.get("step_number", 1)

        # Generate query based on specific intent
        kql = None

        if "count_impact" in intent:
            kql = self._generate_impact_count_query(step_context)
        elif "verify_vip" in intent or "vip" in step_name.lower():
            kql = self._generate_vip_verification_query(step_context)
        elif "ip_reputation" in intent or (
            "ip" in step_name.lower() and "reputation" in step_name.lower()
        ):
            kql = self._generate_ip_analysis_query(step_context)
        elif "failed_signin" in intent or "failed" in step_name.lower():
            kql = self._generate_failed_signin_query(step_context)
        elif "mfa" in step_name.lower():
            kql = self._generate_mfa_analysis_query(step_context)
        elif "location" in step_name.lower() or "geo" in step_name.lower():
            kql = self._generate_location_analysis_query(step_context)
        elif "device" in step_name.lower():
            kql = self._generate_device_analysis_query(step_context)
        elif "application" in step_name.lower() or "app" in step_name.lower():
            kql = self._generate_app_analysis_query(step_context)
        elif "role" in step_name.lower() or "permission" in step_name.lower():
            kql = self._generate_role_permission_query(step_context)
        elif "oauth" in step_name.lower() or "consent" in step_name.lower():
            kql = self._generate_oauth_consent_query(step_context)
        elif "time" in step_name.lower() or "pattern" in step_name.lower():
            kql = self._generate_time_pattern_query(step_context)
        else:
            # Default signin activity query
            kql = self._generate_default_signin_query(step_context)

        if kql:
            # Ensure uniqueness by adding step-specific filters if duplicate
            kql_normalized = self._normalize_query(kql)
            if kql_normalized in self.generated_queries:
                kql = self._make_unique(kql, step_number)

            self.generated_queries.add(self._normalize_query(kql))

            # Validate and fix
            is_valid, errors = self.validator.validate_query(kql)
            if not is_valid:
                kql = self.validator.fix_query(kql)

        return kql

    def _generate_impact_count_query(self, context: Dict) -> str:
        """Generate query to count impacted users"""
        return """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName in ("<USER_EMAIL>")
| summarize 
    TotalSignIns = count(),
    UniqueUsers = dcount(UserPrincipalName),
    UniqueIPs = dcount(IPAddress),
    UniqueApps = dcount(AppDisplayName),
    SuccessfulSignIns = countif(ResultType == "0"),
    FailedSignIns = countif(ResultType != "0"),
    UniqueDays = dcount(format_datetime(TimeGenerated, 'yyyy-MM-dd'))
| extend ImpactScore = (UniqueUsers * 10) + (FailedSignIns * 2)"""

    def _generate_vip_verification_query(self, context: Dict) -> str:
        """Generate VIP user verification query"""
        return """IdentityInfo
| where TimeGenerated > ago(7d)
| where AccountUPN in ("<USER_EMAIL>")
| project 
    AccountUPN,
    Department,
    JobTitle,
    Manager,
    Office,
    Country
| extend IsVIP = case(
    JobTitle contains "VP" or JobTitle contains "Chief" or JobTitle contains "Director" or JobTitle contains "President", "Yes",
    JobTitle contains "Manager" or JobTitle contains "Lead", "Moderate",
    "No"
)
| extend IsExecutive = iff(JobTitle contains "Chief" or JobTitle contains "President", "Yes", "No")"""

    def _generate_ip_analysis_query(self, context: Dict) -> str:
        """Generate comprehensive IP analysis query"""
        return """SigninLogs
| where TimeGenerated > ago(7d)
| where IPAddress in ("<IP_ADDRESS>")
| summarize 
    SignInAttempts = count(),
    UniqueUsers = dcount(UserPrincipalName),
    UniqueApps = dcount(AppDisplayName),
    SuccessRate = round(100.0 * countif(ResultType == "0") / count(), 2),
    FailedLogins = countif(ResultType != "0"),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Locations = make_set(tostring(LocationDetails.countryOrRegion), 5),
    Users = make_set(UserPrincipalName, 10),
    RiskySignIns = countif(IsRisky == true)
    by IPAddress
| extend 
    DaysSeen = datetime_diff('day', LastSeen, FirstSeen),
    RiskIndicator = case(
        RiskySignIns > 0, "High Risk",
        FailedLogins > 10, "Suspicious",
        SuccessRate < 50.0, "Concerning",
        "Normal"
    )"""

    def _generate_failed_signin_query(self, context: Dict) -> str:
        """Generate failed sign-in analysis query"""
        return """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName in ("<USER_EMAIL>")
| where ResultType != "0"
| summarize 
    FailedAttempts = count(),
    UniqueErrorCodes = dcount(ResultType),
    UniqueIPs = dcount(IPAddress),
    ErrorTypes = make_set(ResultDescription, 10),
    ErrorCodes = make_set(ResultType, 10),
    SourceIPs = make_set(IPAddress, 5),
    SourceLocations = make_set(tostring(LocationDetails.countryOrRegion), 5),
    FirstFailure = min(TimeGenerated),
    LastFailure = max(TimeGenerated)
    by UserPrincipalName
| extend 
    FailureDuration = datetime_diff('minute', LastFailure, FirstFailure),
    IsPotentialAttack = iff(FailedAttempts > 5 and UniqueIPs > 3, "Yes", "No")
| order by FailedAttempts desc"""

    def _generate_mfa_analysis_query(self, context: Dict) -> str:
        """Generate MFA analysis query"""
        return """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName in ("<USER_EMAIL>")
| extend MFAMethod = tostring(MfaDetail.authMethod)
| extend MFAStatus = case(
    AuthenticationRequirement == "multiFactorAuthentication", "MFA Required",
    AuthenticationRequirement == "singleFactorAuthentication", "No MFA",
    "Unknown"
)
| summarize 
    TotalSignIns = count(),
    MFASignIns = countif(AuthenticationRequirement == "multiFactorAuthentication"),
    NonMFASignIns = countif(AuthenticationRequirement == "singleFactorAuthentication"),
    UniqueMFAMethods = dcount(MFAMethod),
    MFAMethods = make_set(MFAMethod, 10),
    MFASuccessRate = round(100.0 * countif(ResultType == "0" and AuthenticationRequirement == "multiFactorAuthentication") / countif(AuthenticationRequirement == "multiFactorAuthentication"), 2)
    by UserPrincipalName
| extend MFAAdoptionRate = round(100.0 * MFASignIns / TotalSignIns, 2)"""

    def _generate_location_analysis_query(self, context: Dict) -> str:
        """Generate location-based analysis query"""
        return """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName in ("<USER_EMAIL>")
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend City = tostring(LocationDetails.city)
| extend State = tostring(LocationDetails.state)
| summarize 
    SignInCount = count(),
    UniqueIPs = dcount(IPAddress),
    FailedAttempts = countif(ResultType != "0"),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    IPs = make_set(IPAddress, 5)
    by UserPrincipalName, Country, City, State
| extend TravelSpeed = case(
    datetime_diff('hour', LastSeen, FirstSeen) < 2, "Impossible Travel",
    datetime_diff('hour', LastSeen, FirstSeen) < 6, "Suspicious",
    "Normal"
)
| order by SignInCount desc"""

    def _generate_device_analysis_query(self, context: Dict) -> str:
        """Generate device analysis query"""
        return """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName in ("<USER_EMAIL>")
| extend DeviceId = tostring(DeviceDetail.deviceId)
| extend DeviceOS = tostring(DeviceDetail.operatingSystem)
| extend Browser = tostring(DeviceDetail.browser)
| extend IsCompliant = tostring(DeviceDetail.isCompliant)
| extend IsManaged = tostring(DeviceDetail.isManaged)
| summarize 
    SignInCount = count(),
    FailedSignIns = countif(ResultType != "0"),
    SuccessRate = round(100.0 * countif(ResultType == "0") / count(), 2),
    FirstUsed = min(TimeGenerated),
    LastUsed = max(TimeGenerated),
    Locations = make_set(tostring(LocationDetails.countryOrRegion), 3)
    by UserPrincipalName, DeviceId, DeviceOS, Browser, IsCompliant, IsManaged
| extend RiskLevel = case(
    IsCompliant == "false" or IsManaged == "false", "High Risk",
    FailedSignIns > 5, "Suspicious",
    "Normal"
)
| order by SignInCount desc"""

    def _generate_app_analysis_query(self, context: Dict) -> str:
        """Generate application access analysis query"""
        return """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName in ("<USER_EMAIL>")
| summarize 
    AccessCount = count(),
    UniqueUsers = dcount(UserPrincipalName),
    SuccessfulAccess = countif(ResultType == "0"),
    FailedAccess = countif(ResultType != "0"),
    UniqueIPs = dcount(IPAddress),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated),
    AccessLocations = make_set(tostring(LocationDetails.countryOrRegion), 5)
    by AppDisplayName, ResourceDisplayName
| extend 
    SuccessRate = round(100.0 * SuccessfulAccess / AccessCount, 2),
    RiskIndicator = case(
        FailedAccess > 10, "High Failed Attempts",
        UniqueIPs > 5, "Multiple IPs",
        SuccessRate < 70.0, "Low Success Rate",
        "Normal"
    )
| order by AccessCount desc"""

    def _generate_role_permission_query(self, context: Dict) -> str:
        """Generate role/permission changes query"""
        return """AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("Add member to role", "Remove member from role", "Add app role assignment", "Remove app role assignment")
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatedByApp = tostring(InitiatedBy.app.displayName)
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend RoleName = tostring(TargetResources[0].modifiedProperties[0].newValue)
| summarize 
    ChangeCount = count(),
    Operations = make_set(OperationName),
    AffectedUsers = make_set(TargetUser, 10),
    Roles = make_set(RoleName, 10),
    FirstChange = min(TimeGenerated),
    LastChange = max(TimeGenerated)
    by InitiatedByUser
| extend IsHighRisk = iff(ChangeCount > 5, "Yes", "No")
| order by ChangeCount desc"""

    def _generate_oauth_consent_query(self, context: Dict) -> str:
        """Generate OAuth consent analysis query"""
        return """AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("Consent to application", "Add app role assignment", "Add OAuth2PermissionGrant")
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| extend AppName = tostring(TargetResources[0].displayName)
| extend Permissions = tostring(TargetResources[0].modifiedProperties)
| summarize 
    ConsentCount = count(),
    Applications = make_set(AppName, 10),
    FirstConsent = min(TimeGenerated),
    LastConsent = max(TimeGenerated)
    by InitiatedByUser
| extend RiskLevel = case(
    ConsentCount > 3, "High - Multiple Consents",
    "Normal"
)
| order by ConsentCount desc"""

    def _generate_time_pattern_query(self, context: Dict) -> str:
        """Generate time-based pattern analysis query"""
        return """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName in ("<USER_EMAIL>")
| extend Hour = datetime_part("Hour", TimeGenerated)
| extend DayOfWeek = dayofweek(TimeGenerated)
| extend IsBusinessHours = iff(Hour >= 8 and Hour <= 18 and DayOfWeek >= 1 and DayOfWeek <= 5, "Yes", "No")
| summarize 
    SignInCount = count(),
    FailedAttempts = countif(ResultType != "0"),
    UniqueIPs = dcount(IPAddress),
    Locations = make_set(tostring(LocationDetails.countryOrRegion), 3)
    by UserPrincipalName, Hour, DayOfWeek, IsBusinessHours
| extend AnomalyScore = case(
    IsBusinessHours == "No" and SignInCount > 5, 10,
    IsBusinessHours == "No", 5,
    0
)
| order by AnomalyScore desc, SignInCount desc"""

    def _generate_default_signin_query(self, context: Dict) -> str:
        """Generate default comprehensive sign-in query"""
        return """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName in ("<USER_EMAIL>")
| summarize 
    SignInCount = count(),
    UniqueIPs = dcount(IPAddress),
    UniqueLocations = dcount(tostring(LocationDetails.countryOrRegion)),
    UniqueApps = dcount(AppDisplayName),
    FailedAttempts = countif(ResultType != "0"),
    SuccessfulSignIns = countif(ResultType == "0"),
    RiskySignIns = countif(IsRisky == true),
    IPs = make_set(IPAddress, 5),
    Locations = make_set(tostring(LocationDetails.countryOrRegion), 5),
    Apps = make_set(AppDisplayName, 5)
    by UserPrincipalName
| extend 
    SuccessRate = round(100.0 * SuccessfulSignIns / SignInCount, 2),
    RiskScore = (FailedAttempts * 2) + (RiskySignIns * 5)"""

    def _normalize_query(self, kql: str) -> str:
        """Normalize query for duplicate detection"""
        # Remove whitespace and comments
        normalized = re.sub(r"\s+", " ", kql.lower())
        normalized = re.sub(r"//.*", "", normalized)
        return normalized.strip()

    def _make_unique(self, kql: str, step_number: int) -> str:
        """Add uniqueness to duplicate query"""
        # Add step-specific comment and additional filter
        unique_kql = f"// Step {step_number} specific analysis\n{kql}"

        # Add step-specific time bin if summarize exists
        if "summarize" in kql.lower():
            unique_kql = kql.replace(
                "summarize", f"extend StepNumber = {step_number}\n| summarize"
            )

        return unique_kql


class EnhancedKQLGenerator:
    """Main KQL Generator with uniqueness guarantee"""

    def __init__(self):
        self._init_llms()
        self.unique_generator = UniqueKQLGenerator()
        self.validator = SchemaValidator()

    def _init_llms(self):
        """Initialize LLMs"""
        gemini_key = os.getenv("GOOGLE_API_KEY")
        if gemini_key:
            self.primary_llm = LLM(
                model="gemini/gemini-2.0-flash-exp", api_key=gemini_key, temperature=0.3
            )
        else:
            ollama_model = os.getenv("OLLAMA_CHAT", "ollama/qwen2.5:3b")
            if not ollama_model.startswith("ollama/"):
                ollama_model = f"ollama/{ollama_model}"
            self.primary_llm = LLM(
                model=ollama_model, base_url="http://localhost:11434", temperature=0.3
            )

    def generate_kql_query(
        self, step_name: str, explanation: str, step_number: int, rule_context: str = ""
    ) -> Tuple[str, str]:
        """Generate unique, specific KQL query"""

        if not self._needs_kql(step_name, explanation):
            return "", ""

        # Build context
        step_context = {
            "step_name": step_name,
            "explanation": explanation,
            "step_number": step_number,
            "intent": self._extract_intent(step_name, explanation),
            "focus": self._extract_focus(step_name, explanation),
        }

        # Generate unique query
        kql = self.unique_generator.generate_unique_query(step_context)

        if kql and len(kql.strip()) > 30:
            explanation_text = self._generate_explanation(kql, step_name)
            return kql, explanation_text

        return "", ""

    def _needs_kql(self, step_name: str, explanation: str) -> bool:
        """Check if step needs KQL"""
        combined = f"{step_name} {explanation}".lower()

        skip_keywords = [
            "virustotal",
            "virus total",
            "abuseipdb",
            "document",
            "close incident",
            "escalate",
            "inform",
            "notify",
            "report",
            "classify",
        ]

        if any(kw in combined for kw in skip_keywords):
            return False

        needs_keywords = [
            "sign-in",
            "login",
            "audit",
            "logs",
            "query",
            "check",
            "verify",
            "review",
            "analyze",
            "investigate",
        ]

        return any(kw in combined for kw in needs_keywords)

    def _extract_intent(self, step_name: str, explanation: str) -> str:
        """Extract step intent"""
        combined = f"{step_name} {explanation}".lower()

        if "count" in combined or "impact" in combined:
            return "count_impact"
        elif "vip" in combined:
            return "verify_vip"
        elif "ip" in combined and "reputation" in combined:
            return "ip_reputation"
        elif "failed" in combined:
            return "failed_signin"
        else:
            return "investigation"

    def _extract_focus(self, step_name: str, explanation: str) -> str:
        """Extract focus area"""
        combined = f"{step_name} {explanation}".lower()

        if "user" in combined or "account" in combined:
            return "user"
        elif "ip" in combined or "address" in combined:
            return "ip"
        elif "device" in combined:
            return "device"
        elif "application" in combined or "app" in combined:
            return "application"
        else:
            return "general"

    def _generate_explanation(self, kql: str, step_name: str) -> str:
        """Generate concise explanation"""
        table = "SigninLogs" if "signinlogs" in kql.lower() else "AuditLogs"

        if "summarize" in kql.lower():
            return f"Aggregates {table} data to analyze {step_name.lower()} patterns and metrics."
        else:
            return f"Queries {table} to investigate {step_name.lower()} activity."
