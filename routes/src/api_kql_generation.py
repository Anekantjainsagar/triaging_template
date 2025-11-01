"""
Enhanced KQL Query Generator - FIXED
No hardcoded step numbers - uses intent & focus from context
Placeholders: <USER_EMAIL>, <IP_ADDRESS> injected at runtime
Corrected: ResultType == "0" for SUCCESS
"""

import re
from typing import Optional, Dict
from datetime import datetime, timedelta


class UniqueKQLGenerator:
    """Generates unique KQL queries based on step intent, not step number"""

    def __init__(self):
        self.generated_queries = set()

    def generate_unique_query(self, step_context: Dict) -> Optional[str]:
        """
        Generate unique KQL query based on step intent/focus, not step number

        Args:
            step_context: {
                "step_name": "Geographic Origin & Impossible Travel Detection",
                "explanation": "...",
                "intent": "geographic_analysis",  # From step_name/explanation
                "focus": "location",
            }
        """
        intent = step_context.get("intent", "").lower()
        focus = step_context.get("focus", "").lower()
        step_name = step_context.get("step_name", "").lower()
        explanation = step_context.get("explanation", "").lower()

        # Combine all context to determine query type
        combined = f"{intent} {focus} {step_name} {explanation}"

        kql = None

        # Route to appropriate query generator based on INTENT, not step_number
        if any(
            keyword in combined for keyword in ["scope", "affected", "impact", "count"]
        ):
            kql = self._generate_initial_scope_query()

        elif any(
            keyword in combined
            for keyword in [
                "authentication",
                "method",
                "client",
                "application",
                "legacy",
                "browser",
            ]
        ):
            kql = self._generate_auth_analysis_query()

        elif any(
            keyword in combined
            for keyword in [
                "vip",
                "executive",
                "high-priority",
                "high priority",
                "admin",
                "privilege",
            ]
        ):
            kql = self._generate_vip_verification_query()

        elif any(
            keyword in combined
            for keyword in [
                "geographic",
                "impossible travel",
                "travel",
                "location",
                "geo",
                "country",
            ]
        ):
            kql = self._generate_geographic_analysis_query()

        elif any(
            keyword in combined
            for keyword in [
                "ip threat",
                "ip reputation",
                "source ip",
                "threat intelligence",
            ]
        ):
            kql = self._generate_ip_threat_intelligence_query()

        elif any(
            keyword in combined
            for keyword in [
                "behavioral",
                "anomaly",
                "post-login",
                "post login",
                "activity",
            ]
        ):
            kql = self._generate_behavioral_anomaly_query()

        elif any(
            keyword in combined
            for keyword in [
                "device",
                "health",
                "compliance",
                "endpoint",
                "managed",
                "compliant",
            ]
        ):
            kql = self._generate_device_health_query()

        elif any(
            keyword in combined
            for keyword in [
                "mfa",
                "configuration",
                "account config",
                "security config",
                "password",
            ]
        ):
            kql = self._generate_mfa_config_query()

        elif any(
            keyword in combined
            for keyword in [
                "role",
                "permission",
                "assignment",
                "privilege",
                "oauth",
                "consent",
            ]
        ):
            kql = self._generate_role_permission_query()

        else:
            # Default - general signin analysis
            kql = self._generate_default_signin_query()

        if kql:
            # Ensure uniqueness
            kql_normalized = self._normalize_query(kql)
            if kql_normalized in self.generated_queries:
                # Make unique by adding context marker
                kql = self._add_unique_marker(kql, focus)
            self.generated_queries.add(kql_normalized)
            return kql

        return None

    def _generate_initial_scope_query(self) -> str:
        """Initial Scope & Affected User Identification - Count impact"""
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

    def _generate_auth_analysis_query(self) -> str:
        """Authentication Method & Client Application Analysis"""
        return """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName in ("<USER_EMAIL>")
| summarize
    TotalSignIns = count(),
    UniqueAuthMethods = dcount(AuthenticationMethodsUsed),
    UniqueClientApps = dcount(ClientAppUsed),
    UniqueBrowsers = dcount(tostring(DeviceDetail.browser)),
    UniqueDevices = dcount(tostring(DeviceDetail.operatingSystem)),
    MFASignIns = countif(AuthenticationRequirement == "multiFactorAuthentication"),
    SingleFactorSignIns = countif(AuthenticationRequirement == "singleFactorAuthentication"),
    SuccessRate = round(100.0 * countif(ResultType == "0") / count(), 2),
    AuthMethods = make_set(AuthenticationMethodsUsed, 10),
    ClientApps = make_set(ClientAppUsed, 10),
    Browsers = make_set(tostring(DeviceDetail.browser), 5)
    by UserPrincipalName
| extend
    MFAAdoptionRate = round(100.0 * MFASignIns / TotalSignIns, 2)"""

    def _generate_vip_verification_query(self) -> str:
        """Verify User Account Status - Check if VIP/High-Priority"""
        return """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName in ("<USER_EMAIL>")
| summarize
    TotalSignIns = count(),
    UniqueIPs = dcount(IPAddress),
    UniqueApps = dcount(AppDisplayName),
    SuccessfulSignIns = countif(ResultType == "0"),
    FailedSignIns = countif(ResultType != "0"),
    RiskySignIns = countif(IsRisky == true),
    HighRiskSignIns = countif(RiskLevelAggregated == "high"),
    MediumRiskSignIns = countif(RiskLevelAggregated == "medium"),
    UniqueDays = dcount(format_datetime(TimeGenerated, 'yyyy-MM-dd')),
    FirstSignIn = min(TimeGenerated),
    LastSignIn = max(TimeGenerated)
    by UserPrincipalName, UserDisplayName
| extend
    ImpactScore = (HighRiskSignIns * 10) + (MediumRiskSignIns * 5) + (FailedSignIns * 2),
    AccountRiskLevel = case(
        ImpactScore > 20, "Critical - VIP at Risk",
        ImpactScore > 10, "High - Premium Target",
        ImpactScore > 5, "Medium - Monitor Closely",
        "Low - Standard Account"
    )
| order by ImpactScore desc"""

    def _generate_geographic_analysis_query(self) -> str:
        """Geographic Origin & Impossible Travel Detection"""
        return """SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName in ("<USER_EMAIL>")
| extend
    Country = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city),
    State = tostring(LocationDetails.state)
| summarize
    SignInCount = count(),
    UniqueIPs = dcount(IPAddress),
    SuccessfulSignIns = countif(ResultType == "0"),
    FailedSignIns = countif(ResultType != "0"),
    FirstSignIn = min(TimeGenerated),
    LastSignIn = max(TimeGenerated),
    IPs = make_set(IPAddress, 5)
    by UserPrincipalName, Country, City, State
| extend
    TimeDiffHours = datetime_diff('hour', LastSignIn, FirstSignIn),
    TravelIndicator = case(
        TimeDiffHours < 2 and Country != "IN", "Impossible Travel",
        TimeDiffHours < 6 and Country != "IN", "Suspicious Travel",
        Country != "IN", "International Access",
        "Normal - India"
    )
| order by SignInCount desc"""

    def _generate_ip_threat_intelligence_query(self) -> str:
        """Source IP Threat Intelligence Lookup"""
        return """SigninLogs
| where TimeGenerated > ago(7d)
| where IPAddress in ("<IP_ADDRESS>")
| summarize
    SignInAttempts = count(),
    UniqueUsers = dcount(UserPrincipalName),
    UniqueApps = dcount(AppDisplayName),
    SuccessfulLogins = countif(ResultType == "0"),
    FailedLogins = countif(ResultType != "0"),
    RiskySignIns = countif(IsRisky == true),
    HighRiskSignIns = countif(RiskLevelAggregated == "high"),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Locations = make_set(tostring(LocationDetails.countryOrRegion), 5),
    Users = make_set(UserPrincipalName, 10),
    Apps = make_set(AppDisplayName, 5)
    by IPAddress
| extend
    DaysSeen = datetime_diff('day', LastSeen, FirstSeen),
    SuccessRate = round(100.0 * SuccessfulLogins / SignInAttempts, 2),
    RiskIndicator = case(
        HighRiskSignIns > 0, "High Risk - Malicious Pattern",
        RiskySignIns > 0, "Medium Risk - Flagged",
        FailedLogins > 10, "Suspicious - Multiple Failed Attempts",
        SuccessRate < 50.0, "Concerning - Low Success Rate",
        "Normal"
    )
| order by HighRiskSignIns desc, RiskySignIns desc"""

    def _generate_behavioral_anomaly_query(self) -> str:
        """User Behavioral Anomaly Detection - Post-Login Activity"""
        return """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName in ("<USER_EMAIL>")
| extend
    Hour = datetime_part("Hour", TimeGenerated),
    DayOfWeek = dayofweek(TimeGenerated),
    IsBusinessHours = iff(Hour >= 8 and Hour <= 18 and DayOfWeek >= 1 and DayOfWeek <= 5, "Yes", "No")
| summarize
    SignInCount = count(),
    UniqueIPs = dcount(IPAddress),
    UniqueApps = dcount(AppDisplayName),
    SuccessfulSignIns = countif(ResultType == "0"),
    FailedSignIns = countif(ResultType != "0"),
    RiskySignIns = countif(IsRisky == true),
    BusinessHoursSignIns = countif(IsBusinessHours == "Yes"),
    AfterHoursSignIns = countif(IsBusinessHours == "No")
    by UserPrincipalName, Hour, DayOfWeek, IsBusinessHours
| extend
    AnomalyScore = case(
        IsBusinessHours == "No" and SignInCount > 10, 15,
        IsBusinessHours == "No" and SignInCount > 5, 10,
        IsBusinessHours == "No", 5,
        RiskySignIns > 0, 8,
        0
    )
| order by AnomalyScore desc, SignInCount desc"""

    def _generate_device_health_query(self) -> str:
        """Device Health and Compliance Verification"""
        return """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName in ("<USER_EMAIL>")
| extend
    DeviceId = tostring(DeviceDetail.deviceId),
    DeviceOS = tostring(DeviceDetail.operatingSystem),
    Browser = tostring(DeviceDetail.browser),
    IsCompliant = tostring(DeviceDetail.isCompliant),
    IsManaged = tostring(DeviceDetail.isManaged)
| summarize
    SignInCount = count(),
    SuccessfulSignIns = countif(ResultType == "0"),
    FailedSignIns = countif(ResultType != "0"),
    RiskySignIns = countif(IsRisky == true),
    FirstUsed = min(TimeGenerated),
    LastUsed = max(TimeGenerated),
    Locations = make_set(tostring(LocationDetails.countryOrRegion), 3),
    Apps = make_set(AppDisplayName, 5)
    by UserPrincipalName, DeviceId, DeviceOS, Browser, IsCompliant, IsManaged
| extend
    ComplianceStatus = case(
        IsCompliant == "false", "Non-Compliant",
        IsCompliant == "true", "Compliant",
        "Unknown"
    ),
    ManagementStatus = case(
        IsManaged == "false", "Unmanaged",
        IsManaged == "true", "Managed",
        "Unknown"
    ),
    RiskLevel = case(
        IsCompliant == "false" or IsManaged == "false", "High Risk",
        FailedSignIns > 5, "Suspicious",
        RiskySignIns > 0, "Medium Risk",
        "Normal"
    )
| order by SignInCount desc"""

    def _generate_mfa_config_query(self) -> str:
        """Account Configuration & MFA Status Review"""
        return """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName in ("<USER_EMAIL>")
| summarize
    TotalSignIns = count(),
    MFARequiredSignIns = countif(AuthenticationRequirement == "multiFactorAuthentication"),
    SingleFactorSignIns = countif(AuthenticationRequirement == "singleFactorAuthentication"),
    MFASuccessful = countif(AuthenticationRequirement == "multiFactorAuthentication" and ResultType == "0"),
    MFAFailed = countif(AuthenticationRequirement == "multiFactorAuthentication" and ResultType != "0"),
    UniqueMFAMethods = dcount(tostring(MfaDetail.authMethod)),
    MFAMethods = make_set(tostring(MfaDetail.authMethod), 10),
    SuccessRate = round(100.0 * countif(ResultType == "0") / count(), 2),
    FirstSignIn = min(TimeGenerated),
    LastSignIn = max(TimeGenerated)
    by UserPrincipalName
| extend
    MFAAdoptionRate = round(100.0 * MFARequiredSignIns / TotalSignIns, 2),
    MFASuccessRate = iff(MFARequiredSignIns > 0, round(100.0 * MFASuccessful / MFARequiredSignIns, 2), 0),
    MFAStatus = case(
        MFAAdoptionRate >= 80, "Strong - MFA Enforced",
        MFAAdoptionRate >= 50, "Moderate - Partial MFA",
        "Weak - Limited MFA"
    )
| order by MFAAdoptionRate desc"""

    def _generate_role_permission_query(self) -> str:
        """Role & Permission Analysis - OAuth Consent"""
        return """AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("Add member to role", "Add app role assignment", "Consent to application")
| extend
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    TargetUser = tostring(TargetResources[0].userPrincipalName)
| where InitiatedByUser in ("<USER_EMAIL>") or TargetUser in ("<USER_EMAIL>")
| summarize
    ChangeCount = count(),
    Operations = make_set(OperationName, 10),
    AffectedUsers = make_set(TargetUser, 10),
    FirstChange = min(TimeGenerated),
    LastChange = max(TimeGenerated),
    InitiatedBy = make_set(InitiatedByUser, 5)
    by OperationName
| extend
    IsHighRisk = iff(ChangeCount > 5, "Yes", "No")
| order by ChangeCount desc"""

    def _generate_default_signin_query(self) -> str:
        """Default comprehensive sign-in analysis"""
        return """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName in ("<USER_EMAIL>")
| summarize
    SignInCount = count(),
    UniqueIPs = dcount(IPAddress),
    UniqueLocations = dcount(tostring(LocationDetails.countryOrRegion)),
    UniqueApps = dcount(AppDisplayName),
    SuccessfulSignIns = countif(ResultType == "0"),
    FailedAttempts = countif(ResultType != "0"),
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
        normalized = re.sub(r"\s+", " ", kql.lower())
        normalized = re.sub(r"//.*", "", normalized)
        return normalized.strip()

    def _add_unique_marker(self, kql: str, focus: str) -> str:
        """Add unique marker without hardcoding step numbers"""
        marker = f"// {focus} specific analysis\n"
        return marker + kql


class EnhancedKQLGenerator:
    """Main KQL Generator"""

    def __init__(self):
        self.unique_generator = UniqueKQLGenerator()

    def generate_kql_query(
        self, step_name: str, explanation: str, rule_context: str = ""
    ) -> tuple:
        """Generate unique, specific KQL query with placeholders"""

        # Extract intent from step name and explanation
        intent = self._extract_intent(step_name, explanation)
        focus = self._extract_focus(step_name, explanation)

        if not self._needs_kql(step_name, explanation):
            return "", ""

        step_context = {
            "step_name": step_name,
            "explanation": explanation,
            "intent": intent,
            "focus": focus,
        }

        kql = self.unique_generator.generate_unique_query(step_context)

        if kql and len(kql.strip()) > 30:
            explanation_text = self._generate_explanation(kql, step_name)
            return kql, explanation_text

        return "", ""

    def _extract_intent(self, step_name: str, explanation: str) -> str:
        """Extract intent from content"""
        combined = f"{step_name} {explanation}".lower()
        if "count" in combined or "impact" in combined:
            return "scope_analysis"
        elif "vip" in combined or "executive" in combined:
            return "vip_verification"
        elif "geographic" in combined or "travel" in combined:
            return "geographic_analysis"
        return "investigation"

    def _extract_focus(self, step_name: str, explanation: str) -> str:
        """Extract focus area"""
        combined = f"{step_name} {explanation}".lower()
        if "device" in combined:
            return "device"
        elif "mfa" in combined or "config" in combined:
            return "account_config"
        elif "geographic" in combined or "location" in combined:
            return "location"
        elif "behavior" in combined:
            return "behavior"
        elif "ip" in combined:
            return "ip"
        return "user"

    def _needs_kql(self, step_name: str, explanation: str) -> bool:
        """Check if step needs KQL"""
        combined = f"{step_name} {explanation}".lower()
        skip_keywords = ["virustotal", "abuseipdb", "manual"]
        if any(kw in combined for kw in skip_keywords):
            return False
        return any(kw in combined for kw in ["query", "check", "verify", "analyze"])

    def _generate_explanation(self, kql: str, step_name: str) -> str:
        """Generate concise explanation"""
        table = "SigninLogs" if "signinlogs" in kql.lower() else "AuditLogs"
        return f"Aggregates {table} data to analyze {step_name.lower()} patterns and metrics."
