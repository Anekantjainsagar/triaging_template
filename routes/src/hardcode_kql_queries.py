import requests
import re
from typing import Optional, Dict, Tuple


class HardcodedKQLQueries:
    """Production-ready KQL queries for all investigation scenarios"""

    # ==================== INITIAL SCOPE & IMPACT ANALYSIS ====================

    INITIAL_SCOPE_ANALYSIS = """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "<USER_EMAIL>"
| summarize
    TotalSignIns = count(),
    UniqueIPAddresses = dcount(IPAddress),
    UniqueLocations = dcount(tostring(LocationDetails.countryOrRegion)),
    UniqueApplications = dcount(AppDisplayName),
    SuccessfulSignIns = countif(ResultType == "0"),
    FailedSignIns = countif(ResultType != "0"),
    RiskySignIns = countif(IsRisky == true),
    InteractiveSignIns = countif(IsInteractive == true),
    NonInteractiveSignIns = countif(IsInteractive == false),
    FirstActivity = min(TimeGenerated),
    LastActivity = max(TimeGenerated),
    IPAddressesList = make_set(IPAddress, 10),
    LocationsList = make_set(tostring(LocationDetails.countryOrRegion), 5),
    ApplicationsList = make_set(AppDisplayName, 10)
    by UserPrincipalName, UserDisplayName
| extend
    SuccessRate = round(100.0 * SuccessfulSignIns / TotalSignIns, 2),
    RiskScore = (FailedSignIns * 2) + (RiskySignIns * 5),
    ActivitySpanDays = datetime_diff('day', LastActivity, FirstActivity),
    ThreatLevel = case(
        RiskySignIns > 5, "Critical",
        RiskySignIns > 2, "High",
        FailedSignIns > 10, "Medium",
        "Low"
    )
| project-reorder UserPrincipalName, UserDisplayName, ThreatLevel, RiskScore, TotalSignIns, SuccessRate"""

    # ==================== AUTHENTICATION METHOD ANALYSIS ====================

    AUTH_METHOD_ANALYSIS = """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "<USER_EMAIL>"
| extend AuthenticationDetails = todynamic(AuthenticationDetails)
| mv-expand AuthDetail = AuthenticationDetails
| extend 
    AuthMethod = tostring(AuthDetail.authenticationMethod),
    AuthSuccess = tostring(AuthDetail.succeeded)
| summarize
    TotalSignIns = count(),
    UniqueAuthMethods = dcount(AuthMethod),
    UniqueClientApps = dcount(ClientAppUsed),
    MFARequired = countif(AuthenticationRequirement == "multiFactorAuthentication"),
    SingleFactorAuth = countif(AuthenticationRequirement == "singleFactorAuthentication"),
    SuccessfulAuths = countif(ResultType == "0"),
    FailedAuths = countif(ResultType != "0"),
    BrowserSignIns = countif(ClientAppUsed == "Browser"),
    MobileAppSignIns = countif(ClientAppUsed == "Mobile Apps and Desktop clients"),
    AuthMethodsList = make_set(AuthMethod, 10),
    ClientAppsList = make_set(ClientAppUsed, 10)
    by UserPrincipalName
| extend
    MFAAdoptionRate = round(100.0 * MFARequired / TotalSignIns, 2),
    AuthSuccessRate = round(100.0 * SuccessfulAuths / TotalSignIns, 2)
| extend
    MFAStatus = case(
        MFAAdoptionRate >= 90, "Excellent - Strong MFA",
        MFAAdoptionRate >= 70, "Good - Moderate MFA", 
        MFAAdoptionRate >= 50, "Fair - Partial MFA",
        "Poor - Weak MFA"
    )
| project-reorder UserPrincipalName, MFAStatus, MFAAdoptionRate, TotalSignIns, AuthSuccessRate"""

    # ==================== VIP / EXECUTIVE VERIFICATION ====================

    VIP_ACCOUNT_VERIFICATION = """SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName == "<USER_EMAIL>"
| summarize
    TotalSignIns = count(),
    UniqueIPAddresses = dcount(IPAddress),
    UniqueCountries = dcount(tostring(LocationDetails.countryOrRegion)),
    UniqueApplications = dcount(AppDisplayName),
    HighRiskSignIns = countif(RiskLevelAggregated == "high"),
    MediumRiskSignIns = countif(RiskLevelAggregated == "medium"),
    LowRiskSignIns = countif(RiskLevelAggregated == "low"),
    FailedAttempts = countif(ResultType != "0"),
    SuccessfulSignIns = countif(ResultType == "0"),
    RiskyBehavior = countif(IsRisky == true),
    UniqueDaysActive = dcount(format_datetime(TimeGenerated, 'yyyy-MM-dd')),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    RiskEventTypes = make_set(RiskEventTypes_V2, 10)
    by UserPrincipalName, UserDisplayName, UserId
| extend
    VIPRiskScore = (HighRiskSignIns * 10) + (MediumRiskSignIns * 5) + (FailedAttempts * 2) + (UniqueCountries * 3)
| extend
    AccountClassification = case(
        VIPRiskScore > 30, "🔴 Critical - Executive at High Risk",
        VIPRiskScore > 15, "🟠 High - VIP Requires Attention", 
        VIPRiskScore > 5, "🟡 Medium - Monitor Closely",
        "🟢 Low - Normal Activity"
    ),
    ActivityPattern = case(
        UniqueDaysActive >= 25, "Very Active",
        UniqueDaysActive >= 15, "Active",
        UniqueDaysActive >= 5, "Moderate",
        "Sporadic"
    )
| project-reorder UserPrincipalName, UserDisplayName, AccountClassification, VIPRiskScore, ActivityPattern
| order by VIPRiskScore desc"""

    # ==================== GEOGRAPHIC & IMPOSSIBLE TRAVEL ====================

    GEOGRAPHIC_IMPOSSIBLE_TRAVEL = """SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName == "<USER_EMAIL>"
| extend
    Country = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city),
    State = tostring(LocationDetails.state),
    Latitude = toreal(LocationDetails.geoCoordinates.latitude),
    Longitude = toreal(LocationDetails.geoCoordinates.longitude)
| order by TimeGenerated asc
| extend
    PreviousCountry = prev(Country, 1),
    PreviousCity = prev(City, 1),
    PreviousTime = prev(TimeGenerated, 1),
    PreviousLatitude = prev(Latitude, 1),
    PreviousLongitude = prev(Longitude, 1)
| extend
    TimeDiffMinutes = datetime_diff('minute', TimeGenerated, PreviousTime),
    LocationChanged = iff(Country != PreviousCountry or City != PreviousCity, "Yes", "No")
| where LocationChanged == "Yes"
| summarize
    SignInCount = count(),
    UniqueIPsInLocation = dcount(IPAddress),
    SuccessfulSignIns = countif(ResultType == "0"),
    FailedSignIns = countif(ResultType != "0"),
    RiskySignIns = countif(IsRisky == true),
    FirstSeenInLocation = min(TimeGenerated),
    LastSeenInLocation = max(TimeGenerated),
    IPAddressesList = make_set(IPAddress, 5),
    MinTimeBetweenLocations = min(TimeDiffMinutes)
    by UserPrincipalName, Country, City, State
| extend
    TravelRisk = case(
        MinTimeBetweenLocations < 60 and Country != "IN", "🚨 IMPOSSIBLE TRAVEL - <1 Hour",
        MinTimeBetweenLocations < 180 and Country != "IN", "⚠️ Suspicious Travel - <3 Hours",
        MinTimeBetweenLocations < 360 and Country != "IN", "⚡ Fast Travel - <6 Hours",
        Country != "IN", "✈️ International Access",
        "🏠 Domestic - India"
    ),
    LocationRiskScore = case(
        MinTimeBetweenLocations < 60, 20,
        MinTimeBetweenLocations < 180, 15,
        MinTimeBetweenLocations < 360, 10,
        Country != "IN", 5,
        0
    )
| project-reorder UserPrincipalName, TravelRisk, Country, City, LocationRiskScore, SignInCount
| order by LocationRiskScore desc, SignInCount desc"""

    # ==================== IP THREAT INTELLIGENCE ====================

    IP_THREAT_INTELLIGENCE = """SigninLogs
| where TimeGenerated > ago(7d)
| where IPAddress == "<IP_ADDRESS>"
| extend
    Country = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city),
    ISP = tostring(AutonomousSystemNumber)
| summarize
    TotalAttempts = count(),
    UniqueUsers = dcount(UserPrincipalName),
    UniqueApplications = dcount(AppDisplayName),
    SuccessfulLogins = countif(ResultType == "0"),
    FailedLogins = countif(ResultType != "0"),
    RiskySignIns = countif(IsRisky == true),
    HighRiskSignIns = countif(RiskLevelAggregated == "high"),
    MediumRiskSignIns = countif(RiskLevelAggregated == "medium"),
    InteractiveLogins = countif(IsInteractive == true),
    NonInteractiveLogins = countif(IsInteractive == false),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    UniqueCountries = dcount(Country),
    UniqueCities = dcount(City),
    UsersList = make_set(UserPrincipalName, 20),
    ApplicationsList = make_set(AppDisplayName, 10),
    CountriesList = make_set(Country, 5),
    RiskEvents = make_set(RiskEventTypes_V2, 10)
    by IPAddress, ISP
| extend
    DaysSeen = datetime_diff('day', LastSeen, FirstSeen) + 1,
    SuccessRate = round(100.0 * SuccessfulLogins / TotalAttempts, 2),
    IPThreatScore = (HighRiskSignIns * 10) + (MediumRiskSignIns * 5) + (FailedLogins * 2) + (UniqueUsers * 3)
| extend
    ThreatClassification = case(
        HighRiskSignIns > 5, "🔴 Critical Threat - Malicious Actor",
        HighRiskSignIns > 0, "🟠 High Risk - Known Threat",
        FailedLogins > 20, "🟡 Suspicious - Brute Force Pattern",
        SuccessRate < 40, "⚠️ Concerning - Low Success Rate",
        UniqueUsers > 10, "📊 Shared IP - Multiple Users",
        "🟢 Normal Activity"
    ),
    UsagePattern = case(
        DaysSeen == 1 and TotalAttempts > 20, "Burst Activity",
        DaysSeen > 7, "Persistent Access", 
        TotalAttempts > 50, "High Volume",
        "Standard Usage"
    )
| project-reorder IPAddress, ThreatClassification, IPThreatScore, TotalAttempts, UniqueUsers, SuccessRate
| order by IPThreatScore desc"""

    # ==================== BEHAVIORAL ANOMALY DETECTION ====================

    BEHAVIORAL_ANOMALY_DETECTION = """SigninLogs
| where TimeGenerated > ago(14d)
| where UserPrincipalName == "<USER_EMAIL>"
| extend
    Hour = datetime_part("Hour", TimeGenerated),
    DayOfWeek = dayofweek(TimeGenerated),
    DayName = case(
        DayOfWeek == 0, "Sunday",
        DayOfWeek == 1, "Monday",
        DayOfWeek == 2, "Tuesday",
        DayOfWeek == 3, "Wednesday",
        DayOfWeek == 4, "Thursday",
        DayOfWeek == 5, "Friday",
        DayOfWeek == 6, "Saturday",
        "Unknown"
    ),
    IsBusinessHours = iff(Hour >= 8 and Hour <= 18 and DayOfWeek >= 1 and DayOfWeek <= 5, "Yes", "No"),
    TimeWindow = case(
        Hour >= 0 and Hour < 6, "Late Night (12AM-6AM)",
        Hour >= 6 and Hour < 9, "Early Morning (6AM-9AM)",
        Hour >= 9 and Hour < 12, "Morning (9AM-12PM)",
        Hour >= 12 and Hour < 14, "Lunch (12PM-2PM)",
        Hour >= 14 and Hour < 18, "Afternoon (2PM-6PM)",
        Hour >= 18 and Hour < 22, "Evening (6PM-10PM)",
        "Night (10PM-12AM)"
    )
| summarize
    SignInCount = count(),
    UniqueIPAddresses = dcount(IPAddress),
    UniqueApplications = dcount(AppDisplayName),
    UniqueDevices = dcount(tostring(DeviceDetail.deviceId)),
    SuccessfulSignIns = countif(ResultType == "0"),
    FailedSignIns = countif(ResultType != "0"),
    RiskySignIns = countif(IsRisky == true),
    IPsList = make_set(IPAddress, 5),
    ApplicationsList = make_set(AppDisplayName, 5)
    by UserPrincipalName, DayName, TimeWindow, IsBusinessHours, Hour
| extend
    AnomalyScore = case(
        IsBusinessHours == "No" and SignInCount > 20, 25,
        IsBusinessHours == "No" and SignInCount > 10, 20,
        IsBusinessHours == "No" and UniqueIPAddresses > 3, 15,
        IsBusinessHours == "No" and RiskySignIns > 0, 18,
        RiskySignIns > 0, 10,
        FailedSignIns > 5, 8,
        0
    ),
    BehaviorFlag = case(
        AnomalyScore >= 20, "🔴 Critical Anomaly",
        AnomalyScore >= 15, "🟠 High Anomaly",
        AnomalyScore >= 10, "🟡 Medium Anomaly",
        AnomalyScore > 0, "⚠️ Low Anomaly",
        "✅ Normal"
    )
| project-reorder UserPrincipalName, BehaviorFlag, AnomalyScore, DayName, TimeWindow, IsBusinessHours, SignInCount
| order by AnomalyScore desc, SignInCount desc"""

    # ==================== DEVICE HEALTH & COMPLIANCE ====================

    DEVICE_HEALTH_COMPLIANCE = """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "<USER_EMAIL>"
| extend
    DeviceId = tostring(DeviceDetail.deviceId),
    OperatingSystem = tostring(DeviceDetail.operatingSystem),
    Browser = tostring(DeviceDetail.browser),
    IsCompliant = tostring(DeviceDetail.isCompliant),
    IsManaged = tostring(DeviceDetail.isManaged),
    TrustType = tostring(DeviceDetail.trustType)
| summarize
    TotalSignIns = count(),
    UniqueIPAddresses = dcount(IPAddress),
    UniqueLocations = dcount(tostring(LocationDetails.countryOrRegion)),
    UniqueApplications = dcount(AppDisplayName),
    SuccessfulSignIns = countif(ResultType == "0"),
    FailedSignIns = countif(ResultType != "0"),
    RiskySignIns = countif(IsRisky == true),
    InteractiveSignIns = countif(IsInteractive == true),
    FirstUsed = min(TimeGenerated),
    LastUsed = max(TimeGenerated),
    LocationsList = make_set(tostring(LocationDetails.countryOrRegion), 5),
    ApplicationsList = make_set(AppDisplayName, 10),
    IPsList = make_set(IPAddress, 5)
    by UserPrincipalName, DeviceId, OperatingSystem, Browser, IsCompliant, IsManaged, TrustType
| extend
    DaysUsed = datetime_diff('day', LastUsed, FirstUsed) + 1,
    ComplianceStatus = case(
        IsCompliant == "true", "✅ Compliant",
        IsCompliant == "false", "❌ Non-Compliant",
        "⚠️ Unknown"
    ),
    ManagementStatus = case(
        IsManaged == "true", "✅ Managed",
        IsManaged == "false", "❌ Unmanaged",
        "⚠️ Unknown"
    ),
    DeviceRiskScore = case(
        IsCompliant == "false" and IsManaged == "false", 20,
        IsCompliant == "false" or IsManaged == "false", 15,
        RiskySignIns > 5, 12,
        FailedSignIns > 10, 10,
        IsCompliant == "" or IsManaged == "", 8,
        0
    ),
    DeviceRiskLevel = case(
        DeviceRiskScore >= 20, "🔴 Critical Risk - Non-Compliant & Unmanaged",
        DeviceRiskScore >= 15, "🟠 High Risk - Partial Compliance",
        DeviceRiskScore >= 10, "🟡 Medium Risk - Security Issues",
        DeviceRiskScore > 0, "⚠️ Low Risk - Monitor",
        "🟢 Secure Device"
    )
| project-reorder UserPrincipalName, DeviceRiskLevel, DeviceRiskScore, ComplianceStatus, ManagementStatus, OperatingSystem, Browser, TotalSignIns
| order by DeviceRiskScore desc, TotalSignIns desc"""

    # ==================== MFA CONFIGURATION & STATUS ====================

    MFA_CONFIGURATION_STATUS = """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "<USER_EMAIL>"
| extend
    MFAMethod = tostring(MfaDetail.authMethod),
    MFADetail_authDetail = tostring(MfaDetail.authDetail)
| summarize
    TotalSignIns = count(),
    MFARequiredSignIns = countif(AuthenticationRequirement == "multiFactorAuthentication"),
    SingleFactorSignIns = countif(AuthenticationRequirement == "singleFactorAuthentication"),
    MFASuccessful = countif(AuthenticationRequirement == "multiFactorAuthentication" and ResultType == "0"),
    MFAFailed = countif(AuthenticationRequirement == "multiFactorAuthentication" and ResultType != "0"),
    SingleFactorSuccessful = countif(AuthenticationRequirement == "singleFactorAuthentication" and ResultType == "0"),
    SingleFactorFailed = countif(AuthenticationRequirement == "singleFactorAuthentication" and ResultType != "0"),
    UniqueMFAMethods = dcount(MFAMethod),
    UniqueApplications = dcount(AppDisplayName),
    RiskySignIns = countif(IsRisky == true),
    MFAMethodsList = make_set(MFAMethod, 10),
    ApplicationsList = make_set(AppDisplayName, 10),
    FirstActivity = min(TimeGenerated),
    LastActivity = max(TimeGenerated)
    by UserPrincipalName, UserDisplayName
| extend
    MFAAdoptionRate = round(100.0 * MFARequiredSignIns / TotalSignIns, 2),
    MFASuccessRate = iff(MFARequiredSignIns > 0, round(100.0 * MFASuccessful / MFARequiredSignIns, 2), 0.0),
    SingleFactorSuccessRate = iff(SingleFactorSignIns > 0, round(100.0 * SingleFactorSuccessful / SingleFactorSignIns, 2), 0.0),
    OverallSuccessRate = round(100.0 * (MFASuccessful + SingleFactorSuccessful) / TotalSignIns, 2),
    MFASecurityScore = case(
        MFAAdoptionRate >= 95, 100,
        MFAAdoptionRate >= 80, 85,
        MFAAdoptionRate >= 60, 70,
        MFAAdoptionRate >= 40, 50,
        MFAAdoptionRate >= 20, 30,
        10
    ),
    MFAStatus = case(
        MFAAdoptionRate >= 95, "🟢 Excellent - MFA Fully Enforced",
        MFAAdoptionRate >= 80, "✅ Good - Strong MFA Coverage",
        MFAAdoptionRate >= 60, "🟡 Fair - Moderate MFA Usage",
        MFAAdoptionRate >= 40, "🟠 Poor - Weak MFA Coverage",
        "🔴 Critical - Minimal MFA Protection"
    ),
    SecurityRecommendation = case(
        MFAAdoptionRate < 50, "URGENT: Enforce MFA for all sign-ins",
        MFAAdoptionRate < 80, "Recommended: Increase MFA coverage",
        "Maintain current MFA policies"
    )
| project-reorder UserPrincipalName, UserDisplayName, MFAStatus, MFASecurityScore, MFAAdoptionRate, MFASuccessRate
| order by MFASecurityScore asc"""

    # ==================== ROLE & PERMISSION ANALYSIS ====================

    ROLE_PERMISSION_ANALYSIS = """AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has_any ("Add member to role", "Add app role assignment", "Consent to application", "Add owner to application", "Add owner to service principal")
| extend
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    InitiatedByApp = tostring(InitiatedBy.app.displayName),
    TargetUser = tostring(TargetResources[0].userPrincipalName),
    TargetDisplayName = tostring(TargetResources[0].displayName),
    TargetType = tostring(TargetResources[0].type),
    ModifiedProperties = TargetResources[0].modifiedProperties
| where InitiatedByUser == "<USER_EMAIL>" or TargetUser == "<USER_EMAIL>"
| summarize
    TotalChanges = count(),
    UniqueOperations = dcount(OperationName),
    RoleAdditions = countif(OperationName has "Add member to role"),
    AppRoleAssignments = countif(OperationName has "Add app role assignment"),
    ConsentGrants = countif(OperationName has "Consent to application"),
    OwnerChanges = countif(OperationName has "Add owner"),
    SuccessfulChanges = countif(Result == "success"),
    FailedChanges = countif(Result == "failure"),
    FirstChange = min(TimeGenerated),
    LastChange = max(TimeGenerated),
    OperationsList = make_set(OperationName, 20),
    TargetUsersList = make_set(TargetUser, 20),
    InitiatorsList = make_set(InitiatedByUser, 10)
    by UserType = iff(InitiatedByUser == "<USER_EMAIL>", "Initiator", "Target")
| extend
    DaysSinceFirstChange = datetime_diff('day', now(), FirstChange),
    DaysSinceLastChange = datetime_diff('day', now(), LastChange),
    ChangeFrequency = case(
        TotalChanges > 50, "Very High",
        TotalChanges > 20, "High",
        TotalChanges > 10, "Moderate",
        TotalChanges > 5, "Low",
        "Very Low"
    ),
    RiskScore = (RoleAdditions * 5) + (AppRoleAssignments * 4) + (ConsentGrants * 6) + (OwnerChanges * 7),
    RiskLevel = case(
        RiskScore > 50, "🔴 Critical - Excessive Privilege Changes",
        RiskScore > 30, "🟠 High - Significant Role Activity",
        RiskScore > 15, "🟡 Medium - Moderate Privilege Changes",
        RiskScore > 5, "⚠️ Low - Some Activity",
        "🟢 Normal"
    )
| project-reorder UserType, RiskLevel, RiskScore, TotalChanges, ChangeFrequency, RoleAdditions, AppRoleAssignments
| order by RiskScore desc"""

    # ==================== CONDITIONAL ACCESS POLICY ANALYSIS ====================

    CONDITIONAL_ACCESS_ANALYSIS = """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "<USER_EMAIL>"
| mv-expand ConditionalAccessPolicies
| extend
    PolicyName = tostring(ConditionalAccessPolicies.displayName),
    PolicyResult = tostring(ConditionalAccessPolicies.result),
    EnforcedControls = tostring(ConditionalAccessPolicies.enforcedGrantControls),
    ConditionsSatisfied = toint(ConditionalAccessPolicies.conditionsSatisfied),
    ConditionsNotSatisfied = toint(ConditionalAccessPolicies.conditionsNotSatisfied)
| summarize
    TotalEvaluations = count(),
    SuccessCount = countif(PolicyResult == "success"),
    FailureCount = countif(PolicyResult == "failure"),
    NotAppliedCount = countif(PolicyResult == "notApplied"),
    ReportOnlyCount = countif(PolicyResult has "reportOnly"),
    BlockedCount = countif(EnforcedControls has "Block"),
    MFARequiredCount = countif(EnforcedControls has "Mfa"),
    UniqueSignIns = dcount(Id),
    FirstEvaluation = min(TimeGenerated),
    LastEvaluation = max(TimeGenerated)
    by UserPrincipalName, PolicyName, PolicyResult, EnforcedControls
| extend
    ComplianceRate = round(100.0 * SuccessCount / TotalEvaluations, 2),
    PolicyImpact = case(
        BlockedCount > 0, "🔴 Blocking Access",
        MFARequiredCount > 0 and SuccessCount > 0, "🟢 Enforcing MFA",
        NotAppliedCount == TotalEvaluations, "⚪ Not Applied",
        ReportOnlyCount > 0, "📊 Report Only Mode",
        "✅ Allowing Access"
    )
| project-reorder UserPrincipalName, PolicyName, PolicyImpact, PolicyResult, ComplianceRate, TotalEvaluations
| order by TotalEvaluations desc"""

    # ==================== FAILED SIGN-IN ANALYSIS ====================

    FAILED_SIGNIN_ANALYSIS = """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "<USER_EMAIL>"
| where ResultType != "0"
| extend
    FailureReason = tostring(Status.errorCode),
    FailureDescription = tostring(Status.failureReason),
    Country = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city)
| summarize
    FailureCount = count(),
    UniqueErrorCodes = dcount(FailureReason),
    UniqueIPAddresses = dcount(IPAddress),
    UniqueLocations = dcount(Country),
    UniqueApplications = dcount(AppDisplayName),
    FirstFailure = min(TimeGenerated),
    LastFailure = max(TimeGenerated),
    ErrorCodesList = make_set(FailureReason, 10),
    FailureReasonsList = make_set(FailureDescription, 10),
    IPAddressesList = make_set(IPAddress, 10),
    LocationsList = make_set(strcat(City, ", ", Country), 10),
    ApplicationsList = make_set(AppDisplayName, 10)
    by UserPrincipalName, FailureReason, FailureDescription
| extend
    ThreatLevel = case(
        FailureCount > 50, "🔴 Critical - Possible Attack",
        FailureCount > 20, "🟠 High - Multiple Failures",
        FailureCount > 10, "🟡 Medium - Repeated Failures",
        "⚠️ Low - Few Failures"
    ),
    FailurePattern = case(
        UniqueIPAddresses > 10, "Distributed Attack Pattern",
        UniqueLocations > 5, "Geographic Spread",
        FailureCount > 20 and UniqueIPAddresses <= 2, "Concentrated Attack",
        "Standard Failure"
    )
| project-reorder UserPrincipalName, ThreatLevel, FailurePattern, FailureCount, FailureReason, FailureDescription
| order by FailureCount desc"""

    # ==================== APPLICATION ACCESS ANALYSIS ====================

    APPLICATION_ACCESS_ANALYSIS = """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "<USER_EMAIL>"
| summarize
    TotalAccesses = count(),
    SuccessfulAccesses = countif(ResultType == "0"),
    FailedAccesses = countif(ResultType != "0"),
    UniqueIPAddresses = dcount(IPAddress),
    UniqueLocations = dcount(tostring(LocationDetails.countryOrRegion)),
    RiskyAccesses = countif(IsRisky == true),
    MFAAccesses = countif(AuthenticationRequirement == "multiFactorAuthentication"),
    InteractiveAccesses = countif(IsInteractive == true),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated),
    IPsList = make_set(IPAddress, 10),
    LocationsList = make_set(tostring(LocationDetails.countryOrRegion), 5)
    by UserPrincipalName, AppDisplayName, AppId
| extend
    SuccessRate = round(100.0 * SuccessfulAccesses / TotalAccesses, 2),
    MFARate = round(100.0 * MFAAccesses / TotalAccesses, 2),
    RiskScore = (RiskyAccesses * 5) + (FailedAccesses * 2) + (UniqueIPAddresses * 1),
    RiskLevel = case(
        RiskyAccesses > 10, "🔴 Critical Risk",
        RiskyAccesses > 5, "🟠 High Risk",
        FailedAccesses > 10, "🟡 Medium Risk",
        "🟢 Low Risk"
    ),
    AccessPattern = case(
        TotalAccesses > 100, "Very High Usage",
        TotalAccesses > 50, "High Usage",
        TotalAccesses > 20, "Moderate Usage",
        "Low Usage"
    )
| project-reorder UserPrincipalName, AppDisplayName, RiskLevel, RiskScore, TotalAccesses, SuccessRate, MFARate
| order by RiskScore desc, TotalAccesses desc"""

    # ==================== RISKY SIGN-IN DETAILS ====================

    RISKY_SIGNIN_DETAILS = """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "<USER_EMAIL>"
| where IsRisky == true
| extend
    Country = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city)
| summarize
    RiskySignInCount = count(),
    UniqueIPAddresses = dcount(IPAddress),
    UniqueLocations = dcount(Country),
    UniqueApplications = dcount(AppDisplayName),
    HighRiskCount = countif(RiskLevelAggregated == "high"),
    MediumRiskCount = countif(RiskLevelAggregated == "medium"),
    LowRiskCount = countif(RiskLevelAggregated == "low"),
    SuccessfulRiskySignIns = countif(ResultType == "0"),
    FailedRiskySignIns = countif(ResultType != "0"),
    FirstRiskySignIn = min(TimeGenerated),
    LastRiskySignIn = max(TimeGenerated),
    RiskEventsList = make_set(RiskEventTypes_V2, 20),
    RiskDetailsList = make_set(RiskDetail, 10),
    IPsList = make_set(IPAddress, 10),
    LocationsList = make_set(strcat(City, ", ", Country), 10),
    ApplicationsList = make_set(AppDisplayName, 10)
    by UserPrincipalName, RiskLevelAggregated, RiskState
| extend
    CriticalityScore = (HighRiskCount * 10) + (MediumRiskCount * 5) + (LowRiskCount * 2),
    ThreatLevel = case(
        HighRiskCount > 5, "🔴 Critical - Immediate Action Required",
        HighRiskCount > 0, "🟠 High - Urgent Investigation",
        MediumRiskCount > 10, "🟡 Medium - Monitor Closely",
        "⚠️ Low - Standard Monitoring"
    ),
    RiskPattern = case(
        UniqueIPAddresses > 10, "Multiple IPs - Distributed",
        UniqueLocations > 5, "Multiple Locations - Geographic Anomaly",
        RiskySignInCount > 20, "High Frequency - Persistent Threat",
        "Isolated Risk Events"
    )
| project-reorder UserPrincipalName, ThreatLevel, CriticalityScore, RiskLevelAggregated, RiskState, RiskySignInCount
| order by CriticalityScore desc"""

    # ==================== LEGACY AUTHENTICATION USAGE ====================

    LEGACY_AUTH_USAGE = """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "<USER_EMAIL>"
| where ClientAppUsed in ("Exchange ActiveSync", "IMAP", "POP", "SMTP", "Authenticated SMTP", "Autodiscover", "MAPI", "Offline Address Book", "Outlook Anywhere (RPC over HTTP)", "Other clients")
| extend
    Country = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city),
    OS = tostring(DeviceDetail.operatingSystem)
| summarize
    LegacySignInCount = count(),
    UniqueIPAddresses = dcount(IPAddress),
    UniqueLocations = dcount(Country),
    UniqueProtocols = dcount(ClientAppUsed),
    SuccessfulLegacy = countif(ResultType == "0"),
    FailedLegacy = countif(ResultType != "0"),
    RiskyLegacy = countif(IsRisky == true),
    FirstLegacyAccess = min(TimeGenerated),
    LastLegacyAccess = max(TimeGenerated),
    ProtocolsList = make_set(ClientAppUsed, 10),
    IPsList = make_set(IPAddress, 10),
    LocationsList = make_set(strcat(City, ", ", Country), 10),
    OSList = make_set(OS, 5)
    by UserPrincipalName, ClientAppUsed
| extend
    DaysUsed = datetime_diff('day', LastLegacyAccess, FirstLegacyAccess) + 1,
    SuccessRate = round(100.0 * SuccessfulLegacy / LegacySignInCount, 2),
    SecurityRisk = case(
        LegacySignInCount > 100, "🔴 Critical - Heavy Legacy Usage",
        LegacySignInCount > 50, "🟠 High - Significant Legacy Traffic",
        LegacySignInCount > 20, "🟡 Medium - Moderate Legacy Usage",
        "⚠️ Low - Minimal Legacy Access"
    ),
    Recommendation = "URGENT: Migrate to modern authentication to improve security"
| project-reorder UserPrincipalName, SecurityRisk, ClientAppUsed, LegacySignInCount, SuccessRate, Recommendation
| order by LegacySignInCount desc"""


class KQLQueryFallback:
    API_URL = "https://www.kqlsearch.com/api/querygenerator"

    def __init__(self):
        self.cache = {}

    def generate_query_from_api(self, intent: str, timeout: int = 10) -> Optional[str]:
        """
        Generate KQL query using external API as fallback

        Args:
            intent: Description of what the query should do
            timeout: Request timeout in seconds

        Returns:
            Generated KQL query or None if failed
        """
        # Check cache first
        cache_key = intent.lower().strip()
        if cache_key in self.cache:
            return self.cache[cache_key]

        try:
            response = requests.post(
                self.API_URL,
                json={"input": intent},
                timeout=timeout,
                headers={"Content-Type": "application/json"},
            )

            if response.status_code == 200:
                data = response.json()
                content = data.get("content", "")

                # Extract KQL from markdown code block
                kql = self._extract_kql_from_response(content)

                if kql:
                    # Adapt query to our format
                    adapted_query = self._adapt_query_format(kql, intent)

                    # Cache the result
                    self.cache[cache_key] = adapted_query
                    return adapted_query

        except Exception as e:
            print(f"API fallback failed: {str(e)}")

        return None

    def _extract_kql_from_response(self, content: str) -> Optional[str]:
        """Extract KQL query from API response content"""
        # Remove markdown code blocks
        kql_pattern = r"```kql\n(.*?)\n```"
        match = re.search(kql_pattern, content, re.DOTALL)

        if match:
            return match.group(1).strip()

        # If no code block, try to extract the query directly
        if "SigninLogs" in content or "AuditLogs" in content:
            return content.strip()

        return None

    def _adapt_query_format(self, kql: str, intent: str) -> str:
        """
        Adapt API-generated query to our format with proper placeholders

        Args:
            kql: Raw KQL query from API
            intent: Original intent for context

        Returns:
            Adapted KQL query with <USER_EMAIL> and <IP_ADDRESS> placeholders
        """
        adapted = kql

        # Replace common email patterns with placeholder
        email_patterns = [
            r'UserPrincipalName\s*==\s*"[^"]*"',
            r"UserPrincipalName\s*==\s*\'[^\']*\'",
            r'user\.userPrincipalName\s*==\s*"[^"]*"',
            r'InitiatedBy\.user\.userPrincipalName\s*==\s*"[^"]*"',
        ]

        for pattern in email_patterns:
            adapted = re.sub(
                pattern,
                lambda m: m.group(0).rsplit('"', 2)[0] + '"<USER_EMAIL>"',
                adapted,
            )
            adapted = re.sub(
                pattern.replace('"', "'"),
                lambda m: m.group(0).rsplit("'", 2)[0] + "'<USER_EMAIL>'",
                adapted,
            )

        # Replace IP address patterns with placeholder
        ip_patterns = [
            r'IPAddress\s*==\s*"[\d\.]+"',
            r"IPAddress\s*==\s*\'[\d\.]+\'",
            r'where\s+IPAddress\s+in\s*\("[\d\.]+"\)',
        ]

        for pattern in ip_patterns:
            adapted = re.sub(
                pattern,
                lambda m: (
                    m.group(0).rsplit('"', 2)[0] + '"<IP_ADDRESS>"'
                    if '"' in m.group(0)
                    else m.group(0).rsplit("'", 2)[0] + "'<IP_ADDRESS>'"
                ),
                adapted,
            )

        # Ensure proper time range if missing
        if "TimeGenerated" not in adapted:
            adapted = adapted.replace(
                "SigninLogs\n", "SigninLogs\n| where TimeGenerated > ago(7d)\n"
            )
            adapted = adapted.replace(
                "AuditLogs\n", "AuditLogs\n| where TimeGenerated > ago(7d)\n"
            )

        # Add user filter if analyzing user and not present
        if (
            "user" in intent.lower()
            and "UserPrincipalName" not in adapted
            and "SigninLogs" in adapted
        ):
            lines = adapted.split("\n")
            for i, line in enumerate(lines):
                if "SigninLogs" in line:
                    lines.insert(i + 1, '| where UserPrincipalName == "<USER_EMAIL>"')
                    break
            adapted = "\n".join(lines)

        # Add IP filter if analyzing IP and not present
        if (
            "ip" in intent.lower()
            and "IPAddress" not in adapted
            and "SigninLogs" in adapted
        ):
            lines = adapted.split("\n")
            for i, line in enumerate(lines):
                if "SigninLogs" in line:
                    lines.insert(i + 1, '| where IPAddress == "<IP_ADDRESS>"')
                    break
            adapted = "\n".join(lines)

        return adapted.strip()


class KQLQueryManager:
    # Query mapping
    QUERY_MAP = {
        "initial_scope": HardcodedKQLQueries.INITIAL_SCOPE_ANALYSIS,
        "scope_analysis": HardcodedKQLQueries.INITIAL_SCOPE_ANALYSIS,
        "auth_method": HardcodedKQLQueries.AUTH_METHOD_ANALYSIS,
        "authentication": HardcodedKQLQueries.AUTH_METHOD_ANALYSIS,
        "vip_verification": HardcodedKQLQueries.VIP_ACCOUNT_VERIFICATION,
        "vip_account": HardcodedKQLQueries.VIP_ACCOUNT_VERIFICATION,
        "executive": HardcodedKQLQueries.VIP_ACCOUNT_VERIFICATION,
        "geographic": HardcodedKQLQueries.GEOGRAPHIC_IMPOSSIBLE_TRAVEL,
        "impossible_travel": HardcodedKQLQueries.GEOGRAPHIC_IMPOSSIBLE_TRAVEL,
        "travel": HardcodedKQLQueries.GEOGRAPHIC_IMPOSSIBLE_TRAVEL,
        "ip_threat": HardcodedKQLQueries.IP_THREAT_INTELLIGENCE,
        "ip_intelligence": HardcodedKQLQueries.IP_THREAT_INTELLIGENCE,
        "ip_analysis": HardcodedKQLQueries.IP_THREAT_INTELLIGENCE,
        "behavioral": HardcodedKQLQueries.BEHAVIORAL_ANOMALY_DETECTION,
        "anomaly": HardcodedKQLQueries.BEHAVIORAL_ANOMALY_DETECTION,
        "behavior": HardcodedKQLQueries.BEHAVIORAL_ANOMALY_DETECTION,
        "device_health": HardcodedKQLQueries.DEVICE_HEALTH_COMPLIANCE,
        "device_compliance": HardcodedKQLQueries.DEVICE_HEALTH_COMPLIANCE,
        "compliance": HardcodedKQLQueries.DEVICE_HEALTH_COMPLIANCE,
        "mfa_config": HardcodedKQLQueries.MFA_CONFIGURATION_STATUS,
        "mfa_status": HardcodedKQLQueries.MFA_CONFIGURATION_STATUS,
        "mfa": HardcodedKQLQueries.MFA_CONFIGURATION_STATUS,
        "role_permission": HardcodedKQLQueries.ROLE_PERMISSION_ANALYSIS,
        "permission": HardcodedKQLQueries.ROLE_PERMISSION_ANALYSIS,
        "role": HardcodedKQLQueries.ROLE_PERMISSION_ANALYSIS,
        "conditional_access": HardcodedKQLQueries.CONDITIONAL_ACCESS_ANALYSIS,
        "ca_policy": HardcodedKQLQueries.CONDITIONAL_ACCESS_ANALYSIS,
        "failed_signin": HardcodedKQLQueries.FAILED_SIGNIN_ANALYSIS,
        "failed_login": HardcodedKQLQueries.FAILED_SIGNIN_ANALYSIS,
        "failures": HardcodedKQLQueries.FAILED_SIGNIN_ANALYSIS,
        "application_access": HardcodedKQLQueries.APPLICATION_ACCESS_ANALYSIS,
        "app_access": HardcodedKQLQueries.APPLICATION_ACCESS_ANALYSIS,
        "risky_signin": HardcodedKQLQueries.RISKY_SIGNIN_DETAILS,
        "risky": HardcodedKQLQueries.RISKY_SIGNIN_DETAILS,
        "legacy_auth": HardcodedKQLQueries.LEGACY_AUTH_USAGE,
        "legacy": HardcodedKQLQueries.LEGACY_AUTH_USAGE,
        "vip_verification": HardcodedKQLQueries.VIP_ACCOUNT_VERIFICATION,
        "vip_account": HardcodedKQLQueries.VIP_ACCOUNT_VERIFICATION,
        "vip_user": HardcodedKQLQueries.VIP_ACCOUNT_VERIFICATION,  # âœ… NEW
        "executive": HardcodedKQLQueries.VIP_ACCOUNT_VERIFICATION,
        "executive_account": HardcodedKQLQueries.VIP_ACCOUNT_VERIFICATION,  # âœ… NEW
        "privileged_account": HardcodedKQLQueries.VIP_ACCOUNT_VERIFICATION,  # âœ… NEW
        "account_status": HardcodedKQLQueries.VIP_ACCOUNT_VERIFICATION,  # âœ… NEW
    }

    def __init__(self, enable_api_fallback: bool = True):
        self.enable_api_fallback = enable_api_fallback
        self.fallback = KQLQueryFallback() if enable_api_fallback else None

    def get_query(
        self, query_type: str, use_fallback: bool = True
    ) -> Tuple[Optional[str], str]:
        query_key = query_type.lower().strip()

        # Try to get hardcoded query first
        if query_key in self.QUERY_MAP:
            return self.QUERY_MAP[query_key], "hardcoded"

        # Try partial matching
        for key, query in self.QUERY_MAP.items():
            if query_key in key or key in query_key:
                return query, "hardcoded"

        # Fallback to API if enabled
        if use_fallback and self.enable_api_fallback and self.fallback:
            api_query = self.fallback.generate_query_from_api(query_type)
            if api_query:
                return api_query, "api"

        return None, "not_found"

    def inject_parameters(
        self,
        query: str,
        user_email: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> str:
        result = query

        if user_email:
            result = result.replace("<USER_EMAIL>", user_email)

        if ip_address:
            result = result.replace("<IP_ADDRESS>", ip_address)

        return result

    def list_available_queries(self) -> Dict[str, str]:
        descriptions = {
            "initial_scope": "Initial scope and impact analysis",
            "auth_method": "Authentication method and client app analysis",
            "vip_verification": "VIP/Executive account verification",
            "geographic": "Geographic origin and impossible travel detection",
            "ip_threat": "IP address threat intelligence lookup",
            "behavioral": "User behavioral anomaly detection",
            "device_health": "Device health and compliance verification",
            "mfa_config": "MFA configuration and status review",
            "role_permission": "Role and permission analysis",
            "conditional_access": "Conditional access policy analysis",
            "failed_signin": "Failed sign-in analysis",
            "application_access": "Application access patterns",
            "risky_signin": "Risky sign-in details",
            "legacy_auth": "Legacy authentication usage",
        }
        return descriptions
