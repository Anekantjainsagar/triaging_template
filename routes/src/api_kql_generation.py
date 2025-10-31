"""
Enhanced KQL Query Generator with ACTUAL Schema Validation
Validates against real SigninLogs/AuditLogs/IdentityInfo schemas
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
        # ✅ ACTUAL SigninLogs schema from your document
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

        # ✅ ACTUAL AuditLogs schema (common columns)
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

        # ✅ ACTUAL IdentityInfo schema (common columns)
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

        # ✅ ACTUAL DeviceInfo schema
        self.DEVICEINFO_COLUMNS = {
            "TimeGenerated",
            "DeviceId",
            "DeviceName",
            "OSPlatform",
            "OSVersion",
            "IsCompliant",
            "DeviceType",
            "ManagedBy",
        }

        # ✅ CloudAppEvents schema
        self.CLOUDAPPEVENTS_COLUMNS = {
            "TimeGenerated",
            "AccountObjectId",
            "IPAddress",
            "Application",
            "ActionType",
            "RawEventData",
            "ActivityType",
        }

        self.table_schemas = {
            "SigninLogs": self.SIGNINLOGS_COLUMNS,
            "AuditLogs": self.AUDITLOGS_COLUMNS,
            "IdentityInfo": self.IDENTITYINFO_COLUMNS,
            "DeviceInfo": self.DEVICEINFO_COLUMNS,
            "CloudAppEvents": self.CLOUDAPPEVENTS_COLUMNS,
        }

    def validate_query(self, kql: str) -> Tuple[bool, List[str]]:
        """
        Validate KQL query against actual schemas

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        # Extract table name
        table_match = re.search(
            r"(SigninLogs|AuditLogs|IdentityInfo|DeviceInfo|CloudAppEvents)", kql
        )
        if not table_match:
            return True, []  # Can't validate without table

        table_name = table_match.group(1)
        valid_columns = self.table_schemas.get(table_name, set())

        # Extract all column references
        # Matches: ColumnName ==, | where ColumnName, | project ColumnName, etc.
        column_pattern = (
            r"\b([A-Z][a-zA-Z0-9]*)\b\s*(?:==|!=|>|<|>=|<=|\bin\b|contains|startswith)"
        )
        columns_used = re.findall(column_pattern, kql)

        # Also check project/extend/summarize clauses
        project_match = re.search(r"\|\s*project\s+([^\|]+)", kql)
        if project_match:
            project_cols = re.findall(
                r"\b([A-Z][a-zA-Z0-9]*)\b", project_match.group(1)
            )
            columns_used.extend(project_cols)

        extend_matches = re.findall(
            r"\|\s*extend\s+\w+\s*=\s*[^|]*?([A-Z][a-zA-Z0-9]*)", kql
        )
        columns_used.extend(extend_matches)

        summarize_matches = re.findall(r"\|\s*summarize\s+[^|]*?by\s+([^|]+)", kql)
        for match in summarize_matches:
            by_cols = re.findall(r"\b([A-Z][a-zA-Z0-9]*)\b", match)
            columns_used.extend(by_cols)

        # Check for invalid columns
        for col in set(columns_used):
            if col not in valid_columns and col not in [
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
            ]:
                errors.append(f"❌ Invalid column '{col}' for table {table_name}")

        return len(errors) == 0, errors

    def fix_query(self, kql: str) -> str:
        """
        Automatically fix common schema errors
        """
        # ❌ REMOVE: AlertName (doesn't exist)
        kql = re.sub(r"\|\s*where\s+AlertName\s*==\s*[^\|]+", "", kql)

        # ❌ FIX: MfaResult -> use MfaDetail instead
        kql = re.sub(r"\bMfaResult\b", "tostring(MfaDetail.authMethod)", kql)

        # ❌ FIX: AuthenticationMethod -> use AuthenticationMethodsUsed
        kql = re.sub(r"\bAuthenticationMethod\b", "AuthenticationMethodsUsed", kql)

        # ❌ FIX: Role/IsVIP/IsAdmin (IdentityInfo doesn't have these)
        # Replace with JobTitle-based logic
        kql = re.sub(
            r"\bIsVIP\b",
            '(JobTitle contains "VP" or JobTitle contains "Chief" or JobTitle contains "Director")',
            kql,
        )
        kql = re.sub(
            r"\bIsAdmin\b", '(JobTitle contains "Admin" or JobTitle contains "IT")', kql
        )

        # ❌ FIX: DeviceDetail access (it's a dynamic type)
        # Example: DeviceDetail -> tostring(DeviceDetail.deviceId)
        if "DeviceDetail ==" in kql:
            kql = re.sub(
                r"DeviceDetail\s*==", "tostring(DeviceDetail.deviceId) ==", kql
            )

        # ❌ FIX: Location access (it's string, but LocationDetails is dynamic)
        # Replace Location with LocationDetails.countryOrRegion
        if "| where Location ==" in kql:
            kql = re.sub(
                r"\|\s*where\s+Location\s*==",
                "| where tostring(LocationDetails.countryOrRegion) ==",
                kql,
            )

        # Clean up empty where clauses
        kql = re.sub(r"\|\s*where\s*\|", "|", kql)

        return kql.strip()


class DynamicKQLBuilder:
    """Builds KQL queries dynamically based on step requirements"""

    def __init__(self):
        self.validator = SchemaValidator()

        self.valid_tables = {
            "SigninLogs": list(self.validator.SIGNINLOGS_COLUMNS),
            "AuditLogs": list(self.validator.AUDITLOGS_COLUMNS),
            "IdentityInfo": list(self.validator.IDENTITYINFO_COLUMNS),
            "DeviceInfo": list(self.validator.DEVICEINFO_COLUMNS),
            "CloudAppEvents": list(self.validator.CLOUDAPPEVENTS_COLUMNS),
        }

    def build_query(self, step_context: Dict) -> str:
        """Build KQL query dynamically based on step requirements"""

        table = self._select_table(step_context)
        filters = self._build_filters(step_context, table)
        aggregation = self._build_aggregation(step_context, table)
        projection = self._build_projection(step_context, table)

        query_parts = [table]
        query_parts.extend(filters)

        if aggregation:
            query_parts.append(aggregation)
        elif projection:
            query_parts.append(projection)

        kql = "\n".join(query_parts)

        # ✅ VALIDATE AND FIX
        is_valid, errors = self.validator.validate_query(kql)
        if not is_valid:
            print(f"   ⚠️ Validation errors found: {errors}")
            kql = self.validator.fix_query(kql)
            print(f"   🔧 Applied automatic fixes")

        return kql

    def _select_table(self, context: Dict) -> str:
        """Select most appropriate table based on step intent"""
        intent = context.get("intent", "")
        focus = context.get("focus", "")

        if "signin" in intent or "login" in intent or focus == "user":
            return "SigninLogs"
        elif "role" in intent or "permission" in intent:
            return "AuditLogs"
        elif "device" in intent or focus == "device":
            return "DeviceInfo"
        elif "identity" in intent or "vip" in intent:
            return "IdentityInfo"
        else:
            return "SigninLogs"

    def _build_filters(self, context: Dict, table: str) -> List[str]:
        """Build WHERE clauses based on context"""
        filters = []
        focus = context.get("focus", "")
        timeframe = context.get("timeframe", "last_7d")

        time_mapping = {
            "last_24h": "1d",
            "last_7d": "7d",
            "last_30d": "30d",
            "last_90d": "90d",
        }
        time_value = time_mapping.get(timeframe, "7d")

        if table in ["SigninLogs", "AuditLogs", "CloudAppEvents"]:
            filters.append(f"| where TimeGenerated > ago({time_value})")

        if focus == "user":
            if table == "SigninLogs":
                filters.append('| where UserPrincipalName == "<USER_EMAIL>"')
        elif focus == "ip":
            if table in ["SigninLogs", "CloudAppEvents"]:
                filters.append('| where IPAddress == "<IP_ADDRESS>"')
        elif focus == "device":
            if table == "SigninLogs":
                filters.append("| extend DeviceId = tostring(DeviceDetail.deviceId)")
                filters.append("| where isnotempty(DeviceId)")

        return filters

    def _build_aggregation(self, context: Dict, table: str) -> Optional[str]:
        """Build SUMMARIZE clause if aggregation needed"""
        if not context.get("aggregation_needed", False):
            return None

        intent = context.get("intent", "")
        focus = context.get("focus", "")

        if "count_impact" in intent or "verify_count" in intent:
            return "| summarize UserCount = dcount(UserPrincipalName), TotalSignIns = count()"

        elif focus == "user" and table == "SigninLogs":
            # ✅ FIXED: Use valid columns only
            return (
                "| summarize SignInCount = count(), "
                "UniqueIPs = dcount(IPAddress), "
                'FailedAttempts = countif(ResultType != "0"), '
                "UniqueLocations = dcount(tostring(LocationDetails.countryOrRegion)) "
                "by UserPrincipalName"
            )

        elif focus == "ip" and table == "SigninLogs":
            return (
                "| summarize SignInAttempts = count(), "
                "UniqueUsers = dcount(UserPrincipalName), "
                'FailedLogins = countif(ResultType != "0") '
                "by IPAddress"
            )

        return None

    def _build_projection(self, context: Dict, table: str) -> Optional[str]:
        """Build PROJECT clause for specific field selection"""
        specific_fields = context.get("specific_fields", [])

        if not specific_fields:
            return None

        if "TimeGenerated" not in specific_fields:
            specific_fields.insert(0, "TimeGenerated")

        fields_str = ", ".join(specific_fields)
        return f"| project {fields_str}"


class KQLSearchAPIClient:
    """Client for kqlsearch.com API integration"""

    def __init__(self, api_url: str = "https://www.kqlsearch.com/api/querygenerator"):
        self.api_url = api_url
        self.timeout = 30
        self.validator = SchemaValidator()

    def generate_query(self, input_text: str) -> Optional[str]:
        """Generate KQL query using kqlsearch.com API with validation"""
        payload = {"input": input_text}

        try:
            print(f"   🌐 Calling kqlsearch.com API...")
            response = requests.post(self.api_url, json=payload, timeout=self.timeout)
            response.raise_for_status()

            result = response.json()

            if "content" in result:
                kql_query = result["content"]

                if "```kql" in kql_query:
                    kql_query = kql_query.split("```kql")[1].split("```")[0].strip()
                elif "```" in kql_query:
                    kql_query = kql_query.split("```")[1].split("```")[0].strip()

                # ✅ VALIDATE AND FIX
                is_valid, errors = self.validator.validate_query(kql_query)
                if not is_valid:
                    print(f"   ⚠️ API query has schema errors: {errors}")
                    kql_query = self.validator.fix_query(kql_query)
                    print(f"   🔧 Applied automatic fixes")

                    # Re-validate after fix
                    is_valid, errors = self.validator.validate_query(kql_query)
                    if not is_valid:
                        print(f"   ❌ Still has errors after fix: {errors}")
                        return None

                print(f"   ✅ Valid KQL received from API ({len(kql_query)} chars)")
                return kql_query.strip()
            else:
                print("   ⚠️ No content in API response")
                return None

        except requests.exceptions.Timeout:
            print(f"   ⚠️ API timeout after {self.timeout}s")
            return None
        except requests.exceptions.RequestException as e:
            print(f"   ⚠️ API request failed: {str(e)[:100]}")
            return None
        except Exception as e:
            print(f"   ⚠️ Unexpected error: {str(e)[:100]}")
            return None


class EnhancedKQLGenerator:
    """Advanced KQL Generator with schema validation"""

    def __init__(self):
        self._init_llms()
        self.query_builder = DynamicKQLBuilder()
        self.kql_api = KQLSearchAPIClient()
        self.validator = SchemaValidator()

        try:
            self.web_search = SerperDevTool()
            self.has_web = True
            print("✅ Web search enabled (Serper)")
        except:
            self.web_search = None
            self.has_web = False
            print("⚠️ Web search unavailable")

    def _init_llms(self):
        """Initialize LLMs"""
        gemini_key = os.getenv("GOOGLE_API_KEY")
        if gemini_key:
            self.gemini_llm = LLM(
                model="gemini/gemini-2.5-flash",
                api_key=gemini_key,
                temperature=0.3,
                timeout=120,
                max_retries=2,
            )
            self.primary_llm = self.gemini_llm
            print("✅ Primary LLM: Gemini 2.5 Flash")
        else:
            self.gemini_llm = None

        ollama_model = os.getenv("OLLAMA_CHAT", "ollama/qwen2.5:3b")
        if not ollama_model.startswith("ollama/"):
            ollama_model = f"ollama/{ollama_model}"

        self.ollama_llm = LLM(
            model=ollama_model, base_url="http://localhost:11434", temperature=0.3
        )

        if not self.gemini_llm:
            self.primary_llm = self.ollama_llm

    def generate_kql_query(
        self, step_name: str, explanation: str, step_number: int, rule_context: str = ""
    ) -> Tuple[str, str]:
        """Generate KQL query with schema validation"""

        print(f"\n🔍 Generating KQL for Step {step_number}: {step_name}")

        if not self._needs_kql(step_name, explanation):
            print("   ⏭️ No KQL needed for this step")
            return "", ""

        step_context = self._analyze_step_context(
            step_name, explanation, step_number, rule_context
        )

        print(f"   📊 Context: {step_context.get('intent', 'unknown')}")

        # Try kqlsearch.com API first
        api_input = self._build_api_input(step_name, explanation, step_context)
        kql = self.kql_api.generate_query(api_input)

        if kql and self._validate_kql(kql):
            explanation_text = self._generate_explanation_with_llm(
                kql, step_name, explanation
            )
            print("   ✅ Generated from kqlsearch.com API (validated)")
            return kql, explanation_text

        # Fallback to dynamic builder
        print("   🔄 Trying dynamic query builder...")
        kql = self.query_builder.build_query(step_context)

        if kql and self._validate_kql(kql):
            explanation_text = self._generate_explanation_with_llm(
                kql, step_name, explanation
            )
            print("   ✅ Generated from dynamic builder (validated)")
            return kql, explanation_text

        # Final fallback to LLM with schema hints
        print("   🔄 Trying LLM generation with schema guidance...")
        kql, explanation_text = self._llm_generate_with_schema(
            step_name, explanation, step_number, rule_context, step_context
        )

        if kql and self._validate_kql(kql):
            print("   ✅ Generated using LLM (validated)")
            return kql, explanation_text

        print("   ⚠️ No valid KQL generated")
        return "", ""

    def _llm_generate_with_schema(
        self,
        step_name: str,
        explanation: str,
        step_number: int,
        rule_context: str,
        step_context: Dict,
    ) -> Tuple[str, str]:
        """Generate KQL using LLM with schema hints"""

        # Provide valid columns to LLM
        valid_columns_hint = """
**IMPORTANT: Use ONLY these valid columns:**

SigninLogs:
- UserPrincipalName, IPAddress, TimeGenerated, ResultType, ResultDescription
- AppDisplayName, ClientAppUsed, DeviceDetail (dynamic), LocationDetails (dynamic)
- ConditionalAccessStatus, AuthenticationMethodsUsed, IsInteractive, IsRisky
- RiskLevelAggregated, RiskLevelDuringSignIn, Status (dynamic)

AuditLogs:
- OperationName, TargetResources, InitiatedBy, ActivityDateTime, Category

IdentityInfo:
- AccountUPN, Department, JobTitle, Manager (no IsVIP, no Role columns!)

DeviceInfo:
- DeviceId, DeviceName, OSPlatform, IsCompliant

**CRITICAL RULES:**
1. ❌ DO NOT use: AlertName, MfaResult, Role, IsVIP, IsAdmin
2. ✅ For MFA: use tostring(MfaDetail.authMethod)
3. ✅ For Location: use tostring(LocationDetails.countryOrRegion)
4. ✅ For Device: use tostring(DeviceDetail.deviceId)
5. ✅ For VIP detection: use (JobTitle contains "VP" or JobTitle contains "Chief")
"""

        intent = step_context.get("intent", "investigation")
        focus = step_context.get("focus", "user")

        prompt = f"""Generate a Microsoft Sentinel KQL query for this step.

STEP {step_number}: {step_name}
PURPOSE: {explanation}
INTENT: {intent}
FOCUS: {focus}

{valid_columns_hint}

EXAMPLE TEMPLATE:
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "<USER_EMAIL>"
| summarize 
    SignInCount = count(),
    UniqueIPs = dcount(IPAddress),
    FailedAttempts = countif(ResultType != "0")
    by UserPrincipalName

OUTPUT ONLY THE KQL QUERY (no explanations):"""

        try:
            agent = Agent(
                role="Microsoft Sentinel KQL Expert",
                goal=f"Generate schema-valid KQL query for step {step_number}",
                backstory="Expert in writing valid KQL queries for Azure Sentinel",
                llm=self.primary_llm,
                verbose=False,
            )

            task = Task(
                description=prompt,
                expected_output="Valid, schema-compliant KQL query",
                agent=agent,
            )

            crew = Crew(agents=[agent], tasks=[task], verbose=False)
            result = str(crew.kickoff())

            kql = self._deep_clean_kql(result)

            # ✅ VALIDATE AND FIX
            if kql:
                is_valid, errors = self.validator.validate_query(kql)
                if not is_valid:
                    print(f"   ⚠️ LLM query has errors: {errors}")
                    kql = self.validator.fix_query(kql)
                    print(f"   🔧 Applied automatic fixes")

            if kql and self._validate_kql(kql):
                explanation_text = self._generate_explanation_with_llm(
                    kql, step_name, explanation
                )
                return kql, explanation_text

        except Exception as e:
            print(f"   ⚠️ LLM generation failed: {str(e)[:100]}")

        return "", ""

    def _validate_kql(self, kql: str) -> bool:
        """Validate KQL query"""
        if not kql or len(kql) < 20:
            return False

        valid_tables = [
            "SigninLogs",
            "AuditLogs",
            "IdentityInfo",
            "DeviceInfo",
            "CloudAppEvents",
        ]

        if not any(table in kql for table in valid_tables):
            return False

        kql_operators = ["where", "summarize", "project", "extend"]
        if not any(op in kql.lower() for op in kql_operators):
            return False

        # ✅ FINAL SCHEMA VALIDATION
        is_valid, errors = self.validator.validate_query(kql)
        if not is_valid:
            print(f"   ⚠️ Validation failed: {errors}")
            return False

        return True

    def _needs_kql(self, step_name: str, explanation: str) -> bool:
        """Determine if step needs KQL query"""
        combined = f"{step_name} {explanation}".lower()

        skip_keywords = [
            "virustotal",
            "virus total",
            "document",
            "close incident",
            "escalate",
            "inform",
            "notify",
            "report",
            "classify",
        ]

        if any(keyword in combined for keyword in skip_keywords):
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

        return any(keyword in combined for keyword in needs_keywords)

    def _analyze_step_context(
        self, step_name: str, explanation: str, step_number: int, rule_context: str
    ) -> Dict:
        """Analyze step to determine query requirements"""
        combined = f"{step_name} {explanation} {rule_context}".lower()

        context = {
            "intent": "",
            "focus": "",
            "timeframe": "last_7d",
            "aggregation_needed": False,
            "specific_fields": [],
        }

        if "count" in combined or "impact" in step_name.lower():
            context["intent"] = "count_impact"
            context["aggregation_needed"] = True
        elif "vip" in combined or "verify user" in combined:
            context["intent"] = "verify_vip_user"
            context["focus"] = "user"
            context["aggregation_needed"] = True
        elif "ip" in combined and "reputation" in combined:
            context["intent"] = "check_ip_reputation"
            context["focus"] = "ip"
            context["aggregation_needed"] = True
        elif "signin" in combined or "login" in combined:
            context["intent"] = "check_signin_activity"
            context["focus"] = "user"
            context["aggregation_needed"] = True

        return context

    def _build_api_input(
        self, step_name: str, explanation: str, step_context: Dict
    ) -> str:
        """Build input for kqlsearch.com API"""
        base_input = f"{step_name}: {explanation}"

        intent = step_context.get("intent", "")
        focus = step_context.get("focus", "")

        enhancements = []
        if focus:
            enhancements.append(f"focus on {focus}")
        if step_context.get("aggregation_needed"):
            enhancements.append("with aggregation")

        if enhancements:
            return f"{base_input} ({', '.join(enhancements)})"
        return base_input

    def _deep_clean_kql(self, kql: str) -> str:
        """Clean KQL query"""
        if not kql:
            return ""

        kql = re.sub(r"```kql\s*", "", kql)
        kql = re.sub(r"```\s*", "", kql)

        lines = []
        for line in kql.split("\n"):
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            lines.append(line)

        return "\n".join(lines).strip()

    def _generate_explanation_with_llm(
        self, kql: str, step_name: str, explanation: str
    ) -> str:
        """Generate explanation for KQL query"""
        table = (
            "SigninLogs"
            if "signinlogs" in kql.lower()
            else "AuditLogs" if "auditlogs" in kql.lower() else "logs"
        )

        return f"Queries {table} table to analyze {step_name.lower()} activity."
