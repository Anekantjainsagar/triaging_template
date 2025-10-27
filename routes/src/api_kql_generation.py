"""
Enhanced KQL Query Generator with Dynamic Query Building
Uses step context analysis + dynamic query construction (inspired by kqlsearch.com approach)
Now integrates with kqlsearch.com API for query generation
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


class DynamicKQLBuilder:
    """
    Builds KQL queries dynamically based on step requirements
    Inspired by https://www.kqlsearch.com/querygenerator
    """

    def __init__(self):
        self.valid_tables = {
            "SigninLogs": [
                "UserPrincipalName",
                "IPAddress",
                "Location",
                "DeviceDetail",
                "AuthenticationDetails",
                "ConditionalAccessStatus",
                "TimeGenerated",
            ],
            "AuditLogs": [
                "OperationName",
                "TargetResources",
                "InitiatedBy",
                "ActivityDateTime",
            ],
            "IdentityInfo": ["AccountUPN", "Department", "JobTitle", "Manager"],
            "AADSignInEventsBeta": ["AccountUpn", "IPAddress", "Country", "City"],
            "CloudAppEvents": [
                "AccountObjectId",
                "IPAddress",
                "Application",
                "ActionType",
            ],
            "DeviceInfo": ["DeviceId", "DeviceName", "OSPlatform", "IsCompliant"],
        }

    def build_query(self, step_context: Dict) -> str:
        """
        Build KQL query dynamically based on step requirements

        Args:
            step_context: {
                'intent': 'check_signin_activity' | 'verify_vip_user' | 'analyze_ip' | etc,
                'focus': 'user' | 'ip' | 'device' | 'role',
                'timeframe': 'last_7d' | 'last_24h' | 'last_30d',
                'aggregation_needed': True/False,
                'specific_fields': ['field1', 'field2']
            }
        """

        # Step 1: Select appropriate table
        table = self._select_table(step_context)

        # Step 2: Build filters
        filters = self._build_filters(step_context, table)

        # Step 3: Build aggregations (if needed)
        aggregation = self._build_aggregation(step_context, table)

        # Step 4: Build projections
        projection = self._build_projection(step_context, table)

        # Step 5: Assemble query
        query_parts = [table]
        query_parts.extend(filters)

        if aggregation:
            query_parts.append(aggregation)
        elif projection:
            query_parts.append(projection)

        return "\n".join(query_parts)

    def _select_table(self, context: Dict) -> str:
        """Select most appropriate table based on step intent"""
        intent = context.get("intent", "")
        focus = context.get("focus", "")

        # Intent-based table selection
        if "signin" in intent or "login" in intent or focus == "user":
            return "SigninLogs"
        elif "role" in intent or "permission" in intent:
            return "AuditLogs"
        elif "device" in intent or focus == "device":
            return "DeviceInfo"
        elif "identity" in intent or "vip" in intent:
            return "IdentityInfo"
        else:
            return "SigninLogs"  # Default

    def _build_filters(self, context: Dict, table: str) -> List[str]:
        """Build WHERE clauses based on context"""
        filters = []
        focus = context.get("focus", "")
        timeframe = context.get("timeframe", "last_7d")

        # Time filter (always needed)
        time_mapping = {
            "last_24h": "1d",
            "last_7d": "7d",
            "last_30d": "30d",
            "last_90d": "90d",
        }
        time_value = time_mapping.get(timeframe, "7d")

        if table in ["SigninLogs", "AuditLogs", "CloudAppEvents"]:
            filters.append(f"| where TimeGenerated > ago({time_value})")

        # Focus-specific filters
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

        elif focus == "multiple_users":
            # For bulk user analysis
            if table == "SigninLogs":
                filters.append('| where UserPrincipalName in ("<USER_LIST>")')

        return filters

    def _build_aggregation(self, context: Dict, table: str) -> Optional[str]:
        """Build SUMMARIZE clause if aggregation needed"""
        if not context.get("aggregation_needed", False):
            return None

        intent = context.get("intent", "")
        focus = context.get("focus", "")

        # Define aggregation patterns
        if "count_impact" in intent or "verify_count" in intent:
            # Count distinct users
            return "| summarize UserCount = dcount(UserPrincipalName), TotalSignIns = count()"

        elif focus == "user" and table == "SigninLogs":
            # Detailed user activity summary
            return (
                "| summarize SignInCount = count(), "
                "UniqueIPs = dcount(IPAddress), "
                'FailedAttempts = countif(ResultType != "0"), '
                "UniqueLocations = dcount(Location) "
                "by UserPrincipalName"
            )

        elif focus == "ip" and table == "SigninLogs":
            # IP activity summary
            return (
                "| summarize SignInAttempts = count(), "
                "UniqueUsers = dcount(UserPrincipalName), "
                'FailedLogins = countif(ResultType != "0") '
                "by IPAddress"
            )

        elif focus == "device":
            # Device compliance summary
            return (
                "| summarize DeviceSignIns = count(), "
                "UniqueUsers = dcount(UserPrincipalName) "
                "by DeviceId, IsCompliant = tostring(DeviceDetail.isCompliant)"
            )

        return None

    def _build_projection(self, context: Dict, table: str) -> Optional[str]:
        """Build PROJECT clause for specific field selection"""
        specific_fields = context.get("specific_fields", [])

        if not specific_fields:
            return None

        # Add timestamp by default
        if "TimeGenerated" not in specific_fields and table in self.valid_tables:
            specific_fields.insert(0, "TimeGenerated")

        fields_str = ", ".join(specific_fields)
        return f"| project {fields_str}"


class KQLSearchAPIClient:
    """
    Client for kqlsearch.com API integration
    """

    def __init__(self, api_url: str = "https://www.kqlsearch.com/api/querygenerator"):
        self.api_url = api_url
        self.timeout = 30

    def generate_query(self, input_text: str) -> Optional[str]:
        """
        Generate KQL query using kqlsearch.com API

        Args:
            input_text: Description of what to query

        Returns:
            KQL query string or None if failed
        """
        payload = {"input": input_text}

        try:
            print(f"   🌐 Calling kqlsearch.com API...")
            response = requests.post(self.api_url, json=payload, timeout=self.timeout)
            response.raise_for_status()

            result = response.json()

            if "content" in result:
                kql_query = result["content"]

                # Clean the query from markdown markers
                if "```kql" in kql_query:
                    kql_query = kql_query.split("```kql")[1].split("```")[0].strip()
                elif "```" in kql_query:
                    kql_query = kql_query.split("```")[1].split("```")[0].strip()

                print(f"   ✅ KQL received from API ({len(kql_query)} chars)")
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
        except json.JSONDecodeError as e:
            print(f"   ⚠️ JSON parsing error: {str(e)[:100]}")
            return None
        except Exception as e:
            print(f"   ⚠️ Unexpected error: {str(e)[:100]}")
            return None


class EnhancedKQLGenerator:
    """
    Advanced KQL Generator with dynamic query building
    Now integrates kqlsearch.com API as primary generation method
    """

    def __init__(self):
        self._init_llms()
        self.query_builder = DynamicKQLBuilder()
        self.kql_api = KQLSearchAPIClient()

        # Initialize web search
        try:
            self.web_search = SerperDevTool()
            self.has_web = True
            print("✅ Web search enabled (Serper)")
        except Exception as e:
            self.web_search = None
            self.has_web = False
            print(f"⚠️ Web search unavailable: {str(e)}")

    def _init_llms(self):
        """Initialize LLMs"""
        gemini_key = os.getenv("GOOGLE_API_KEY")
        if gemini_key:
            # ✅ USE STABLE MODEL NAME
            self.gemini_llm = LLM(
                model="gemini/gemini-2.5-flash",  # NOT gemini-2.5-flash
                api_key=gemini_key,
                temperature=0.3,
                timeout=120,
                max_retries=2,
            )
            self.primary_llm = self.gemini_llm
            print("✅ Primary LLM: Gemini 1.5 Flash")
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
        """
        Generate KQL query using multi-tier approach:
        1. Try kqlsearch.com API first
        2. Fallback to dynamic query builder
        3. Final fallback to LLM generation

        Returns:
            Tuple[kql_query, kql_explanation]
        """
        print(f"\n🔍 Generating KQL for Step {step_number}: {step_name}")

        # Step 1: Check if KQL is needed
        if not self._needs_kql(step_name, explanation):
            print("   ⏭️  No KQL needed for this step")
            return "", ""

        # Step 2: Analyze step to extract context
        step_context = self._analyze_step_context(
            step_name, explanation, step_number, rule_context
        )

        print(f"   📊 Context: {step_context.get('intent', 'unknown')}")

        # Step 3: Try kqlsearch.com API FIRST
        api_input = self._build_api_input(step_name, explanation, step_context)
        kql = self.kql_api.generate_query(api_input)

        if kql and self._validate_kql(kql):
            explanation_text = self._generate_explanation_with_llm(
                kql, step_name, explanation
            )
            print("   ✅ Generated from kqlsearch.com API")
            return kql, explanation_text

        # Step 4: Fallback to dynamic query builder
        print("   🔄 Trying dynamic query builder...")
        kql = self.query_builder.build_query(step_context)

        if kql and self._validate_kql(kql):
            explanation_text = self._generate_explanation_with_llm(
                kql, step_name, explanation
            )
            print("   ✅ Generated from dynamic builder")
            return kql, explanation_text

        # Step 5: Final fallback to LLM with better context
        print("   🔄 Trying LLM generation...")
        kql, explanation_text = self._llm_generate_with_context(
            step_name, explanation, step_number, rule_context, step_context
        )

        if kql and self._validate_kql(kql):
            print("   ✅ Generated using LLM")
            return kql, explanation_text

        print("   ⚠️  No valid KQL generated")
        return "", ""

    def _build_api_input(
        self, step_name: str, explanation: str, step_context: Dict
    ) -> str:
        """
        Build comprehensive input for kqlsearch.com API

        Args:
            step_name: Name of the investigation step
            explanation: Detailed explanation of the step
            step_context: Parsed context dictionary

        Returns:
            Formatted input string for API
        """
        # Combine step name and explanation
        base_input = f"{step_name}\t{explanation}"

        # Add context-specific details
        intent = step_context.get("intent", "")
        focus = step_context.get("focus", "")
        timeframe = step_context.get("timeframe", "last_7d")

        # Enhance with specific requirements
        enhancements = []

        if focus:
            enhancements.append(f"focus on {focus}")

        if timeframe:
            time_text = timeframe.replace("_", " ").replace("last ", "last ")
            enhancements.append(f"for {time_text}")

        if step_context.get("aggregation_needed"):
            enhancements.append("with aggregation and statistics")

        # Combine everything
        if enhancements:
            enhanced_input = f"{base_input} ({', '.join(enhancements)})"
        else:
            enhanced_input = base_input

        return enhanced_input

    def _analyze_step_context(
        self, step_name: str, explanation: str, step_number: int, rule_context: str
    ) -> Dict:
        """
        Analyze step to determine what kind of query is needed
        Returns context dict for query builder
        """
        combined = f"{step_name} {explanation} {rule_context}".lower()

        context = {
            "intent": "",
            "focus": "",
            "timeframe": "last_7d",  # Default
            "aggregation_needed": False,
            "specific_fields": [],
        }

        # Determine intent from step name/explanation
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

        elif "device" in combined or "endpoint" in combined:
            context["intent"] = "verify_device"
            context["focus"] = "device"
            context["aggregation_needed"] = True

        elif "role" in combined or "permission" in combined:
            context["intent"] = "check_role_assignment"
            context["focus"] = "role"
            context["aggregation_needed"] = False

        elif "mfa" in combined or "multi-factor" in combined:
            context["intent"] = "verify_mfa"
            context["focus"] = "user"
            context["aggregation_needed"] = True

        # Determine timeframe
        if "24" in combined or "day" in combined:
            context["timeframe"] = "last_24h"
        elif "7" in combined or "week" in combined:
            context["timeframe"] = "last_7d"
        elif "30" in combined or "month" in combined:
            context["timeframe"] = "last_30d"

        # Determine focus (multiple users vs single user)
        if step_number == 1 or "all users" in combined or "multiple" in combined:
            context["focus"] = "multiple_users"
            context["aggregation_needed"] = True

        return context

    def _needs_kql(self, step_name: str, explanation: str) -> bool:
        """Determine if step needs KQL query"""
        combined = f"{step_name} {explanation}".lower()

        # Skip these types of steps
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
            "user confirms",
            "confirmation",
            "scenarios",
            "true positive",
            "false positive",
            "get confirmation",
            "awareness",
            "training",
            "policy",
            "procedure",
            "manual",
        ]

        if any(keyword in combined for keyword in skip_keywords):
            return False

        # Needs KQL if investigating data
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
            "user activity",
            "device",
            "role",
            "permission",
            "authentication",
            "mfa",
            "location",
            "count",
            "gather",
        ]

        return any(keyword in combined for keyword in needs_keywords)

    def _generate_explanation_with_llm(
        self, kql: str, step_name: str, explanation: str
    ) -> str:
        """Generate SPECIFIC, UNIQUE KQL explanation"""

        # Extract key elements from KQL
        has_summarize = "summarize" in kql.lower()
        has_dcount = "dcount" in kql.lower()
        has_join = "join" in kql.lower()

        table = (
            "SigninLogs"
            if "signinlogs" in kql.lower()
            else (
                "AuditLogs"
                if "auditlogs" in kql.lower()
                else "DeviceInfo" if "deviceinfo" in kql.lower() else "logs"
            )
        )

        prompt = f"""Write ONE unique sentence explaining this KQL query.

    KQL: {kql[:200]}
    Step: {step_name}

    Requirements:
    - ONE sentence ONLY (max 25 words)
    - Be SPECIFIC about what's being analyzed
    - Include: data source, timeframe, aggregation type
    - NO generic phrases like "queries data" or "analyzes logs"
    - Make it UNIQUE - don't reuse explanations

    Example formats:
    âœ… "Counts distinct user accounts from SigninLogs over 7 days and groups by authentication method."
    âœ… "Aggregates failed sign-in attempts by IP address and identifies IPs with 5+ failures."
    âœ… "Joins SigninLogs with AuditLogs to correlate authentication with privilege changes."

    Generate ONE specific sentence:"""

        try:
            agent = Agent(
                role="KQL Query Explainer",
                goal="Generate one unique, specific KQL explanation",
                backstory="Expert at explaining queries concisely",
                llm=self.primary_llm,
                verbose=False,
            )

            task = Task(description=prompt, expected_output="One sentence", agent=agent)
            crew = Crew(agents=[agent], tasks=[task], verbose=False, max_rpm=5)

            result = str(crew.kickoff()).strip()
            result = self._clean_explanation(result)

            # Ensure it's one sentence
            if "." in result:
                result = result.split(".")[0] + "."

            # Fallback if too generic
            if len(result.split()) < 8 or any(
                generic in result.lower()
                for generic in ["queries data", "analyzes logs", "checks information"]
            ):
                return self._generate_explanation(kql)

            return result

        except Exception as e:
            print(f"   ⚠️ Explanation failed: {str(e)[:50]}")
            return self._generate_explanation(kql)

    def _clean_explanation(self, explanation: str) -> str:
        """Clean explanation from LLM artifacts"""
        # Remove common prefixes
        prefixes = [
            "This query",
            "The query",
            "Explanation:",
            "Output:",
            "Here's",
            "Here is",
            "The KQL",
            "This KQL",
            "Answer:",
            "Result:",
        ]

        for prefix in prefixes:
            if explanation.lower().startswith(prefix.lower()):
                explanation = explanation[len(prefix) :].strip()
                if explanation.startswith(":"):
                    explanation = explanation[1:].strip()

        # Capitalize first letter
        if explanation:
            explanation = explanation[0].upper() + explanation[1:]

        return explanation.strip()

    def _clean_explanation(self, explanation: str) -> str:
        """Clean explanation from LLM artifacts"""
        # Remove common prefixes
        prefixes = [
            "This query",
            "The query",
            "Explanation:",
            "Output:",
            "Here's",
            "Here is",
        ]

        for prefix in prefixes:
            if explanation.lower().startswith(prefix.lower()):
                explanation = explanation[len(prefix) :].strip()
                if explanation.startswith(":"):
                    explanation = explanation[1:].strip()

        return explanation.strip()

    def _llm_generate_with_context(
        self,
        step_name: str,
        explanation: str,
        step_number: int,
        rule_context: str,
        step_context: Dict,
    ) -> Tuple[str, str]:
        """Generate KQL using LLM with rich context"""
        try:
            # Build focused prompt with step context
            intent = step_context.get("intent", "investigation")
            focus = step_context.get("focus", "user")

            prompt = f"""Generate a Microsoft Sentinel KQL query for this specific step.

STEP {step_number}: {step_name}
PURPOSE: {explanation}
INTENT: {intent}
FOCUS: {focus}

REQUIREMENTS:
1. Use SigninLogs, AuditLogs, IdentityInfo, or DeviceInfo tables
2. CRITICAL: Make query UNIQUE for this specific step - do NOT reuse generic patterns
3. Use appropriate filters based on the step's focus:
   - For step {step_number}, customize the query specifically for: {step_name}
4. Use placeholders: <USER_EMAIL>, <IP_ADDRESS>, <TIMESPAN>
5. Include summarize if analyzing patterns/counts
6. Keep concise (8-15 lines)
7. No comments or explanations in the query

EXAMPLE STRUCTURE (customize based on step):
SigninLogs
| where TimeGenerated > ago(<TIMESPAN>)
| where [SPECIFIC_FILTER_FOR_THIS_STEP]
| summarize [RELEVANT_AGGREGATIONS_FOR_THIS_STEP]
| project [RELEVANT_FIELDS_FOR_THIS_STEP]

OUTPUT ONLY THE KQL QUERY:"""

            agent = Agent(
                role="Microsoft Sentinel KQL Expert",
                goal=f"Generate unique KQL query for step {step_number}: {intent}",
                backstory="Expert in writing custom KQL queries for specific investigation needs",
                llm=self.primary_llm,
                verbose=False,
            )

            task = Task(
                description=prompt,
                expected_output="Valid, unique KQL query",
                agent=agent,
            )

            crew = Crew(agents=[agent], tasks=[task], verbose=False)
            result = str(crew.kickoff())

            kql = self._deep_clean_kql(result)

            if kql and self._validate_kql(kql):
                explanation_text = self._generate_explanation_with_llm(
                    kql, step_name, explanation
                )
                return kql, explanation_text

        except Exception as e:
            print(f"   ⚠️  LLM generation failed: {str(e)[:100]}")

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
            "AADSignInEventsBeta",
        ]

        if not any(table in kql for table in valid_tables):
            return False

        kql_operators = ["where", "summarize", "project", "extend"]
        if not any(op in kql.lower() for op in kql_operators):
            return False

        return True

    def _deep_clean_kql(self, kql: str) -> str:
        """Clean KQL query aggressively"""
        if not kql:
            return ""

        # Remove markdown
        kql = re.sub(r"```kql\s*", "", kql)
        kql = re.sub(r"```\s*", "", kql)

        # Remove LLM artifacts
        artifacts = [
            "I now can give",
            "FINAL ANSWER:",
            "Here is",
            "The query",
            "KQL Query:",
            "Output:",
        ]

        for artifact in artifacts:
            if artifact in kql:
                parts = kql.split(artifact, 1)
                kql = parts[-1] if len(parts) > 1 else parts[0]

        # Clean line by line
        lines = []
        for line in kql.split("\n"):
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            if any(
                stop in line.lower() for stop in ["this query", "explanation:", "note:"]
            ):
                break
            lines.append(line)

        return "\n".join(lines).strip()

    def _generate_explanation(self, kql: str) -> str:
        """Generate SPECIFIC explanation from KQL structure"""
        kql_lower = kql.lower()

        # Identify table
        table = (
            "SigninLogs"
            if "signinlogs" in kql_lower
            else (
                "AuditLogs"
                if "auditlogs" in kql_lower
                else (
                    "DeviceInfo"
                    if "deviceinfo" in kql_lower
                    else (
                        "CloudAppEvents"
                        if "cloudappevents" in kql_lower
                        else "security logs"
                    )
                )
            )
        )

        # Identify timeframe
        if "ago(1d)" in kql_lower or "ago(24h)" in kql_lower:
            timeframe = "last 24 hours"
        elif "ago(7d)" in kql_lower:
            timeframe = "last 7 days"
        elif "ago(30d)" in kql_lower:
            timeframe = "last 30 days"
        else:
            timeframe = "specified timeframe"

        # Identify key operations
        if "dcount" in kql_lower and "userprincipalname" in kql_lower:
            action = f"Counts unique user accounts from {table} over {timeframe}"
        elif (
            "summarize" in kql_lower
            and "count()" in kql_lower
            and "ipaddress" in kql_lower
        ):
            action = f"Aggregates sign-in attempts by IP address from {table} over {timeframe}"
        elif "join" in kql_lower:
            action = f"Correlates data from multiple log sources over {timeframe}"
        elif "where" in kql_lower and "location" in kql_lower:
            action = f"Filters {table} by geographic location over {timeframe}"
        elif "where" in kql_lower and "resulttype" in kql_lower:
            action = f"Filters authentication results from {table} over {timeframe}"
        elif "oauth" in kql_lower or "grant" in kql_lower:
            action = f"Queries OAuth permission grants from {table} over {timeframe}"
        elif "failed" in kql_lower or 'resulttype != "0"' in kql_lower:
            action = f"Identifies failed authentication attempts from {table} over {timeframe}"
        elif "summarize" in kql_lower:
            action = f"Aggregates authentication data from {table} over {timeframe}"
        elif "project" in kql_lower:
            action = f"Extracts specific fields from {table} over {timeframe}"
        else:
            action = f"Queries {table} data over {timeframe}"

        return f"{action}."
