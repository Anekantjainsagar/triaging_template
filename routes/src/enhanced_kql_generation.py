"""
Enhanced KQL Query Generator with Web Research and LLM Generation
Uses Serper for web search, Gemini/Ollama for generation, and strict validation
"""

import re
import os
from typing import Optional, Tuple, Dict, List
from crewai import LLM, Agent, Task, Crew
from crewai_tools import SerperDevTool
from dotenv import load_dotenv
import time

load_dotenv()


class EnhancedKQLGenerator:
    """
    Advanced KQL Generator with:
    1. Web search for real-world examples
    2. Multi-LLM support (Gemini + Ollama)
    3. Strict validation and cleaning
    4. Context-aware generation
    5. Smart step classification (investigative vs verification/closure)
    """

    def __init__(self):
        # Initialize LLMs
        self._init_llms()

        # Initialize web search
        try:
            self.web_search = SerperDevTool()
            self.has_web = True
            print("✅ Web search enabled (Serper)")
        except Exception as e:
            self.web_search = None
            self.has_web = False
            print(f"⚠️ Web search unavailable: {str(e)}")

        # KQL validation patterns
        self.valid_tables = [
            "SigninLogs",
            "AuditLogs",
            "IdentityInfo",
            "ThreatIntelligenceIndicator",
            "SecurityIncident",
            "DeviceInfo",
            "SecurityAlert",
            "OfficeActivity",
            "AADSignInEventsBeta",
            "CloudAppEvents",
        ]

        self.kql_operators = [
            "where",
            "extend",
            "project",
            "summarize",
            "join",
            "union",
            "let",
            "make_set",
            "make_list",
            "dcount",
            "count",
            "countif",
            "bin",
            "ago",
            "now",
            "between",
        ]

    def _init_llms(self):
        """Initialize multiple LLMs for fallback"""
        # Primary: Gemini (better for structured output)
        gemini_key = os.getenv("GOOGLE_API_KEY")
        if gemini_key:
            self.gemini_llm = LLM(
                model="gemini/gemini-1.5-flash", api_key=gemini_key, temperature=0.3
            )
            self.primary_llm = self.gemini_llm
            print("✅ Primary LLM: Gemini 1.5 Flash")
        else:
            self.gemini_llm = None
            print("⚠️ Gemini API key not found")

        # Fallback: Ollama (local)
        ollama_model = os.getenv("OLLAMA_CHAT", "ollama/qwen2.5:3b")
        if not ollama_model.startswith("ollama/"):
            ollama_model = f"ollama/{ollama_model}"

        self.ollama_llm = LLM(
            model=ollama_model, base_url="http://localhost:11434", temperature=0.3
        )

        if not self.gemini_llm:
            self.primary_llm = self.ollama_llm
            print(f"✅ Primary LLM: {ollama_model}")
        else:
            print(f"✅ Fallback LLM: {ollama_model}")

    def is_investigative_step(
        self, step_name: str, explanation: str, step_number: int
    ) -> bool:
        """
        🎯 CORE CLASSIFICATION: Determine if step is investigative or verification/closure

        Returns:
            True if step involves actual investigation (data gathering)
            False if step is verification, decision-making, or administrative
        """
        combined = f"{step_name} {explanation}".lower()

        # ❌ SKIP: Verification/Decision Steps (IF/THEN logic)
        verification_patterns = [
            # User confirmation scenarios
            "if user confirms",
            "if user says",
            "user confirmation",
            "get confirmation",
            "user says they are not aware",
            "user says no",
            "user says yes",
            "based on the investigation",
            "if you still find it suspicious",
            # True/False positive classification
            "true positive",
            "false positive",
            "treat it as",
            "close it as",
            "classify as",
            # Conditional logic
            "if malicious",
            "if suspicious",
            "if clean",
            "then close",
            "then treat",
            # Decision points
            "scenarios",
            "confirmation received",
        ]

        if any(pattern in combined for pattern in verification_patterns):
            print(f"   ⏭️  Step {step_number}: VERIFICATION/DECISION - Skipping")
            return False

        # ❌ SKIP: Administrative/Closure Actions
        admin_patterns = [
            # Communication actions
            "inform",
            "notify",
            "reach out",
            "contact",
            "escalate to",
            "send email",
            "alert team",
            # Remediation actions
            "reset password",
            "disable account",
            "revoke token",
            "block ip",
            "reset the account",
            "temporary disable",
            # Closure activities
            "close incident",
            "track for closer",
            "closer confirmation",
            "document the steps",
            "document findings",
            "after all the investigation",
            # Reporting
            "create report",
            "generate ticket",
            "update documentation",
        ]

        if any(pattern in combined for pattern in admin_patterns):
            print(f"   ⏭️  Step {step_number}: ADMINISTRATIVE - Skipping")
            return False

        # ❌ SKIP: Generic/Non-Technical Steps
        generic_patterns = [
            "awareness",
            "training",
            "policy",
            "procedure",
            "guideline",
        ]

        if any(pattern in combined for pattern in generic_patterns):
            print(f"   ⏭️  Step {step_number}: NON-TECHNICAL - Skipping")
            return False

        # ✅ INCLUDE: Data Investigation Steps
        investigation_patterns = [
            # Data gathering
            "gather details",
            "collect information",
            "extract data",
            "pull logs",
            # Data analysis
            "check",
            "verify",
            "review",
            "analyze",
            "investigate",
            "examine",
            "inspect",
            "validate",
            "assess",
            # Specific data sources
            "sign-in logs",
            "signin logs",
            "audit logs",
            "authentication logs",
            "activity logs",
            # Technical checks
            "run kql",
            "query",
            "search logs",
            "filter events",
            # Specific investigations
            "ip address",
            "ip reputation",
            "user activity",
            "device info",
            "location",
            "geo location",
            "user agent",
            "authentication",
            "mfa",
            "role",
            "permission",
            "login patterns",
            "failed attempts",
            # Threat intelligence
            "virustotal",
            "virus total",
            "threat intelligence",
            "reputation check",
        ]

        is_investigative = any(
            pattern in combined for pattern in investigation_patterns
        )

        if is_investigative:
            print(f"   ✅ Step {step_number}: INVESTIGATIVE - Including")
        else:
            print(f"   ⏭️  Step {step_number}: UNCLEAR - Skipping by default")

        return is_investigative

    def generate_kql_query(
        self, step_name: str, explanation: str, step_number: int, rule_context: str = ""
    ) -> Tuple[str, str]:
        """
        Generate KQL query using multi-strategy approach

        Returns:
            Tuple[kql_query, kql_explanation]
        """
        print(f"\n🔍 Generating KQL for Step {step_number}: {step_name}")

        # Strategy 1: Check if this is even an investigative step
        if not self.is_investigative_step(step_name, explanation, step_number):
            return "", ""

        # Strategy 2: Check if KQL is specifically needed (some steps are investigative but manual)
        if not self._needs_kql(step_name, explanation):
            print("   ⏭️  No KQL needed for this step (manual investigation)")
            return "", ""

        # Strategy 3: Web search for real examples
        if self.has_web:
            kql, explanation = self._search_and_generate(
                step_name, explanation, rule_context
            )
            if kql and self._validate_kql(kql):
                print("   ✅ Generated from web research")
                return kql, explanation

        # Strategy 4: LLM generation with context
        kql, explanation = self._llm_generate_with_context(
            step_name, explanation, step_number, rule_context
        )
        if kql and self._validate_kql(kql):
            print("   ✅ Generated using LLM")
            return kql, explanation

        # Strategy 5: Template-based fallback
        kql, explanation = self._template_based_generation(step_name, explanation)
        if kql:
            print("   ✅ Generated from template")
            return kql, explanation

        print("   ⚠️  No valid KQL generated")
        return "", ""

    def _needs_kql(self, step_name: str, explanation: str) -> bool:
        """
        Determine if investigative step needs KQL query (vs manual investigation)

        This is called AFTER is_investigative_step() confirms it's investigative
        """
        combined = f"{step_name} {explanation}".lower()

        # Some investigative steps are MANUAL (e.g., VirusTotal, VIP list checks)
        manual_investigation_patterns = [
            "virustotal",
            "virus total",
            "vip list",
            "vip user",
            "cross-check",
            "cross check",
            "validate against",
            "compare with",
        ]

        # If it's a manual investigation, no KQL needed
        if any(pattern in combined for pattern in manual_investigation_patterns):
            return False

        # Otherwise, if it's investigative and mentions data sources, it needs KQL
        needs_kql_patterns = [
            "sign-in",
            "signin",
            "login",
            "audit",
            "logs",
            "query",
            "kql",
            "sentinel",
        ]

        return any(pattern in combined for pattern in needs_kql_patterns)

    def _search_and_generate(
        self, step_name: str, explanation: str, context: str
    ) -> Tuple[str, str]:
        """Search web for KQL examples and generate query"""
        try:
            # Construct focused search query
            search_terms = self._extract_key_terms(step_name, explanation)
            search_query = f"Microsoft Sentinel KQL query {search_terms} site:learn.microsoft.com OR site:github.com"

            print(f"   🌐 Searching: {search_query[:80]}...")

            # Create search agent
            search_agent = Agent(
                role="KQL Security Researcher",
                goal="Find relevant Microsoft Sentinel KQL query examples",
                backstory="Expert in finding and adapting security queries from Microsoft documentation",
                llm=self.primary_llm,
                tools=[self.web_search],
                verbose=False,
            )

            search_task = Task(
                description=f"""
Search for Microsoft Sentinel KQL query examples for: {step_name}

Context: {explanation}

Find queries that:
1. Use Microsoft Sentinel tables (SigninLogs, AuditLogs, etc.)
2. Are relevant to: {search_terms}
3. Include proper operators (where, extend, project, summarize)
4. Can be adapted for security investigation

Return the most relevant KQL example found.
""",
                expected_output="KQL query example with explanation",
                agent=search_agent,
            )

            crew = Crew(agents=[search_agent], tasks=[search_task], verbose=False)

            result = str(crew.kickoff())

            # Extract and adapt KQL from search results
            kql = self._extract_kql_from_text(result)
            if kql:
                # Adapt the found query to the specific step
                adapted_kql = self._adapt_kql_to_step(kql, step_name, explanation)
                if adapted_kql:
                    kql_explanation = self._generate_explanation(adapted_kql)
                    return adapted_kql, kql_explanation

        except Exception as e:
            print(f"   ⚠️  Web search failed: {str(e)[:100]}")

        return "", ""

    def _extract_key_terms(self, step_name: str, explanation: str) -> str:
        """Extract key terms for focused search"""
        combined = f"{step_name} {explanation}".lower()

        # Key term mappings
        term_patterns = {
            "sign-in": ["signin", "login", "authentication"],
            "role": ["role assignment", "privileged role", "rbac"],
            "ip": ["ip address", "ip reputation", "source ip"],
            "user": ["user activity", "user behavior", "account"],
            "mfa": ["multi-factor", "mfa", "authentication method"],
            "device": ["device compliance", "endpoint", "device info"],
            "audit": ["audit logs", "administrative actions"],
            "location": ["geographic location", "impossible travel"],
        }

        found_terms = []
        for category, terms in term_patterns.items():
            if any(term in combined for term in terms):
                found_terms.append(category)

        return " ".join(found_terms[:3]) if found_terms else "security investigation"

    def _extract_kql_from_text(self, text: str) -> Optional[str]:
        """Extract KQL query from text/markdown"""
        # Try to find code blocks
        patterns = [
            r"```kql\s*(.*?)```",
            r"```kusto\s*(.*?)```",
            r"```\s*(SigninLogs|AuditLogs.*?)```",
        ]

        for pattern in patterns:
            matches = re.findall(pattern, text, re.DOTALL | re.IGNORECASE)
            if matches:
                kql = matches[0].strip()
                if self._contains_valid_table(kql):
                    return kql

        # Try to find queries without code blocks
        for table in self.valid_tables:
            if table in text:
                # Extract from table name to end of logical query
                start = text.find(table)
                end = start + 2000  # Reasonable query length
                potential_kql = text[start:end]

                # Find end of query (before explanation text)
                end_markers = [
                    "\n\nThis query",
                    "\n\nExplanation:",
                    "\n\nNote:",
                    "\n\n##",
                    "\n\nOutput:",
                ]
                for marker in end_markers:
                    if marker in potential_kql:
                        potential_kql = potential_kql[: potential_kql.find(marker)]

                if self._contains_valid_table(potential_kql):
                    return potential_kql.strip()

        return None

    def _adapt_kql_to_step(
        self, base_kql: str, step_name: str, explanation: str
    ) -> Optional[str]:
        """Adapt found KQL to specific step requirements"""
        try:
            prompt = f"""Adapt this KQL query for the specific investigation step.

BASE QUERY:
{base_kql}

TARGET STEP: {step_name}
REQUIREMENTS: {explanation}

INSTRUCTIONS:
1. Keep the core query structure
2. Adapt filters and conditions for this specific step
3. Use placeholders: <USER_EMAIL>, <IP_ADDRESS>, <TIMESPAN>, <DEVICE_ID>
4. Ensure query is concise (max 15 lines)
5. Remove any explanatory comments
6. Make it ready to run in Microsoft Sentinel

OUTPUT ONLY THE ADAPTED KQL QUERY, NO EXPLANATIONS:"""

            agent = Agent(
                role="KQL Adaptation Expert",
                goal="Adapt KQL queries to specific investigation needs",
                backstory="Expert in modifying KQL queries for security investigations",
                llm=self.primary_llm,
                verbose=False,
            )

            task = Task(
                description=prompt, expected_output="Adapted KQL query", agent=agent
            )

            crew = Crew(agents=[agent], tasks=[task], verbose=False)
            result = str(crew.kickoff())

            # Clean the result
            adapted = self._deep_clean_kql(result)
            return adapted if len(adapted) > 20 else None

        except Exception as e:
            print(f"   ⚠️  Adaptation failed: {str(e)[:50]}")
            return None

    def _llm_generate_with_context(
        self, step_name: str, explanation: str, step_number: int, context: str
    ) -> Tuple[str, str]:
        """Generate KQL using LLM with rich context"""
        try:
            # Determine query type and provide examples
            query_type = self._determine_query_type(step_name, explanation)
            examples = self._get_relevant_examples(query_type)

            prompt = f"""Generate a Microsoft Sentinel KQL query for this security investigation step.

STEP {step_number}: {step_name}
PURPOSE: {explanation}
RULE CONTEXT: {context}
QUERY TYPE: {query_type}

REFERENCE EXAMPLES:
{examples}

REQUIREMENTS:
1. Use ONLY these tables: {', '.join(self.valid_tables[:5])}
2. Use these operators: where, extend, project, summarize, join
3. Use placeholders: <USER_EMAIL>, <IP_ADDRESS>, <TIMESPAN>, <DEVICE_ID>
4. Keep query concise (8-15 lines maximum)
5. Focus on security investigation data
6. No comments or explanations in the query
7. Make it executable in Microsoft Sentinel

IMPORTANT: Output ONLY the KQL query, nothing else. No markdown, no explanations.

KQL Query:"""

            agent = Agent(
                role="Microsoft Sentinel KQL Expert",
                goal="Generate accurate KQL queries for security investigations",
                backstory="10+ years experience writing KQL queries for Microsoft Sentinel",
                llm=self.primary_llm,
                verbose=False,
            )

            task = Task(
                description=prompt, expected_output="Valid KQL query", agent=agent
            )

            crew = Crew(agents=[agent], tasks=[task], verbose=False)
            result = str(crew.kickoff())

            # Clean and validate
            kql = self._deep_clean_kql(result)

            if kql and self._validate_kql(kql):
                explanation = self._generate_explanation(kql)
                return kql, explanation

        except Exception as e:
            print(f"   ⚠️  LLM generation failed: {str(e)[:100]}")

        return "", ""

    def _determine_query_type(self, step_name: str, explanation: str) -> str:
        """Determine the type of query needed"""
        combined = f"{step_name} {explanation}".lower()

        if "sign-in" in combined or "login" in combined:
            return "user_authentication"
        elif "role" in combined or "permission" in combined:
            return "role_assignment"
        elif "ip" in combined and "reputation" in combined:
            return "ip_analysis"
        elif "device" in combined or "endpoint" in combined:
            return "device_compliance"
        elif "mfa" in combined or "multi-factor" in combined:
            return "mfa_verification"
        elif "audit" in combined:
            return "audit_trail"
        elif "location" in combined or "geographic" in combined:
            return "location_analysis"
        else:
            return "general_investigation"

    def _get_relevant_examples(self, query_type: str) -> str:
        """Get relevant KQL examples for the query type"""
        examples = {
            "user_authentication": """SigninLogs
| where UserPrincipalName == "<USER_EMAIL>"
| where TimeGenerated > ago(<TIMESPAN>)
| summarize SignInCount = count(), UniqueIPs = dcount(IPAddress), FailedAttempts = countif(ResultType != "0")
  by UserPrincipalName""",
            "role_assignment": """AuditLogs
| where OperationName == "Add member to role"
| where TimeGenerated > ago(<TIMESPAN>)
| extend RoleName = tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[1].newValue)
| project TimeGenerated, RoleName, InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)""",
            "ip_analysis": """SigninLogs
| where IPAddress == "<IP_ADDRESS>"
| where TimeGenerated > ago(<TIMESPAN>)
| summarize SignInAttempts = count(), UniqueUsers = dcount(UserPrincipalName)
  by IPAddress""",
            "device_compliance": """SigninLogs
| where UserPrincipalName == "<USER_EMAIL>"
| extend DeviceId = tostring(DeviceDetail.deviceId)
| extend IsCompliant = tostring(DeviceDetail.isCompliant)
| summarize by DeviceId, IsCompliant""",
            "mfa_verification": """SigninLogs
| where UserPrincipalName == "<USER_EMAIL>"
| extend MFAResult = tostring(AuthenticationDetails[0].succeeded)
| summarize MFASuccess = countif(MFAResult == "true"), MFAFailures = countif(MFAResult == "false")
  by UserPrincipalName""",
        }

        return examples.get(query_type, examples["user_authentication"])

    def _template_based_generation(
        self, step_name: str, explanation: str
    ) -> Tuple[str, str]:
        """Generate KQL from templates as last resort"""
        query_type = self._determine_query_type(step_name, explanation)
        template = self._get_relevant_examples(query_type)

        if template:
            explanation = self._generate_explanation(template)
            return template, explanation

        return "", ""

    def _validate_kql(self, kql: str) -> bool:
        """Strict KQL validation"""
        if not kql or len(kql) < 20:
            return False

        # Must contain at least one valid table
        if not self._contains_valid_table(kql):
            print("   ❌ No valid table found")
            return False

        # Must contain at least one operator
        if not any(op in kql.lower() for op in self.kql_operators):
            print("   ❌ No valid KQL operators")
            return False

        # Should not be too long
        if len(kql) > 1500:
            print("   ❌ Query too long")
            return False

        # Should not contain artifacts
        artifacts = [
            "I now can give",
            "FINAL ANSWER",
            "Here is",
            "The query",
            "Explanation:",
            "Note:",
        ]
        if any(artifact in kql for artifact in artifacts):
            print("   ❌ Contains artifacts")
            return False

        return True

    def _contains_valid_table(self, kql: str) -> bool:
        """Check if KQL contains valid Sentinel table"""
        return any(table in kql for table in self.valid_tables)

    def _deep_clean_kql(self, kql: str) -> str:
        """Aggressively clean KQL query"""
        if not kql:
            return ""

        # Remove markdown
        kql = re.sub(r"```kql\s*", "", kql)
        kql = re.sub(r"```kusto\s*", "", kql)
        kql = re.sub(r"```\s*", "", kql)

        # Remove LLM artifacts
        artifacts = [
            "I now can give",
            "FINAL ANSWER:",
            "Final Answer:",
            "Here is the",
            "Here's the",
            "The query",
            "This query",
            "KQL Query:",
            "Query:",
            "Output:",
            "Result:",
        ]

        for artifact in artifacts:
            if artifact in kql:
                parts = kql.split(artifact, 1)
                kql = parts[-1] if len(parts) > 1 else parts[0]

        # Clean line by line
        lines = []
        in_query = False

        for line in kql.split("\n"):
            line = line.strip()

            # Skip empty lines
            if not line:
                continue

            # Start of query (contains table name)
            if any(table in line for table in self.valid_tables):
                in_query = True

            if not in_query:
                continue

            # Skip comment lines
            if line.startswith("//") or line.startswith("#"):
                continue

            # Remove inline comments
            if "//" in line:
                line = line.split("//")[0].strip()

            # Stop at explanation text
            stop_phrases = [
                "this query",
                "explanation:",
                "note:",
                "output:",
                "the above",
                "result:",
                "aggregates",
                "queries",
            ]
            if any(phrase in line.lower() for phrase in stop_phrases):
                break

            lines.append(line)

        kql = "\n".join(lines)

        # Replace hardcoded values with placeholders
        kql = re.sub(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "<USER_EMAIL>", kql
        )
        kql = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<IP_ADDRESS>", kql)
        kql = re.sub(r"ago\(\d+[dhm]\)", "ago(<TIMESPAN>)", kql)

        return kql.strip()

    def _generate_explanation(self, kql: str) -> str:
        """Generate concise explanation from KQL structure"""
        kql_lower = kql.lower()

        # Detect table
        table = next((t for t in self.valid_tables if t in kql), "logs")

        # Detect operations
        operations = []
        if "summarize" in kql_lower:
            operations.append("aggregates data")
        if "join" in kql_lower:
            operations.append("correlates multiple sources")
        if "extend" in kql_lower:
            operations.append("enriches with additional fields")
        if "project" in kql_lower:
            operations.append("selects specific columns")

        # Build explanation
        if "signinlogs" in kql_lower:
            base = "Queries sign-in activity"
        elif "auditlogs" in kql_lower:
            base = "Queries administrative actions"
        elif "identityinfo" in kql_lower:
            base = "Retrieves user identity information"
        elif "threatintelligence" in kql_lower:
            base = "Checks against threat intelligence"
        else:
            base = f"Queries {table}"

        if operations:
            return f"{base}, {' and '.join(operations)}."
        else:
            return f"{base} for investigation."


# Compatibility wrapper for existing code
class DynamicKQLGenerator(EnhancedKQLGenerator):
    """Wrapper to maintain backward compatibility"""

    pass
