import re
from typing import Optional, Dict, Tuple
from routes.src.hardcode_kql_queries import KQLQueryManager


class EnhancedKQLGenerator:
    def __init__(self):
        # Initialize query manager with API fallback enabled
        self.query_manager = KQLQueryManager(enable_api_fallback=True)
        print("✅ KQL Generator initialized with hardcoded queries + API fallback")

    def _deduplicate_queries_in_template(self, template_rows: list) -> list:
        """
        Remove rows with duplicate KQL queries (post-generation deduplication)

        Args:
            template_rows: List of template row dictionaries

        Returns:
            Deduplicated list of template rows
        """
        from difflib import SequenceMatcher

        print("\n   🧹 Post-generation KQL deduplication...")

        seen_queries = {}
        deduplicated = []
        removed_count = 0

        for row in template_rows:
            kql = row.get("kql_query", "").strip()
            step_name = row.get("step_name", "")

            # Always keep steps without KQL (header, external tools)
            if not kql or len(kql) < 30:
                deduplicated.append(row)
                continue

            # Normalize KQL for comparison
            normalized = re.sub(r"\s+", " ", kql.lower())
            normalized = re.sub(r"//.*", "", normalized)  # Remove comments

            # Check against all previously seen queries
            is_duplicate = False
            duplicate_of = None

            for seen_step, seen_query in seen_queries.items():
                similarity = SequenceMatcher(None, normalized, seen_query).ratio()

                # If 85%+ similar, consider duplicate
                if similarity > 0.85:
                    is_duplicate = True
                    duplicate_of = seen_step
                    break

            if not is_duplicate:
                seen_queries[step_name] = normalized
                deduplicated.append(row)
            else:
                print(f"      ⏭️  Removed duplicate: '{step_name[:60]}'")
                print(f"         (duplicates: '{duplicate_of[:60]}')")
                removed_count += 1

        print(f"   ✅ Removed {removed_count} duplicate KQL queries")
        return deduplicated

    def generate_kql_query(
        self, step_name: str, explanation: str, rule_context: str = ""
    ) -> Tuple[str, str]:
        """
        Generate KQL query for investigation step

        Args:
            step_name: Name of the investigation step
            explanation: Detailed explanation of what to check
            rule_context: Additional context about the alert/rule

        Returns:
            Tuple of (kql_query, kql_explanation)
        """

        # Check if this step needs KQL
        if not self._needs_kql(step_name, explanation):
            return "", ""

        # Extract intent and focus from step context
        intent = self._extract_intent(step_name, explanation)
        focus = self._extract_focus(step_name, explanation)

        print(f"   🔍 Query intent: {intent} | Focus: {focus}")

        # Get appropriate query from manager
        kql_query, source = self.query_manager.get_query(
            query_type=intent, use_fallback=True  # Use API if no hardcoded query found
        )

        if kql_query and len(kql_query.strip()) > 30:
            # Generate explanation based on query content
            explanation_text = self._generate_explanation(kql_query, step_name, source)

            print(f"   ✅ Query retrieved from: {source.upper()}")
            return kql_query, explanation_text

        # If all fails, return empty
        print(f"   ⚠️ No KQL query found for: {step_name[:60]}")
        return "", ""

    def _extract_intent(self, step_name: str, explanation: str) -> str:
        """
        Extract investigation intent from step context with STRICTER matching

        Returns intent keyword that maps to hardcoded query types
        """
        combined = f"{step_name} {explanation}".lower()

        # ✅ PRIORITY ORDER: More specific intents first to avoid false matches

        # 1. VIP/Executive (HIGHEST PRIORITY - very specific)
        if any(
            kw in combined
            for kw in [
                "vip",
                "executive",
                "high-priority",
                "high priority",
                "privileged account",
                "account status",
                "account is vip",
            ]
        ):
            return "vip_verification"

        # 2. Geographic/Travel (HIGH PRIORITY - specific keywords)
        if any(
            kw in combined
            for kw in [
                "geographic",
                "geography",
                "impossible travel",
                "travel analysis",
                "location analysis",
                "geo",
                "unusual location",
            ]
        ):
            return "geographic"

        # 3. IP Intelligence (HIGH PRIORITY - specific)
        if any(
            kw in combined
            for kw in [
                "ip threat",
                "ip reputation",
                "source ip reputation",
                "threat intelligence",
                "ip analysis",
                "lookup of source ip",
            ]
        ):
            return "ip_threat"

        # 4. Authentication (MEDIUM PRIORITY - check for auth-specific terms)
        if any(
            kw in combined
            for kw in [
                "authentication pattern",
                "auth method",
                "authentication requirement",
                "client app",
                "browser",
                "legacy auth",
                "mfa detail",
            ]
        ):
            return "auth_method"

        # 5. Behavioral/Post-Compromise (MEDIUM PRIORITY - specific activity analysis)
        if any(
            kw in combined
            for kw in [
                "behavioral",
                "behavior analysis",
                "post-compromise",
                "post-login activity",
                "anomaly",
                "unusual activity",
                "activity pattern",
                "auditlogs",
                "post sign-in",
            ]
        ):
            return "behavioral"

        # 6. Device/Endpoint (MEDIUM PRIORITY)
        if any(
            kw in combined
            for kw in [
                "device health",
                "endpoint health",
                "compliance",
                "device detail",
                "managed device",
                "compliant device",
            ]
        ):
            return "device_health"

        # 7. MFA Configuration (MEDIUM PRIORITY)
        if any(
            kw in combined
            for kw in [
                "mfa config",
                "multi-factor configuration",
                "multifactor",
                "mfa status",
                "security config",
            ]
        ):
            return "mfa_config"

        # 8. Permissions/Roles (MEDIUM PRIORITY)
        if any(
            kw in combined
            for kw in [
                "role assignment",
                "permission",
                "privilege escalation",
                "oauth",
                "consent",
                "grant",
            ]
        ):
            return "role_permission"

        # 9. Conditional Access (LOW PRIORITY)
        if any(
            kw in combined
            for kw in [
                "conditional access",
                "ca policy",
                "policy evaluation",
                "blocked",
            ]
        ):
            return "conditional_access"

        # 10. Failed Sign-ins (LOW PRIORITY)
        if any(
            kw in combined
            for kw in [
                "failed signin",
                "failed login",
                "failure",
                "error code",
                "failed attempt",
            ]
        ):
            return "failed_signin"

        # 11. Application Access (LOW PRIORITY)
        if any(
            kw in combined
            for kw in [
                "application access",
                "app access",
                "risky app",
                "application usage",
            ]
        ):
            return "application_access"

        # 12. Risky Sign-ins (LOW PRIORITY)
        if any(
            kw in combined for kw in ["risky signin", "high risk signin", "risk level"]
        ):
            return "risky_signin"

        # 13. Scope Analysis (LAST RESORT - only if explicitly mentioned)
        if any(
            kw in combined
            for kw in [
                "scope verification",
                "affected users",
                "impact assessment",
                "count users",
                "total number",
            ]
        ):
            return "initial_scope"

        # ✅ FALLBACK: If no specific match, try to infer from general context
        # Use API fallback for truly unique queries
        print(f"   ⚠️  No specific intent match for: {step_name[:60]}")
        return step_name  # Return step name itself to trigger API fallback

    def _extract_focus(self, step_name: str, explanation: str) -> str:
        """
        Extract focus area from step context
        Used for logging and secondary intent detection
        """
        combined = f"{step_name} {explanation}".lower()

        if any(kw in combined for kw in ["device", "endpoint", "compliance"]):
            return "device"
        elif any(kw in combined for kw in ["mfa", "config", "configuration"]):
            return "account_config"
        elif any(
            kw in combined for kw in ["geographic", "location", "travel", "country"]
        ):
            return "location"
        elif any(kw in combined for kw in ["behavior", "anomaly", "pattern"]):
            return "behavior"
        elif any(kw in combined for kw in ["ip", "address", "source"]):
            return "ip"
        elif any(kw in combined for kw in ["application", "app", "access"]):
            return "application"
        elif any(kw in combined for kw in ["role", "permission", "privilege"]):
            return "permission"

        return "user"

    def _needs_kql(self, step_name: str, explanation: str) -> bool:
        """
        Determine if step needs KQL query

        Returns False for:
        - External tool steps (VirusTotal, AbuseIPDB)
        - Manual investigation steps
        - Reporting/closure steps
        """
        combined = f"{step_name} {explanation}".lower()

        # ❌ Skip external tools and manual steps
        skip_keywords = [
            "virustotal",
            "virus total",
            "abuseipdb",
            "abuse ipdb",
            "abuse",
            "document",
            "close incident",
            "escalate",
            "inform",
            "notify",
            "report",
            "classify",
            "manual investigation",
            "manually check",
        ]

        if any(keyword in combined for keyword in skip_keywords):
            return False

        # ✅ Include data investigation types
        needs_keywords = [
            "sign-in",
            "signin",
            "login",
            "audit",
            "logs",
            "query",
            "check user",
            "verify user",
            "review",
            "analyze",
            "investigate",
            "count",
            "gather",
            "extract",
            "device",
            "endpoint",
            "role",
            "permission",
            "assignment",
            "group",
            "membership",
            "mfa",
            "authentication",
            "location",
            "oauth",
            "grant",
            "ip address",
            "behavior",
            "anomaly",
            "activity",
            "access",
            "application",
            "failed",
            "risky",
        ]

        return any(keyword in combined for keyword in needs_keywords)

    def _generate_explanation(self, kql: str, step_name: str, source: str) -> str:
        """
        Generate concise explanation for the KQL query

        Args:
            kql: The KQL query string
            step_name: Name of the investigation step
            source: Source of query ("hardcoded" or "api")
        """
        # Determine table being queried
        table = (
            "SigninLogs"
            if "signinlogs" in kql.lower()
            else "AuditLogs" if "auditlogs" in kql.lower() else "Unknown"
        )

        # Identify key operations
        operations = []
        if "summarize" in kql.lower():
            operations.append("aggregates data")
        if "extend" in kql.lower():
            operations.append("enriches fields")
        if "project" in kql.lower():
            operations.append("formats output")
        if "order by" in kql.lower():
            operations.append("ranks results")

        ops_text = ", ".join(operations) if operations else "queries data"

        # Build explanation
        explanation = (
            f"This query {ops_text} from {table} to analyze {step_name.lower()}."
        )

        # Add source context for API-generated queries
        if source == "api":
            explanation += " (AI-generated query with placeholder injection)"

        return explanation

    def get_available_query_types(self):
        """
        Get list of all available hardcoded query types

        Returns:
            Dictionary of query types and descriptions
        """
        return self.query_manager.list_available_queries()
