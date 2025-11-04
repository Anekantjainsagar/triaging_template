import re
from datetime import datetime
from typing import Optional, Tuple
from routes.src.hardcode_kql_queries import KQLQueryManager
from routes.src.kql_query_standardizer import KQLQueryStandardizer


class EnhancedKQLGenerator:
    def __init__(self, enable_standardization: bool = True):
        # Initialize query manager with API fallback enabled
        self.query_manager = KQLQueryManager(enable_api_fallback=True)
        print("✅ KQL Generator initialized with hardcoded queries + API fallback")

        # Initialize standardizer (only for AI-generated queries)
        self.enable_standardization = enable_standardization
        if enable_standardization:
            self.standardizer = KQLQueryStandardizer()
            print("✅ KQL Standardization enabled (for AI-generated queries only)")

    def _deduplicate_queries_in_template(self, template_rows: list) -> list:
        from difflib import SequenceMatcher

        print("\n   Deduplicating KQL queries...")

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
                print(f"      Removed duplicate: '{step_name[:60]}'")
                print(f"         (duplicates: '{duplicate_of[:60]}')")
                removed_count += 1

        print(f"   âœ… Removed {removed_count} duplicate KQL queries")
        return deduplicated

    def generate_kql_query(
        self,
        step_name: str,
        explanation: str,
        rule_context: str = "",
        reference_datetime_obj: Optional[datetime] = None,
    ) -> Tuple[str, str]:
        """
        Generate KQL query for investigation step

        CRITICAL CHANGE:
        - Hardcoded queries: Return AS-IS (no standardization)
        - AI-generated queries: Apply standardization if enabled
        - Data injection: Happens later via TemplateKQLInjector
        """

        # Check if this step needs KQL
        if not self._needs_kql(step_name, explanation):
            return "", ""

        # Extract intent and focus from step context
        intent = self._extract_intent(step_name, explanation)
        focus = self._extract_focus(step_name, explanation)

        print(f"   Query intent: {intent} | Focus: {focus}")

        # Try to get query from hardcoded manager first
        kql_query, source = self.query_manager.get_query(
            query_type=intent, use_fallback=False  # ⭐ Don't fallback yet
        )

        # =====================================================
        # CASE 1: Hardcoded query found
        # =====================================================
        if kql_query and len(kql_query.strip()) > 30 and source == "hardcoded":
            print(f"   ✅ Using hardcoded query (NO standardization needed)")

            # Return hardcoded query AS-IS with explanation
            explanation_text = self._generate_explanation(kql_query, step_name, source)
            return kql_query, explanation_text

        # =====================================================
        # CASE 2: No hardcoded query, try API fallback
        # =====================================================
        print(f"   ℹ️  No hardcoded query, attempting API fallback...")

        kql_query, source = self.query_manager.get_query(
            query_type=intent, use_fallback=True  # ⭐ Now try API
        )

        if kql_query and len(kql_query.strip()) > 30:
            # API-generated query - apply standardization
            if self.enable_standardization:
                print(f"   🔧 Standardizing API-generated query...")

                kql_query, standardized_explanation = (
                    self.standardizer.standardize_query(
                        raw_kql=kql_query,
                        query_intent=f"{step_name} {explanation}",
                        reference_datetime_obj=reference_datetime_obj,
                    )
                )

                # Validate standardized query
                is_valid, reason = KQLQueryStandardizer.validate_standardized_query(
                    kql_query
                )
                if is_valid:
                    print(f"   ✅ Query standardized and validated")
                    return kql_query, standardized_explanation
                else:
                    print(f"   ⚠️  Standardization validation failed: {reason}")
                    explanation_text = self._generate_explanation(
                        kql_query, step_name, source
                    )
                    return kql_query, explanation_text
            else:
                # Return API query without standardization
                explanation_text = self._generate_explanation(
                    kql_query, step_name, source
                )
                return kql_query, explanation_text

        # =====================================================
        # CASE 3: No query found at all
        # =====================================================
        print(f"   ⚠️  No KQL query found for: {step_name[:60]}")
        return "", ""

    def _extract_intent(self, step_name: str, explanation: str) -> str:
        """Extract intent from step context"""
        combined = f"{step_name} {explanation}".lower()

        # 1. VIP/Executive (HIGHEST PRIORITY)
        vip_keywords = [
            "vip",
            "executive",
            "high-priority",
            "high priority",
            "privileged account",
            "account status",
            "verify user account status",
            "check if account is vip",
            "vip or high-priority",
        ]

        if any(kw in combined for kw in vip_keywords):
            print(f"   ✅ VIP intent detected")
            return "vip_verification"

        # 2. Geographic/Travel (HIGH PRIORITY)
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

        # 3. IP Intelligence (HIGH PRIORITY)
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

        # 4. Authentication (MEDIUM PRIORITY)
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

        # 5. Behavioral/Post-Compromise (MEDIUM PRIORITY)
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

        # 13. Scope Analysis (LAST RESORT)
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

        # FALLBACK: Use step name for API fallback
        print(f"   ⚠️  No specific intent match - using step name as fallback")
        return step_name

    def _extract_focus(self, step_name: str, explanation: str) -> str:
        """Extract focus area from step context"""
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

        # Skip external tools and manual steps
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

        # Include data investigation types
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

        return explanation
