import re
from typing import Tuple, Optional
from datetime import datetime, timedelta


class KQLQueryStandardizer:
    """Standardizes and normalizes generated KQL queries"""

    def __init__(self):
        self.primary_tables = [
            "SigninLogs",
            "AuditLogs",
            "DeviceInfo",
            "CloudAppEvents",
            "IdentityInfo",
        ]

    def standardize_query(
        self,
        raw_kql: str,
        query_intent: str = "",
        reference_datetime_obj: Optional[datetime] = None,
    ) -> Tuple[str, str]:
        """
        Standardize a raw KQL query into our format

        Args:
            raw_kql: Raw KQL from API or LLM
            query_intent: What this query is trying to do (for context)
            reference_datetime_obj: Alert timeGenerated for 7-day calculation

        Returns:
            Tuple of (standardized_kql, explanation)
        """

        if not raw_kql or len(raw_kql.strip()) < 20:
            return "", "Query too short to standardize"

        # Step 1: Identify primary table
        primary_table = self._identify_primary_table(raw_kql)
        if not primary_table:
            return "", "Could not identify primary table (SigninLogs/AuditLogs/etc)"

        # Step 2: Extract main logic (everything after the table)
        main_logic = self._extract_main_logic(raw_kql, primary_table)

        # Step 3: Extract user/IP filters that exist
        has_user_filter = self._has_user_filter(main_logic)
        has_ip_filter = self._has_ip_filter(main_logic)

        # Step 4: Build standardized query structure
        standardized = self._build_standardized_structure(
            primary_table,
            main_logic,
            has_user_filter,
            has_ip_filter,
            query_intent,
            reference_datetime_obj,
        )

        # Step 5: Generate explanation
        explanation = self._generate_explanation(
            primary_table, query_intent, has_user_filter, has_ip_filter
        )

        return standardized, explanation

    def _identify_primary_table(self, kql: str) -> Optional[str]:
        """Identify which table the query primarily uses"""
        kql_lower = kql.lower()

        for table in self.primary_tables:
            if f"{table.lower()}" in kql_lower:
                # Find first occurrence
                if re.search(rf"\b{table.lower()}\b", kql_lower):
                    return table

        return None

    def _extract_main_logic(self, raw_kql: str, primary_table: str) -> str:
        """
        Extract the main query logic, removing comment lines and messy formatting
        """
        lines = raw_kql.split("\n")

        # Find where primary table is mentioned
        table_line_idx = -1
        for idx, line in enumerate(lines):
            if re.search(rf"\b{primary_table}\b", line, re.IGNORECASE):
                table_line_idx = idx
                break

        if table_line_idx == -1:
            return raw_kql

        # Get everything from table onwards
        logic_lines = lines[table_line_idx + 1 :]

        # Remove pure comment lines
        cleaned_lines = []
        for line in logic_lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("//"):
                # Remove inline comments
                if "//" in line:
                    line = line.split("//")[0]
                cleaned_lines.append(line)

        return "\n".join(cleaned_lines).strip()

    def _has_user_filter(self, logic: str) -> bool:
        """Check if query already filters by UserPrincipalName"""
        user_patterns = [
            r"UserPrincipalName\s*==",
            r"UserPrincipalName\s*in\s*\(",
            r"where.*UserPrincipalName",
            r"InitiatedBy.*user.*UserPrincipalName",
        ]

        return any(
            re.search(pattern, logic, re.IGNORECASE) for pattern in user_patterns
        )

    def _has_ip_filter(self, logic: str) -> bool:
        """Check if query already filters by IPAddress"""
        ip_patterns = [
            r"IPAddress\s*==",
            r"IPAddress\s*in\s*\(",
            r"where.*IPAddress",
            r"SourceIPAddress",
        ]

        return any(re.search(pattern, logic, re.IGNORECASE) for pattern in ip_patterns)

    def _build_standardized_structure(
        self,
        primary_table: str,
        main_logic: str,
        has_user_filter: bool,
        has_ip_filter: bool,
        query_intent: str,
        reference_datetime_obj: Optional[datetime],
    ) -> str:
        """Build standardized query structure"""

        # Step 1: Start with table name
        standardized = f"{primary_table}\n"

        # Step 2: Add TimeGenerated filter with 7-day lookback
        standardized += self._build_time_filter(reference_datetime_obj)

        # Step 3: Add user filter if needed
        if "user" in query_intent.lower() and not has_user_filter:
            standardized += '| where UserPrincipalName == "<USER_EMAIL>"\n'
        elif has_user_filter:
            # Extract existing user filter and normalize it
            standardized += self._normalize_user_filter(main_logic)

        # Step 4: Add IP filter if needed
        if "ip" in query_intent.lower() and not has_ip_filter:
            standardized += '| where IPAddress == "<IP_ADDRESS>"\n'
        elif has_ip_filter:
            standardized += self._normalize_ip_filter(main_logic)

        # Step 5: Add the rest of the logic (aggregations, projections, etc)
        # Remove redundant WHERE clauses from main_logic
        cleaned_logic = self._remove_redundant_filters(
            main_logic, has_user_filter, has_ip_filter
        )

        if cleaned_logic.strip():
            standardized += cleaned_logic

        return self._format_query(standardized)

    def _build_time_filter(self, reference_datetime_obj: Optional[datetime]) -> str:
        """Build standardized TimeGenerated filter"""

        if reference_datetime_obj:
            # 7-day lookback from reference datetime
            start_dt = reference_datetime_obj - timedelta(days=7)
            start_str = start_dt.strftime("%Y-%m-%d %H:%M:%S")
            end_str = reference_datetime_obj.strftime("%Y-%m-%d %H:%M:%S")

            return (
                f"| where TimeGenerated > datetime({start_str}Z) "
                f"and TimeGenerated <= datetime({end_str}Z)\n"
            )
        else:
            # Fallback to ago(7d)
            return "| where TimeGenerated > ago(7d)\n"

    def _normalize_user_filter(self, logic: str) -> str:
        """Normalize existing user filter to use <USER_EMAIL> placeholder"""

        # Pattern 1: UserPrincipalName == "someone@domain.com"
        pattern1 = r'where\s+UserPrincipalName\s*==\s*"[^"]*"'
        if re.search(pattern1, logic, re.IGNORECASE):
            replacement = 'where UserPrincipalName == "<USER_EMAIL>"'
            return re.sub(pattern1, replacement, logic, flags=re.IGNORECASE) + "\n"

        # Pattern 2: UserPrincipalName in (...)
        pattern2 = r"where\s+UserPrincipalName\s*in\s*\([^)]*\)"
        if re.search(pattern2, logic, re.IGNORECASE):
            # Replace content but keep structure
            return '| where UserPrincipalName in ("<USER_EMAIL>")\n'

        # Pattern 3: InitiatedBy.user.userPrincipalName
        pattern3 = r'InitiatedBy\.user\.userPrincipalName\s*==\s*"[^"]*"'
        if re.search(pattern3, logic, re.IGNORECASE):
            replacement = 'InitiatedBy.user.userPrincipalName == "<USER_EMAIL>"'
            return re.sub(pattern3, replacement, logic, flags=re.IGNORECASE) + "\n"

        return ""

    def _normalize_ip_filter(self, logic: str) -> str:
        """Normalize existing IP filter to use <IP_ADDRESS> placeholder"""

        # Pattern: IPAddress == "1.2.3.4"
        pattern = r'where\s+IPAddress\s*==\s*"[\d\.]+"'
        if re.search(pattern, logic, re.IGNORECASE):
            return '| where IPAddress == "<IP_ADDRESS>"\n'

        return ""

    def _remove_redundant_filters(
        self, logic: str, has_user_filter: bool, has_ip_filter: bool
    ) -> str:
        """Remove redundant WHERE clauses that we've already added"""

        cleaned = logic

        # Remove TimeGenerated filters (we added our own)
        cleaned = re.sub(
            r"\|\s*where\s+TimeGenerated.*?(?=\||$)",
            "",
            cleaned,
            flags=re.IGNORECASE | re.DOTALL,
        )

        # Remove user filters if we're handling them
        if has_user_filter:
            cleaned = re.sub(
                r"\|\s*where\s+UserPrincipalName.*?(?=\||$)",
                "",
                cleaned,
                flags=re.IGNORECASE | re.DOTALL,
            )

        # Remove IP filters if we're handling them
        if has_ip_filter:
            cleaned = re.sub(
                r"\|\s*where\s+IPAddress.*?(?=\||$)",
                "",
                cleaned,
                flags=re.IGNORECASE | re.DOTALL,
            )

        # Clean up double pipes
        cleaned = re.sub(r"\|\s*\|", "|", cleaned)

        # Remove leading pipes
        cleaned = re.sub(r"^\|\s*", "", cleaned)

        return cleaned.strip()

    def _format_query(self, query: str) -> str:
        """Format query for consistency"""

        # Clean whitespace
        lines = query.split("\n")
        formatted_lines = []

        for line in lines:
            stripped = line.strip()
            if stripped and stripped != "|":
                formatted_lines.append(stripped)

        # Join with newlines
        formatted = "\n".join(formatted_lines)

        # Clean up any remaining issues
        formatted = re.sub(r"\n\s*\n", "\n", formatted)  # Remove double newlines
        formatted = re.sub(r"\|\s+\|", "|", formatted)  # Remove double pipes

        return formatted.strip()

    def _generate_explanation(
        self,
        primary_table: str,
        query_intent: str,
        has_user_filter: bool,
        has_ip_filter: bool,
    ) -> str:
        """Generate explanation for the standardized query"""

        parts = []

        # What table
        parts.append(f"Queries {primary_table} table")

        # How filtering
        if has_user_filter:
            parts.append("filtered by user (<USER_EMAIL>)")
        if has_ip_filter:
            parts.append("filtered by IP address (<IP_ADDRESS>)")

        # Time window
        parts.append("with 7-day lookback from alert timestamp")

        # What operation
        if "summarize" in query_intent.lower():
            parts.append("aggregates and summarizes data")
        if "anomaly" in query_intent.lower():
            parts.append("to detect anomalies")
        if "threat" in query_intent.lower():
            parts.append("for threat analysis")

        explanation = " - ".join(parts)
        return explanation[0].upper() + explanation[1:]

    @staticmethod
    def validate_standardized_query(query: str) -> Tuple[bool, str]:
        """
        Validate that query meets standardization requirements

        Returns:
            Tuple of (is_valid, reason)
        """

        if not query or len(query.strip()) < 30:
            return False, "Query too short"

        # Must have a primary table
        tables = [
            "SigninLogs",
            "AuditLogs",
            "DeviceInfo",
            "CloudAppEvents",
            "IdentityInfo",
        ]
        has_table = any(table in query for table in tables)
        if not has_table:
            return False, "No primary table found"

        # Should have TimeGenerated filter
        if "TimeGenerated" not in query:
            return False, "Missing TimeGenerated filter"

        # Should have placeholder format or explicit filters
        has_placeholders = "<USER_EMAIL>" in query or "<IP_ADDRESS>" in query
        has_explicit = "where" in query.lower()

        if not (has_placeholders or has_explicit):
            return False, "No user/IP filtering found"

        return True, "Valid"


class EnhancedKQLGeneratorWithStandardization:
    """
    Wrapper around EnhancedKQLGenerator that applies standardization
    Use this instead of calling generate_kql_query directly
    """

    def __init__(self, base_generator=None):
        if base_generator:
            self.base_generator = base_generator
        else:
            # Import here to avoid circular dependency
            from routes.src.api_kql_generation import EnhancedKQLGenerator

            self.base_generator = EnhancedKQLGenerator()

        self.standardizer = KQLQueryStandardizer()

    def generate_kql_query_with_standardization(
        self,
        step_name: str,
        explanation: str,
        rule_context: str = "",
        reference_datetime_obj: Optional[datetime] = None,
    ) -> Tuple[str, str]:
        """
        Generate KQL query and automatically standardize it

        Returns:
            Tuple of (standardized_kql, explanation)
        """

        # Step 1: Generate raw KQL using base generator
        raw_kql, raw_explanation = self.base_generator.generate_kql_query(
            step_name=step_name, explanation=explanation, rule_context=rule_context
        )

        if not raw_kql or len(raw_kql.strip()) < 30:
            return "", raw_explanation

        # Step 2: Standardize the generated query
        try:
            standardized_kql, standardized_explanation = (
                self.standardizer.standardize_query(
                    raw_kql=raw_kql,
                    query_intent=f"{step_name} {explanation}",
                    reference_datetime_obj=reference_datetime_obj,
                )
            )

            # Validate
            is_valid, reason = KQLQueryStandardizer.validate_standardized_query(
                standardized_kql
            )

            if is_valid:
                return standardized_kql, standardized_explanation
            else:
                # Fall back to raw if standardization failed
                print(
                    f"⚠️ Standardization validation failed: {reason} - using raw query"
                )
                return raw_kql, raw_explanation

        except Exception as e:
            print(f"⚠️ Standardization failed: {str(e)[:100]} - using raw query")
            return raw_kql, raw_explanation


# ==================== INTEGRATION EXAMPLES ====================


def example_usage():
    """Example: How to use the standardizer"""

    # Example 1: Standardize a messy API-generated query
    messy_query = """// This is a comment
    SigninLogs
    | where TimeGenerated >= ago(30d) // Look back 30 days
    | summarize Count = count() by UserPrincipalName, bin(TimeGenerated, 1d)
    | join kind=inner (
        SigninLogs
        | where ResultType != "0"
        | summarize FailedCount = count() by UserPrincipalName, bin(TimeGenerated, 1d)
    ) on UserPrincipalName, TimeGenerated
    | project UserPrincipalName, Count, FailedCount
    | order by FailedCount desc"""

    standardizer = KQLQueryStandardizer()

    # Without reference datetime (fallback to ago(7d))
    standardized, explanation = standardizer.standardize_query(
        raw_kql=messy_query, query_intent="analyze user signin patterns"
    )

    print("STANDARDIZED QUERY:")
    print(standardized)
    print(f"\nEXPLANATION: {explanation}")

    # Example 2: With reference datetime
    reference_dt = datetime(2025, 10, 3, 12, 45, 0)

    standardized_with_time, explanation = standardizer.standardize_query(
        raw_kql=messy_query,
        query_intent="analyze user signin patterns",
        reference_datetime_obj=reference_dt,
    )

    print("\n\nSTANDARDIZED WITH ABSOLUTE DATES:")
    print(standardized_with_time)

    # Example 3: Full integration with generator
    print("\n\n" + "=" * 80)
    print("FULL INTEGRATION EXAMPLE")
    print("=" * 80)

    enhanced_gen = EnhancedKQLGeneratorWithStandardization()

    kql, explanation = enhanced_gen.generate_kql_query_with_standardization(
        step_name="Investigate post-login user activity",
        explanation="Check for unusual actions after successful signin",
        rule_context="suspicious signin alert",
        reference_datetime_obj=reference_dt,
    )

    print(f"\nGenerated KQL:\n{kql}")
    print(f"\nExplanation: {explanation}")


if __name__ == "__main__":
    example_usage()
