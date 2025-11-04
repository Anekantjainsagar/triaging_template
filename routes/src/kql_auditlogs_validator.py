import re
from datetime import datetime
from typing import Tuple, Optional


class KQLAuditLogsValidator:
    """Validates and fixes KQL queries that incorrectly use AuditLogs table"""

    @staticmethod
    def contains_auditlogs(kql_query: str) -> bool:
        """
        Check if query contains AuditLogs table

        Returns:
            True if AuditLogs is found in the query
        """
        if not kql_query:
            return False

        # Check for AuditLogs table usage
        patterns = [
            r"\bAuditLogs\b",  # Word boundary match
            r"join.*AuditLogs",  # Join with AuditLogs
            r"union.*AuditLogs",  # Union with AuditLogs
        ]

        for pattern in patterns:
            if re.search(pattern, kql_query, re.IGNORECASE):
                return True

        return False

    @staticmethod
    def extract_primary_table(kql_query: str) -> Optional[str]:
        """Extract the primary table from KQL query"""
        # Look for table name at start of query or after pipes
        table_pattern = r"^\s*([A-Za-z]+)\s*\|"
        match = re.search(table_pattern, kql_query.strip())

        if match:
            return match.group(1)

        return None

    @staticmethod
    def remove_auditlogs_join(kql_query: str) -> str:
        # Pattern to match join with AuditLogs
        join_pattern = r"\|\s*join\s+kind=\w+\s+\(AuditLogs\)[^\|]*"

        cleaned = re.sub(join_pattern, "", kql_query, flags=re.IGNORECASE)

        # Clean up any double pipes
        cleaned = re.sub(r"\|\s*\|", "|", cleaned)

        return cleaned.strip()


def validate_and_fix_api_query(
    kql_query: str,
    step_name: str,
    explanation: str,
    reference_datetime_obj: Optional[datetime] = None,
    max_retries: int = 2,
) -> Tuple[str, str, bool]:
    
    validator = KQLAuditLogsValidator()

    # Check if query contains AuditLogs
    if not validator.contains_auditlogs(kql_query):
        print(f"   ✅ Query validation passed - no AuditLogs detected")
        return kql_query, explanation, False

    print(f"   ⚠️ Query contains AuditLogs - attempting to fix...")

    # Get primary table
    primary_table = validator.extract_primary_table(kql_query)

    if primary_table and primary_table.lower() == "auditlogs":
        # Primary table IS AuditLogs - need complete regeneration
        print(f"   🔄 Primary table is AuditLogs - regenerating query...")
        return _regenerate_query_without_auditlogs(
            step_name, explanation, reference_datetime_obj, max_retries
        )

    # AuditLogs is in a JOIN - try to remove it
    print(f"   🔧 Removing AuditLogs join...")
    fixed_query = validator.remove_auditlogs_join(kql_query)

    # Verify the fix
    if validator.contains_auditlogs(fixed_query):
        # Still has AuditLogs - regenerate completely
        print(f"   🔄 Could not remove AuditLogs - regenerating query...")
        return _regenerate_query_without_auditlogs(
            step_name, explanation, reference_datetime_obj, max_retries
        )

    print(f"   ✅ Successfully removed AuditLogs join")
    return fixed_query, explanation, True


def _regenerate_query_without_auditlogs(
    step_name: str,
    explanation: str,
    reference_datetime_obj: Optional[datetime],
    max_retries: int,
) -> Tuple[str, str, bool]:
    
    from routes.src.api_kql_generation import EnhancedKQLGenerator

    generator = EnhancedKQLGenerator()

    # Add explicit instruction to avoid AuditLogs
    enhanced_step_name = (
        f"{step_name} (use SigninLogs or IdentityInfo only, NOT AuditLogs)"
    )

    for attempt in range(max_retries):
        print(f"   🔄 Regeneration attempt {attempt + 1}/{max_retries}...")

        # Generate new query
        new_query, new_explanation = generator.generate_kql_query(
            step_name=enhanced_step_name,
            explanation=explanation,
            rule_context="",
            reference_datetime_obj=reference_datetime_obj,
        )

        # Validate the new query
        validator = KQLAuditLogsValidator()

        if not validator.contains_auditlogs(new_query):
            print(f"   ✅ Regenerated query is valid (no AuditLogs)")
            return new_query, new_explanation, True

        print(f"   ⚠️ Regenerated query still contains AuditLogs - retrying...")

    # If all retries failed, return empty query
    print(f"   ❌ Failed to regenerate valid query after {max_retries} attempts")
    return "", "Query generation failed - manual investigation required", True


# Integration example for api_kql_generation.py
def enhanced_generate_kql_query_with_validation(
    self,
    step_name: str,
    explanation: str,
    rule_context: str = "",
    reference_datetime_obj: Optional[datetime] = None,
) -> Tuple[str, str]:
    
    # Generate query using existing logic
    kql_query, kql_explanation = self.generate_kql_query(
        step_name=step_name,
        explanation=explanation,
        rule_context=rule_context,
        reference_datetime_obj=reference_datetime_obj,
    )

    # If query was generated via API (not hardcoded), validate it
    if kql_query and len(kql_query.strip()) > 30:
        # Check if this came from API (heuristic: contains certain patterns)
        is_api_generated = any(
            [
                "join" in kql_query.lower() and "auditlogs" in kql_query.lower(),
                kql_query.strip().lower().startswith("auditlogs"),
            ]
        )

        if is_api_generated:
            print(f"   🔍 Validating API-generated query for AuditLogs usage...")

            validated_query, validated_explanation, was_fixed = (
                validate_and_fix_api_query(
                    kql_query=kql_query,
                    step_name=step_name,
                    explanation=explanation,
                    reference_datetime_obj=reference_datetime_obj,
                )
            )

            if was_fixed:
                print(f"   ✅ Query was validated and fixed")
                return validated_query, validated_explanation

    return kql_query, kql_explanation
