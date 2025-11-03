"""
ENHANCED: kql_query_standardizer.py
With automatic syntax error learning and recovery
Focuses on PIPE validation only - accepts all data as-is
"""

import re
from typing import Tuple, Optional, Dict, List
from datetime import datetime, timedelta


class KQLSyntaxValidator:
    """Validates and fixes common KQL syntax errors - PIPE FOCUSED"""

    @staticmethod
    def validate_query(query: str) -> Tuple[bool, str, List[str]]:
        """
        Validate KQL query for syntax issues

        Returns:
            Tuple of (is_valid, error_message, suggested_fixes)
        """
        issues = []

        # Check 1: Missing pipes between statements
        statements = [
            "where",
            "summarize",
            "extend",
            "project",
            "order by",
            "sort by",
            "limit",
            "distinct",
            "top",
            "join",
            "union",
            "make-series",
        ]

        for stmt in statements:
            # Look for statement not preceded by pipe (except at start)
            pattern = rf"(?<!\|)\s+{re.escape(stmt)}\s+"
            matches = re.finditer(pattern, query, re.IGNORECASE)
            for match in matches:
                if match.start() > 0:  # Not at start of query
                    issues.append(
                        f"Missing pipe before '{stmt}' at position {match.start()}"
                    )

        # Check 2: Unmatched parentheses
        open_parens = query.count("(")
        close_parens = query.count(")")
        if open_parens != close_parens:
            issues.append(
                f"Unmatched parentheses: {open_parens} open, {close_parens} close"
            )

        # Check 3: Unmatched quotes
        double_quotes = query.count('"') % 2
        if double_quotes != 0:
            issues.append("Unmatched double quotes in query")

        # Check 4: Invalid operators
        if re.search(r"\bin\s*\(\s*\)", query):
            issues.append("Empty 'in' operator - must have at least one value")

        # Check 5: Check for proper pipes before aggregate statements
        for stmt in ["summarize", "extend", "project", "order by"]:
            # Look for statement not preceded by pipe
            pattern = rf"(?<!\|)\s+{re.escape(stmt)}\s+"
            if re.search(pattern, query, re.IGNORECASE):
                # Make sure it's not at the very start
                if query.strip().lower().startswith(stmt.lower()):
                    continue
                issues.append(f"Missing pipe before '{stmt}'")

        # Check 6: Missing operators
        if re.search(r'"\s*,\s*"', query):  # Comma inside quotes
            issues.append("Possible malformed list - check comma placement")

        # Check 7: Invalid table name
        valid_tables = [
            "SigninLogs",
            "AuditLogs",
            "DeviceInfo",
            "CloudAppEvents",
            "IdentityInfo",
            "SecurityEvent",
            "CommonSecurityLog",
        ]
        has_valid_table = any(table in query for table in valid_tables)
        if not has_valid_table:
            issues.append("No valid KQL table found (SigninLogs, AuditLogs, etc.)")

        is_valid = len(issues) == 0
        error_msg = "; ".join(issues) if issues else "Query appears valid"

        return is_valid, error_msg, issues

    @staticmethod
    def fix_query(query: str) -> Tuple[str, List[str]]:
        """
        Attempt to fix common KQL syntax errors

        Returns:
            Tuple of (fixed_query, list_of_fixes_applied)
        """
        fixed = query
        fixes_applied = []

        # Fix 1: Add missing pipes before statements
        for stmt in ["where", "summarize", "extend", "project", "order by", "sort by"]:
            # Pattern: end of some expression followed directly by statement
            pattern = rf"([\]\)'\"])\s*({re.escape(stmt)})\s+"

            def add_pipe(match):
                fixes_applied.append(f"Added pipe before '{stmt}'")
                return f"{match.group(1)} | {match.group(2)} "

            fixed = re.sub(pattern, add_pipe, fixed, flags=re.IGNORECASE)

        # Fix 2: Remove double pipes
        if "||" in fixed:
            fixed = fixed.replace("||", "|")
            fixes_applied.append("Removed double pipes")

        # Fix 3: Fix spaces in IP addresses (e.g., "203.197.238.210" format)
        def fix_ip_spacing(match):
            ip = match.group(1)
            # Remove spaces from inside quotes
            ip_clean = ip.replace(" ", "")
            if ip != ip_clean:
                fixes_applied.append(f"Removed spaces from IP: {ip}")
            return f'"{ip_clean}"'

        fixed = re.sub(r'"([\d\.\s:a-f]+)"', fix_ip_spacing, fixed)

        # Fix 4: Ensure commas between list items (FIXED REGEX)
        # Look for patterns like "email1" "email2" and add comma
        # OLD (BROKEN): r'("\w+@[\w\.]+")(\s+)("'
        # NEW (FIXED):  r'("\w+@[\w\.]+")(\s+)("\w+@[\w\.]+")' 
        fixed = re.sub(r'("\w+@[\w\.]+")(\s+)("\w+@[\w\.]+")', r"\1, \3", fixed)
        if re.search(r'"\w+@[\w\.]+".*"\w+@[\w\.]+"', fixed):
            fixes_applied.append("Fixed email list formatting")

        # Fix 5: Remove invalid colons in IPv4-like numbers
        # Pattern: number:number that looks like IPv4 corruption
        def fix_malformed_ips(match):
            full = match.group(0)
            # Check if this looks like corrupted IPv4 (e.g., "1336:a49c")
            if re.match(r'"\d{3,4}:[a-f0-9]{4,}"', full):
                # This is likely corrupted data, comment it out
                fixes_applied.append(f"Removed malformed IP: {full}")
                return ""  # Remove it
            return full

        fixed = re.sub(r'"(\d{1,4}:[a-f0-9]+)"', fix_malformed_ips, fixed)

        # Fix 6: Clean up trailing commas in lists
        fixed = re.sub(r",\s*\)", ")", fixed)
        if "," in fixed:
            fixes_applied.append("Cleaned up trailing commas")

        # Fix 7: Ensure proper spacing around pipes
        fixed = re.sub(r"\|\s+\|", "|", fixed)
        fixed = re.sub(r"\s*\|\s*", " | ", fixed)

        return fixed, fixes_applied


class KQLSyntaxErrorLearner:
    """Learns from KQL execution errors to prevent future issues"""

    def __init__(self):
        self.error_patterns = {}  # Maps error patterns to fixes
        self.error_history = []  # History of errors and fixes
        self.correction_success_rate = {}  # Tracks which fixes work

    def learn_from_error(
        self,
        original_query: str,
        error_message: str,
        fixed_query: str,
        execution_success: bool,
    ):
        """
        Learn from KQL execution error

        Args:
            original_query: The query that failed
            error_message: Error message from execution
            fixed_query: The corrected query
            execution_success: Whether the fix worked
        """

        # Extract error pattern
        error_pattern = self._extract_error_pattern(error_message)

        # Calculate what changed between original and fixed
        changes = self._calculate_diff(original_query, fixed_query)

        # Store learning
        learning_entry = {
            "original": original_query,
            "error": error_message,
            "error_pattern": error_pattern,
            "fixed": fixed_query,
            "changes": changes,
            "success": execution_success,
            "timestamp": datetime.now().isoformat(),
        }

        self.error_history.append(learning_entry)

        # Update error pattern database
        if error_pattern not in self.error_patterns:
            self.error_patterns[error_pattern] = []

        self.error_patterns[error_pattern].append(
            {"fix": changes, "success": execution_success}
        )

        # Update success rate
        if error_pattern in self.correction_success_rate:
            current_rate = self.correction_success_rate[error_pattern]
            self.correction_success_rate[error_pattern] = (
                current_rate + execution_success
            ) / 2
        else:
            self.correction_success_rate[error_pattern] = (
                1.0 if execution_success else 0.0
            )

        print(f"✅ Learned from error:")
        print(f"   Pattern: {error_pattern}")
        print(f"   Fix success: {execution_success}")
        print(
            f"   Success rate: {self.correction_success_rate.get(error_pattern, 0)*100:.1f}%"
        )

    def suggest_fix_for_error(
        self, error_message: str, original_query: str
    ) -> Optional[str]:
        """
        Suggest fix based on previously learned patterns

        Args:
            error_message: Current error message
            original_query: Current query that failed

        Returns:
            Suggested fixed query or None
        """
        error_pattern = self._extract_error_pattern(error_message)

        if error_pattern not in self.error_patterns:
            return None

        # Get most successful fix for this pattern
        fixes = self.error_patterns[error_pattern]
        successful_fixes = [f for f in fixes if f["success"]]

        if not successful_fixes:
            return None

        # Apply most common successful fix
        best_fix = max(successful_fixes, key=lambda x: successful_fixes.count(x))

        fixed_query = original_query
        for change_type, change_detail in best_fix["fix"].items():
            fixed_query = self._apply_change(fixed_query, change_type, change_detail)

        return fixed_query

    def _extract_error_pattern(self, error_message: str) -> str:
        """Extract the core error pattern from error message"""

        # Common patterns
        if "SyntaxError" in error_message:
            # Extract the problematic keyword/position
            match = re.search(r"could not be parsed at '(\w+)'", error_message)
            if match:
                return f"SyntaxError:{match.group(1)}"
            return "SyntaxError:Unknown"

        elif "BadArgumentError" in error_message:
            return "BadArgumentError"

        elif "UnknownColumn" in error_message:
            match = re.search(r"'(\w+)'", error_message)
            if match:
                return f"UnknownColumn:{match.group(1)}"
            return "UnknownColumn"

        elif "semantic error" in error_message.lower():
            return "SemanticError"

        else:
            return "UnknownError"

    def _calculate_diff(self, original: str, fixed: str) -> Dict[str, str]:
        """Calculate what changed between original and fixed"""
        changes = {}

        if "|" in fixed and "|" not in original:
            changes["added_pipe"] = "Added pipe separator"

        if fixed.count("(") != original.count("("):
            changes["parentheses_balanced"] = "Fixed parentheses"

        if len(fixed) < len(original):
            changes["removed_invalid_data"] = (
                f"Removed {len(original)-len(fixed)} chars"
            )

        if fixed != original:
            changes["query_modified"] = "Query was modified"

        return changes

    def _apply_change(self, query: str, change_type: str, detail: str) -> str:
        """Apply a learned change to a query"""

        if change_type == "added_pipe":
            # Add pipes before statements
            for stmt in ["summarize", "where", "extend", "project"]:
                query = re.sub(
                    rf'([\]\)"])\s+({stmt})\s+',
                    rf"\1 | \2 ",
                    query,
                    flags=re.IGNORECASE,
                )

        elif change_type == "parentheses_balanced":
            # Fix unmatched parentheses
            open_p = query.count("(")
            close_p = query.count(")")

            if close_p > open_p:
                # Remove extra closing parens
                while query.count(")") > query.count("("):
                    query = query.rsplit(")", 1)[0]
            elif open_p > close_p:
                # Add closing parens
                query += ")" * (open_p - close_p)

        return query

    def get_learning_stats(self) -> Dict:
        """Get statistics on learning"""
        return {
            "total_errors_learned": len(self.error_history),
            "unique_error_patterns": len(self.error_patterns),
            "average_success_rate": (
                sum(self.correction_success_rate.values())
                / len(self.correction_success_rate)
                if self.correction_success_rate
                else 0
            ),
            "error_patterns": self.error_patterns,
            "success_rates": self.correction_success_rate,
        }


class KQLQueryStandardizer:
    """Standardizes and normalizes generated KQL queries with error learning"""

    def __init__(self):
        self.primary_tables = [
            "SigninLogs",
            "AuditLogs",
            "DeviceInfo",
            "CloudAppEvents",
            "IdentityInfo",
        ]

        # Initialize error learner
        self.error_learner = KQLSyntaxErrorLearner()
        self.syntax_validator = KQLSyntaxValidator()

    def standardize_query(
        self,
        raw_kql: str,
        query_intent: str = "",
        reference_datetime_obj: Optional[datetime] = None,
    ) -> Tuple[str, str]:
        """
        Standardize a raw KQL query into our format
        WITH SYNTAX VALIDATION AND AUTO-CORRECTION

        Args:
            raw_kql: Raw KQL from API or LLM
            query_intent: What this query is trying to do (for context)
            reference_datetime_obj: Alert timeGenerated for 7-day calculation

        Returns:
            Tuple of (standardized_kql, explanation)
        """

        if not raw_kql or len(raw_kql.strip()) < 20:
            return "", "Query too short to standardize"

        # STEP 1: Validate incoming query
        print(f"\n🔍 KQL Validation & Standardization")
        print(f"{'='*60}")

        is_valid, error_msg, issues = self.syntax_validator.validate_query(raw_kql)

        if not is_valid:
            print(f"⚠️  Issues detected: {len(issues)}")
            for issue in issues[:3]:  # Show first 3
                print(f"   - {issue}")

            # Try to fix
            print(f"\n🔧 Attempting automatic correction...")
            raw_kql, fixes = self.syntax_validator.fix_query(raw_kql)

            for fix in fixes:
                print(f"   ✅ {fix}")

            # Validate again
            is_valid, error_msg, issues = self.syntax_validator.validate_query(raw_kql)

            if not is_valid:
                print(f"⚠️  Still has issues after auto-fix: {issues[0]}")
        else:
            print(f"✅ Query passed validation")

        # STEP 2: Identify primary table
        primary_table = self._identify_primary_table(raw_kql)
        if not primary_table:
            return "", "Could not identify primary table (SigninLogs/AuditLogs/etc)"

        # STEP 3: Extract main logic
        main_logic = self._extract_main_logic(raw_kql, primary_table)

        # STEP 4: Check filters
        has_user_filter = self._has_user_filter(main_logic)
        has_ip_filter = self._has_ip_filter(main_logic)

        # STEP 5: Build standardized structure
        standardized = self._build_standardized_structure(
            primary_table,
            main_logic,
            has_user_filter,
            has_ip_filter,
            query_intent,
            reference_datetime_obj,
        )

        # STEP 6: Final validation
        final_is_valid, final_error, final_issues = (
            self.syntax_validator.validate_query(standardized)
        )

        if not final_is_valid:
            print(f"⚠️  Final query still has issues: {final_issues[0]}")
            standardized, _ = self.syntax_validator.fix_query(standardized)

        print(f"✅ Query standardization complete\n")

        # STEP 7: Generate explanation
        explanation = self._generate_explanation(
            primary_table, query_intent, has_user_filter, has_ip_filter
        )

        return standardized, explanation

    def report_execution_error(
        self,
        original_query: str,
        error_message: str,
        attempted_fix: str,
        fix_worked: bool,
    ):
        """
        Report KQL execution error for learning

        Call this when a query fails to execute so the system learns
        """
        self.error_learner.learn_from_error(
            original_query=original_query,
            error_message=error_message,
            fixed_query=attempted_fix,
            execution_success=fix_worked,
        )

    def get_suggested_fix(
        self, error_message: str, original_query: str
    ) -> Optional[str]:
        """Get suggested fix for an error based on learned patterns"""
        return self.error_learner.suggest_fix_for_error(error_message, original_query)

    def _identify_primary_table(self, kql: str) -> Optional[str]:
        """Identify which table the query primarily uses"""
        kql_lower = kql.lower()

        for table in self.primary_tables:
            if f"{table.lower()}" in kql_lower:
                if re.search(rf"\b{table.lower()}\b", kql_lower):
                    return table

        return None

    def _extract_main_logic(self, raw_kql: str, primary_table: str) -> str:
        """Extract the main query logic, removing comment lines and messy formatting"""
        lines = raw_kql.split("\n")

        table_line_idx = -1
        for idx, line in enumerate(lines):
            if re.search(rf"\b{primary_table}\b", line, re.IGNORECASE):
                table_line_idx = idx
                break

        if table_line_idx == -1:
            return raw_kql

        logic_lines = lines[table_line_idx + 1 :]

        cleaned_lines = []
        for line in logic_lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("//"):
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

        standardized = f"{primary_table}\n"
        standardized += self._build_time_filter(reference_datetime_obj)

        if "user" in query_intent.lower() and not has_user_filter:
            standardized += '| where UserPrincipalName == "<USER_EMAIL>"\n'
        elif has_user_filter:
            standardized += self._normalize_user_filter(main_logic)

        if "ip" in query_intent.lower() and not has_ip_filter:
            standardized += '| where IPAddress == "<IP_ADDRESS>"\n'
        elif has_ip_filter:
            standardized += self._normalize_ip_filter(main_logic)

        cleaned_logic = self._remove_redundant_filters(
            main_logic, has_user_filter, has_ip_filter
        )

        if cleaned_logic.strip():
            standardized += cleaned_logic

        return self._format_query(standardized)

    def _build_time_filter(self, reference_datetime_obj: Optional[datetime]) -> str:
        """Build standardized TimeGenerated filter"""

        if reference_datetime_obj:
            start_dt = reference_datetime_obj - timedelta(days=7)
            start_str = start_dt.strftime("%Y-%m-%d %H:%M:%S")
            end_str = reference_datetime_obj.strftime("%Y-%m-%d %H:%M:%S")

            return (
                f"| where TimeGenerated > datetime({start_str}Z) "
                f"and TimeGenerated <= datetime({end_str}Z)\n"
            )
        else:
            return "| where TimeGenerated > ago(7d)\n"

    def _normalize_user_filter(self, logic: str) -> str:
        """Normalize existing user filter to use <USER_EMAIL> placeholder"""

        pattern1 = r'where\s+UserPrincipalName\s*==\s*"[^"]*"'
        if re.search(pattern1, logic, re.IGNORECASE):
            replacement = 'where UserPrincipalName == "<USER_EMAIL>"'
            return re.sub(pattern1, replacement, logic, flags=re.IGNORECASE) + "\n"

        pattern2 = r"where\s+UserPrincipalName\s*in\s*\([^)]*\)"
        if re.search(pattern2, logic, re.IGNORECASE):
            return '| where UserPrincipalName in ("<USER_EMAIL>")\n'

        pattern3 = r'InitiatedBy\.user\.userPrincipalName\s*==\s*"[^"]*"'
        if re.search(pattern3, logic, re.IGNORECASE):
            replacement = 'InitiatedBy.user.userPrincipalName == "<USER_EMAIL>"'
            return re.sub(pattern3, replacement, logic, flags=re.IGNORECASE) + "\n"

        return ""

    def _normalize_ip_filter(self, logic: str) -> str:
        """Normalize existing IP filter to use <IP_ADDRESS> placeholder"""

        pattern = r'where\s+IPAddress\s*==\s*"[\d\.]+"'
        if re.search(pattern, logic, re.IGNORECASE):
            return '| where IPAddress == "<IP_ADDRESS>"\n'

        return ""

    def _remove_redundant_filters(
        self, logic: str, has_user_filter: bool, has_ip_filter: bool
    ) -> str:
        cleaned = logic

        # ✅ FIXED: More precise regex that stops at newline or next pipe
        # Remove TimeGenerated filters (already added at top)
        cleaned = re.sub(
            r"\|\s*where\s+TimeGenerated[^\n|]+",  # ✅ Stops at newline or pipe
            "",
            cleaned,
            flags=re.IGNORECASE,
        )

        # Remove user filters if already added
        if has_user_filter:
            cleaned = re.sub(
                r"\|\s*where\s+UserPrincipalName[^\n|]+",
                "",
                cleaned,
                flags=re.IGNORECASE,
            )

        # Remove IP filters if already added
        if has_ip_filter:
            cleaned = re.sub(
                r"\|\s*where\s+IPAddress[^\n|]+",
                "",
                cleaned,
                flags=re.IGNORECASE,
            )

        # Clean up double pipes and leading pipes
        cleaned = re.sub(r"\|\s*\|", "|", cleaned)
        cleaned = re.sub(r"^\|\s*", "", cleaned)

        return cleaned.strip()

    def _format_query(self, query: str) -> str:
        """Format query for consistency"""

        lines = query.split("\n")
        formatted_lines = []

        for line in lines:
            stripped = line.strip()
            if stripped and stripped != "|":
                formatted_lines.append(stripped)

        formatted = "\n".join(formatted_lines)
        formatted = re.sub(r"\n\s*\n", "\n", formatted)
        formatted = re.sub(r"\|\s+\|", "|", formatted)

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

        parts.append(f"Queries {primary_table} table")

        if has_user_filter:
            parts.append("filtered by user (<USER_EMAIL>)")
        if has_ip_filter:
            parts.append("filtered by IP address (<IP_ADDRESS>)")

        parts.append("with 7-day lookback from alert timestamp")

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
        """Validate that query meets standardization requirements"""

        if not query or len(query.strip()) < 30:
            return False, "Query too short"

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

        if "TimeGenerated" not in query:
            return False, "Missing TimeGenerated filter"

        has_placeholders = "<USER_EMAIL>" in query or "<IP_ADDRESS>" in query
        has_explicit = "where" in query.lower()

        if not (has_placeholders or has_explicit):
            return False, "No user/IP filtering found"

        return True, "Valid"
