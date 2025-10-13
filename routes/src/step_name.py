import re
from typing import Dict, List


class IntelligentStepNameGenerator:
    """
    Generates clear, action-focused step names based on content analysis
    """

    def __init__(self):
        # Action verb patterns for different investigation types
        self.action_patterns = {
            "analysis": ["Analyze", "Review", "Examine", "Assess", "Evaluate"],
            "verification": ["Verify", "Validate", "Confirm", "Check"],
            "extraction": ["Extract", "Gather", "Collect", "Retrieve"],
            "lookup": ["Query", "Search", "Lookup", "Find"],
            "comparison": ["Compare", "Correlate", "Match"],
            "decision": ["Classify", "Determine", "Decide"],
            "action": ["Execute", "Implement", "Apply", "Perform"],
            "documentation": ["Document", "Record", "Log"],
            "escalation": ["Escalate", "Report", "Notify"],
        }

        # Subject matter patterns
        self.subject_patterns = {
            "user": ["User Account", "User Identity", "User Profile", "Account"],
            "role": ["Role Assignment", "Privileged Role", "Role Permissions"],
            "signin": ["Sign-In Activity", "Login Patterns", "Authentication"],
            "device": ["Device Information", "Device Compliance", "Endpoint"],
            "ip": ["IP Reputation", "Source IP", "Network Location"],
            "mfa": ["MFA Status", "Multi-Factor Authentication"],
            "location": ["Geographic Location", "Travel Patterns"],
            "threat": ["Threat Indicators", "Security Alerts"],
            "logs": ["Audit Logs", "Security Logs", "Activity Logs"],
        }

    def generate_step_name(
        self, raw_name: str, explanation: str, step_num: int, context: str = ""
    ) -> str:
        """
        Generate clear, descriptive step name

        Args:
            raw_name: Original step name from template
            explanation: Detailed explanation
            step_num: Step number in sequence
            context: Additional context (rule name, etc.)

        Returns:
            Clear, action-focused step name
        """
        # Clean raw name first
        clean_name = self._clean_raw_name(raw_name)

        # If already good, use it
        if self._is_good_name(clean_name):
            return clean_name

        # Generate from content
        combined_text = f"{clean_name} {explanation}".lower()

        # Detect action type
        action = self._detect_action(combined_text)

        # Detect subject
        subject = self._detect_subject(combined_text)

        # Build name
        if action and subject:
            return f"{action} {subject}"
        elif subject:
            return f"Review {subject}"
        elif action:
            return f"{action} Investigation Data"
        else:
            return f"Investigation Step {step_num}"

    def _clean_raw_name(self, name: str) -> str:
        """Clean raw name from template"""
        # Remove numbering
        name = re.sub(r"^\d+\.?\d*\s*", "", name)
        name = re.sub(r"^Step\s*\d+:?\s*", "", name, flags=re.IGNORECASE)

        # Remove markdown
        name = re.sub(r"[*#_`]", "", name)

        # Clean whitespace
        name = " ".join(name.split())

        return name.strip()

    def _is_good_name(self, name: str) -> bool:
        """Check if name is already clear and descriptive"""
        if not name or len(name) < 8:
            return False

        # Generic names to reject
        generic_terms = [
            "investigation step",
            "step",
            "complete",
            "document findings",
            "gather details",
        ]

        name_lower = name.lower()
        if any(term in name_lower for term in generic_terms):
            return False

        # Good name should have action verb + subject
        words = name.split()
        if len(words) >= 2:
            return True

        return False

    def _detect_action(self, text: str) -> str:
        """Detect appropriate action verb"""
        # Check for specific action patterns
        if any(
            word in text for word in ["execute", "remediat", "block", "reset", "lock"]
        ):
            return "Execute"

        if any(word in text for word in ["escalat", "notify", "report", "inform"]):
            return "Escalate"

        if any(word in text for word in ["document", "record", "log", "final"]):
            return "Document"

        if any(word in text for word in ["classify", "determine", "decide", "assess"]):
            return "Classify"

        if any(word in text for word in ["validate", "verify", "confirm", "check"]):
            return "Verify"

        if any(word in text for word in ["extract", "gather", "collect", "retrieve"]):
            return "Extract"

        if any(word in text for word in ["query", "search", "lookup", "kql"]):
            return "Query"

        if any(word in text for word in ["analyze", "review", "examine", "pattern"]):
            return "Analyze"

        if any(word in text for word in ["compare", "correlate", "match"]):
            return "Compare"

        return "Review"

    def _detect_subject(self, text: str) -> str:
        """Detect subject matter"""
        # Role-related
        if any(
            word in text
            for word in ["role", "privileged", "global admin", "administrator"]
        ):
            if "assign" in text:
                return "Role Assignment Details"
            if "high-risk" in text or "privileged" in text:
                return "High-Risk Role Status"
            return "Role Permissions"

        # User-related
        if any(word in text for word in ["user", "account", "identity"]):
            if "vip" in text:
                return "VIP User Status"
            if "detail" in text or "information" in text:
                return "User Account Details"
            return "User Identity Information"

        # Sign-in related
        if any(
            word in text for word in ["sign-in", "signin", "login", "authentication"]
        ):
            if "pattern" in text or "unusual" in text or "suspicious" in text:
                return "Sign-In Patterns"
            if "history" in text or "logs" in text:
                return "Sign-In History"
            return "Authentication Activity"

        # Device-related
        if "device" in text:
            if "complian" in text:
                return "Device Compliance Status"
            if "known" in text or "registered" in text:
                return "Registered Devices"
            return "Device Information"

        # IP-related
        if "ip" in text:
            if "reputation" in text or "threat" in text:
                return "IP Reputation"
            if "source" in text:
                return "Source IP Address"
            if "block" in text:
                return "IP Blocking"
            return "IP Address Details"

        # MFA-related
        if "mfa" in text or "multi-factor" in text:
            return "MFA Status"

        # Location-related
        if any(
            word in text for word in ["location", "geographic", "travel", "geolocation"]
        ):
            if "unusual" in text or "impossible" in text:
                return "Unusual Location Activity"
            return "Geographic Location"

        # Initiator/assigning user
        if any(
            word in text
            for word in ["initiator", "assigning user", "performed", "initiated"]
        ):
            return "Initiator Permissions"

        # Threat-related
        if any(
            word in text for word in ["threat", "malicious", "suspicious", "indicator"]
        ):
            return "Threat Indicators"

        # Logs
        if any(word in text for word in ["audit", "log", "activity"]):
            return "Audit Logs"

        # Remediation
        if any(word in text for word in ["remediat", "action", "response"]):
            return "Remediation Actions"

        # Classification
        if any(word in text for word in ["classif", "final", "decision"]):
            return "Incident Classification"

        # Escalation
        if "escalat" in text:
            if "l3" in text or "l2" in text:
                return "to L3/Security Team"
            return "to Appropriate Team"

        # Metadata
        if any(word in text for word in ["metadata", "timestamp", "time of", "when"]):
            return "Event Metadata"

        return "Investigation Data"

