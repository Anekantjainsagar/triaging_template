import re
import pandas as pd


def extract_rule_number(rule_text: str) -> str:
    """Extract rule number from rule text."""
    if pd.isna(rule_text):
        return "N/A"

    rule_text = str(rule_text).strip()

    # Pattern: Rule#123, rule 123, 123/2/002, etc.
    patterns = [
        r"[Rr]ule\s*#?\s*(\d+(?:[\/\-\.]\d+)*)",  # rule#286/2/002
        r"^(\d+(?:[\/\-\.]\d+)+)",  # 286/2/002
        r"#(\d+)",  # #286
        r"^(\d{2,})",  # Starting with 2+ digits
    ]

    for pattern in patterns:
        match = re.search(pattern, rule_text)
        if match:
            return match.group(1)

    return "N/A"


def extract_alert_name(rule_text: str) -> str:
    """Extract alert/rule name from full rule text."""
    if pd.isna(rule_text):
        return "N/A"

    rule_text = str(rule_text).strip()

    # Remove rule number prefix
    # Pattern: "Rule#123 - Alert Name" or "123/2/002 - Alert Name"
    cleaned = re.sub(r"^[Rr]ule\s*#?\s*\d+(?:[\/\-\.]\d+)*\s*[-:]\s*", "", rule_text)
    cleaned = re.sub(r"^\d+(?:[\/\-\.]\d+)+\s*[-:]\s*", "", cleaned)
    cleaned = re.sub(r"^#\d+\s*[-:]\s*", "", cleaned)

    # If nothing was removed, return the original (it's already just the name)
    return cleaned.strip() if cleaned.strip() != rule_text else rule_text


def _strip_step_number_prefix(text: str) -> str:
    if not text:
        return text

    cleaned = re.sub(r"^\d+[\.\):]\s*", "", text.strip())
    return cleaned
