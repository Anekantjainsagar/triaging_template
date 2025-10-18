import os
import re
import glob
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


def standardize_column_name(col_name: str) -> str:
    """Standardizes column names by removing special chars and whitespace."""
    col_name = str(col_name).strip().lower()
    col_name = re.sub(r"[^a-z0-9_]+", "_", col_name)
    col_name = re.sub(r"_+", "_", col_name).strip("_")
    return col_name


def read_all_tracker_sheets(data_folder: str = "data") -> pd.DataFrame:
    """Reads all tracker sheets and returns consolidated DataFrame."""
    all_data = []

    column_mapping = {
        "s_no": "s_no",
        "sno": "s_no",
        "date": "date",
        "month": "month",
        "shift": "shift",
        "incidnet_no": "incident_no",
        "incidnetno": "incident_no",
        "incidentno": "incident_no",
        "incident_no": "incident_no",
        "data_connecter": "data_connector",
        "dataconnecter": "data_connector",
        "priority": "priority",
        "alert_incident": "alert_incident",
        "alertincident": "alert_incident",
        "name_of_the_shift_engineer": "shift_engineer",
        "nameoftheshiftengineer": "shift_engineer",
        "handover_shift_engineer": "handover_engineer",
        "handovershiftengineer": "handover_engineer",
        "reported_time_stamp": "reported_time_stamp",
        "reportedtimestamp": "reported_time_stamp",
        "responded_time_stamp": "responded_time_stamp",
        "respondedtimestamp": "responded_time_stamp",
        "responded_time": "responded_time_stamp",
        "respondedtime": "responded_time_stamp",
        "mttd_mins": "mttd_mins",
        "mttdmins": "mttd_mins",
        "mttd": "mttd_mins",
        "resolution_time_stamp": "resolution_time_stamp",
        "resolutiontimestamp": "resolution_time_stamp",
        "mttr_mins": "mttr_mins",
        "mttrmins": "mttr_mins",
        "mttr": "mttr_mins",
        "time_to_breach_sla": "time_to_breach_sla",
        "timetobreachsla": "time_to_breach_sla",
        "remaining_mins_to_breach": "remaining_mins_to_breach",
        "remainingminstobreach": "remaining_mins_to_breach",
        "resolver_comments": "resolver_comments",
        "resolvercomments": "resolver_comments",
        "vip_users": "vip_users",
        "vipusers": "vip_users",
        "rule": "rule",
        "service_owner": "service_owner",
        "serviceowner": "service_owner",
        "status": "status",
        "remarks_comments": "remarks_comments",
        "remarkscomments": "remarks_comments",
        "false_true_positive": "false_true_positive",
        "falsetruepositive": "false_true_positive",
        "why_false_positive": "why_false_positive",
        "whyfalsepositive": "why_false_positive",
        "justification": "justification",
        "quality_audit": "quality_audit",
        "qualityaudit": "quality_audit",
        "description": "description",
    }

    if not os.path.exists(data_folder):
        os.makedirs(data_folder, exist_ok=True)
        return pd.DataFrame()

    # Read Excel files
    xlsx_files = glob.glob(os.path.join(data_folder, "*.xlsx"))
    for file in xlsx_files:
        try:
            df = pd.read_excel(file, engine="openpyxl")
            df.columns = [
                column_mapping.get(
                    standardize_column_name(col), standardize_column_name(col)
                )
                for col in df.columns
            ]
            all_data.append(df)
            print(f"Successfully loaded: {file}")
        except Exception as e:
            print(f"Error reading {file}: {e}")

    # Read CSV files
    csv_files = glob.glob(os.path.join(data_folder, "*.csv"))
    for file in csv_files:
        try:
            df = pd.read_csv(file, encoding="utf-8")
        except UnicodeDecodeError:
            try:
                df = pd.read_csv(file, encoding="latin1")
            except Exception as e:
                print(f"Error reading {file}: {e}")
                continue

        df.columns = [
            column_mapping.get(
                standardize_column_name(col), standardize_column_name(col)
            )
            for col in df.columns
        ]
        all_data.append(df)
        print(f"Successfully loaded: {file}")

    if not all_data:
        return pd.DataFrame()

    all_columns = set()
    for df in all_data:
        all_columns.update(df.columns)

    for i in range(len(all_data)):
        for col in all_columns:
            if col not in all_data[i].columns:
                all_data[i][col] = None

    final_df = pd.concat(all_data, ignore_index=True, axis=0)
    print(f"Total records loaded: {len(final_df)}")

    return final_df


def consolidate_rule_data(df: pd.DataFrame, rule_number: str) -> dict:
    """Consolidate ALL incidents for a specific rule with detailed pattern analysis."""
    if df.empty:
        return {}

    rule_clean = str(rule_number).strip()

    if "rule" in df.columns:
        rule_data = df[
            df["rule"].astype(str).str.contains(rule_clean, na=False, regex=False)
        ]
    else:
        return {}

    if rule_data.empty:
        return {}

    all_resolver_comments = []
    tp_count = 0
    fp_count = 0
    common_justifications = []
    fp_indicators = []
    tp_indicators = []

    # Analyze ALL incidents
    for _, row in rule_data.iterrows():
        comment = str(row.get("resolver_comments", "")).lower()
        if comment and comment != "n/a" and comment != "nan":
            all_resolver_comments.append(str(row.get("resolver_comments", "")))

            # Extract FP indicators
            if any(
                word in comment
                for word in [
                    "clean",
                    "legitimate",
                    "known",
                    "registered",
                    "nothing suspicious",
                ]
            ):
                fp_indicators.append(comment)

            # Extract TP indicators
            if any(
                word in comment
                for word in [
                    "malicious",
                    "suspicious",
                    "unauthorized",
                    "escalat",
                    "compromise",
                ]
            ):
                tp_indicators.append(comment)

        classification = str(row.get("false_true_positive", "")).lower()
        if "true" in classification:
            tp_count += 1
        elif "false" in classification:
            fp_count += 1

        justification = str(row.get("why_false_positive", ""))
        if justification and justification != "N/A" and justification != "nan":
            common_justifications.append(justification)

    summary = {
        "rule": rule_number,
        "total_incidents": len(rule_data),
        "true_positives": tp_count,
        "false_positives": fp_count,
        "tp_rate": (
            round(tp_count / len(rule_data) * 100, 1) if len(rule_data) > 0 else 0
        ),
        "fp_rate": (
            round(fp_count / len(rule_data) * 100, 1) if len(rule_data) > 0 else 0
        ),
        "all_resolver_comments": "\n---\n".join(all_resolver_comments),  # ALL comments
        "common_justifications": ", ".join(set(common_justifications)),
        "fp_indicators": "\n".join(set(fp_indicators)),  # Top FP patterns
        "tp_indicators": "\n".join(set(tp_indicators)),  # Top TP patterns
        "sample_incidents": rule_data.to_dict("records"),  # ALL incidents as dict
    }

    return summary
