import pandas as pd
import os
import glob
import re
import json
from datetime import datetime
from io import BytesIO


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


def export_rule_incidents_to_excel(df: pd.DataFrame, rule_number: str) -> BytesIO:
    """
    Export all incidents related to a specific rule to Excel format.
    Returns BytesIO object for Streamlit download.
    """
    rule_clean = str(rule_number).strip()

    # Filter data for the specific rule
    if "rule" in df.columns:
        rule_data = df[
            df["rule"].astype(str).str.contains(rule_clean, na=False, regex=False)
        ].copy()
    else:
        rule_data = pd.DataFrame()

    if rule_data.empty:
        # Create empty dataframe with expected columns
        rule_data = pd.DataFrame(columns=df.columns)

    # Sort by date (most recent first)
    if "reported_time_stamp" in rule_data.columns:
        rule_data = rule_data.sort_values("reported_time_stamp", ascending=False)

    # Create Excel file in memory
    output = BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        rule_data.to_excel(writer, sheet_name="Incidents", index=False)

        # Create summary sheet
        summary_data = {
            "Metric": [
                "Total Incidents",
                "True Positives",
                "False Positives",
                "TP Rate (%)",
                "FP Rate (%)",
                "Average MTTD (mins)",
                "Average MTTR (mins)",
            ],
            "Value": [
                len(rule_data),
                len(
                    rule_data[
                        rule_data["false_true_positive"]
                        .astype(str)
                        .str.contains("True", na=False, case=False)
                    ]
                ),
                len(
                    rule_data[
                        rule_data["false_true_positive"]
                        .astype(str)
                        .str.contains("False", na=False, case=False)
                    ]
                ),
                (
                    round(
                        len(
                            rule_data[
                                rule_data["false_true_positive"]
                                .astype(str)
                                .str.contains("True", na=False, case=False)
                            ]
                        )
                        / len(rule_data)
                        * 100,
                        2,
                    )
                    if len(rule_data) > 0
                    else 0
                ),
                (
                    round(
                        len(
                            rule_data[
                                rule_data["false_true_positive"]
                                .astype(str)
                                .str.contains("False", na=False, case=False)
                            ]
                        )
                        / len(rule_data)
                        * 100,
                        2,
                    )
                    if len(rule_data) > 0
                    else 0
                ),
                (
                    round(
                        pd.to_numeric(rule_data["mttd_mins"], errors="coerce").mean(), 2
                    )
                    if "mttd_mins" in rule_data.columns
                    else 0
                ),
                (
                    round(
                        pd.to_numeric(rule_data["mttr_mins"], errors="coerce").mean(), 2
                    )
                    if "mttr_mins" in rule_data.columns
                    else 0
                ),
            ],
        }
        summary_df = pd.DataFrame(summary_data)
        summary_df.to_excel(writer, sheet_name="Summary", index=False)

    output.seek(0)
    return output


def search_alerts_in_data(df: pd.DataFrame, query: str, top_n: int = 5) -> list:
    """Search for alerts matching query in the dataframe."""
    if df.empty:
        return []

    query_lower = query.lower()
    df = df.copy()
    df["search_score"] = 0

    if "rule" in df.columns:
        df["search_score"] += (
            df["rule"]
            .fillna("")
            .astype(str)
            .str.lower()
            .str.contains(query_lower, regex=False)
            .astype(int)
            * 10
        )

    if "description" in df.columns:
        df["search_score"] += (
            df["description"]
            .fillna("")
            .astype(str)
            .str.lower()
            .str.contains(query_lower, regex=False)
            .astype(int)
            * 5
        )

    if "alert_incident" in df.columns:
        df["search_score"] += (
            df["alert_incident"]
            .fillna("")
            .astype(str)
            .str.lower()
            .str.contains(query_lower, regex=False)
            .astype(int)
            * 5
        )

    if "resolver_comments" in df.columns:
        df["search_score"] += (
            df["resolver_comments"]
            .fillna("")
            .astype(str)
            .str.lower()
            .str.contains(query_lower, regex=False)
            .astype(int)
            * 2
        )

    if "data_connector" in df.columns:
        df["search_score"] += (
            df["data_connector"]
            .fillna("")
            .astype(str)
            .str.lower()
            .str.contains(query_lower, regex=False)
            .astype(int)
            * 3
        )

    top_matches = df[df["search_score"] > 0].nlargest(
        min(top_n * 3, len(df)), "search_score"
    )

    results = []
    seen_rules = set()

    for _, row in top_matches.iterrows():
        rule = str(row.get("rule", "Unknown Rule"))
        incident = str(row.get("incident_no", "N/A"))

        if rule not in seen_rules:
            alert_key = f"{rule} - Incident {incident}"
            results.append(alert_key)
            seen_rules.add(rule)

        if len(results) >= top_n:
            break

    return results


def consolidate_incident_data(df: pd.DataFrame, incident_id: str) -> dict:
    """Consolidate all data for a specific incident."""
    if df.empty:
        return {}

    incident_id_clean = str(incident_id).strip()

    if "incident_no" in df.columns:
        incident_data = df[
            df["incident_no"].astype(str).str.strip() == incident_id_clean
        ]

        if incident_data.empty:
            incident_data = df[
                df["incident_no"]
                .astype(str)
                .str.contains(incident_id_clean, na=False, regex=False)
            ]
    else:
        return {}

    if incident_data.empty:
        return {}

    consolidated = incident_data.iloc[0].to_dict()
    consolidated = {
        k: (str(v) if pd.notna(v) and str(v) != "nan" and str(v) != "" else "N/A")
        for k, v in consolidated.items()
    }

    return consolidated


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


def get_triaging_template(rule_number: str) -> str:
    """Find and read the triaging template for a rule - IMPROVED VERSION."""
    template_dir = "data/triaging_templates"

    print(f"\n{'='*80}")
    print(f"SEARCHING FOR TRIAGING TEMPLATE: {rule_number}")
    print(f"{'='*80}")

    if not os.path.exists(template_dir):
        os.makedirs(template_dir, exist_ok=True)
        return generate_generic_template(rule_number)

    # Extract rule number
    rule_num_match = re.search(r"#?(\d+)", rule_number)
    rule_num_only = (
        rule_num_match.group(1)
        if rule_num_match
        else rule_number.replace("#", "").strip()
    )

    # Find matching template file
    all_files = os.listdir(template_dir)
    matched_files = [f for f in all_files if rule_num_only in f]

    if not matched_files:
        print(f"No template found for rule {rule_num_only}")
        return generate_generic_template(rule_number)

    template_file = matched_files[0]
    template_path = os.path.join(template_dir, template_file)
    file_ext = os.path.splitext(template_file)[1].lower()

    print(f"Ã¢Å“â€¦ TEMPLATE FOUND: {template_file}")

    try:
        if file_ext == ".csv":
            # Parse CSV template and return STRUCTURED format
            return parse_csv_template_to_structured_text(template_path)
        elif file_ext == ".xlsx":
            df = pd.read_excel(template_path)
            return parse_csv_template_to_structured_text(df)
        else:
            with open(template_path, "r", encoding="utf-8") as f:
                return f.read()
    except Exception as e:
        print(f"Error reading template: {str(e)}")
        return generate_generic_template(rule_number)


def parse_csv_template_to_structured_text(csv_path: str) -> str:
    """
    Parse CSV template into structured text that LLM can understand.
    Extracts the LOGICAL FLOW and CONTEXT between steps.
    """
    # Try multiple encodings
    df = None
    for encoding in ["utf-8", "latin1", "cp1252"]:
        try:
            df = pd.read_csv(csv_path, encoding=encoding)
            break
        except:
            continue

    if df is None:
        return "Template parsing failed"

    # Clean column names
    df.columns = df.columns.str.strip()

    structured_template = "# TRIAGING TEMPLATE STRUCTURE\n\n"
    structured_template += "## IMPORTANT: Follow this EXACT sequential logic\n\n"

    current_step = 1
    previous_step_context = ""

    for idx, row in df.iterrows():
        # Skip header rows or empty rows
        if pd.isna(row.get("Inputs Required", "")) or "Rule#" in str(
            row.get("Inputs Required", "")
        ):
            continue

        sr_no = str(row.get("Sr.No.", current_step)).strip()
        input_required = str(row.get("Inputs Required", "")).strip()
        instructions = str(row.get("Instructions", "")).strip()
        input_details = str(row.get("INPUT details", "")).strip()

        if not input_required or input_required == "nan":
            continue

        # Build structured step with CONTEXT
        structured_template += f"\n---\n"
        structured_template += f"STEP_{sr_no}: {input_required}\n\n"

        # Add context from previous step if applicable
        if previous_step_context:
            structured_template += (
                f"CONTEXT_FROM_PREVIOUS_STEP: {previous_step_context}\n\n"
            )

        structured_template += f"INSTRUCTIONS: {instructions}\n\n"

        if input_details and input_details != "nan" and input_details != "NA":
            structured_template += f"EXAMPLE_OUTPUT: {input_details}\n\n"
            # Store this as context for next step
            previous_step_context = (
                f"Based on '{input_required}', the result was: {input_details}"
            )

        # Extract conditional logic if present
        if "if" in instructions.lower() or "then" in instructions.lower():
            structured_template += (
                f"CONDITIONAL_LOGIC: This step contains decision points\n"
            )

        if "yes" in instructions.lower() and "no" in instructions.lower():
            structured_template += (
                f"BRANCHING: This step has YES/NO outcomes that affect next steps\n"
            )

        current_step += 1

    structured_template += "\n---\n"
    structured_template += "\n## KEY PATTERNS TO LEARN:\n"
    structured_template += "1. Each step builds on previous findings\n"
    structured_template += "2. Conditional logic determines next actions\n"
    structured_template += "3. User inputs guide investigation direction\n"
    structured_template += "4. Final classification depends on cumulative evidence\n"

    return structured_template


def generate_generic_template(rule_number: str) -> str:
    """Generate a generic triaging template."""
    return f"""
# Generic Security Incident Triaging Template
# Rule: {rule_number}

## Incident Overview
- Incident Number: [To be filled]
- Reported Time: [To be filled]
- Priority: [To be filled]
- Data Connector: [To be filled]

## Investigation Steps

### 1. Initial Triage
- Review alert details
- Identify affected user(s)
- Check incident priority

### 2. IP Reputation Check
- Source IP address(es):
- Reputation status:
- Geolocation:

### 3. User Behavior Analysis
- User sign-in history:
- Known devices:
- Typical locations:
- MFA status:

### 4. Application & Service Review
- Applications accessed:
- Services used:
- Unusual activity:

### 5. Historical Context
- Previous incidents:
- Pattern analysis:
- False positive history:

## Final Assessment
- Classification: [ ] True Positive  [ ] False Positive  [ ] Benign Positive
- Justification:
- Escalation: [ ] Yes  [ ] No
- Actions taken:

## Resolver Comments
[Document your findings here]
"""


def generate_completed_template(
    incident_data: dict, triaging_output: dict, final_prediction: dict
) -> str:
    """Generate the completed triaging template with all findings."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    template = f"""
================================================================================
SECURITY INCIDENT TRIAGING REPORT
Generated: {timestamp}
================================================================================

INCIDENT DETAILS
--------------------------------------------------------------------------------
Incident Number:        {incident_data.get('incident_no', 'N/A')}
Rule:                   {incident_data.get('rule', 'N/A')}
Priority:               {incident_data.get('priority', 'N/A')}
Data Connector:         {incident_data.get('data_connector', 'N/A')}
Reported Time:          {incident_data.get('reported_time_stamp', 'N/A')}
Responded Time:         {incident_data.get('responded_time_stamp', 'N/A')}
Resolution Time:        {incident_data.get('resolution_time_stamp', 'N/A')}
MTTD:                   {incident_data.get('mttd_mins', 'N/A')} minutes
MTTR:                   {incident_data.get('mttr_mins', 'N/A')} minutes
Shift Engineer:         {incident_data.get('shift_engineer', 'N/A')}
VIP Users Involved:     {incident_data.get('vip_users', 'No')}

TRIAGING INVESTIGATION STEPS
--------------------------------------------------------------------------------
"""

    for i, (step_name, findings) in enumerate(triaging_output.items(), 1):
        template += f"\nStep {i}: {step_name}\n"
        template += "-" * 80 + "\n"
        template += f"{findings}\n"

    template += f"""
AI ANALYSIS & PREDICTION
--------------------------------------------------------------------------------
Final Classification:   {final_prediction.get('prediction', 'N/A')}
Confidence Level:       {final_prediction.get('confidence_score', 'N/A')}
Reasoning:              {final_prediction.get('reasoning', 'N/A')}

HISTORICAL CONTEXT
--------------------------------------------------------------------------------
Previous Classification: {incident_data.get('false_true_positive', 'N/A')}
Why False Positive:      {incident_data.get('why_false_positive', 'N/A')}
Justification:           {incident_data.get('justification', 'N/A')}
Quality Audit:           {incident_data.get('quality_audit', 'N/A')}

ORIGINAL RESOLVER COMMENTS
--------------------------------------------------------------------------------
{incident_data.get('resolver_comments', 'N/A')}

================================================================================
END OF REPORT
================================================================================
"""

    return template
