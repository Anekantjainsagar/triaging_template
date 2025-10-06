import pandas as pd
import os
import glob
import re
import json
from datetime import datetime

def standardize_column_name(col_name: str) -> str:
    """Standardizes column names by removing special chars and whitespace."""
    col_name = str(col_name).strip().lower()
    col_name = re.sub(r'[^a-z0-9_]+', '_', col_name)
    col_name = re.sub(r'_+', '_', col_name).strip('_')
    return col_name

def read_all_tracker_sheets(data_folder: str = "data") -> pd.DataFrame:
    """Reads all tracker sheets and returns consolidated DataFrame."""
    all_data = []
    
    # Enhanced column mapping based on your data
    column_mapping = {
        's_no': 's_no',
        'sno': 's_no',
        'date': 'date',
        'month': 'month',
        'shift': 'shift',
        'incidnet_no': 'incident_no',
        'incidnetno': 'incident_no',
        'incidentno': 'incident_no',
        'incident_no': 'incident_no',
        'data_connecter': 'data_connector',
        'dataconnecter': 'data_connector',
        'priority': 'priority',
        'alert_incident': 'alert_incident',
        'alertincident': 'alert_incident',
        'name_of_the_shift_engineer': 'shift_engineer',
        'nameoftheshiftengineer': 'shift_engineer',
        'handover_shift_engineer': 'handover_engineer',
        'handovershiftengineer': 'handover_engineer',
        'reported_time_stamp': 'reported_time_stamp',
        'reportedtimestamp': 'reported_time_stamp',
        'responded_time_stamp': 'responded_time_stamp',
        'respondedtimestamp': 'responded_time_stamp',
        'responded_time': 'responded_time_stamp',
        'respondedtime': 'responded_time_stamp',
        'mttd_mins': 'mttd_mins',
        'mttdmins': 'mttd_mins',
        'mttd': 'mttd_mins',
        'resolution_time_stamp': 'resolution_time_stamp',
        'resolutiontimestamp': 'resolution_time_stamp',
        'mttr_mins': 'mttr_mins',
        'mttrmins': 'mttr_mins',
        'mttr': 'mttr_mins',
        'time_to_breach_sla': 'time_to_breach_sla',
        'timetobreachsla': 'time_to_breach_sla',
        'remaining_mins_to_breach': 'remaining_mins_to_breach',
        'remainingminstobreach': 'remaining_mins_to_breach',
        'resolver_comments': 'resolver_comments',
        'resolvercomments': 'resolver_comments',
        'vip_users': 'vip_users',
        'vipusers': 'vip_users',
        'rule': 'rule',
        'service_owner': 'service_owner',
        'serviceowner': 'service_owner',
        'status': 'status',
        'remarks_comments': 'remarks_comments',
        'remarkscomments': 'remarks_comments',
        'false_true_positive': 'false_true_positive',
        'falsetruepositive': 'false_true_positive',
        'why_false_positive': 'why_false_positive',
        'whyfalsepositive': 'why_false_positive',
        'justification': 'justification',
        'quality_audit': 'quality_audit',
        'qualityaudit': 'quality_audit',
        'description': 'description'
    }

    # Check if directory exists
    if not os.path.exists(data_folder):
        print(f"Warning: Data folder '{data_folder}' does not exist. Creating it...")
        os.makedirs(data_folder, exist_ok=True)
        return pd.DataFrame()

    # Read Excel files
    xlsx_files = glob.glob(os.path.join(data_folder, "*.xlsx"))
    for file in xlsx_files:
        try:
            df = pd.read_excel(file, engine='openpyxl')
            # Standardize columns
            df.columns = [column_mapping.get(standardize_column_name(col), standardize_column_name(col)) 
                         for col in df.columns]
            all_data.append(df)
            print(f"Successfully loaded: {file}")
        except Exception as e:
            print(f"Error reading {file}: {e}")

    # Read CSV files
    csv_files = glob.glob(os.path.join(data_folder, "*.csv"))
    for file in csv_files:
        try:
            # Try UTF-8 first
            df = pd.read_csv(file, encoding='utf-8')
        except UnicodeDecodeError:
            try:
                # Fallback to latin1
                df = pd.read_csv(file, encoding='latin1')
            except Exception as e:
                print(f"Error reading {file}: {e}")
                continue
        
        # Standardize columns
        df.columns = [column_mapping.get(standardize_column_name(col), standardize_column_name(col)) 
                     for col in df.columns]
        all_data.append(df)
        print(f"Successfully loaded: {file}")
    
    if not all_data:
        print("No data files found. Please add tracker sheets to data/tracker_sheets/")
        return pd.DataFrame()
    
    # Ensure all dataframes have same columns
    all_columns = set()
    for df in all_data:
        all_columns.update(df.columns)
    
    for i in range(len(all_data)):
        for col in all_columns:
            if col not in all_data[i].columns:
                all_data[i][col] = None
    
    # Concatenate all dataframes
    final_df = pd.concat(all_data, ignore_index=True, axis=0)
    print(f"Total records loaded: {len(final_df)}")
    
    return final_df


def search_alerts_in_data(df: pd.DataFrame, query: str, top_n: int = 5) -> list:
    """Search for alerts matching query in the dataframe."""
    if df.empty:
        return []
    
    query_lower = query.lower()
    
    # Create search score based on multiple columns
    df = df.copy()
    df['search_score'] = 0
    
    # Rule matching (highest priority)
    if 'rule' in df.columns:
        df['search_score'] += df['rule'].fillna('').astype(str).str.lower().str.contains(query_lower, regex=False).astype(int) * 10
    
    # Description matching
    if 'description' in df.columns:
        df['search_score'] += df['description'].fillna('').astype(str).str.lower().str.contains(query_lower, regex=False).astype(int) * 5
    
    # Alert/Incident type matching
    if 'alert_incident' in df.columns:
        df['search_score'] += df['alert_incident'].fillna('').astype(str).str.lower().str.contains(query_lower, regex=False).astype(int) * 5
    
    # Resolver comments matching (lower priority)
    if 'resolver_comments' in df.columns:
        df['search_score'] += df['resolver_comments'].fillna('').astype(str).str.lower().str.contains(query_lower, regex=False).astype(int) * 2
    
    # Data connector matching
    if 'data_connector' in df.columns:
        df['search_score'] += df['data_connector'].fillna('').astype(str).str.lower().str.contains(query_lower, regex=False).astype(int) * 3
    
    # Get top matches
    top_matches = df[df['search_score'] > 0].nlargest(min(top_n * 3, len(df)), 'search_score')
    
    # Format results - group by rule
    results = []
    seen_rules = set()
    
    for _, row in top_matches.iterrows():
        rule = str(row.get('rule', 'Unknown Rule'))
        incident = str(row.get('incident_no', 'N/A'))
        
        # Create alert entry
        if rule not in seen_rules:
            alert_key = f"{rule} - Incident {incident}"
            results.append(alert_key)
            seen_rules.add(rule)
        
        if len(results) >= top_n:
            break
    
    return results


def consolidate_rule_data(df: pd.DataFrame, rule_number: str) -> dict:
    """Consolidate ALL incidents for a specific rule to learn patterns."""
    if df.empty:
        return {}
    
    # Clean rule number
    rule_clean = str(rule_number).strip()
    
    # Find all rows matching the rule
    if 'rule' in df.columns:
        rule_data = df[df['rule'].astype(str).str.contains(rule_clean, na=False, regex=False)]
    else:
        return {}
    
    if rule_data.empty:
        print(f"No historical data found for rule: {rule_number}")
        return {}
    
    print(f"Found {len(rule_data)} historical incidents for {rule_number}")
    
    # Aggregate insights from all incidents
    all_resolver_comments = []
    tp_count = 0
    fp_count = 0
    common_justifications = []
    
    for _, row in rule_data.iterrows():
        # Collect resolver comments
        comment = str(row.get('resolver_comments', ''))
        if comment and comment != 'N/A' and comment != 'nan':
            all_resolver_comments.append(comment)
        
        # Count TP/FP
        classification = str(row.get('false_true_positive', '')).lower()
        if 'true' in classification:
            tp_count += 1
        elif 'false' in classification:
            fp_count += 1
        
        # Collect justifications
        justification = str(row.get('why_false_positive', ''))
        if justification and justification != 'N/A' and justification != 'nan':
            common_justifications.append(justification)
    
    # Create summary
    summary = {
        'rule': rule_number,
        'total_incidents': len(rule_data),
        'true_positives': tp_count,
        'false_positives': fp_count,
        'tp_rate': round(tp_count / len(rule_data) * 100, 1) if len(rule_data) > 0 else 0,
        'fp_rate': round(fp_count / len(rule_data) * 100, 1) if len(rule_data) > 0 else 0,
        'all_resolver_comments': '\n---\n'.join(all_resolver_comments[:10]),  # Last 10
        'common_justifications': ', '.join(set(common_justifications)),
        'sample_incidents': rule_data.head(5).to_dict('records')
    }
    
    return summary

def consolidate_incident_data(df: pd.DataFrame, incident_id: str) -> dict:
    """Consolidate all data for a specific incident."""
    if df.empty:
        return {}
    
    # Clean the incident ID for matching
    incident_id_clean = str(incident_id).strip()
    
    # Find all rows matching the incident
    if 'incident_no' in df.columns:
        # Try exact match first
        incident_data = df[df['incident_no'].astype(str).str.strip() == incident_id_clean]
        
        # If no exact match, try contains
        if incident_data.empty:
            incident_data = df[df['incident_no'].astype(str).str.contains(incident_id_clean, na=False, regex=False)]
    else:
        return {}
    
    if incident_data.empty:
        print(f"No data found for incident: {incident_id}")
        return {}
    
    # Get the first (or only) row
    consolidated = incident_data.iloc[0].to_dict()
    
    # Clean None/NaN values and convert to strings
    consolidated = {k: (str(v) if pd.notna(v) and str(v) != 'nan' and str(v) != '' else 'N/A') 
                   for k, v in consolidated.items()}
    
    print(f"Consolidated data for incident {incident_id}: {len(consolidated)} fields")
    
    return consolidated


def get_triaging_template(rule_number: str) -> str:
    """Find and read the triaging template for a rule."""
    template_dir = "data/triaging_templates"
    
    # Create directory if it doesn't exist
    if not os.path.exists(template_dir):
        os.makedirs(template_dir, exist_ok=True)
    
    # Clean rule number
    rule_clean = rule_number.replace('#', '').replace('Rule', '').strip()
    
    # Try different file formats and naming conventions
    possible_names = [
        f"{rule_number}",
        f"Rule{rule_clean}",
        f"Rule#{rule_clean}",
        rule_clean
    ]
    
    for name in possible_names:
        for ext in ['.txt', '.md', '.xlsx', '.csv']:
            template_path = os.path.join(template_dir, f"{name}{ext}")
            
            if os.path.exists(template_path):
                print(f"Found template: {template_path}")
                
                if ext in ['.txt', '.md']:
                    with open(template_path, 'r', encoding='utf-8') as f:
                        return f.read()
                elif ext == '.xlsx':
                    df = pd.read_excel(template_path)
                    return df.to_string()
                elif ext == '.csv':
                    df = pd.read_csv(template_path)
                    return df.to_string()
    
    # Return generic template if not found
    print(f"No template found for {rule_number}. Using generic template.")
    return generate_generic_template(rule_number)


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


def generate_completed_template(incident_data: dict, triaging_output: dict, final_prediction: dict) -> str:
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
    
    # Add each triaging step
    for i, (step_name, findings) in enumerate(triaging_output.items(), 1):
        template += f"\nStep {i}: {step_name}\n"
        template += "-" * 80 + "\n"
        template += f"{findings}\n"
    
    # Add AI prediction
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