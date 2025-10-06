import pandas as pd
import os
import glob
import re

def standardize_column_name(col_name: str) -> str:
    """
    Standardizes a column name by converting to lowercase, removing non-alphanumeric characters,
    and replacing spaces with underscores.
    """
    col_name = col_name.strip().lower()
    # Replace non-alphanumeric characters (except underscore) with nothing
    col_name = re.sub(r'[^a-z0-9_]+', '', col_name) 
    return col_name

def read_all_tracker_sheets(data_folder: str) -> pd.DataFrame:
    """
    Reads all .xlsx and .csv files, standardizes column names, and concatenates them.

    Args:
        data_folder (str): The path to the folder containing tracker sheets.

    Returns:
        pd.DataFrame: A single DataFrame with all data concatenated and columns standardized.
    """
    all_data = []

    # A single, comprehensive column mapping to standardize all dataframes
    # This mapping is based on the data you provided.
    column_mapping = {
        'incidnetno': 'incident',
        'dataconnecter': 'dataconnecter', # Keep original name for now
        'alertincident': 'alert_incident',
        'reportedtimestamp': 'reported_time_stamp',
        'respondedtime': 'responded_time_stamp',
        'mttd': 'mttd_mins',
        'resolutiontimestamp': 'resolution_time_stamp',
        'mttr': 'mttr_mins',
        'timetobreachsla': 'time_to_breach_sla',
        'remainingminstobreach': 'remaining_mins_to_breach',
        'resolvercomments': 'resolver_comments',
        'vipusers': 'vip_users',
        'shortincidentdescription': 'description', # This is the key fix
        'serviceowner': 'service_owner',
        'status': 'status',
        'remarkscomments': 'remarks_comments',
        'falsetruepositive': 'false_true_positive',
        'templateavailable': 'template_available',
        'qualityaudit': 'quality_audit'
    }

    # Read all .xlsx files
    xlsx_files = glob.glob(os.path.join(data_folder, "*.xlsx"))
    for file in xlsx_files:
        try:
            xls_dict = pd.read_excel(file, sheet_name=None, engine='openpyxl')
            for _, df in xls_dict.items():
                df.columns = [column_mapping.get(standardize_column_name(col), standardize_column_name(col)) for col in df.columns]
                all_data.append(df)
        except Exception as e:
            print(f"Error reading Excel file {file}: {e}")

    # Read all .csv files
    csv_files = glob.glob(os.path.join(data_folder, "*.csv"))
    for file in csv_files:
        try:
            df = pd.read_csv(file, encoding='utf-8')
        except UnicodeDecodeError:
            try:
                df = pd.read_csv(file, encoding='latin1')
            except Exception as e:
                print(f"Error reading CSV file {file}: {e}")
                continue
        except Exception as e:
            print(f"Error reading CSV file {file}: {e}")
            continue

        df.columns = [column_mapping.get(standardize_column_name(col), standardize_column_name(col)) for col in df.columns]
        all_data.append(df)
    
    if all_data:
        # Before concatenating, ensure all dataframes have the same columns to avoid errors
        all_columns = set()
        for df in all_data:
            all_columns.update(df.columns)

        for i in range(len(all_data)):
            for col in all_columns:
                if col not in all_data[i].columns:
                    all_data[i][col] = None
        
        return pd.concat(all_data, ignore_index=True, axis=0)
    else:
        return pd.DataFrame()


def get_triaging_template(rule_number: str) -> str:
    """
    Finds and returns the path to a triaging template based on the rule number.
    
    Args:
        rule_number (str): The rule number (e.g., "Rule#280").
        
    Returns:
        str: The path to the template file.
        
    Raises:
        FileNotFoundError: If no matching template is found.
    """
    template_path = os.path.join("data", "triaging_templates", f"{rule_number}.txt")
    if os.path.exists(template_path):
        return template_path
    else:
        raise FileNotFoundError(f"Template for {rule_number} not found at {template_path}")

def create_and_save_excel(df: pd.DataFrame, incident_id: str):
    """
    Saves a pandas DataFrame to a new Excel file.
    
    Args:
        df (pd.DataFrame): The DataFrame to save.
        incident_id (str): The incident ID to use in the filename.
    """
    output_dir = "consolidated_data"
    os.makedirs(output_dir, exist_ok=True)
    filename = os.path.join(output_dir, f"consolidated_INC_{incident_id}.xlsx")
    df.to_excel(filename, index=False)
    return filename

def generate_empty_template():
    """Generates the structure for an empty triaging template."""
    return """
Incident Details:
- Incident Number:
- Reported Time:
- Affected User(s):

Triaging Steps:
1. Step Name: 
   - Instructions: 
   - Required Data:
2. Step Name:
   - Instructions:
   - Required Data:

Prediction and Analysis:
- Based on data from Step 1, the likelihood of a TP is...
- Based on data from Step 2, the likelihood of a FP is...

Final Verdict:
- True Positive (TP) / False Positive (FP) / Benign Positive (BP):
- Justification:
- Escalation Required: Yes/No
    - If Yes, to which team:
"""

def generate_final_template(user_inputs: dict): 
    """Fills the empty template with user-provided data."""
    template = generate_empty_template()
    # Logic to replace placeholders with user_inputs data
    final_template = template
    return final_template