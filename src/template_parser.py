import pandas as pd
import re
from typing import List, Dict

class TemplateParser:
    """Deterministic parser that extracts steps from CSV/Excel templates"""
    
    def parse_csv_template(self, csv_path: str) -> List[Dict]:
        """Parse CSV template"""
        print(f"\n📖 Parsing CSV template: {csv_path}")
        
        # Try different encodings
        df = None
        for encoding in ['utf-8', 'latin1', 'cp1252']:
            try:
                df = pd.read_csv(csv_path, encoding=encoding)
                print(f"✅ Successfully read CSV with {encoding} encoding")
                break
            except Exception as e:
                print(f"❌ Failed with {encoding}: {str(e)}")
                continue
        
        if df is None:
            print("❌ Could not read CSV with any encoding")
            return []
        
        return self._extract_steps_from_dataframe(df)
    
    def parse_excel_template(self, excel_path: str) -> List[Dict]:
        """Parse Excel template"""
        print(f"\n📖 Parsing Excel template: {excel_path}")
        
        try:
            df = pd.read_excel(excel_path, engine='openpyxl')
            print(f"✅ Successfully read Excel file")
            return self._extract_steps_from_dataframe(df)
        except Exception as e:
            print(f"❌ Failed to read Excel: {str(e)}")
            return []
    
    def _extract_steps_from_dataframe(self, df: pd.DataFrame) -> List[Dict]:
        """Extract investigation steps from DataFrame"""
        
        # Clean column names
        df.columns = df.columns.str.strip()
        
        print(f"\n📊 DataFrame columns: {list(df.columns)}")
        print(f"📏 DataFrame shape: {df.shape}")
        
        # Identify key columns (case-insensitive)
        input_col = self._find_column(df, ['Inputs Required', 'Input Required', 'Step Name', 'Name'])
        instruction_col = self._find_column(df, ['Instructions', 'Instruction', 'Details', 'Description'])
        example_col = self._find_column(df, ['INPUT details', 'Input Details', 'Example', 'Sample'])
        
        print(f"✅ Found columns - Input: {input_col}, Instructions: {instruction_col}, Example: {example_col}")
        
        if not input_col:
            print("❌ Could not find 'Inputs Required' column")
            return []
        
        steps = []
        
        for idx, row in df.iterrows():
            step_name = str(row.get(input_col, '')).strip()
            
            # Skip if empty, header, or rule description
            if (not step_name or 
                step_name == 'nan' or 
                len(step_name) < 3 or
                'Rule#' in step_name or
                'Sr.No' in step_name):
                continue
            
            instructions = str(row.get(instruction_col, '')).strip() if instruction_col else ""
            example = str(row.get(example_col, '')).strip() if example_col else ""
            
            # Clean up nan values
            if instructions == 'nan':
                instructions = f"Complete {step_name}"
            if example == 'nan':
                example = ""
            
            print(f"\n📋 Extracted Step: {step_name}")
            
            # Generate KQL query
            kql_query = self._generate_kql_for_step(step_name, instructions, example)
            
            # Build expected output
            expected_output = self._build_expected_output(step_name, example, instructions)
            
            steps.append({
                "step_name": step_name,
                "explanation": instructions,
                "kql_query": kql_query,
                "expected_output": expected_output,
                "user_input_required": True,
                "example_finding": example
            })
        
        print(f"\n✅ Total steps extracted: {len(steps)}")
        return steps
    
    def _find_column(self, df: pd.DataFrame, possible_names: List[str]) -> str:
        """Find column by trying multiple possible names (case-insensitive)"""
        for col in df.columns:
            for possible in possible_names:
                if possible.lower() in col.lower():
                    return col
        return None
    
    def _generate_kql_for_step(self, step_name: str, instructions: str, example: str) -> str:
        """Generate appropriate KQL query based on step"""
        
        step_lower = step_name.lower()
        instructions_lower = instructions.lower()
        
        # Rule #183 - Detect Passwordless Authentication
        if 'kql' in step_lower or 'run' in step_lower and 'query' in instructions_lower:
            return """SigninLogs
| where TimeGenerated > ago(7d)
| where AuthenticationRequirement == "singleFactorAuthentication"
| mv-expand todynamic(AuthenticationDetails)
| extend AuthMethod = tostring(AuthenticationDetails.authenticationMethod)
| where AuthMethod in ("FIDO2 security key", "Passwordless phone sign-in", "Windows Hello for Business")
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, AuthMethod, DeviceDetail
| order by TimeGenerated desc"""
        
        # Rule #280 / Rule #286 - Atypical Travel
        if 'sign' in step_lower and 'log' in step_lower:
            return """SigninLogs
| where UserPrincipalName == "<USER_EMAIL>"
| where TimeGenerated > ago(7d)
| project TimeGenerated, IPAddress, Location, AppDisplayName, DeviceDetail, AuthenticationRequirement
| order by TimeGenerated desc"""
        
        # IP reputation check
        if 'ip' in step_lower or 'reputation' in instructions_lower:
            return """SigninLogs
| where UserPrincipalName == "<USER_EMAIL>"
| where TimeGenerated > ago(7d)
| distinct IPAddress
| project IPAddress"""
        
        # User activity
        if 'user' in step_lower and 'activity' in step_lower:
            return """SigninLogs
| where UserPrincipalName == "<USER_EMAIL>"
| where TimeGenerated > ago(30d)
| summarize 
    LoginCount = count(),
    UniqueIPs = dcount(IPAddress),
    UniqueLocations = dcount(Location)
by UserPrincipalName"""
        
        # VIP check
        if 'vip' in step_lower:
            return "// Check against VIP user list"
        
        # Role assignment (Rule #14)
        if 'role' in step_lower or 'privileged' in step_lower:
            return """AuditLogs
| where OperationName == "Add member to role"
| where TimeGenerated > ago(7d)
| project TimeGenerated, Identity, TargetResources, InitiatedBy
| order by TimeGenerated desc"""
        
        return ""
    
    def _build_expected_output(self, step_name: str, example: str, instructions: str) -> str:
        """Build expected output"""
        
        # If we have a real example from template, use it
        if example and len(example) > 10:
            return f"Typically shows: {example}"
        
        step_lower = step_name.lower()
        instructions_lower = instructions.lower()
        
        # Pattern matching for expected outputs
        if 'ip' in step_lower:
            return "Typically shows: Clean IP, No malicious reputation, Known IP range. If found → False Positive."
        elif 'device' in step_lower:
            return "Typically shows: Known device, Registered device, Corporate device. If found → False Positive."
        elif 'vip' in step_lower:
            return "Expected: Yes/No based on VIP user list check."
        elif 'mfa' in step_lower:
            return "Typically shows: MFA successful, MFA enabled. If found → False Positive."
        elif 'user' in step_lower and 'confirm' in step_lower:
            return "Typically shows: User confirmed legitimate activity. If found → False Positive."
        elif 'application' in step_lower or 'app' in step_lower:
            return "Typically shows: Known applications, Approved apps. If found → False Positive."
        elif 'escalat' in step_lower or 'escalat' in instructions_lower:
            return "Decision: Escalate if True Positive confirmed, else close as False Positive."
        else:
            return "Document investigation findings."