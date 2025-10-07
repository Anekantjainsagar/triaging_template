import pandas as pd
import re
from typing import List, Dict

class TemplateParser:
    """Deterministic parser that extracts steps from CSV/Excel templates"""
    
    def parse_csv_template(self, csv_path: str) -> List[Dict]:
        """Parse CSV template"""
        print(f"\n📖 Parsing CSV template: {csv_path}")
        
        df = None
        for encoding in ['utf-8', 'latin1', 'cp1252']:
            try:
                df = pd.read_csv(csv_path, encoding=encoding)
                print(f"✅ Successfully read CSV with {encoding} encoding")
                break
            except Exception as e:
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
        """Extract investigation steps from DataFrame - FIXED VERSION"""
        
        df.columns = df.columns.str.strip()
        
        print(f"\n📊 DataFrame columns: {list(df.columns)}")
        print(f"🔍 DataFrame shape: {df.shape}")
        
        # Identify columns
        step_col = self._find_column(df, ['Step Name', 'Inputs Required', 'Step', 'Name'])
        explanation_col = self._find_column(df, ['Explanation', 'Instructions', 'Instruction'])
        input_col = self._find_column(df, ['Input', 'Input Required', 'Inputs'])
        kql_col = self._find_column(df, ['KQL Query', 'KQL', 'Query'])
        remarks_col = self._find_column(df, ['Remarks', 'Remarks/Comments', 'Comments', 'Expected Output'])
        
        print(f"✅ Columns - Step: {step_col}, Explanation: {explanation_col}, Input: {input_col}, KQL: {kql_col}")
        
        if not step_col:
            print("❌ Could not find step name column")
            return []
        
        steps = []
        
        for idx, row in df.iterrows():
            step_name = str(row.get(step_col, '')).strip()
            
            # ⭐ CRITICAL: Skip metadata rows (not investigation steps)
            if self._is_metadata_row(step_name):
                print(f"⏭️  Skipping metadata row: {step_name}")
                continue
            
            # Skip empty or invalid rows
            if not step_name or step_name == 'nan' or len(step_name) < 3:
                continue
            
            # ⭐ Only include ACTIONABLE investigation steps
            if not self._is_investigation_step(step_name):
                print(f"⏭️  Skipping non-investigation row: {step_name}")
                continue
            
            # Extract data from columns
            explanation = str(row.get(explanation_col, '')).strip() if explanation_col else ""
            input_required = str(row.get(input_col, '')).strip() if input_col else ""
            kql_query = str(row.get(kql_col, '')).strip() if kql_col else ""
            remarks = ""
            
            # Clean 'nan' values
            if explanation == 'nan' or not explanation:
                explanation = self._generate_explanation(step_name, remarks)
            if input_required == 'nan':
                input_required = self._extract_inputs(step_name, explanation)
            if kql_query == 'nan':
                kql_query = ""
            if remarks == 'nan':
                remarks = ""
            
            # ⭐ Generate proper KQL query (parameterized, not hardcoded)
            kql_query = self._generate_kql_for_step(step_name, explanation, kql_query)
            
            # ⭐ Build expected output
            expected_output = self._build_expected_output(step_name, remarks, explanation)
            
            print(f"\n📋 Extracted Step: {step_name}")
            print(f"   Has KQL: {'Yes' if kql_query else 'No'}")
            print(f"   Has Explanation: {'Yes' if explanation else 'No'}")
            
            steps.append({
                "step_name": step_name,
                "explanation": explanation,
                "input_required": input_required,
                "kql_query": kql_query,
                "expected_output": expected_output,
                "user_input_required": True
            })
        
        print(f"\n✅ Total actionable steps extracted: {len(steps)}")
        return steps
    
    def _is_metadata_row(self, step_name: str) -> bool:
        """Check if this is a metadata row (not an investigation step)"""
        metadata_keywords = [
            'incident', 'reported time', 'provide the username', 'username which are involved',
            'rule#', 'rule analysis', 'historical reference', 'vips users', 'vip users',
            'user account details', 'total historical', 'false positive rate', 'true positive rate'
        ]
        
        step_lower = step_name.lower()
        
        # Check for exact matches or patterns
        for keyword in metadata_keywords:
            if keyword in step_lower:
                return True
        
        # Check if it's just a number or date
        if re.match(r'^\d+$', step_name):
            return True
        
        # Check if it's a timestamp
        if re.match(r'\d{2}-\d{2}-\d{4}', step_name):
            return True
        
        return False
    
    def _is_investigation_step(self, step_name: str) -> bool:
        """Check if this is a real investigation step"""
        step_lower = step_name.lower()
        
        # Investigation step indicators
        investigation_keywords = [
            'run', 'check', 'verify', 'review', 'analyze', 'investigate', 
            'query', 'collect', 'confirm', 'contact', 'assess', 'document',
            'escalat', 'classification', 'justification', 'kql', 'sign in log',
            'ip reputation', 'device', 'mfa', 'authentication'
        ]
        
        return any(keyword in step_lower for keyword in investigation_keywords)
    
    def _generate_explanation(self, step_name: str, remarks: str) -> str:
        """Generate explanation if missing"""
        step_lower = step_name.lower()
        
        # Generate based on step name
        if 'kql' in step_lower or 'query' in step_lower:
            return "Run the KQL query to retrieve sign-in logs and authentication details. Analyze the results for suspicious patterns or legitimate activity indicators."
        elif 'ip' in step_lower and 'reputation' in step_lower:
            return "Check the source IP address reputation using threat intelligence tools. Clean IP with no alerts indicates legitimate activity (False Positive)."
        elif 'user confirmation' in step_lower:
            return "Contact the user to verify if they recognize the activity. User confirmation of legitimate activity supports False Positive classification."
        elif 'device' in step_lower:
            return "Verify if the device used is registered and known to the user. Known devices with proper enrollment indicate legitimate access."
        elif 'mfa' in step_lower or 'authentication' in step_lower:
            return "Check multi-factor authentication status. Successful MFA completion indicates legitimate user access."
        elif 'collect' in step_lower and 'info' in step_lower:
            return "Gather key information from logs including username, application, user agent, and timestamp for analysis."
        elif 'escalat' in step_lower:
            return "Determine escalation path based on findings. Escalate to IT Team or L3 SOC if True Positive is confirmed."
        elif 'classification' in step_lower:
            return "Classify the incident as True Positive, False Positive, or Benign Positive based on all investigation findings."
        elif 'justification' in step_lower:
            return "Provide detailed justification for the classification, referencing specific findings from investigation steps."
        elif 'confidence' in step_lower:
            return "Assess confidence level (High/Medium/Low) based on the quality and completeness of evidence gathered."
        else:
            return f"Complete {step_name} and document findings."
    
    def _extract_inputs(self, step_name: str, explanation: str) -> str:
        """Extract what inputs are required"""
        step_lower = step_name.lower()
        
        if 'kql' in step_lower or 'sign in' in step_lower or 'log' in step_lower:
            return "User principal name (email)"
        elif 'ip' in step_lower:
            return "Source IP address"
        elif 'device' in step_lower:
            return "Device ID or device name"
        elif 'user confirmation' in step_lower:
            return "User contact information"
        elif 'classification' in step_lower:
            return "All investigation findings"
        else:
            return "Investigation findings from previous steps"
    
    def _find_column(self, df: pd.DataFrame, possible_names: List[str]) -> str:
        """Find column by trying multiple possible names (case-insensitive)"""
        for col in df.columns:
            for possible in possible_names:
                if possible.lower() in col.lower():
                    return col
        return None
    
    def _generate_kql_for_step(self, step_name: str, explanation: str, existing_kql: str) -> str:
        """Generate PARAMETERIZED KQL query (no hardcoded values)"""
        
        # If existing KQL is valid, clean and use it
        if existing_kql and len(existing_kql) > 20 and existing_kql != 'nan':
            # Remove hardcoded emails/values
            clean_kql = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '<USER_EMAIL>', existing_kql)
            clean_kql = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', '<IP_ADDRESS>', clean_kql)
            return clean_kql.strip()
        
        step_lower = step_name.lower()
        explanation_lower = explanation.lower()
        
        # Rule #183 - Passwordless Authentication
        if 'passwordless' in step_lower or 'passwordless' in explanation_lower:
            return """SigninLogs
| where TimeGenerated > ago(7d)
| where AuthenticationRequirement == "singleFactorAuthentication"
| mv-expand todynamic(AuthenticationDetails)
| extend AuthMethod = tostring(AuthenticationDetails.authenticationMethod)
| where AuthMethod in ("FIDO2 security key", "Passwordless phone sign-in", "Windows Hello for Business")
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, AuthMethod, DeviceDetail
| order by TimeGenerated desc"""
        
        # Sign-in logs check
        if 'sign' in step_lower and 'log' in step_lower:
            return """SigninLogs
| where UserPrincipalName == "<USER_EMAIL>"
| where TimeGenerated > ago(7d)
| project TimeGenerated, IPAddress, Location, AppDisplayName, DeviceDetail, AuthenticationRequirement
| order by TimeGenerated desc"""
        
        # IP reputation check
        if 'ip' in step_lower or 'reputation' in explanation_lower:
            return """SigninLogs
| where UserPrincipalName == "<USER_EMAIL>"
| where TimeGenerated > ago(7d)
| distinct IPAddress
| project IPAddress"""
        
        # Device check
        if 'device' in step_lower:
            return """SigninLogs
| where UserPrincipalName == "<USER_EMAIL>"
| where TimeGenerated > ago(7d)
| distinct DeviceDetail
| project DeviceDetail"""
        
        # MFA/Authentication check
        if 'mfa' in step_lower or 'authentication' in step_lower:
            return """SigninLogs
| where UserPrincipalName == "<USER_EMAIL>"
| where TimeGenerated > ago(7d)
| project TimeGenerated, AuthenticationRequirement, AuthenticationDetails, ConditionalAccessStatus
| order by TimeGenerated desc"""
        
        return ""
    
    def _build_expected_output(self, step_name: str, remarks: str, explanation: str) -> str:
        """Build expected output from remarks or generate"""
        
        # Use remarks if available
        if remarks and len(remarks) > 10 and remarks != 'nan':
            # Clean up remarks
            clean_remarks = re.sub(r'High FP rate.*', '', remarks).strip()
            if clean_remarks:
                return clean_remarks
        
        step_lower = step_name.lower()
        
        # Generate expected output based on step type
        if 'ip' in step_lower:
            return "Typically shows: Clean IP, No malicious reputation, Known IP range. If found → False Positive."
        elif 'device' in step_lower:
            return "Typically shows: Known device, Registered device, Corporate device. If found → False Positive."
        elif 'mfa' in step_lower or 'authentication' in step_lower:
            return "Typically shows: MFA successful, MFA enabled. If found → False Positive."
        elif 'user confirmation' in step_lower:
            return "Typically shows: User confirmed legitimate activity. If found → False Positive."
        elif 'kql' in step_lower or 'query' in step_lower:
            return "Review query results for suspicious patterns, unknown devices, or anomalous behavior."
        elif 'collect' in step_lower:
            return "Document key details: username, application, IP address, timestamp, device information."
        elif 'classification' in step_lower:
            return "Final determination: True Positive / False Positive / Benign Positive with supporting evidence."
        else:
            return "Document investigation findings."