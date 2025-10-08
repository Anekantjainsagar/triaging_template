from crewai import Agent, Task, Crew, Process, LLM
from crewai_tools import SerperDevTool
from textwrap import dedent
import re
from typing import List, Dict


class KQLSearchTool:
    """Tool to generate KQL queries using LLM with detailed purpose"""

    def __init__(self, llm):
        self.llm = llm

    def generate_kql_with_purpose(self, step_name: str, explanation: str) -> dict:
        """Generate KQL query with detailed purpose using LLM"""
        
        # Check if step needs KQL
        step_lower = step_name.lower()
        
        # Skip manual/documentation steps
        if any(word in step_lower for word in ['incident', 'reported time', 'username', 'user confirmation', 'inform', 'track', 'closer', 'user account details']):
            return {"query": "", "purpose": ""}
        
        # Use LLM to generate KQL with purpose
        agent = Agent(
            role="KQL Query Expert",
            goal="Generate detailed KQL queries with clear purpose for security investigations",
            backstory="Expert in Microsoft Sentinel KQL queries and security incident triaging",
            llm=self.llm,
            verbose=False
        )
        
        prompt = dedent(f"""
        Generate a KQL query for this investigation step:
        
        STEP: {step_name}
        CONTEXT: {explanation}
        
        REQUIREMENTS:
        1. Generate ONLY if step requires querying logs/data
        2. Use placeholders: <USER_EMAIL>, <IP_ADDRESS>, <TIMESPAN>, <APP_NAME>
        3. Use tables: SigninLogs, AuditLogs, IdentityInfo, AADNonInteractiveUserSignInLogs
        4. Write DETAILED purpose (2-3 sentences explaining what the query does and why)
        5. Keep query concise and focused on the step's goal
        
        OUTPUT FORMAT:
        PURPOSE: [2-3 sentences explaining what this query does and why it's important]
        QUERY:
        [KQL query here]
        
        If no query needed, output:
        PURPOSE: Manual investigation step
        QUERY: N/A
        """)
        
        task = Task(
            description=prompt,
            expected_output="KQL query with detailed purpose",
            agent=agent
        )
        
        try:
            crew = Crew(agents=[agent], tasks=[task], verbose=False)
            result = crew.kickoff()
            result_str = str(result)
            
            # Parse purpose and query
            purpose_match = re.search(r'PURPOSE:\s*(.+?)(?=QUERY:|$)', result_str, re.DOTALL)
            query_match = re.search(r'QUERY:\s*(.+?)$', result_str, re.DOTALL)
            
            purpose = purpose_match.group(1).strip() if purpose_match else ""
            query = query_match.group(1).strip() if query_match else ""
            
            # Clean query
            if query and query.upper() != "N/A":
                query = self._clean_kql(query)
            else:
                query = ""
            
            return {
                "query": query,
                "purpose": purpose if purpose != "Manual investigation step" else ""
            }
            
        except Exception as e:
            print(f"⚠️ LLM generation failed: {str(e)}")
            # Fallback to pattern-based
            return self._fallback_generation(step_name, explanation)
    
    def _fallback_generation(self, step_name: str, explanation: str) -> dict:
        """Pattern-based fallback for common queries"""
        combined = f"{step_name} {explanation}".lower()
        
        # VIP User check
        if "vip" in combined:
            return {
                "query": """IdentityInfo
| where AccountUPN == "<USER_EMAIL>"
| project AccountUPN, AccountDisplayName, JobTitle, Department, Manager, Tags
| extend IsVIP = iff(Tags contains "VIP" or Tags contains "Executive", "Yes", "No")""",
                "purpose": "Query user identity information to verify VIP status by checking Tags field for VIP or Executive designation. Essential for prioritizing incident response."
            }
        
        # Passwordless authentication / Application sign-in
        elif "application" in combined and ("sign" in combined or "password" in combined):
            return {
                "query": """AADNonInteractiveUserSignInLogs
| where UserPrincipalName in ("<USER_EMAIL>")
| where TimeGenerated > ago(<TIMESPAN>)
| where AppDisplayName != ""
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, UserAgent, AuthenticationRequirement
| order by TimeGenerated desc""",
                "purpose": "Query non-interactive sign-in logs to identify applications accessed without password authentication. Critical for detecting passwordless authentication attempts and potential account compromise scenarios."
            }
        
        # Sign-in logs / AD logs
        elif "sign" in combined or "ad log" in combined:
            return {
                "query": """SigninLogs
| where UserPrincipalName == "<USER_EMAIL>"
| where TimeGenerated > ago(<TIMESPAN>)
| extend DeviceName = tostring(DeviceDetail.displayName)
| extend IsCompliant = tostring(DeviceDetail.isCompliant)
| extend Location = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion)
| project TimeGenerated, UserPrincipalName, IPAddress, Location, DeviceName, IsCompliant, AppDisplayName, AuthenticationRequirement
| order by TimeGenerated desc""",
                "purpose": "Analyze user sign-in activity to verify authentication methods, detect anomalous patterns, and validate device compliance. Helps identify legitimate vs suspicious authentication attempts."
            }
        
        # Collect basic info
        elif "basic info" in combined or "username" in combined and "app" in combined:
            return {
                "query": """AADNonInteractiveUserSignInLogs
| where UserPrincipalName in ("<USER_EMAIL>")
| where TimeGenerated > ago(<TIMESPAN>)
| project TimeGenerated, UserPrincipalName, AppDisplayName, UserAgent, IPAddress, Location = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion)
| order by TimeGenerated desc""",
                "purpose": "Collect basic authentication details including username, application, user agent, and timestamp. Provides foundational data for investigating passwordless authentication events."
            }
        
        return {"query": "", "purpose": ""}
    
    def _clean_kql(self, kql: str) -> str:
        """Clean KQL query"""
        if not kql:
            return ""
        
        # Remove markdown
        kql = re.sub(r'```[a-z]*\s*', '', kql)
        kql = re.sub(r'```', '', kql)
        
        # Clean whitespace
        lines = [line.strip() for line in kql.split('\n') if line.strip()]
        kql = '\n'.join(lines)
        
        return kql.strip()


class WebLLMEnhancer:
    """
    Enhanced template processor that:
    - KEEPS EXACT ORIGINAL STEP NAMES (no modification)
    - Generates concise explanations (20-30 words)
    - Creates detailed KQL queries with purpose using LLM
    - Leaves Remarks/Comments empty
    """

    def __init__(self):
        self.llm = LLM(model="ollama/qwen2.5:0.5b", base_url="http://localhost:11434")
        self.kql_tool = KQLSearchTool(self.llm)

    def enhance_template_steps(self, rule_number: str, original_steps: list) -> list:
        """
        Main enhancement pipeline - KEEPS EXACT STEP NAMES
        """
        print(f"\n{'='*80}")
        print(f"🌐 ENHANCED PROCESSING FOR {rule_number}")
        print(f"{'='*80}")
        print(f"📥 Input: {len(original_steps)} original steps")

        enhanced_steps = []

        for i, step in enumerate(original_steps, 1):
            # ✅ KEEP EXACT ORIGINAL STEP NAME (just strip whitespace)
            original_name = step.get("step_name", f"Step {i}").strip()
            
            original_exp = step.get("explanation", "")
            
            # ✅ GENERATE CONCISE EXPLANATION (20-30 words)
            concise_exp = self._generate_concise_explanation(original_name, original_exp)
            
            # ✅ GENERATE KQL WITH DETAILED PURPOSE USING LLM
            kql_data = self.kql_tool.generate_kql_with_purpose(original_name, concise_exp)
            
            enhanced_step = {
                "step_name": original_name,  # ✅ EXACT ORIGINAL NAME
                "explanation": concise_exp,  # ✅ Concise 20-30 words
                "kql_query": kql_data["query"],  # ✅ Relevant query
                "kql_purpose": kql_data["purpose"],  # ✅ Detailed purpose
                "input_required": "",  # ✅ Will be removed in Excel
                "expected_output": "",  # ✅ Not used
                "remarks": ""  # ✅ Empty as requested
            }
            
            enhanced_steps.append(enhanced_step)
            
            print(f"\n✅ Step {i}: {original_name}")
            print(f"   Explanation: {len(concise_exp.split())} words")
            if kql_data["query"]:
                print(f"   KQL: Generated ({len(kql_data['query'])} chars)")
            else:
                print(f"   KQL: Not needed (manual step)")

        print(f"\n{'='*80}")
        print(f"✅ ENHANCEMENT COMPLETE")
        print(f"   Total steps: {len(enhanced_steps)}")
        print(f"   Steps with KQL: {len([s for s in enhanced_steps if s.get('kql_query')])}")
        print(f"{'='*80}\n")

        return enhanced_steps

    def _generate_concise_explanation(self, step_name: str, original_exp: str) -> str:
        """
        Generate concise explanation (20-30 words) using LLM
        """
        # If original is already concise and good, use it
        word_count = len(original_exp.split())
        if 15 <= word_count <= 35 and original_exp and not original_exp.startswith("Complete"):
            return original_exp
        
        # Use LLM to make it concise
        agent = Agent(
            role="Technical Writer",
            goal="Create concise, clear investigation step descriptions",
            backstory="Expert at writing concise technical documentation",
            llm=self.llm,
            verbose=False
        )
        
        prompt = dedent(f"""
        Create a concise explanation for this investigation step:
        
        STEP NAME: {step_name}
        ORIGINAL: {original_exp if original_exp else "Manual investigation step"}
        
        REQUIREMENTS:
        - EXACTLY 20-30 words
        - Action-focused (what to DO)
        - Clear and specific
        - No fluff or repetition
        - If original is empty or generic, infer from step name
        
        OUTPUT FORMAT:
        [Your concise explanation here - 20-30 words only]
        """)
        
        task = Task(
            description=prompt,
            expected_output="Concise 20-30 word explanation",
            agent=agent
        )
        
        try:
            crew = Crew(agents=[agent], tasks=[task], verbose=False)
            result = crew.kickoff()
            concise = str(result).strip()
            
            # Validate word count
            words = concise.split()
            if 15 <= len(words) <= 35:
                return concise
            else:
                # Truncate if too long
                if len(words) > 30:
                    return ' '.join(words[:30]) + '.'
                # Use original if too short
                return original_exp if original_exp else f"Complete {step_name} investigation step."
                
        except Exception as e:
            print(f"⚠️ Concise generation failed: {str(e)}")
            # Fallback: use original or generate simple one
            if original_exp:
                sentences = original_exp.split('.')
                return sentences[0].strip() + '.' if sentences else original_exp
            else:
                return f"Complete {step_name} and document findings in investigation tracker."


# Testing function
if __name__ == "__main__":
    enhancer = WebLLMEnhancer()
    
    # Test with EXACT Rule#183 steps from CSV
    test_steps = [
        {
            "step_name": "Incident",
            "explanation": "",
            "input_required": "208306",
            "kql_query": ""
        },
        {
            "step_name": "Reported Time",
            "explanation": "",
            "input_required": "",
            "kql_query": ""
        },
        {
            "step_name": "Provide the username which are involved in the incident",
            "explanation": "",
            "input_required": "obarkhordarian@arcutis.com,jfennewald@arcutis.com,nkolla@arcutis.com",
            "kql_query": ""
        },
        {
            "step_name": "VIPS Users ?",
            "explanation": "Cross verify if the user is VIP or not - with the list (Shared by Arcutis)",
            "input_required": "No",
            "kql_query": ""
        },
        {
            "step_name": "Run the KQL query",
            "explanation": "Verify the logs whether there is any Application without sign in attempts",
            "input_required": "Triaging steps: IP : Clean, Closure comments :Observed events...",
            "kql_query": ""
        },
        {
            "step_name": "Collect the basic info like UserName, App DisplayName, User Agent, Time",
            "explanation": "If there is any application sign in without password check whether the application is critical or not",
            "input_required": "Triaging steps: IP : Clean...",
            "kql_query": ""
        },
        {
            "step_name": "User Confirmation - If YES",
            "explanation": "If no critical applications close the incident as false positive",
            "input_required": "No need",
            "kql_query": ""
        },
        {
            "step_name": "User Confirmation --- NO. (True Positive)",
            "explanation": "If any critical application found consider as True Positive",
            "input_required": "NA",
            "kql_query": ""
        },
        {
            "step_name": "Run The KQL to check - AD logs (Sign in logs)",
            "explanation": "Ensure that the passwordless authentication method used is legitimate (e.g., biometrics, hardware tokens).If there is critical applications without password then reach out IT team to set password by enabling MFA",
            "input_required": "Yes, run user signin logs",
            "kql_query": ""
        },
        {
            "step_name": "User Account Details",
            "explanation": "If the authentication is Legitimate then consider it as False Positive and close the incident",
            "input_required": "iwalsh@arcutis.com",
            "kql_query": ""
        },
        {
            "step_name": "Inform to IT Team",
            "explanation": "If unauthorized, take appropriate action such as locking accounts, resetting passwords, or investigating further.",
            "input_required": "no need",
            "kql_query": ""
        },
        {
            "step_name": "Track for the closer/closer confirmation",
            "explanation": "Enhance monitoring to detect similar events in the future",
            "input_required": "",
            "kql_query": ""
        }
    ]
    
    enhanced = enhancer.enhance_template_steps("Rule#183", test_steps)
    
    print("\n" + "="*80)
    print("FINAL OUTPUT PREVIEW")
    print("="*80)
    
    for i, step in enumerate(enhanced, 1):
        print(f"\n{i}. {step['step_name']}")
        print(f"   Explanation: {step['explanation']}")
        if step['kql_query']:
            print(f"   KQL Purpose: {step['kql_purpose'][:80]}...")
            print(f"   Has KQL: Yes ({len(step['kql_query'])} chars)")
        else:
            print(f"   Has KQL: No (manual step)")