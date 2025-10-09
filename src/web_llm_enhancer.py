from crewai import Agent, Task, Crew, LLM
from crewai_tools import SerperDevTool
import re


class WebLLMEnhancer:
    """
    Enhances triaging template steps with:
    - Original step names (cleaned only)
    - Concise 20-30 word explanations (LLM-generated)
    - Detailed KQL queries (DynamicKQLGenerator + LLM enhancement)
    - NO Remarks/Comments
    - ALL placeholders (no hardcoded values)
    """

    def __init__(self):
        self.llm = LLM(model="ollama/qwen2.5:0.5b", base_url="http://localhost:11434")

        try:
            self.web_search = SerperDevTool()
        except:
            self.web_search = None
            print("⚠️ Web search unavailable. Using LLM-only enhancement.")

    def enhance_template_steps(self, rule_number: str, original_steps: list) -> list:
        """
        Main enhancement pipeline:
        - Keep original step names
        - Generate 20-30 word explanations
        - Generate detailed KQL queries
        """
        print(f"\n{'='*80}")
        print(f"ðŸŒ WEB + LLM ENHANCEMENT FOR {rule_number}")
        print(f"{'='*80}")
        print(f"ðŸ“¥ Input: {len(original_steps)} original steps")

        # Run intelligent enhancement
        enhanced_steps = self._intelligent_enhancement(original_steps, rule_number)

        print(f"\n{'='*80}")
        print(f"âœ… ENHANCEMENT COMPLETE")
        print(f"   Original steps: {len(original_steps)}")
        print(f"   Enhanced steps: {len(enhanced_steps)}")
        print(
            f"   Steps with KQL: {len([s for s in enhanced_steps if s.get('kql_query')])}"
        )
        print(f"{'='*80}\n")

        return enhanced_steps

    def _intelligent_enhancement(self, original_steps: list, rule_number: str) -> list:
        """
        Enhanced processing: Keep original names, enhance explanations, generate detailed KQL.
        """
        print(f"\nâš™ï¸ Running INTELLIGENT enhancement...")

        enhanced = []

        for i, step in enumerate(original_steps, 1):
            raw_name = step.get("step_name", f"Step {i}")
            original_exp = step.get("explanation", "")
            original_kql = step.get("kql_query", "")

            # ✅ KEEP ORIGINAL NAME (just clean it)
            clean_name = self._clean_step_name(raw_name)

            # 🔧 GENERATE CONCISE EXPLANATION (20-30 words using LLM)
            enhanced_exp = self._generate_concise_explanation(
                clean_name, original_exp, rule_number
            )

            # 🔧 GENERATE DETAILED KQL QUERY (using DynamicKQLGenerator + LLM)
            kql_query = self._generate_detailed_kql(
                clean_name, enhanced_exp, original_kql, rule_number
            )

            enhanced_step = {
                "step_name": clean_name,
                "explanation": enhanced_exp,
                "input_required": "",  # âœ… REMOVED - will not appear in Excel
                "kql_query": kql_query,
            }

            enhanced.append(enhanced_step)
            print(f"✅ Enhanced step {i}: {clean_name}")
            print(f"   📝 Explanation: {len(enhanced_exp.split())} words")
            if kql_query:
                print(f"   📊 KQL query generated ({len(kql_query)} chars)")

        return enhanced

    def _clean_step_name(self, raw_name: str) -> str:
        """Just clean the original name - don't change it"""
        # Remove numbering
        clean = re.sub(r"^\d+\.?\d*\s*", "", raw_name)
        clean = re.sub(r"^Step\s*\d+:?\s*", "", clean, flags=re.IGNORECASE)
        
        # Remove markdown
        clean = re.sub(r"[*#_`]", "", clean)
        
        # Clean whitespace
        clean = " ".join(clean.split())
        
        return clean.strip() if clean else raw_name

    def _generate_concise_explanation(
        self, step_name: str, original_exp: str, rule_number: str
    ) -> str:
        """
        Generate 20-30 word concise explanation using LLM.
        """
        # If original is already concise (20-40 words), use it
        word_count = len(original_exp.split())
        if 20 <= word_count <= 40 and original_exp:
            return original_exp
        
        # Use LLM to generate concise explanation
        prompt = f"""Rewrite this investigation step explanation to be exactly 20-30 words. Make it actionable and specific.

Step Name: {step_name}
Original Explanation: {original_exp}
Rule: {rule_number}

Requirements:
- Exactly 20-30 words
- Clear action verb
- What to investigate
- Expected outcome
- No fluff or repetition

Example: "Query Azure AD audit logs for privileged role assignments. Identify high-risk roles like Global Admin. Document assignment details including user, timestamp, and initiator."

Generate 20-30 word explanation:"""

        try:
            agent = Agent(
                role="Security Documentation Expert",
                goal="Create concise, actionable investigation steps",
                backstory="Expert in writing clear security documentation",
                llm=self.llm,
                verbose=False,
            )

            task = Task(
                description=prompt,
                expected_output="A 20-30 word explanation",
                agent=agent,
            )

            crew = Crew(agents=[agent], tasks=[task], verbose=False)
            result = crew.kickoff()

            explanation = str(result).strip()
            
            # Validate word count
            words = explanation.split()
            if 15 <= len(words) <= 35:
                return explanation
            
        except Exception as e:
            print(f"   ⚠️ LLM explanation failed: {str(e)}")
        
        # Fallback: Truncate original to ~25 words
        if original_exp:
            words = original_exp.split()
            return " ".join(words[:25]) + ("..." if len(words) > 25 else "")
        
        return f"Complete {step_name} investigation and document findings."

    def _generate_detailed_kql(
        self, step_name: str, explanation: str, original_kql: str, rule_number: str
    ) -> str:
        """
        Generate detailed, relevant KQL query using DynamicKQLGenerator + LLM enhancement.
        """
        # If step doesn't need KQL (documentation/decision steps), return empty
        step_lower = step_name.lower()
        if any(
            word in step_lower
            for word in [
                "document",
                "final",
                "classification",
                "enhance monitoring",
                "escalate to",
                "coordinate with",
                "inform user",
            ]
        ):
            return ""
        
        # Step 1: Use DynamicKQLGenerator for base query
        from src.kql_generation import DynamicKQLGenerator
        
        kql_gen = DynamicKQLGenerator()
        base_kql = kql_gen.generate_kql_query(step_name, explanation, rule_number)
        
        # If we got a good base query, enhance it with LLM for more detail
        if base_kql and len(base_kql) > 50:
            enhanced_kql = self._enhance_kql_with_llm(base_kql, step_name, explanation)
            return enhanced_kql if enhanced_kql else base_kql
        
        # Step 2: If no base query, try original
        if original_kql and len(original_kql.strip()) > 30:
            enhanced_kql = self._enhance_kql_with_llm(original_kql, step_name, explanation)
            return enhanced_kql if enhanced_kql else self._clean_kql_placeholders(original_kql)
        
        # Step 3: Generate from scratch using LLM
        generated_kql = self._generate_kql_from_scratch(step_name, explanation, rule_number)
        return generated_kql if generated_kql else ""
    
    def _enhance_kql_with_llm(self, base_kql: str, step_name: str, explanation: str) -> str:
        """
        Use LLM to make KQL query more detailed and relevant.
        """
        prompt = f"""Enhance this KQL query to make it more detailed and purpose-specific for this investigation step.

Step Name: {step_name}
Purpose: {explanation}

Current KQL:
{base_kql}

Enhancement Requirements:
1. Add helpful comments explaining what each section does
2. Add more relevant fields in extend/project if applicable
3. Ensure all table names are correct (SigninLogs, AuditLogs, IdentityInfo, etc.)
4. Keep placeholders: <USER_EMAIL>, <IP_ADDRESS>, <TIMESPAN>, <DEVICE_ID>
5. Make it production-ready but keep it under 20 lines
6. Add summarize/join clauses if they add value for this investigation

Return ONLY the enhanced KQL query, no explanations:"""

        try:
            agent = Agent(
                role="KQL Query Optimization Expert",
                goal="Enhance KQL queries for security investigations",
                backstory="Expert in Microsoft Sentinel KQL optimization",
                llm=self.llm,
                verbose=False,
            )

            task = Task(
                description=prompt,
                expected_output="Enhanced KQL query",
                agent=agent,
            )

            crew = Crew(agents=[agent], tasks=[task], verbose=False)
            result = crew.kickoff()

            enhanced = str(result).strip()
            
            # Validate it's still KQL
            if any(kw in enhanced for kw in ["where", "extend", "project", "summarize"]):
                return self._clean_kql_placeholders(enhanced)
            
        except Exception as e:
            print(f"   ⚠️ KQL enhancement failed: {str(e)}")
        
        return ""
    
    def _generate_kql_from_scratch(self, step_name: str, explanation: str, rule_number: str) -> str:
        """
        Generate KQL query from scratch using LLM when no template matches.
        """
        prompt = f"""Generate a Microsoft Sentinel KQL query for this security investigation step.

Rule: {rule_number}
Step: {step_name}
Purpose: {explanation}

Requirements:
1. Use ONLY valid table names: SigninLogs, AuditLogs, IdentityInfo, ThreatIntelligenceIndicator, SecurityIncident, DeviceInfo
2. Use placeholders: <USER_EMAIL>, <IP_ADDRESS>, <TIMESPAN>, <DEVICE_ID>
3. Include TimeGenerated filter: where TimeGenerated > ago(<TIMESPAN>)
4. Use proper KQL operators: where, extend, project, summarize, join
5. Make it specific to the investigation purpose
6. Keep under 15 lines
7. Add inline comments for clarity

Example format:
// Query audit logs for role assignments
AuditLogs
| where TimeGenerated > ago(<TIMESPAN>)
| where OperationName == "Add member to role"
| extend RoleName = tostring(TargetResources[0].modifiedProperties)
| project TimeGenerated, UserPrincipalName, RoleName, Result

Generate production-ready KQL query:"""

        try:
            agent = Agent(
                role="Security KQL Developer",
                goal="Generate KQL queries for security investigations",
                backstory="Expert in writing KQL for Microsoft Sentinel",
                llm=self.llm,
                verbose=False,
            )

            task = Task(
                description=prompt,
                expected_output="A valid KQL query",
                agent=agent,
            )

            crew = Crew(agents=[agent], tasks=[task], verbose=False)
            result = crew.kickoff()

            kql = str(result).strip()
            
            # Validate and clean
            if any(kw in kql for kw in ["where", "extend", "project", "summarize"]):
                return self._clean_kql_placeholders(kql)
            
        except Exception as e:
            print(f"   ⚠️ KQL generation failed: {str(e)}")
        
        return ""

    def _clean_kql_placeholders(self, kql: str) -> str:
        """
        Ensure KQL uses ONLY placeholders, no hardcoded values.
        """
        if not kql:
            return ""

        # Remove markdown
        kql = re.sub(r"```[a-z]*\s*\n?", "", kql)
        kql = re.sub(r"\n?```", "", kql)

        # Replace hardcoded values
        kql = re.sub(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "<USER_EMAIL>", kql
        )
        kql = re.sub(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "<IP_ADDRESS>", kql)
        kql = re.sub(
            r'datetime\(["\'][\d\-:TZ]+["\']\)', "ago(<TIMESPAN>)", kql
        )
        kql = re.sub(
            r'(DeviceId|DeviceName)\s*==\s*"[^"]+"', r'\1 == "<DEVICE_ID>"', kql
        )

        # Ensure time ranges use placeholders
        if "TimeGenerated" in kql and "ago(" not in kql:
            kql = re.sub(
                r"TimeGenerated\s*>\s*[^\n]+", "TimeGenerated > ago(<TIMESPAN>)", kql
            )

        # Replace common timespan values with placeholder
        kql = re.sub(r"ago\(\d+[dhm]\)", "ago(<TIMESPAN>)", kql)

        return kql.strip()