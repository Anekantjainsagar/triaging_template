import os
from crewai import Task
import json
from textwrap import dedent


class TriagingTasks:
    def __init__(self):
        pass

    def synthesize_knowledge_task(
        self, agent, consolidated_data, template_content, rule_number, rule_history=None
    ):
        """
        FIXED: Extract steps from template, then enhance with web research.
        """
        if rule_history is None:
            rule_history = {}

        total_incidents = rule_history.get("total_incidents", 0)
        fp_rate = rule_history.get("fp_rate", 0)
        tp_rate = rule_history.get("tp_rate", 0)

        return Task(
            description=dedent(
                f"""
                Your task: LEARN from the template, then ENHANCE with research.
                
                ===========================================================================
                PHASE 1: LEARN FROM TEMPLATE (MANDATORY - EXTRACT EVERYTHING)
                ===========================================================================
                
                The template shows how analysts have triaged {rule_number} before:
                
                TEMPLATE:
                {template_content}
                
                EXTRACTION TASK:
                
                1. **Find the Step Names/Titles** in the template:
                - Look for rows like "Inputs Required" or numbered steps
                - Extract EVERY step name
                - Example from template: "Check Alert Details", "Verify Role Sensitivity", "Review Sign-In Logs"
                
                2. **Find the Instructions/Explanations** for each step:
                - Look for "Instructions" column or detailed descriptions
                - Extract what the analyst should DO at each step
                - Example: "Username, Role Assigned, Time of Assignment, Initiator, Source IP, Location"
                
                3. **Find Decision Points** (IF/THEN logic):
                - Look for phrases like "If suspicious, escalate", "If True Positive", "If unauthorized"
                - Extract the branching logic
                - Example: "If suspicious, escalate to L3/IT for investigation"
                
                4. **Find Expected Outputs** (what analysts typically find):
                - Look for "INPUT details" column or example findings
                - Example: "Observed the Events and checked user...nothing Suspicious activities found"
                
                5. **Identify the Sequential Flow**:
                - What order are steps in?
                - Which steps depend on previous steps?
                - Example: Step 1 → Step 2 → Step 3 (if condition met) → Step 4
                
                OUTPUT YOUR EXTRACTION:
                ```
                EXTRACTED_FROM_TEMPLATE:
                
                Step 1: [Name from template]
                Explanation: [Instructions from template]
                Decision Logic: [IF/THEN if present]
                Example Finding: [From INPUT details if available]
                
                Step 2: [Name from template]
                Explanation: [Instructions from template]
                Decision Logic: [IF/THEN if present]
                Example Finding: [From INPUT details if available]
                
                [Continue for ALL steps found in template...]
                
                SEQUENTIAL_FLOW:
                Step 1 → Step 2 → [branches: if X then Step 3A, else Step 3B] → Step 4...
                ```
                
                ===========================================================================
                PHASE 2: MAP INCIDENT DATA (MANDATORY)
                ===========================================================================
                
                Extract SPECIFIC entities from this incident:
                
                INCIDENT DATA:
                {consolidated_data}
                
                Find and list:
                - Exact usernames (e.g., john.doe@company.com)
                - Exact IP addresses (e.g., 192.168.1.100)
                - Applications mentioned
                - Roles/permissions mentioned
                - Timestamps
                - Locations
                - Device names
                
                OUTPUT:
                ```
                INCIDENT_ENTITIES:
                - Users: [list]
                - IPs: [list]
                - Applications: [list]
                - Roles: [list]
                - Timestamps: [list]
                - Locations: [list]
                - Devices: [list]
                ```
                
                ===========================================================================
                PHASE 3: APPLY HISTORICAL CONTEXT (MANDATORY)
                ===========================================================================
                
                Historical data for {rule_number}:
                - Total incidents: {total_incidents}
                - FP Rate: {fp_rate}%
                - TP Rate: {tp_rate}%
                - Common FP patterns: {rule_history.get('fp_indicators', 'N/A')}
                - Common TP patterns: {rule_history.get('tp_indicators', 'N/A')}
                
                For EACH template step, note:
                - What percentage of past incidents found specific things at this step?
                - Did those findings lead to FP or TP?
                
                Example: "In Step 3 (IP Check), 82% of incidents found 'clean IP' → those became FP"
                
                ===========================================================================
                PHASE 4: WEB RESEARCH ENHANCEMENT (DO THIS NOW)
                ===========================================================================
                
                Now use web search to ENHANCE the template steps:
                
                **Search Task 1: Find KQL Queries**
                If template steps mention checking logs but don't have queries:
                - Search: "{rule_number} KQL query"
                - Search: "[step name] Azure Sentinel KQL"
                - Search: "SigninLogs KQL query for [specific check]"
                
                Example searches:
                - "Privileged role assignment KQL query Sentinel"
                - "Atypical travel investigation KQL Azure"
                - "Check user sign-in logs KQL last 7 days"
                
                **Search Task 2: Find Additional Investigation Steps**
                If template seems incomplete:
                - Search: "{rule_number} investigation steps best practices"
                - Search: "[alert type] SOC playbook"
                - Search: "How to investigate [alert type] false positive"
                
                **Search Task 3: Find Decision Criteria**
                For steps with unclear decisions:
                - Search: "[alert type] true positive indicators"
                - Search: "[alert type] false positive common causes"
                
                OUTPUT YOUR RESEARCH:
                ```
                WEB_RESEARCH_FINDINGS:
                
                KQL Queries Found:
                - For Step [N] ([step name]): [KQL query from web]
                - For Step [M] ([step name]): [KQL query from web]
                
                Additional Steps Recommended:
                - [New step name]: [Why needed, from which source]
                
                Enhanced Decision Criteria:
                - For [step name]: [Additional FP/TP indicators found online]
                
                Sources Used:
                - [https://www.youtube.com/watch?v=KsZ6tROaVOQ](https://www.youtube.com/watch?v=KsZ6tROaVOQ)
                - [https://www.youtube.com/watch?v=-s7TCuCpB5c](https://www.youtube.com/watch?v=-s7TCuCpB5c)
                ```
                
                ===========================================================================
                FINAL SYNTHESIS OUTPUT (COMBINE ALL PHASES)
                ===========================================================================
                
                # COMPLETE SYNTHESIS FOR {rule_number}
                
                ## 1. TEMPLATE STEPS (Extracted from Phase 1)
                [Every step with name, explanation, decision logic, example findings]
                
                ## 2. INCIDENT DATA (From Phase 2)
                [All specific entities to use in investigation]
                
                ## 3. HISTORICAL PATTERNS (From Phase 3)
                [What past incidents found at each step, FP/TP correlation]
                
                ## 4. WEB-ENHANCED STEPS (From Phase 4)
                [Template steps + KQL queries from web + additional steps if needed]
                
                For each step, show:
                - Step name (from template)
                - Explanation (from template)
                - KQL Query (from template OR web research)
                - Expected Output (from template examples + historical data)
                - Decision Logic (from template + web-enhanced criteria)
                - Incident-specific: How to apply this step with actual data (user: X, IP: Y)
                
                ## 5. INVESTIGATION BLUEPRINT
                Step-by-step guide showing:
                1. [Step name from template]
                - Run: [KQL query with actual incident data]
                - Look for: [Expected finding from template/history]
                - Decide: [IF finding = X THEN Y, from template logic]
                
                CRITICAL: Make it so clear that the next agent can generate steps
                that are IDENTICAL to template structure but ENHANCED with:
                - Real KQL queries from web
                - Actual incident entities
                - Historical success rates
                - Clear decision criteria
            """
            ),
            expected_output=dedent(
                """
                A 5-section synthesis:
                
                1. TEMPLATE STEPS - Every step extracted with full details
                2. INCIDENT DATA - All specific entities (names, IPs, etc.)
                3. HISTORICAL PATTERNS - Statistical context per step
                4. WEB-ENHANCED STEPS - Template + queries/steps from web research
                5. INVESTIGATION BLUEPRINT - Step-by-step with actual data
                
                Each step must have:
                - Name (from template)
                - Explanation (from template)
                - KQL (from template OR web, populated with incident data)
                - Expected output (from template examples + history)
                - Decision logic (from template + web)
            """
            ),
            agent=agent,
        )


    def generate_triaging_plan_task(self, agent, synthesis_output, rule_number):
        """
        FIXED: Generate plan using EXTRACTED template steps + web enhancements.
        """
        return Task(
            description=dedent(
                f"""
                Generate triaging plan for {rule_number} using the synthesis.
                
                SYNTHESIS (contains extracted template + web research):
                {synthesis_output}
                
                ===========================================================================
                YOUR TASK: TRANSFORM SYNTHESIS INTO STRUCTURED STEPS
                ===========================================================================
                
                The synthesis contains:
                - TEMPLATE STEPS (what analysts actually do)
                - WEB-ENHANCED STEPS (KQL queries, additional checks)
                - INCIDENT DATA (actual usernames, IPs to use)
                - HISTORICAL PATTERNS (what typically found)
                
                You must OUTPUT one formatted step for EACH template step.
                
                ===========================================================================
                STEP GENERATION RULES
                ===========================================================================
                
                For EACH step in "TEMPLATE STEPS" or "WEB-ENHANCED STEPS":
                
                1. **STEP Name**:
                - Use EXACT name from template
                - If too long, shorten but keep meaning
                - Example: Template: "Check Alert Details" → Keep as "Check Alert Details"
                
                2. **EXPLANATION** (2-3 sentences):
                - Sentence 1: What to check (from template explanation)
                - Sentence 2: What indicates FP vs TP (from historical patterns + web)
                - Sentence 3: Escalation criteria (from template decision logic)
                
                Example:
                "Check the source IP reputation using VirusTotal or threat intelligence. 
                Clean IP with no alerts indicates legitimate activity (FP). 
                Malicious IP requires immediate escalation to L3 SOC."
                
                3. **KQL Query**:
                - Use query from "WEB_RESEARCH_FINDINGS" if available
                - Otherwise use query from template
                - POPULATE with actual incident data (real username, IP)
                - If no query exists, leave empty
                
                Example:
                ```
                SigninLogs
                | where UserPrincipalName == "john.doe@company.com"
                | where TimeGenerated > ago(7d)
                | project TimeGenerated, IPAddress, Location, DeviceDetail
                | order by TimeGenerated desc
                ```
                
                4. **EXPECTED_OUTPUT**:
                Format: "Based on [X] past incidents ([Y]% FP): Typically shows '[specific finding from template/history]'. If found → [FP/TP]."
                
                Example:
                "Based on 45 past incidents (82% FP): Typically shows 'Same country travel (US to US), Known device, MFA satisfied'. If found → False Positive (82% likelihood)."
                
                5. **DECISION_POINT** (if template had IF/THEN):
                Extract from template's decision logic
                
                Example:
                "If impossible travel detected (e.g., India to USA in 10 minutes) AND unknown device → Escalate immediately. Else proceed to IP check."
                
                INPUT_REQUIRED: Yes
                
                ===========================================================================
                OUTPUT FORMAT (MANDATORY - EXACT FORMAT)
                ===========================================================================
                
                For each template step, output:
                
                ***
                ### [STEP NUMBER]. [STEP NAME] 🔍
                
                * **Explanation:** [2-3 sentences: what to check, FP/TP indicators, escalation]
                * **Input Required:** [Required data for this step]
                * **KQL Query:** ```
                [Complete query from web research with actual incident data]
                ```
                * **Expected Output:** [Based on historical data]
                * **Decision Point:** [IF/THEN OR empty]
                
                ***
                
                ===========================================================================
                COMPLETE EXAMPLE (Template: Rule#286 Atypical Travel)
                ===========================================================================
                
                ***
                ### 1. Check Alert Details 🔍
                
                * **Explanation:** Gather incident details including user, IP, and timestamp. Review if locations are geographically impossible within the timeframe. Atypical travel between distant locations in short time indicates TP.
                * **Input Required:** Incident details and security context.
                * **KQL Query:**
                ```
                SigninLogs
                | where UserPrincipalName == "chorton@arcutis.com"
                | where TimeGenerated > ago(1d)
                | project TimeGenerated, IPAddress, Location, DeviceDetail, AppDisplayName
                | order by TimeGenerated desc
                ```
                * **Expected Output:** Based on 58 past incidents (78% FP): Typically shows 'Same country travel (US to US), Known device, MFA satisfied'. If found -> False Positive (78% likelihood).
                * **Decision Point:** If impossible travel detected (e.g., India to USA in 10 minutes) AND unknown device → Escalate immediately. Else proceed to IP check.
                
                ***
                
                ***
                ### 2. IP Reputation Check 📊
                
                * **Explanation:** Verify IP reputation using VirusTotal or threat intelligence feeds. Clean IP with no malicious history indicates legitimate activity (FP). Malicious IP requires immediate escalation and blocking.
                * **Input Required:** Source IP address.
                * **KQL Query:**
                ```
                SigninLogs
                | where UserPrincipalName == "chorton@arcutis.com"
                | where TimeGenerated > ago(7d)
                | distinct IPAddress
                | project IPAddress
                ```
                * **Expected Output:** Based on 58 past incidents (78% FP): Typically shows 'Clean IP, No threats, Corporate IP range'. If found -> False Positive (78% likelihood).
                * **Decision Point:** If IP is malicious OR flagged as VPN/TOR → Escalate to IT for blocking. Else proceed to user behavior check.
                
                ***
                
                ***
                ### 3. Contact User for Verification ✅
                
                * **Explanation:** Reach out to user to confirm if they traveled to the detected location and recognize the device/IP. User confirmation of legitimate activity closes as FP. User denial or no response requires escalation.
                * **Input Required:** User principal name.
                * **KQL Query:** N/A
                * **Expected Output:** Based on 58 past incidents (78% FP): Typically shows 'User confirmed travel, Using VPN, Business trip'. If found -> False Positive (78% likelihood).
                * **Decision Point:** If user confirms activity → Close as FP. If user denies OR no response within 2 hours → Escalate to IT and disable account.
                
                ***
                
                ===========================================================================
                FINAL DECISION STEP (ADD THIS AT THE END)
                ===========================================================================
                
                After all template steps, add:
                
                ***
                ### Final Classification & Documentation 📂
                
                * **Explanation:** Based on all findings from previous steps, classify as True Positive, False Positive, or Benign Positive. Document detailed justification referencing specific step numbers and findings. Determine escalation path based on classification.
                * **Input Required:** Classification decision and supporting evidence.
                * **KQL Query:** N/A
                * **Expected Output:** Classification with comprehensive justification citing evidence from Steps 1-[N]. Clear documentation of all actions taken and next steps.
                * **Decision Point:** If TP confirmed → Escalate per template (IT Team/L3 SOC). If FP confirmed → Close with justification. If uncertain → Escalate to L3 for review.
                
                ***
                
                ===========================================================================
                QUALITY REQUIREMENTS
                ===========================================================================
                
                ✅ Every template step is included (no steps missed)
                ✅ Steps are in template's original order
                ✅ Each step has 2-3 sentence explanation
                ✅ KQL queries use ACTUAL incident data (real username, IP)
                ✅ Expected outputs reference historical % and specific findings
                ✅ Decision points are clear (IF X THEN Y)
                ✅ Final decision step is added
                ✅ Total steps = template steps + 1 (final decision)
            """
            ),
            expected_output=dedent(
                """
                Steps formatted EXACTLY as shown:
                
                ***
                ### [STEP NUMBER]. [STEP NAME] 🔍
                
                * **Explanation:** [2-3 sentences]
                * **Input Required:** [Required data for this step]
                * **KQL Query:** ```
                [Query with actual data OR empty]
                ```
                * **Expected Output:** [Based on historical data]
                * **Decision Point:** [IF/THEN OR empty]
                
                ***
                
                Output one block per template step + final decision step.
                Must include ALL steps from template in original order.
            """
            ),
            agent=agent,
            context=[synthesis_output] if synthesis_output else [],
        )


    def real_time_prediction_task(
        self,
        agent,
        triaging_comments: dict,
        rule_number: str,
        rule_history: dict,
        template_content: str,
    ):
        """
        FIXED: Prediction based on template's decision criteria.
        """
        all_comments = "\n\n".join(
            [f"**{step}**: {comment}" for step, comment in triaging_comments.items()]
        )

        return Task(
            description=dedent(
                f"""
                Predict classification for {rule_number} based on completed triaging.
                
                ===========================================================================
                COMPLETED INVESTIGATION FINDINGS:
                ===========================================================================
                {all_comments}
                
                ===========================================================================
                TEMPLATE'S DECISION CRITERIA (MUST FOLLOW):
                ===========================================================================
                {template_content}
                
                Extract from template:
                - What conditions = True Positive?
                - What conditions = False Positive?
                - What are escalation triggers?
                
                ===========================================================================
                HISTORICAL BASELINE:
                ===========================================================================
                - Total Past Incidents: {rule_history.get('total_incidents', 0)}
                - FP Rate: {rule_history.get('fp_rate', 0)}%
                - TP Rate: {rule_history.get('tp_rate', 0)}%
                - Common FP Indicators: {rule_history.get('fp_indicators', 'N/A')}
                - Common TP Indicators: {rule_history.get('tp_indicators', 'N/A')}
                
                ===========================================================================
                PREDICTION PROCESS (FOLLOW EXACTLY):
                ===========================================================================
                
                **STEP 1: Map findings to template decision criteria**
                
                Go through each completed step's findings:
                - Does finding match template's FP criteria? (e.g., "clean IP", "user confirmed")
                - Does finding match template's TP criteria? (e.g., "malicious IP", "user denied")
                - Were any escalation triggers met?
                
                **STEP 2: Calculate probability adjustments**
                
                Start with historical baseline: FP={rule_history.get('fp_rate', 50)}%, TP={rule_history.get('tp_rate', 50)}%
                
                For EACH finding, adjust:
                - Strong FP indicator (matches template FP criteria) → +15-20% FP
                - Weak FP indicator → +5-10% FP
                - Strong TP indicator (matches template TP criteria) → +15-20% TP
                - Weak TP indicator → +5-10% TP
                
                **STEP 3: Normalize to 100%**
                
                Ensure: FP% + TP% + BP% = 100%
                
                **STEP 4: Validate against template**
                
                Does highest percentage match template's decision logic?
                - If template says "if clean IP + user confirm → FP", and both found → FP% should be highest
                
                ===========================================================================
                OUTPUT FORMAT (MANDATORY):
                ===========================================================================
                
                ---
                PREDICTION_TYPE: [False Positive / True Positive / Benign Positive]
                
                CONFIDENCE_PERCENTAGES:
                - False Positive Likelihood: [X]%
                - True Positive Likelihood: [Y]%
                - Benign Positive Likelihood: [Z]%
                (MUST SUM TO 100%)
                
                CONFIDENCE_LEVEL: [High / Medium / Low]
                
                KEY_FACTORS:
                1. [Step N finding]: [How it matches template criteria]
                2. [Step M finding]: [How it matches template criteria]
                3. [Template decision point met/not met]
                4. [Historical pattern alignment]
                
                TEMPLATE_ALIGNMENT:
                "[Explain how findings match template's decision logic]"
                Example: "Template states: 'If clean IP AND MFA success → FP'. Both conditions met in Steps 2 and 4."
                
                HISTORICAL_COMPARISON:
                "[Compare to past {rule_history.get('total_incidents', 0)} incidents]"
                Example: "Findings match 82% of past FP cases where clean IP and user confirmation were found."
                
                REASONING:
                "[2-3 sentences why these percentages]"
                
                RECOMMENDED_ACTION:
                "[From template's escalation logic]"
                - If TP → [action from template]
                - If FP → Close with justification
                ---
                
                ===========================================================================
                EXAMPLE OUTPUT:
                ===========================================================================
                
                ---
                PREDICTION_TYPE: False Positive
                
                CONFIDENCE_PERCENTAGES:
                - False Positive Likelihood: 85%
                - True Positive Likelihood: 10%
                - Benign Positive Likelihood: 5%
                
                CONFIDENCE_LEVEL: High
                
                KEY_FACTORS:
                1. Step 2 (IP Check): Found "Clean IP, No threats" - matches template FP criteria
                2. Step 4 (User Verification): User confirmed legitimate travel - strong FP indicator per template
                3. Step 3 (Device Check): Known device with MFA satisfied - template FP pattern
                4. Historical: 78% of past incidents with these patterns were FP
                
                TEMPLATE_ALIGNMENT:
                Template decision logic states: "If clean IP AND user confirms travel AND known device → False Positive". All three conditions were met across Steps 2, 3, and 4, strongly supporting FP classification per template guidance.
                
                HISTORICAL_COMPARISON:
                This incident matches 85% of the 58 past {rule_number} cases that were False Positives. Historical FP rate is 78%, and this case shows the same pattern: clean IP + user confirmation + known device + MFA satisfied.
                
                REASONING:
                The combination of clean IP reputation (Step 2), user confirmation of legitimate travel (Step 4), and known device with MFA (Step 3) strongly indicates legitimate activity. These findings align perfectly with the template's FP decision criteria and match 85% of historical FP patterns.
                
                RECOMMENDED_ACTION:
                Per template: Close as False Positive. Document: "Legitimate user travel confirmed via IP reputation check, user verification, and device recognition. No escalation required."
                ---
                
                ===========================================================================
                VALIDATION CHECKLIST:
                ===========================================================================
                
                Before outputting, verify:
                ✅ Percentages total 100%
                ✅ Prediction type matches highest %
                ✅ Key factors reference actual step findings
                ✅ Template alignment explains decision logic match
                ✅ Historical comparison included
                ✅ Recommended action from template
            """
            ),
            expected_output=dedent(
                """
                Complete prediction with:
                1. Prediction type (FP/TP/BP)
                2. Three percentages summing to 100%
                3. Confidence level
                4. 4-5 key factors referencing steps
                5. Template alignment explanation
                6. Historical comparison
                7. Clear reasoning (2-3 sentences)
                8. Recommended action from template
                
                Must match MANDATORY OUTPUT FORMAT exactly.
            """
            ),
            agent=agent,
        )

    def predict_outcome_task(self, agent, consolidated_data, rule_number):
        """Task to predict incident outcomes based on historical data."""
        return Task(
            description=dedent(
                f"""
                Predict the outcome for: {rule_number}
                
                Perform a comprehensive analysis of this incident: {str(consolidated_data)}...
                
                INCIDENT DATA:
                {json.dumps(consolidated_data, indent=2)}
                
                ANALYSIS STEPS:
                1. Extract and analyze resolver comments for key indicators
                2. Review historical classification and justification
                3. Apply pattern recognition based on known TP/FP patterns
                4. Consider context: priority, VIP users, time of day, etc.
                
                Historical context:
                - Previous Classification: {consolidated_data.get('false_true_positive', 'N/A')}
                - Justification: {consolidated_data.get('why_false_positive', 'N/A')}
                - Resolver Comments: {consolidated_data.get('resolver_comments', 'N/A')}
                
                FALSE POSITIVE indicators:
                - IP reputation explicitly marked as "clean"
                - "Known device" or "registered device" mentioned
                - "Known apps" or "legitimate applications"
                - "MFA satisfied" or "MFA enabled and successful"
                - "Legitimate user behavior"
                - VPN usage (Nord VPN, ExpressVPN, corporate VPN)
                - "BAS testing" or "security testing"
                - "Nothing suspicious found"
                - "No unauthorized access"
                - User confirmation of legitimate activity
                
                TRUE POSITIVE indicators:
                - "Services not running" or "service down"
                - "Unauthorized access" or "suspicious access"
                - "Malicious IP" or "bad reputation"
                - "Suspicious activity detected"
                - "Unknown device" or "unregistered device"
                - "Failed MFA" or "MFA bypass"
                - "Escalated to L3/SOC"
                - "Anomalous behavior"
                - "Data exfiltration" or "unusual downloads"
                - Multiple failed login attempts
                - Access to sensitive resources
                
                UNCERTAIN indicators:
                - Incomplete investigation
                - Missing data points
                - Conflicting information
                - Pending user confirmation
                
                Historical context:
                - Previous Classification: {consolidated_data.get('false_true_positive', 'N/A')}
                - Justification: {consolidated_data.get('why_false_positive', 'N/A')}
                - Resolver Comments: {consolidated_data.get('resolver_comments', 'N/A')}
                
                Provide prediction with:
                - Classification (Likely True Positive / Likely False Positive / Requires Further Investigation)
                - Confidence Level (High 80-100% / Medium 50-79% / Low <50%)
                - Detailed reasoning with specific evidence
                - Key indicators that led to this prediction
            """
            ),
            expected_output=dedent(
                """
                A comprehensive prediction summary:
                
                PREDICTION: [Likely True Positive / Likely False Positive / Requires Further Investigation]
                
                CONFIDENCE: [High (80-100%) / Medium (50-79%) / Low (<50%)]
                
                REASONING: [3-5 sentences explaining the prediction based on specific evidence from the incident data. Reference exact phrases or indicators found in resolver comments, IP status, device information, etc.]
                
                KEY_INDICATORS: [Bullet list of 3-5 specific data points that support this prediction]
                
                RECOMMENDATION: [Specific next steps based on prediction]
            """
            ),
            agent=agent,
        )

