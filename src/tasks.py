import os
from crewai import Task
from textwrap import dedent


class TriagingTasks:
    def __init__(self):
        pass

    def search_alerts_task(self, agent, search_query):
        """Task to search for relevant alerts based on user query."""
        return Task(
            description=dedent(
                f"""
                Search for security alerts related to: '{search_query}'
                
                Use the Alert Search Tool to find the top 5 most relevant alerts.
                Focus on matching:
                - Rule numbers
                - Alert descriptions
                - Incident types
                - Data connectors
                
                Return a simple list of alert titles in the format:
                Rule#XXX - Incident XXXXXX
            """
            ),
            expected_output=dedent(
                """
                A numbered list of 5 relevant alerts, each on a new line.
                Example:
                1. Rule#280 - Incident 208308
                2. Rule#286 - Incident 208303
                3. Rule#002 - Incident 208307
            """
            ),
            agent=agent,
        )

    def consolidate_data_task(self, agent, incident_id):
        """Task to consolidate all data for a specific incident."""
        return Task(
            description=dedent(
                f"""
                Consolidate all data for incident: {incident_id}
                
                Use the Incident Consolidation Tool to gather:
                - All incident metadata
                - Timeline information (reported, responded, resolution times)
                - Engineer details
                - Resolver comments
                - Classification and justification
                
                Return the complete incident data in a structured format.
            """
            ),
            expected_output=dedent(
                f"""
                A comprehensive data summary for incident {incident_id} including:
                - Incident number
                - Rule information
                - Priority and status
                - Timeline metrics
                - Investigation findings
                - Historical classification
            """
            ),
            agent=agent,
        )

    def retrieve_template_task(self, agent, rule_number):
        """Task to retrieve the triaging template for a rule."""
        return Task(
            description=dedent(
                f"""
                Retrieve the triaging template for: {rule_number}
                
                Use the Template Retrieval Tool to find the correct template.
                If no specific template exists, a generic one will be provided.
                
                Return the complete template content.
            """
            ),
            expected_output=dedent(
                f"""
                The full triaging template for {rule_number} including:
                - Investigation steps
                - Required checks
                - Data points to collect
                - Decision criteria
            """
            ),
            agent=agent,
        )

    def synthesize_knowledge_task(
        self, agent, consolidated_data, template_content, rule_number, rule_history=None
    ):
        """
        Task to synthesize information AND use web search strategically.
        """
        # Safely extract rule history values with defaults
        if rule_history is None:
            rule_history = {}

        total_incidents = rule_history.get("total_incidents", 0)
        fp_rate = rule_history.get("fp_rate", 0)
        tp_rate = rule_history.get("tp_rate", 0)
        all_resolver_comments = rule_history.get("all_resolver_comments", "N/A")
        common_justifications = rule_history.get("common_justifications", "N/A")
        fp_indicators = rule_history.get(
            "fp_indicators", "Clean IP, known devices, legitimate apps"
        )
        tp_indicators = rule_history.get(
            "tp_indicators", "Malicious activity, unauthorized access"
        )

        return Task(
            description=dedent(
                f"""
                Analyze and synthesize comprehensive information for: {rule_number}
                
                You have access to:
                1. **Incident Data**: {consolidated_data[:800]}...
                2. **Template Structure** (LEARN THIS SEQUENCE): 
                {template_content[:1500]}...
                3. **Web Search Tool** (Serper) - USE THIS STRATEGICALLY
                
                YOUR MULTI-PHASE TASK:
                =======================
                
                PHASE 1: UNDERSTAND THE TEMPLATE LOGIC
                - The template shows SEQUENTIAL steps with dependencies
                - Identify: What gets checked first? What depends on what?
                - Extract: Conditional logic (IF X THEN Y patterns)
                - Note: Which steps branch based on previous results?
                
                PHASE 2: EXTRACT ACTUAL INCIDENT ENTITIES
                - From the incident data, extract:
                * Exact usernames (e.g., jsmith@company.com)
                * Exact IP addresses if mentioned
                * Applications mentioned
                * Any other specific identifiers
                - These will be used in EVERY subsequent step
                
                PHASE 3: STRATEGIC WEB SEARCH (if needed)
                - Only search if you need clarification on:
                * Alert type behavior (e.g., "passwordless authentication risks")
                * Investigation best practices for this specific rule type
                * Common false positive patterns
                
                Example searches:
                - "Rule 183 passwordless authentication false positive indicators"
                - "Azure AD passwordless authentication investigation steps"
                - "How to verify legitimate passwordless authentication"
                
                DO NOT search for generic security info - be SPECIFIC to the rule type.
                
                PHASE 4: MAP TEMPLATE TO INCIDENT
                Create a synthesis that shows:
                
                1. **Template Flow Summary**: 
                "The template follows this sequence: [Step 1] → [Step 2] → [Step 3 branches if condition X]..."
                
                2. **Incident-Specific Entities**:
                "This incident involves:"
                - Users: [exact usernames]
                - IPs: [if available]
                - Apps: [if mentioned]
                - Timeline: [key timestamps]
                
                3. **Investigation Strategy** (from template + web research):
                "Based on template structure and {rule_number} best practices:"
                - First, we'll [action from Step 1 using actual user data]
                - Then, check [Step 2 condition] which will determine [next path]
                - If [condition from template], we'll [branch action]
                - Final classification will depend on [cumulative evidence]
                
                4. **Historical Pattern Context**:
                "From {total_incidents} past incidents:"
                - {fp_rate}% were False Positives because [common reasons]
                - {tp_rate}% were True Positives because [common reasons]
                - Expected findings: [specific phrases/values from history]
                
                5. **Critical Decision Points** (from template):
                Extract IF/THEN logic:
                - "If VIP user = YES, then [action A], else [action B]"
                - "If critical app found, escalate; if not, likely FP"
                
                FORMAT YOUR OUTPUT:
                ===================
                
                # SYNTHESIS FOR {rule_number}
                
                ## Template Investigation Flow
                [Sequential summary of template steps with dependencies]
                
                ## This Incident's Key Entities
                - Users: [exact list]
                - IPs: [exact list if available]
                - Apps: [exact list if available]
                - Timestamps: [key times]
                
                ## Investigation Strategy (Template + Research)
                [Step-by-step plan that follows template logic]
                
                ## Historical Patterns ({total_incidents} incidents)
                - FP Rate: {fp_rate}% typically show: [patterns]
                - TP Rate: {tp_rate}% typically show: [patterns]
                
                ## Critical Decision Points
                [List of IF/THEN branches from template]
                
                ## Web Research Findings (if searched)
                [Key insights from Serper search about this alert type]
                
                IMPORTANT: Your synthesis should make it EASY for the next agent to:
                1. Generate steps that follow template sequence
                2. Use actual incident data (real usernames, etc.)
                3. Include conditional logic from template
                4. Connect each step to previous findings
            """
            ),
            expected_output=dedent(
                """
                A structured synthesis document that includes:
                
                1. Clear template flow diagram (Step A → Step B → [if X then C else D])
                2. All specific entities from incident (exact usernames, IPs, apps)
                3. Investigation strategy that maps template to this incident
                4. Historical patterns with percentages and specific indicators
                5. All conditional logic extracted from template
                6. Web research findings (if searches were performed)
                
                The synthesis should read like an investigation blueprint that another
                analyst could follow step-by-step, knowing exactly what to check and
                in what order, using the actual data from this specific incident.
            """
            ),
            agent=agent,
        )

    def generate_triaging_plan_task(self, agent, synthesis_output, rule_number):
        """Task to generate detailed step-by-step triaging plan with KQL queries."""
        return Task(
            description=dedent(
                f"""
                Generate a comprehensive, detailed triaging plan for: {rule_number}
                
                Based on the synthesis: {synthesis_output}
                
                Create a DETAILED step-by-step investigation plan. Each step MUST include:
                
                1. **Step Name**: Clear, action-oriented title (e.g., "Verify IP Reputation and Geolocation")
                
                2. **Explanation**: Detailed 4-6 sentences covering:
                   - What exactly to investigate
                   - Why this step is important
                   - What indicators to look for (specific values, patterns)
                   - How to interpret findings (what's normal vs suspicious)
                   - Decision criteria (when to escalate, when to close)
                
                3. **KQL Query**: If applicable, provide the EXACT KQL query for:
                   - Azure Sentinel / Log Analytics
                   - Microsoft 365 Defender
                   - Include filters for specific fields
                   - Add comments explaining the query
                
                4. **User Input Required**: Yes/No
                   - Set to "No" only for informational/review steps
                   - Set to "Yes" for all investigation steps
                
                IMPORTANT GUIDELINES:
                - Create 6-10 steps (comprehensive but not overwhelming)
                - Order steps logically (initial triage â†’ detailed investigation â†’ classification)
                - Include specific technical checks (IP reputation, MFA status, device fingerprint, etc.)
                - Provide decision trees in explanations ("If X is found, then Y")
                - Reference industry best practices where applicable
                - Include escalation criteria clearly
                
                Common investigation patterns by rule type:
                
                **For Sophos/EDR Alerts (Rule#280):**
                - Service health check
                - Process/file analysis
                - Endpoint status verification
                - False positive pattern recognition
                - Escalation to L3 decision
                
                **For Atypical Travel (Rule#286):**
                - Impossible travel calculation
                - IP/geolocation analysis
                - Device trust verification
                - MFA validation
                - VPN usage check
                - User behavior baseline comparison
                
                **For Privileged Role Assignment (Rule#014):**
                - Role sensitivity assessment
                - Initiator verification
                - PIM vs permanent assignment
                - Business justification check
                - Change management validation
                - Post-assignment activity monitoring
                
                **For Passwordless Authentication (Rule#183):**
                - Authentication method verification
                - Application criticality assessment
                - Certificate/token validation
                - User confirmation
                - MFA enforcement check
                
                FORMAT each step EXACTLY as:
                ---
                STEP: [Clear Step Name]
                EXPLANATION: [4-6 detailed sentences with specific guidance, indicators, and decision criteria]
                KQL: [Complete query with comments, or "N/A" if not applicable]
                INPUT_REQUIRED: [Yes/No]
                ---
            """
            ),
            expected_output=dedent(
                """
                A structured plan with 6-10 detailed investigation steps.
                
                Each step formatted as:
                ---
                STEP: Verify IP Reputation and Geographic Location
                EXPLANATION: Check the source IP address against threat intelligence databases to determine if it's associated with malicious activity. Use VirusTotal, AbuseIPDB, or Azure Sentinel threat intelligence. Also verify the geographic location matches expected user behavior. If the IP is clean and location is normal (user's home country/city), this indicates a potential false positive. If the IP has a poor reputation score or originates from an unexpected country, this warrants further investigation and possible escalation. Document the IP address, reputation score, and location in your findings.
                KQL: SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "user@domain.com"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, DeviceDetail, AppDisplayName
| summarize SignInCount = count() by IPAddress, Location
INPUT_REQUIRED: Yes
                ---
            """
            ),
            agent=agent,
            context=[synthesis_output] if synthesis_output else [],
        )

    def predict_outcome_task(self, agent, consolidated_data, rule_number):
        """Task to predict True Positive vs False Positive with detailed analysis."""
        return Task(
            description=dedent(
                f"""
                Predict the outcome for: {rule_number}
                
                Perform a comprehensive analysis of this incident: {str(consolidated_data)[:1000]}...
                
                ANALYSIS STEPS:
                1. Extract and analyze resolver comments for key indicators
                2. Review historical classification and justification
                3. Apply pattern recognition based on known TP/FP patterns
                4. Consider context: priority, VIP users, time of day, etc.
                
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
                - Resolver Comments: {consolidated_data.get('resolver_comments', 'N/A')[:200]}
                
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

    def generate_triaging_plan_task(self, agent, synthesis_output, rule_number):
        """Task to generate detailed step-by-step triaging plan with expected outputs."""
        return Task(
            description=dedent(
                f"""
                Generate a comprehensive triaging plan for: {rule_number}
                
                Based on the synthesis with FULL HISTORICAL DATA: {synthesis_output}
                
                Each step MUST include:
                
                1. **Step Name**: Clear, action-oriented title
                
                2. **Explanation**: Detailed 4-6 sentences
                
                3. **KQL Query**: If applicable
                
                4. **EXPECTED OUTPUT**: Critical addition - what should the analyst expect to find?
                - Based on historical patterns from ALL past incidents
                - Include percentage likelihood (e.g., "80% of cases show clean IP")
                - List specific phrases/values to look for
                - Indicate if this supports False Positive or True Positive
                
                Example for IP check:
                "Expected Output: Based on 45 historical incidents (82% False Positive rate), 
                you should typically find: 'Clean IP reputation', 'No malicious indicators', 
                'Known IP range'. If these are found, incident leans toward False Positive."
                
                5. **User Input Required**: Yes/No
                
                FORMAT each step EXACTLY as:
                ---
                STEP: [Step Name]
                EXPLANATION: [Detailed guidance]
                KQL: [Query or N/A]
                EXPECTED_OUTPUT: [What to expect based on historical data - be specific with percentages and examples]
                INPUT_REQUIRED: [Yes/No]
                ---
            """
            ),
            expected_output=dedent(
                """
                6-10 steps, each with EXPECTED_OUTPUT field showing:
                - Historical percentage likelihood
                - Specific phrases/values to look for
                - How this indicates FP vs TP
                
                Example:
                ---
                STEP: Verify IP Reputation
                EXPLANATION: Check source IP against threat intelligence...
                KQL: SigninLogs | where...
                EXPECTED_OUTPUT: Based on 45 past incidents (82% FP rate): Expect "Clean IP", "No threats detected", "Known corporate IP range". Finding these indicates ~82% chance of False Positive. If instead you find "Malicious IP" or "Bad reputation", indicates True Positive.
                INPUT_REQUIRED: Yes
                ---
            """
            ),
            agent=agent,
            context=[synthesis_output] if synthesis_output else [],
        )

    def combine_results_task(self, agent, triaging_plan, predictions):
        """Task to combine the triaging plan and predictions into final output."""
        return Task(
            description=dedent(
                f"""
                Combine the triaging plan and predictions into a cohesive output.
                
                Triaging Plan:
                {triaging_plan}
                
                Predictions:
                {predictions}
                
                Create a structured output that analysts can use during investigation.
            """
            ),
            expected_output=dedent(
                """
                A combined output with:
                1. Investigation Steps (from triaging plan)
                2. AI Predictions (overall prediction with reasoning)
                3. Key Focus Areas (what to watch for)
            """
            ),
            agent=agent,
        )
