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
        """Task to generate CONCISE, ACTION-FOCUSED triaging plan."""
        return Task(
            description=dedent(
                f"""
                Generate a CONCISE and ACTIONABLE triaging plan for: {rule_number}
                
                Based on synthesis: {synthesis_output}
                
                CRITICAL REQUIREMENTS:
                ====================
                
                1. **Step Names**: Must be SPECIFIC and ACTION-ORIENTED
                ❌ BAD: "Verify IP Reputation and Geolocation"
                ✅ GOOD: "Check Source IP: Threat Intelligence"
                
                ❌ BAD: "User Behavior Analysis and Pattern Review"
                ✅ GOOD: "Review User Sign-in History"
                
                2. **Explanations**: Keep to 2-3 sentences MAX. Format:
                - Sentence 1: What to check (specific action)
                - Sentence 2: What indicates FP vs TP (decision criteria)
                - Sentence 3 (optional): When to escalate
                
                3. **Expected Output**: ONE clear sentence showing the most common finding
                Format: "Typically shows: [specific value/pattern]. If found → [FP/TP]"
                
                4. **Step Count**: Create 5-8 steps only (quality over quantity)
                
                STEP STRUCTURE TEMPLATE:
                =======================
                
                ---
                STEP: [Verb] + [Specific Target] + [Brief Context]
                
                EXPLANATION: [Action sentence]. [Decision criteria]. [Escalation if needed].
                
                KQL: [Query if applicable, otherwise empty]
                
                EXPECTED_OUTPUT: Typically shows: [specific finding from historical data]. If found → [indicates FP/TP].
                
                INPUT_REQUIRED: Yes/No
                ---
                
                EXAMPLES OF GOOD STEPS:
                ======================
                
                Example 1 (IP Check):
                ---
                STEP: Check Source IP Reputation
                EXPLANATION: Query threat intelligence for the source IP address. Clean reputation with no alerts indicates legitimate activity (FP). Malicious IP or high-risk score requires immediate escalation.
                KQL: SigninLogs | where IPAddress == "x.x.x.x" | project TimeGenerated, IPAddress, Location, RiskLevel
                EXPECTED_OUTPUT: Typically shows: "Clean IP, No threats, Known range". If found → False Positive (85% historical rate).
                INPUT_REQUIRED: Yes
                ---
                
                Example 2 (User Confirmation):
                ---
                STEP: Confirm Activity with User
                EXPLANATION: Contact user to verify if they performed this action. User confirmation of legitimate activity closes as FP. No response or user denial requires L3 escalation.
                KQL: N/A
                EXPECTED_OUTPUT: Typically shows: "User confirmed legitimate action". If found → False Positive (90% historical rate).
                INPUT_REQUIRED: Yes
                ---
                
                Example 3 (MFA Check):
                ---
                STEP: Verify MFA Completion
                EXPLANATION: Check if multi-factor authentication was successfully completed. MFA success indicates legitimate access (FP). Missing or failed MFA is suspicious (TP).
                KQL: SigninLogs | where UserPrincipalName == "user@domain.com" | project MfaDetail, AuthenticationRequirement
                EXPECTED_OUTPUT: Typically shows: "MFA successful, All requirements met". If found → False Positive (88% historical rate).
                INPUT_REQUIRED: Yes
                ---
                
                RULE-SPECIFIC GUIDANCE:
                ======================
                
                **For Sophos/EDR Alerts:**
                - Step 1: Check Sophos Service Status
                - Step 2: Review Endpoint Health
                - Step 3: Analyze Process/File Behavior
                - Step 4: Check for Known False Positives
                - Step 5: Escalate if Service Down
                
                **For Atypical Travel:**
                - Step 1: Calculate Travel Timeframe
                - Step 2: Check Source/Destination IPs
                - Step 3: Verify Device Consistency
                - Step 4: Check VPN Usage
                - Step 5: Confirm with User
                
                **For Passwordless Authentication:**
                - Step 1: Check Authentication Method
                - Step 2: Verify Certificate/Token Validity
                - Step 3: Review Application Access
                - Step 4: Check User MFA Status
                - Step 5: Confirm with User
                
                **For Privileged Role Assignment:**
                - Step 1: Identify Assigned Role
                - Step 2: Verify Initiator Authorization
                - Step 3: Check Change Management Ticket
                - Step 4: Review Post-Assignment Activity
                - Step 5: Validate Business Justification
                
                QUALITY CHECKLIST:
                ==================
                - [ ] Each step name is under 6 words
                - [ ] Each explanation is under 50 words
                - [ ] Expected output references historical FP/TP rate
                - [ ] KQL queries are complete (not truncated)
                - [ ] Total steps between 5-8
                - [ ] Steps follow logical investigation order
                - [ ] Each step has clear FP vs TP criteria
            """
            ),
            expected_output=dedent(
                """
                5-8 concise, actionable steps formatted exactly as:
                
                ---
                STEP: [Action-focused name under 6 words]
                EXPLANATION: [2-3 sentences, under 50 words total]
                KQL: [Complete query or empty]
                EXPECTED_OUTPUT: Typically shows: [specific finding]. If found → [FP/TP with percentage].
                INPUT_REQUIRED: Yes/No
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

    def real_time_prediction_task(
        self,
        agent,
        triaging_comments: dict,
        rule_number: str,
        rule_history: dict,
        template_content: str,
    ):
        """Task to predict outcome in real-time based on triaging comments."""

        # Combine all comments/answers provided so far
        all_comments = "\n\n".join(
            [f"**{step}**: {comment}" for step, comment in triaging_comments.items()]
        )

        return Task(
            description=dedent(
                f"""
                Provide REAL-TIME prediction for: {rule_number}
                
                Based on triaging comments collected so far:
                {all_comments}
                
                Historical Context:
                - Total Past Incidents: {rule_history.get('total_incidents', 0)}
                - Historical FP Rate: {rule_history.get('fp_rate', 0)}%
                - Historical TP Rate: {rule_history.get('tp_rate', 0)}%
                - Common FP Indicators: {rule_history.get('fp_indicators', 'N/A')[:200]}
                - Common TP Indicators: {rule_history.get('tp_indicators', 'N/A')[:200]}
                
                Template Guidance:
                {template_content[:500]}...
                
                YOUR TASK:
                ==========
                
                1. **Analyze Each Comment**: Review every finding documented by the analyst
                
                2. **Pattern Matching**: Compare findings against historical FP/TP patterns
                
                3. **Web Research** (if needed): Search for similar cases or indicators
                - Example: "Rule {rule_number.split('#')[1] if '#' in rule_number else rule_number} + [key finding] false positive rate"
                
                4. **Calculate Probabilities**:
                - Start with historical baseline (FP: {rule_history.get('fp_rate', 50)}%, TP: {rule_history.get('tp_rate', 50)}%)
                - Adjust based on each finding:
                    * If finding matches common FP patterns → increase FP probability
                    * If finding matches common TP patterns → increase TP probability
                - Consider strength of evidence (strong indicators = larger adjustment)
                
                5. **Provide Classification Prediction**:
                
                Format your response EXACTLY as:
                
                ---
                PREDICTION_TYPE: [False Positive / True Positive / Benign Positive]
                
                CONFIDENCE_PERCENTAGES:
                - False Positive Likelihood: [X]%
                - True Positive Likelihood: [Y]%
                - Benign Positive Likelihood: [Z]%
                (Note: X + Y + Z should equal 100%)
                
                CONFIDENCE_LEVEL: [High (80-100%) / Medium (50-79%) / Low (<50%)]
                
                KEY_FACTORS:
                1. [Finding from comments that supports this prediction]
                2. [Another supporting finding]
                3. [Another supporting finding]
                
                HISTORICAL_COMPARISON:
                [How this case compares to the {rule_history.get('total_incidents', 0)} past incidents]
                
                REASONING:
                [2-3 sentence explanation of why these percentages were assigned based on the evidence]
                
                WEB_RESEARCH_FINDINGS: (if search was performed)
                [Key insights from web search that influenced prediction]
                ---
                
                CRITICAL INDICATORS:
                
                **Strong False Positive Indicators** (increase FP %):
                - "Clean IP", "No malicious reputation", "Known IP"
                - "Registered device", "Known device", "Corporate device"
                - "MFA successful", "MFA enabled"
                - "User confirmed", "Legitimate activity"
                - "Known applications", "Approved apps"
                - "VPN usage" (NordVPN, ExpressVPN, corporate VPN)
                - "BAS testing", "Security testing"
                - "Nothing suspicious", "Normal behavior"
                
                **Strong True Positive Indicators** (increase TP %):
                - "Malicious IP", "Bad reputation", "Threat detected"
                - "Unknown device", "Unregistered device"
                - "Failed MFA", "MFA bypass"
                - "Unauthorized access", "Suspicious activity"
                - "Service not running", "Service down"
                - "Data exfiltration", "Unusual downloads"
                - "Multiple failed attempts"
                - "Sensitive data access"
                
                **Benign Positive Indicators** (increase BP %):
                - "Legitimate but unexpected", "Authorized but unusual"
                - "Policy violation but not malicious"
                - "Configuration issue", "Misconfiguration"
                - "Automated process", "Scheduled task"
            """
            ),
            expected_output=dedent(
                """
                A comprehensive real-time prediction with exact percentages:
                
                ---
                PREDICTION_TYPE: [Most Likely Classification]
                
                CONFIDENCE_PERCENTAGES:
                - False Positive Likelihood: X%
                - True Positive Likelihood: Y%
                - Benign Positive Likelihood: Z%
                
                CONFIDENCE_LEVEL: [High/Medium/Low]
                
                KEY_FACTORS:
                [Numbered list of supporting evidence from comments]
                
                HISTORICAL_COMPARISON:
                [How this case aligns with historical patterns]
                
                REASONING:
                [Clear explanation of percentage calculations]
                
                WEB_RESEARCH_FINDINGS:
                [If web search was used, what was found]
                ---
            """
            ),
            agent=agent,
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
