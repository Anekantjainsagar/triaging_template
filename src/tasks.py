import os
from crewai import Task
from textwrap import dedent

class TriagingTasks:
    def __init__(self):
        pass

    def search_alerts_task(self, agent, search_query):
        """Task to search for relevant alerts based on user query."""
        return Task(
            description=dedent(f"""
                Search for security alerts related to: '{search_query}'
                
                Use the Alert Search Tool to find the top 5 most relevant alerts.
                Focus on matching:
                - Rule numbers
                - Alert descriptions
                - Incident types
                - Data connectors
                
                Return a simple list of alert titles in the format:
                Rule#XXX - Incident XXXXXX
            """),
            expected_output=dedent("""
                A numbered list of 5 relevant alerts, each on a new line.
                Example:
                1. Rule#280 - Incident 208308
                2. Rule#286 - Incident 208303
                3. Rule#002 - Incident 208307
            """),
            agent=agent
        )

    def consolidate_data_task(self, agent, incident_id):
        """Task to consolidate all data for a specific incident."""
        return Task(
            description=dedent(f"""
                Consolidate all data for incident: {incident_id}
                
                Use the Incident Consolidation Tool to gather:
                - All incident metadata
                - Timeline information (reported, responded, resolution times)
                - Engineer details
                - Resolver comments
                - Classification and justification
                
                Return the complete incident data in a structured format.
            """),
            expected_output=dedent(f"""
                A comprehensive data summary for incident {incident_id} including:
                - Incident number
                - Rule information
                - Priority and status
                - Timeline metrics
                - Investigation findings
                - Historical classification
            """),
            agent=agent
        )

    def retrieve_template_task(self, agent, rule_number):
        """Task to retrieve the triaging template for a rule."""
        return Task(
            description=dedent(f"""
                Retrieve the triaging template for: {rule_number}
                
                Use the Template Retrieval Tool to find the correct template.
                If no specific template exists, a generic one will be provided.
                
                Return the complete template content.
            """),
            expected_output=dedent(f"""
                The full triaging template for {rule_number} including:
                - Investigation steps
                - Required checks
                - Data points to collect
                - Decision criteria
            """),
            agent=agent
        )

    def synthesize_knowledge_task(self, agent, consolidated_data, template_content, rule_number):
        """Task to synthesize all available information about the incident."""
        return Task(
            description=dedent(f"""
                Analyze and synthesize information for: {rule_number}
                
                You have access to:
                1. Incident Data: {consolidated_data}
                2. Template: {template_content[:300]}...
                
                Create a comprehensive summary that includes:
                - What type of security alert this is
                - Key indicators from the incident data
                - Historical patterns from resolver comments
                - Critical data points (IP, user, location, MFA, device)
                - Common outcomes for this rule type
                
                Focus on actionable insights that will help guide the investigation.
            """),
            expected_output=dedent("""
                A clear summary with:
                1. Incident Overview (2-3 sentences)
                2. Key Data Points (bullet list)
                3. Historical Context (what typically happens with this rule)
                4. Investigation Focus Areas (what to check carefully)
            """),
            agent=agent
        )

    def generate_triaging_plan_task(self, agent, synthesis_output, rule_number):
        """Task to generate the step-by-step triaging plan."""
        return Task(
            description=dedent(f"""
                Generate a detailed triaging plan for: {rule_number}
                
                Based on the synthesis: {synthesis_output}
                
                Create a step-by-step investigation plan. Each step should include:
                1. Step Name: Brief, clear title
                2. Explanation: What to check and why (2-3 sentences)
                3. KQL Query: If applicable, provide the KQL query
                4. User Input Required: Yes/No
                
                Typical steps for security incidents:
                - Initial Assessment
                - IP Reputation Check
                - User Sign-in History
                - MFA Verification
                - Device/Application Analysis
                - Historical Pattern Review
                - Final Classification
                
                For Rule#280 (Sophos), add: Service Status Check, Escalation Decision
                For Rule#286 (Atypical Travel), add: Geographic Analysis, Travel Pattern Check
                For Rule#002 (Conditional Access), add: Policy Review, Access Pattern Analysis
            """),
            expected_output=dedent("""
                A structured plan with 5-8 investigation steps.
                
                Each step formatted as:
                STEP: [Step Name]
                EXPLANATION: [What to check and why]
                KQL: [Query if applicable, or "N/A"]
                INPUT_REQUIRED: [Yes/No]
                ---
            """),
            agent=agent,
            context=[synthesis_output] if synthesis_output else []
        )

    def predict_outcome_task(self, agent, consolidated_data, rule_number):
        """Task to predict True Positive vs False Positive likelihood."""
        return Task(
            description=dedent(f"""
                Predict the outcome for: {rule_number}
                
                Analyze this incident data: {consolidated_data}
                
                Look for these patterns:
                
                FALSE POSITIVE indicators:
                - "clean IP" or "IP reputation: clean"
                - "known device" or "registered device"
                - "known apps" or "legitimate applications"
                - "MFA satisfied" or "MFA enabled"
                - "legitimate user"
                - "Nord VPN" or "VPN usage"
                - "BAS testing"
                - "nothing suspicious"
                
                TRUE POSITIVE indicators:
                - "services not running"
                - "unauthorized access"
                - "malicious IP"
                - "suspicious activity"
                - "unknown device"
                - "failed MFA"
                - "escalated"
                
                Also check historical classification:
                - Previous Classification: {consolidated_data.get('false_true_positive', 'N/A')}
                - Reason: {consolidated_data.get('why_false_positive', 'N/A')}
                
                Provide prediction with confidence level and clear reasoning.
            """),
            expected_output=dedent("""
                A prediction summary:
                
                PREDICTION: [Likely True Positive / Likely False Positive / Uncertain]
                CONFIDENCE: [High / Medium / Low]
                REASONING: [2-3 sentences explaining why based on the data patterns]
                KEY_INDICATORS: [List of specific data points that support this prediction]
            """),
            agent=agent
        )

    def combine_results_task(self, agent, triaging_plan, predictions):
        """Task to combine the triaging plan and predictions into final output."""
        return Task(
            description=dedent(f"""
                Combine the triaging plan and predictions into a cohesive output.
                
                Triaging Plan:
                {triaging_plan}
                
                Predictions:
                {predictions}
                
                Create a structured output that analysts can use during investigation.
            """),
            expected_output=dedent("""
                A combined output with:
                1. Investigation Steps (from triaging plan)
                2. AI Predictions (overall prediction with reasoning)
                3. Key Focus Areas (what to watch for)
            """),
            agent=agent
        )