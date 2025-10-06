import os
from crewai import Task
from textwrap import dedent
import json

class TriagingTasks:
    def __init__(self):
        pass

    def search_alerts_task(self, agent, search_query):
        """
        Task for the Data Analyst to search and find relevant alerts based on a query.
        """
        return Task(
            description=dedent(f"""
                Read all data from the '/data/tracker_sheets' directory.
                Analyze the data to find the top 5 alerts that are most relevant
                to the user's search query: '{search_query}'.
                The relevance should be based on keywords in the 'Description' and 'Rule#' columns.
                
                Your final output must be a concise Python list of strings, where each string is the
                title of a relevant alert, in the format 'Rule#<number> - <description>'.
            """),
            expected_output=dedent("""
                A Python list of strings, where each string is the title of a relevant alert.
                Example: ['Rule#280 - Sophos services missing', 'Rule#002 - Conditional access bypass']
            """),
            agent=agent
        )

    def consolidate_data_task(self, agent, incident_id):
        """
        Task for the Data Consolidation Agent to gather all data for a specific incident.
        """
        return Task(
            description=dedent(f"""
                You have been provided with an incident ID: {incident_id}.
                Your task is to locate the corresponding tracker sheet row(s) for this incident.
                Consolidate all the information from those rows into a single, comprehensive
                data structure (e.g., a dictionary or pandas DataFrame).
            """),
            expected_output=dedent(f"""
                A consolidated JSON object containing all the details from the tracker sheet
                for incident {incident_id}. This should include all columns and their values.
            """),
            agent=agent
        )

    def retrieve_template_task(self, agent, rule_number):
        """
        Task for the Template Search Agent to find the correct triaging template.
        """
        return Task(
            description=dedent(f"""
                Given the rule number '{rule_number}', search the '/data/triaging_templates' folder
                to find the corresponding triaging template file.
                
                Once found, read the entire content of the file and return it as a string.
            """),
            expected_output=dedent(f"""
                The complete textual content of the triaging template for rule {rule_number}.
            """),
            agent=agent
        )
    
    def combine_results_task(self, agent, consolidated_data, template_content):
        """
        Task for a utility agent to combine the outputs of two other tasks into a single object.
        """
        return Task(
            description=dedent(f"""
                You are a data utility expert. Your task is to take the following two pieces of information
                and combine them into a single JSON object.
                
                - Consolidated Data: {consolidated_data}
                - Template Content: {template_content}
                
                Ensure the output is a single, valid JSON object.
            """),
            expected_output=dedent("""
                A single JSON object with two keys: 'consolidated_data' and 'template_content'.
                Example:
                {
                    "consolidated_data": {"incident": "INC_001", ...},
                    "template_content": "Rule Name: ... Step 1: ..."
                }
            """),
            agent=agent
        )

    def synthesize_knowledge_task(self, agent, consolidated_data, template_content):
        """
        Task for the Knowledge Synthesis Agent to combine all available info.
        """
        return Task(
            description=dedent(f"""
                You are a knowledge synthesis expert. Your task is to analyze the following
                information and create a comprehensive summary:
                
                - **Consolidated Incident Data:** {consolidated_data}
                - **Triaging Template:** {template_content}
                
                Based on this, and using your web search tool if necessary for additional context,
                provide a clear and concise summary of the incident and the required triaging steps.
            """),
            expected_output=dedent("""
                A JSON object containing a summary of the incident and a list of key triaging steps with brief
                explanations.
            """),
            agent=agent
        )

    def generate_content_task(self, agent, synthesized_knowledge):
        """
        Task for the Content Generation Agent to create the output for the UI.
        """
        return Task(
            description=dedent(f"""
                Based on the following synthesized knowledge: {synthesized_knowledge},
                your task is to generate:
                1. An empty triaging template with placeholders.
                2. A detailed, step-by-step plan for the user. Each step must have a clear, easy-to-understand explanation and any required KQL queries.
            """),
            expected_output=dedent("""
                A JSON object with two keys:
                - 'empty_template': A string of the formatted empty template.
                - 'triaging_plan': A list of dictionaries, where each dictionary represents a step and contains keys for 'step_name', 'explanation', 'kql_query' (if applicable), and 'user_input_required'.
            """),
            agent=agent
        )

    def predict_outcome_task(self, agent, consolidated_data):
        """
        Task for the Prediction & Analysis Agent to predict the TP/FP outcome.
        """
        return Task(
            description=dedent(f"""
                Analyze the following consolidated incident data: {consolidated_data}.
                Based on historical data and common resolver comments, predict the likelihood of this incident
                being a True Positive (TP) or False Positive (FP) at each stage of the triaging process.
                
                Your analysis should focus on how key data points (e.g., 'IP Reputation - clean', 'Known device')
                affect the final outcome.
            """),
            expected_output=dedent("""
                A JSON object containing an array of predictions for each step. Each item in the array should have
                keys for 'step_name', 'prediction', and 'confidence_score'.
            """),
            agent=agent
        )

    def combine_final_results_task(self, agent, triaging_plan, predictions):
        """
        Task to combine the final triaging plan and predictions into a single object.
        """
        return Task(
            description=dedent(f"""
                You are a data utility expert. Your task is to combine the generated triaging plan
                and the predictive analysis into a single JSON object.
                
                - Triaging Plan: {triaging_plan}
                - Predictions: {predictions}
            """),
            expected_output=dedent("""
                A single JSON object with two keys: 'triaging_plan' and 'predictions'.
                Example:
                {
                    "triaging_plan": [{"step_name": "Check IP", ...}],
                    "predictions": [{"step_name": "Check IP", "prediction": "Likely TP", ...}]
                }
            """),
            agent=agent
        )