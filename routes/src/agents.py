import os
import pandas as pd
from crewai import Agent, LLM
from crewai_tools import SerperDevTool
from crewai.tools import BaseTool


# Custom tool for reading tracker data
class DataReadingTool(BaseTool):
    name: str = "Data Reading Tool"
    description: str = (
        "Reads and consolidates data from all tracker sheets in the data directory."
    )

    def _run(self, query: str = "") -> str:
        """Read all tracker sheets and return data as JSON string."""
        try:
            from routes.src.utils import read_all_tracker_sheets

            df = read_all_tracker_sheets("data")

            if df.empty:
                return "No data found in tracker sheets."

            # Convert to JSON for LLM processing
            return df.to_json(orient="records", lines=False)
        except Exception as e:
            return f"Error reading data: {str(e)}"


# Custom tool for searching alerts
class AlertSearchTool(BaseTool):
    name: str = "Alert Search Tool"
    description: str = (
        "Search for security alerts in the tracker data based on keywords."
    )

    def _run(self, query: str) -> str:
        """Search for alerts matching the query."""
        try:
            from routes.src.utils import read_all_tracker_sheets, search_alerts_in_data

            df = read_all_tracker_sheets("data")

            if df.empty:
                return "No data available to search."

            results = search_alerts_in_data(df, query, top_n=5)

            if not results:
                return f"No alerts found matching query: {query}"

            return "\n".join(results)
        except Exception as e:
            return f"Error searching alerts: {str(e)}"


# Custom tool for consolidating incident data
class IncidentConsolidationTool(BaseTool):
    name: str = "Incident Consolidation Tool"
    description: str = "Consolidate all data for a specific incident number."

    def _run(self, incident_id: str) -> str:
        """Consolidate data for a specific incident."""
        try:
            from routes.src.utils import (
                read_all_tracker_sheets,
                consolidate_incident_data,
            )
            import json

            df = read_all_tracker_sheets("data")

            if df.empty:
                return "No data available."

            consolidated = consolidate_incident_data(df, incident_id)

            if not consolidated:
                return f"No data found for incident: {incident_id}"

            return json.dumps(consolidated, indent=2)
        except Exception as e:
            return f"Error consolidating incident data: {str(e)}"


# Custom tool for template retrieval
class TemplateRetrievalTool(BaseTool):
    name: str = "Template Retrieval Tool"
    description: str = "Retrieve the triaging template for a specific rule number."

    def _run(self, rule_number: str) -> str:
        """Retrieve template for a rule."""
        try:
            from routes.src.utils import get_triaging_template

            template = get_triaging_template(rule_number)
            return template
        except Exception as e:
            return f"Error retrieving template: {str(e)}"


# Initialize the LLM with Ollama
ollama_llm = LLM(model="ollama/qwen2.5:0.5b", base_url="http://localhost:11434")

# Initialize web search tool (optional - requires API key)
try:
    serper_tool = SerperDevTool()
except:
    serper_tool = None
    print("Warning: SerperDevTool not configured. Web search will be unavailable.")


# --- Agent Definitions ---
class TriagingAgents:
    def __init__(self):
        self.llm = ollama_llm
        self.web_search_tool = serper_tool

        # Initialize custom tools
        self.data_reading_tool = DataReadingTool()
        self.alert_search_tool = AlertSearchTool()
        self.incident_consolidation_tool = IncidentConsolidationTool()
        self.template_retrieval_tool = TemplateRetrievalTool()

    def prediction_analysis_agent(self):
        """Agent that predicts incident outcomes based on historical data."""
        return Agent(
            role="Security Prediction Analyst",
            goal="Analyze historical patterns to predict whether incidents are True Positives or False Positives.",
            backstory=(
                "You are a data scientist specializing in security analytics. You analyze patterns "
                "in historical incident data to predict outcomes. Your predictions help analysts "
                "prioritize their investigations and set expectations for incident resolution."
            ),
            tools=[self.incident_consolidation_tool, self.data_reading_tool],
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
        )

    def real_time_prediction_agent(self):
        """Agent that provides real-time predictions during triaging based on comments/answers."""
        return Agent(
            role="Real-Time Prediction Analyst",
            goal="Analyze triaging comments and answers in real-time to predict True/False/Benign Positive likelihood.",
            backstory=(
                "You are an AI prediction specialist who analyzes investigation findings as they "
                "are documented. You use historical patterns, template guidance, and web research "
                "to provide live predictions of incident classification with confidence percentages."
            ),
            tools=[self.incident_consolidation_tool, self.data_reading_tool]
            + ([self.web_search_tool] if self.web_search_tool else []),
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
        )
