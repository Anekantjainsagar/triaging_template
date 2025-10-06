import os
import pandas as pd
from crewai import Agent, LLM
from crewai_tools import SerperDevTool
from crewai.tools import BaseTool
from pydantic import Field

# Custom tool for reading tracker data
class DataReadingTool(BaseTool):
    name: str = "Data Reading Tool"
    description: str = "Reads and consolidates data from all tracker sheets in the data directory."
    
    def _run(self, query: str = "") -> str:
        """Read all tracker sheets and return data as JSON string."""
        try:
            from src.utils import read_all_tracker_sheets
            df = read_all_tracker_sheets('data')
            
            if df.empty:
                return "No data found in tracker sheets."
            
            # Convert to JSON for LLM processing
            return df.to_json(orient='records', lines=False)
        except Exception as e:
            return f"Error reading data: {str(e)}"

# Custom tool for searching alerts
class AlertSearchTool(BaseTool):
    name: str = "Alert Search Tool"
    description: str = "Search for security alerts in the tracker data based on keywords."
    
    def _run(self, query: str) -> str:
        """Search for alerts matching the query."""
        try:
            from src.utils import read_all_tracker_sheets, search_alerts_in_data
            df = read_all_tracker_sheets('data')
            
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
            from src.utils import read_all_tracker_sheets, consolidate_incident_data
            import json
            
            df = read_all_tracker_sheets('data')
            
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
            from src.utils import get_triaging_template
            
            template = get_triaging_template(rule_number)
            return template
        except Exception as e:
            return f"Error retrieving template: {str(e)}"

# Initialize the LLM with Ollama
ollama_llm = LLM(
    model="ollama/qwen2.5:0.5b",
    base_url="http://localhost:11434"
)

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

    def data_analyst_agent(self):
        """Agent that searches and analyzes security alerts."""
        return Agent(
            role='Security Data Analyst',
            goal='Search and identify the most relevant security alerts based on user queries.',
            backstory=(
                "You are an expert security data analyst with deep knowledge of cybersecurity incidents. "
                "You excel at quickly identifying relevant alerts from large datasets and understanding "
                "security patterns. You always provide clear, actionable results."
            ),
            tools=[self.alert_search_tool, self.data_reading_tool],
            verbose=True,
            allow_delegation=False,
            llm=self.llm
        )

    def data_consolidation_agent(self):
        """Agent that consolidates incident data."""
        return Agent(
            role='Data Consolidation Specialist',
            goal='Consolidate all relevant data for a specific security incident into a single, organized format.',
            backstory=(
                "You are a meticulous data engineer specializing in security operations. "
                "Your expertise lies in gathering scattered incident data and organizing it "
                "into comprehensive reports that analysts can easily understand and act upon."
            ),
            tools=[self.incident_consolidation_tool],
            verbose=True,
            allow_delegation=False,
            llm=self.llm
        )

    def template_search_agent(self):
        """Agent that retrieves triaging templates."""
        return Agent(
            role='Security Playbook Specialist',
            goal='Find and retrieve the correct triaging template for security rules.',
            backstory=(
                "You are a security playbook expert who maintains and retrieves standardized "
                "investigation procedures. You ensure analysts follow the correct triaging steps "
                "for each type of security alert."
            ),
            tools=[self.template_retrieval_tool],
            verbose=True,
            allow_delegation=False,
            llm=self.llm
        )

    def knowledge_synthesis_agent(self):
        """Agent that synthesizes information from multiple sources."""
        tools = [self.incident_consolidation_tool]
        if self.web_search_tool:
            tools.append(self.web_search_tool)
        
        return Agent(
            role='Security Intelligence Analyst',
            goal='Synthesize incident data, templates, and threat intelligence into comprehensive analysis.',
            backstory=(
                "You are a senior security analyst with expertise in correlating information "
                "from multiple sources. You excel at understanding the full context of security "
                "incidents and providing clear summaries for investigation teams."
            ),
            tools=tools,
            verbose=True,
            allow_delegation=False,
            llm=self.llm
        )

    def content_generation_agent(self):
        """Agent that creates triaging plans and documentation."""
        return Agent(
            role='Security Documentation Specialist',
            goal='Generate clear, step-by-step triaging plans and documentation for security analysts.',
            backstory=(
                "You are a technical writer specializing in security operations. You transform "
                "complex security procedures into easy-to-follow steps that any analyst can understand. "
                "Your documentation is known for its clarity and actionability."
            ),
            tools=[],
            verbose=True,
            allow_delegation=False,
            llm=self.llm
        )

    def prediction_analysis_agent(self):
        """Agent that predicts incident outcomes based on historical data."""
        return Agent(
            role='Security Prediction Analyst',
            goal='Analyze historical patterns to predict whether incidents are True Positives or False Positives.',
            backstory=(
                "You are a data scientist specializing in security analytics. You analyze patterns "
                "in historical incident data to predict outcomes. Your predictions help analysts "
                "prioritize their investigations and set expectations for incident resolution."
            ),
            tools=[self.incident_consolidation_tool, self.data_reading_tool],
            verbose=True,
            allow_delegation=False,
            llm=self.llm
        )

    def utility_agent(self):
        """Simple utility agent for combining data."""
        return Agent(
            role='Data Utility Specialist',
            goal='Perform data transformation and combination tasks.',
            backstory=(
                "You are a utility specialist who excels at quickly combining and formatting "
                "data from multiple sources into structured outputs."
            ),
            tools=[],
            verbose=True,
            allow_delegation=False,
            llm=self.llm
        )