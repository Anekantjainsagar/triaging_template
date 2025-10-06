import os
from crewai import Agent, LLM
from crewai_tools import SerperDevTool
from crewai_tools import FileReadTool

# Initialize the LLM with Ollama
ollama_llm = LLM(
    model="ollama/qwen2.5:0.5b",
    base_url="http://localhost:11434"
)

# Initialize web search tool
serper_tool = SerperDevTool()

# Initialize specific file tools
file_read_tool = FileReadTool()

# Helper function for writing files
def write_output(content, filename):
    """Helper function to write content to a file"""
    try:
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
        return f"Successfully wrote to {filename}"
    except Exception as e:
        return f"Error writing to {filename}: {str(e)}"

# --- Agent Definitions ---
class TriagingAgents:
    def __init__(self):
        self.web_search_tool = serper_tool
        self.file_read_tool = file_read_tool
        self.llm = ollama_llm

    def data_analyst_agent(self):
        """
        Agent responsible for analyzing the raw data from tracker sheets.
        """
        return Agent(
            role='Data Analyst',
            goal='Identify and summarize the top 5 most relevant security alerts based on a user query.',
            backstory=(
                "You are an expert data analyst specializing in cybersecurity. "
                "Your primary task is to sift through large datasets of security incidents "
                "to find the most pertinent information quickly and accurately."
            ),
            tools=[self.file_read_tool],
            verbose=True,
            allow_delegation=False,
            llm=self.llm
        )

    def data_consolidation_agent(self):
        """
        Agent that consolidates all rows of a specific incident from the tracker sheets.
        """
        return Agent(
            role='Data Consolidation Specialist',
            goal='Consolidate all relevant data for a specific security incident into a single, clean format.',
            backstory=(
                "You are a meticulous data engineer. Your job is to take scattered "
                "data points related to a single incident and organize them into "
                "a single, coherent document for further analysis."
            ),
            tools=[self.file_read_tool],
            verbose=True,
            allow_delegation=False,
            llm=self.llm
        )

    def template_search_agent(self):
        """
        Agent that searches for the correct triaging template.
        """
        return Agent(
            role='Template Retrieval Specialist',
            goal='Find the correct triaging template for a given security rule number or keyword.',
            backstory=(
                "You are a librarian of security playbooks. You know exactly where "
                "to find the right template based on a given rule number or description, "
                "ensuring the investigation follows the correct procedure."
            ),
            tools=[self.file_read_tool],
            verbose=True,
            allow_delegation=False,
            llm=self.llm
        )
    
    def utility_agent(self):
        """
        A simple agent to perform utility tasks like combining outputs.
        """
        return Agent(
            role='Utility Expert',
            goal='Perform simple utility tasks such as combining data outputs from other agents.',
            backstory="You are a helpful assistant who can quickly and accurately combine information.",
            tools=[],
            verbose=True,
            allow_delegation=False,
            llm=self.llm
        )

    def knowledge_synthesis_agent(self):
        """
        Agent that synthesizes information from the template, tracker data, and web search.
        """
        return Agent(
            role='Knowledge Synthesis Analyst',
            goal='Synthesize a comprehensive understanding of a security incident by combining information from multiple sources.',
            backstory=(
                "You are an expert researcher with a knack for connecting the dots. "
                "You can take raw data, a triaging template, and external research to "
                "form a complete picture of an incident."
            ),
            tools=[self.web_search_tool, self.file_read_tool],
            verbose=True,
            llm=self.llm
        )

    def content_generation_agent(self):
        """
        Agent that creates the empty triaging template and step-by-step explanations.
        """
        return Agent(
            role='Security Content Creator',
            goal='Generate an empty triaging template and easy-to-understand step-by-step explanations for the user.',
            backstory=(
                "You are a technical writer for a security team. You can take complex "
                "triaging steps and simplify them into clear, actionable instructions, "
                "making the process accessible to all analysts."
            ),
            tools=[],
            verbose=True,
            llm=self.llm
        )

    def prediction_analysis_agent(self):
        """
        Agent that predicts the outcome of the incident (TP/FP) based on historical data.
        """
        return Agent(
            role='Predictive Analyst',
            goal='Analyze historical incident data to predict the likelihood of a true positive or false positive.',
            backstory=(
                "You are a machine learning specialist for a SOC. You can analyze "
                "past resolver comments and outcomes to provide real-time predictions "
                "on the likely result of an ongoing investigation."
            ),
            tools=[self.file_read_tool],
            verbose=True,
            llm=self.llm
        )