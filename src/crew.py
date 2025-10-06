import os
from crewai import Crew, Process
from .agents import TriagingAgents
from .tasks import TriagingTasks
import json

class TriagingCrew:
    def __init__(self):
        self.triaging_agents = TriagingAgents()
        self.triaging_tasks = TriagingTasks()

    def run(self, search_query: str = None, incident_id: str = None, rule_number: str = None, consolidated_data=None):
        """
        Main function to run the triaging crew.
        The specific tasks and agents used will depend on the phase of the triaging process.
        """
        if search_query:
            # Phase 1: Search for alerts
            data_analyst = self.triaging_agents.data_analyst_agent()
            search_alerts_task = self.triaging_tasks.search_alerts_task(data_analyst, search_query)
            
            crew = Crew(
                agents=[data_analyst],
                tasks=[search_alerts_task],
                process=Process.sequential,
                verbose=True
            )
            # The output of this task is a list of alert titles
            return crew.kickoff()

        elif incident_id and rule_number:
            # Phase 2: Consolidate data and retrieve template
            data_consolidation_agent = self.triaging_agents.data_consolidation_agent()
            template_search_agent = self.triaging_agents.template_search_agent()

            consolidate_task = self.triaging_tasks.consolidate_data_task(data_consolidation_agent, incident_id)
            retrieve_template_task = self.triaging_tasks.retrieve_template_task(template_search_agent, rule_number)

            final_task = self.triaging_tasks.combine_results_task(
                agent=self.triaging_agents.utility_agent(), # A new utility agent to combine results
                consolidated_data=consolidate_task.output,
                template_content=retrieve_template_task.output
            )

            crew = Crew(
                agents=[data_consolidation_agent, template_search_agent, self.triaging_agents.utility_agent()],
                tasks=[consolidate_task, retrieve_template_task, final_task],
                process=Process.sequential,
                verbose=True
            )
            return crew.kickoff()

        elif consolidated_data and rule_number:
            # Phase 3: Synthesize knowledge, generate content, and predict outcome
            knowledge_synthesis_agent = self.triaging_agents.knowledge_synthesis_agent()
            content_generation_agent = self.triaging_agents.content_generation_agent()
            prediction_analysis_agent = self.triaging_agents.prediction_analysis_agent()
            
            # Use placeholders for now, as tasks are chained. CrewAI will handle
            # the task output passing automatically.
            synthesize_task = self.triaging_tasks.synthesize_knowledge_task(
                knowledge_synthesis_agent, consolidated_data, "Template Content Placeholder"
            )
            generate_content_task = self.triaging_tasks.generate_content_task(
                content_generation_agent, synthesize_task.output
            )
            predict_outcome_task = self.triaging_tasks.predict_outcome_task(
                prediction_analysis_agent, consolidated_data
            )
            
            # A final task to combine the outputs from generation and prediction
            final_output_task = self.triaging_tasks.combine_final_results_task(
                agent=self.triaging_agents.utility_agent(),
                triaging_plan=generate_content_task.output,
                predictions=predict_outcome_task.output
            )

            crew = Crew(
                agents=[knowledge_synthesis_agent, content_generation_agent, prediction_analysis_agent, self.triaging_agents.utility_agent()],
                tasks=[synthesize_task, generate_content_task, predict_outcome_task, final_output_task],
                process=Process.sequential,
                verbose=True
            )
            return crew.kickoff()