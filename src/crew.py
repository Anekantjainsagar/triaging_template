import os
from crewai import Crew, Process
from src.agents import TriagingAgents
from src.tasks import TriagingTasks
import json
import re

class TriagingCrew:
    def __init__(self):
        self.agents = TriagingAgents()
        self.tasks = TriagingTasks()

    def run_analysis_phase(self, consolidated_data: dict, template_content: str, rule_number: str):
        """
        Run the complete analysis phase using LLM to generate dynamic triaging plan.
        No hardcoded rules - learns from data and templates.
        """
        try:
            print("\n" + "="*80)
            print("Starting AI-Powered Dynamic Analysis...")
            print("="*80)
            
            # NEW: Get historical data for this rule
            from src.utils import read_all_tracker_sheets, consolidate_rule_data
            all_data = read_all_tracker_sheets('data/tracker_sheets')
            rule_history = consolidate_rule_data(all_data, rule_number)
            
            print(f"\nHistorical Context: {rule_history.get('total_incidents', 0)} past incidents")
            print(f"True Positive Rate: {rule_history.get('tp_rate', 0)}%")
            print(f"False Positive Rate: {rule_history.get('fp_rate', 0)}%")
            
            # Create agents
            knowledge_agent = self.agents.knowledge_synthesis_agent()
            content_agent = self.agents.content_generation_agent()
            prediction_agent = self.agents.prediction_analysis_agent()
            
            # Convert consolidated data to string
            data_summary = self._create_data_summary(consolidated_data)
            
            # Add historical context to data summary
            data_summary += f"""

    HISTORICAL PATTERN ANALYSIS FOR {rule_number}:
    Total Past Incidents: {rule_history.get('total_incidents', 0)}
    True Positive Rate: {rule_history.get('tp_rate', 0)}%
    False Positive Rate: {rule_history.get('fp_rate', 0)}%
    Common Justifications: {rule_history.get('common_justifications', 'N/A')}

    Sample Resolver Comments from Past Incidents:
    {rule_history.get('all_resolver_comments', 'N/A')[:1000]}
    """
            
            # Task 1: Learn from historical data and templates
            print("\n[1/3] Learning from historical patterns and templates...")
            synthesis_task = self.tasks.synthesize_knowledge_task(
                agent=knowledge_agent,
                consolidated_data=data_summary,
                template_content=template_content,
                rule_number=rule_number
            )
            
            # Task 2: Generate dynamic triaging plan based on learning
            print("\n[2/3] Generating dynamic triaging plan from learned patterns...")
            plan_task = self.tasks.generate_triaging_plan_task(
                agent=content_agent,
                synthesis_output=synthesis_task,
                rule_number=rule_number
            )
            
            # Task 3: Predict outcome using pattern recognition
            print("\n[3/3] Analyzing historical patterns for prediction...")
            prediction_task = self.tasks.predict_outcome_task(
                agent=prediction_agent,
                consolidated_data=consolidated_data,  # Pass the original DICT
                rule_number=rule_number
            )
            
            # Create and run crew
            crew = Crew(
                agents=[knowledge_agent, content_agent, prediction_agent],
                tasks=[synthesis_task, plan_task, prediction_task],
                process=Process.sequential,
                verbose=True
            )
            
            print("\n" + "="*80)
            print("Running CrewAI Workflow...")
            print("="*80 + "\n")
            
            result = crew.kickoff()
            
            print("\n" + "="*80)
            print("AI Analysis Complete!")
            print("="*80 + "\n")
            
            # Parse results dynamically
            triaging_plan = self._parse_triaging_plan_dynamic(plan_task.output)
            predictions = self._parse_predictions_dynamic(prediction_task.output)
            
            # Validate outputs - if parsing failed, try to extract any structure
            if not triaging_plan or len(triaging_plan) == 0:
                print("Warning: Unable to parse AI plan. Attempting fallback extraction...")
                triaging_plan = self._extract_steps_from_text(str(plan_task.output))
            
            if not predictions or len(predictions) == 0:
                print("Warning: Unable to parse AI predictions. Attempting fallback extraction...")
                predictions = self._extract_prediction_from_text(str(prediction_task.output))
            
            # Last resort: basic structure
            if not triaging_plan:
                triaging_plan = self._create_minimal_plan(consolidated_data, template_content)
            
            if not predictions:
                predictions = self._create_minimal_prediction(consolidated_data)
            
            return {
                'triaging_plan': triaging_plan,
                'predictions': predictions
            }
            
        except Exception as e:
            print(f"\nError in AI analysis: {str(e)}")
            import traceback
            traceback.print_exc()
            
            # Emergency fallback
            return {
                'triaging_plan': self._create_minimal_plan(consolidated_data, template_content),
                'predictions': self._create_minimal_prediction(consolidated_data)
            }

    def _create_data_summary(self, data: dict) -> str:
        """Create a structured summary for LLM processing."""
        summary = f"""
INCIDENT DATA:
Incident Number: {data.get('incident_no', 'N/A')}
Rule: {data.get('rule', 'N/A')}
Priority: {data.get('priority', 'N/A')}
Data Connector: {data.get('data_connector', 'N/A')}
Alert/Incident Type: {data.get('alert_incident', 'N/A')}
Date: {data.get('date', 'N/A')} {data.get('month', '')}
Shift: {data.get('shift', 'N/A')}
Engineer: {data.get('shift_engineer', 'N/A')}

TIMELINE METRICS:
Reported Time: {data.get('reported_time_stamp', 'N/A')}
Responded Time: {data.get('responded_time_stamp', 'N/A')}
Resolution Time: {data.get('resolution_time_stamp', 'N/A')}
MTTD (Mean Time To Detect): {data.get('mttd_mins', 'N/A')} minutes
MTTR (Mean Time To Resolve): {data.get('mttr_mins', 'N/A')} minutes

INVESTIGATION FINDINGS (RESOLVER COMMENTS):
{data.get('resolver_comments', 'N/A')}

HISTORICAL OUTCOME:
Classification: {data.get('false_true_positive', 'N/A')}
Why False Positive: {data.get('why_false_positive', 'N/A')}
Justification: {data.get('justification', 'N/A')}
Quality Audit: {data.get('quality_audit', 'N/A')}

ADDITIONAL CONTEXT:
Status: {data.get('status', 'N/A')}
VIP Users Involved: {data.get('vip_users', 'N/A')}
Service Owner: {data.get('service_owner', 'N/A')}
Remarks: {data.get('remarks_comments', 'N/A')}
"""
        return summary

    def _parse_triaging_plan_dynamic(self, output) -> list:
        """Dynamically parse triaging plan from LLM output using multiple strategies."""
        output_str = str(output)
        steps = []
        
        # Strategy 1: Look for structured STEP format
        step_pattern = r'STEP:\s*(.+?)\s*EXPLANATION:\s*(.+?)\s*(?:KQL:\s*(.+?)\s*)?INPUT_REQUIRED:\s*(.+?)(?=STEP:|---|\Z)'
        matches = re.findall(step_pattern, output_str, re.DOTALL | re.IGNORECASE)
        
        if matches:
            for match in matches:
                steps.append({
                    'step_name': match[0].strip(),
                    'explanation': match[1].strip(),
                    'kql_query': match[2].strip() if len(match) > 2 and match[2].strip() and match[2].strip().lower() != 'n/a' else '',
                    'user_input_required': 'yes' in match[3].lower() if len(match) > 3 else True
                })
        
        # Strategy 2: Look for numbered/bulleted lists
        if not steps:
            numbered_pattern = r'(?:^|\n)(?:\d+\.|[-•*])\s*(.+?)(?=\n(?:\d+\.|[-•*])|\Z)'
            matches = re.findall(numbered_pattern, output_str, re.DOTALL | re.MULTILINE)
            
            for match in matches:
                text = match.strip()
                if len(text) > 10:  # Skip very short matches
                    # Try to split into name and explanation
                    lines = text.split('\n', 1)
                    step_name = lines[0].strip()
                    explanation = lines[1].strip() if len(lines) > 1 else text
                    
                    steps.append({
                        'step_name': step_name[:150],  # Limit length
                        'explanation': explanation,
                        'kql_query': self._extract_kql_from_text(text),
                        'user_input_required': True
                    })
        
        # Strategy 3: Look for section headers (###, ##, etc.)
        if not steps:
            header_pattern = r'(?:^|\n)#{1,3}\s*(.+?)(?:\n+)(.+?)(?=\n#{1,3}|\Z)'
            matches = re.findall(header_pattern, output_str, re.DOTALL | re.MULTILINE)
            
            for match in matches:
                steps.append({
                    'step_name': match[0].strip(),
                    'explanation': match[1].strip(),
                    'kql_query': self._extract_kql_from_text(match[1]),
                    'user_input_required': True
                })
        
        return steps if steps else []

    def _extract_kql_from_text(self, text: str) -> str:
        """Extract KQL query from text if present."""
        # Look for code blocks
        kql_pattern = r'```(?:kql|kusto|sql)?\s*\n(.+?)\n```'
        match = re.search(kql_pattern, text, re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(1).strip()
        
        # Look for SigninLogs queries
        if 'SigninLogs' in text or 'where' in text.lower():
            lines = text.split('\n')
            query_lines = []
            in_query = False
            for line in lines:
                if 'SigninLogs' in line or '| where' in line:
                    in_query = True
                if in_query:
                    query_lines.append(line)
                    if not line.strip().startswith('|') and len(query_lines) > 1:
                        break
            if query_lines:
                return '\n'.join(query_lines).strip()
        
        return ''

    def _parse_predictions_dynamic(self, output) -> list:
        """Dynamically parse predictions from LLM output."""
        output_str = str(output)
        
        # Try structured format first
        prediction_match = re.search(r'PREDICTION:\s*(.+?)(?:\n|$)', output_str, re.IGNORECASE)
        confidence_match = re.search(r'CONFIDENCE:\s*(.+?)(?:\n|$)', output_str, re.IGNORECASE)
        reasoning_match = re.search(r'REASONING:\s*(.+?)(?:\n\n|\Z)', output_str, re.IGNORECASE | re.DOTALL)
        
        if prediction_match:
            return [{
                'step_name': 'Overall Assessment',
                'prediction': prediction_match.group(1).strip(),
                'confidence_score': confidence_match.group(1).strip() if confidence_match else 'Medium',
                'reasoning': reasoning_match.group(1).strip() if reasoning_match else output_str[:300]
            }]
        
        return []

    def _extract_steps_from_text(self, text: str) -> list:
        """Emergency extraction of any step-like structure from text."""
        steps = []
        
        # Split by double newlines or numbered points
        sections = re.split(r'\n\n+|\n(?=\d+\.)', text)
        
        for section in sections:
            section = section.strip()
            if len(section) > 20:  # Meaningful content
                # First line as name, rest as explanation
                lines = section.split('\n', 1)
                steps.append({
                    'step_name': lines[0].strip()[:150],
                    'explanation': lines[1].strip() if len(lines) > 1 else section,
                    'kql_query': '',
                    'user_input_required': True
                })
                
                if len(steps) >= 8:  # Cap at reasonable number
                    break
        
        return steps

    def _extract_prediction_from_text(self, text: str) -> list:
        """Emergency extraction of prediction from any text."""
        # Look for positive/negative keywords
        text_lower = text.lower()
        
        if 'true positive' in text_lower:
            prediction = 'Likely True Positive'
        elif 'false positive' in text_lower:
            prediction = 'Likely False Positive'
        else:
            prediction = 'Requires Investigation'
        
        return [{
            'step_name': 'Overall Assessment',
            'prediction': prediction,
            'confidence_score': 'Medium',
            'reasoning': text[:300]
        }]

    def _create_minimal_plan(self, incident_data: dict, template: str) -> list:
        """Create minimal viable plan from template if LLM completely fails."""
        # Extract any structure from template
        if template and len(template) > 100:
            lines = template.split('\n')
            steps = []
            for line in lines:
                line = line.strip()
                if line.startswith('#') or line.startswith('Step') or line.endswith(':'):
                    if len(steps) < 6:
                        steps.append({
                            'step_name': line.replace('#', '').strip(),
                            'explanation': 'Please review this step based on the incident details.',
                            'kql_query': '',
                            'user_input_required': True
                        })
            if steps:
                return steps
        
        # Absolute minimum fallback
        return [
            {
                'step_name': '1. Review Incident Details',
                'explanation': f'Review the incident: {incident_data.get("rule", "N/A")}. Check all provided information.',
                'kql_query': '',
                'user_input_required': True
            },
            {
                'step_name': '2. Investigate Key Indicators',
                'explanation': 'Based on resolver comments, investigate the key security indicators.',
                'kql_query': '',
                'user_input_required': True
            },
            {
                'step_name': '3. Make Final Classification',
                'explanation': 'Classify as True Positive, False Positive, or Benign Positive with justification.',
                'kql_query': '',
                'user_input_required': True
            }
        ]

    def _create_minimal_prediction(self, incident_data: dict) -> list:
        """Create minimal prediction if LLM fails."""
        comments = str(incident_data.get('resolver_comments', '')).lower()
        
        # Simple keyword detection
        if any(word in comments for word in ['clean', 'legitimate', 'nothing suspicious']):
            prediction = 'Likely False Positive'
        elif any(word in comments for word in ['escalat', 'malicious', 'compromise']):
            prediction = 'Likely True Positive'
        else:
            prediction = 'Requires Investigation'
        
        return [{
            'step_name': 'Overall Assessment',
            'prediction': prediction,
            'confidence_score': 'Low',
            'reasoning': 'Automated pattern detection from resolver comments.'
        }]