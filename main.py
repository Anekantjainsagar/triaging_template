import streamlit as st
import pandas as pd
import os
from src.crew import TriagingCrew
from src.utils import read_all_tracker_sheets, create_and_save_excel
from src.agents import TriagingAgents 
import json # Import json to handle agent output

# --- Page Configuration ---
st.set_page_config(
    page_title="AI-Powered Security Incident Triaging",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- State Management ---
if "step" not in st.session_state:
    st.session_state.step = 0
if "alerts" not in st.session_state:
    st.session_state.alerts = []
if "consolidated_data" not in st.session_state:
    st.session_state.consolidated_data = None
if "selected_alert" not in st.session_state:
    st.session_state.selected_alert = None
if "template_content" not in st.session_state:
    st.session_state.template_content = None
if "triaging_plan" not in st.session_state:
    st.session_state.triaging_plan = None
if "triaging_output" not in st.session_state:
    st.session_state.triaging_output = {}
if "predictions" not in st.session_state:
    st.session_state.predictions = {}

# --- App Title and Description ---
st.title("AI-Powered Security Incident Triaging System 🤖")
st.markdown("This tool helps security analysts triage alerts efficiently by automating data consolidation, template retrieval, and step-by-step guidance.")

# Instantiate the crew
crew = TriagingCrew()

# --- Step 1: Search and Select Alert ---
if st.session_state.step == 0:
    st.header("Step 1: Search for a Security Alert")
    search_query = st.text_input("Enter a keyword to find related security alerts (e.g., 'Sophos', 'Atypical Travel', 'Privileged Role'):")

    if st.button("Search Alerts"):
        if search_query:
            with st.spinner("Searching for relevant alerts..."):
                try:
                    # Execute the CrewAI task for searching alerts
                    crew_output = crew.run(search_query=search_query)

                    # --- New parsing logic to handle the agent's verbose output ---
                    # The output is a string, so we need to find the list within it.
                    # We look for the part of the string that starts with '[' and ends with ']'.
                    import re
                    match = re.search(r'\[.*\]', crew_output, re.DOTALL)
                    if match:
                        alerts_list_str = match.group(0)
                        # Now, use eval() to convert the string representation of the list into an actual list
                        alerts_list = eval(alerts_list_str)
                    else:
                        alerts_list = []
                    # --- End of new parsing logic ---

                    if alerts_list:
                        st.session_state.alerts = alerts_list
                        st.session_state.step = 1
                        st.rerun()
                    else:
                        st.error("No relevant alerts found. Please try a different keyword.")
                except Exception as e:
                    st.error(f"An error occurred during the search: {e}")
                    st.error(f"Crew output was: {crew_output}")
        else:
            st.warning("Please enter a search query.")
            
# --- Step 2: Display and Select Alert ---
if st.session_state.step == 1:
    st.header("Step 2: Select a Top Alert")
    st.markdown("Found the following related alerts:")
    
    for alert_title in st.session_state.alerts:
        # We need a way to get incident and rule number from the title
        # Assuming the format is 'Rule#<number> - <description>'
        parts = alert_title.split(' - ', 1)
        rule = parts[0]
        description = parts[1]
        
        # A mock dictionary to simulate the selected alert data
        alert_data = {'incident': 'INC_MOCK_001', 'rule': rule, 'description': description}
        
        if st.button(alert_title, key=alert_title):
            st.session_state.selected_alert = alert_data
            st.session_state.step = 2
            st.rerun()

# --- Step 3: Data Consolidation & Template Retrieval ---
if st.session_state.step == 2:
    st.header("Step 3: Consolidating Data and Retrieving Template")
    
    selected_incident = st.session_state.selected_alert.get('incident')
    rule_number = st.session_state.selected_alert.get('rule')
    
    if selected_incident and rule_number:
        st.info(f"You have selected Incident **{selected_incident}** with Rule **{rule_number}**.")
    
        progress_bar = st.progress(0, text="Starting data consolidation and template retrieval...")
        
        with st.spinner("CrewAI agents are working..."):
            try:
                # Run the data consolidation and template retrieval phase
                crew_output_str = crew.run(incident_id=selected_incident, rule_number=rule_number)
                
                # The output is a string representation of a JSON object.
                crew_output = json.loads(crew_output_str)

                # The keys in the output should match the final task output.
                st.session_state.consolidated_data = crew_output.get('consolidated_data')
                st.session_state.template_content = crew_output.get('template_content')
                
                progress_bar.progress(100, text="Data and template ready. Starting analysis...")
                st.session_state.step = 3
                st.success("Data consolidation and template retrieval complete!")
                st.balloons()
                st.rerun()

            except Exception as e:
                st.error(f"An error occurred during data consolidation/template retrieval: {e}")
                progress_bar.empty()
    else:
        st.error("Incident ID or Rule number is missing from the selected alert.")
        st.session_state.step = 0
        st.stop()

# --- Step 4: Step-by-Step Triaging Walkthrough ---
if st.session_state.step == 3:
    st.header("Step 4: AI-Powered Triaging Walkthrough")
    st.subheader(st.session_state.selected_alert.get('description', 'N/A'))
    
    # Check if the triaging plan has been generated yet
    if st.session_state.triaging_plan is None:
        st.info("Generating a step-by-step triaging plan and predictions...")
        
        try:
            # Run the synthesis, generation, and prediction phase
            crew_output_str = crew.run(
                consolidated_data=st.session_state.consolidated_data, 
                rule_number=st.session_state.selected_alert.get('rule')
            )
            
            crew_output = json.loads(crew_output_str)

            # Store the generated plan and predictions
            st.session_state.triaging_plan = crew_output.get('triaging_plan')
            st.session_state.predictions = crew_output.get('predictions')
            st.session_state.current_step_index = 0
            st.rerun()

        except Exception as e:
            st.error(f"An error occurred during plan generation: {e}")
            st.session_state.step = 2 # Go back to the previous step to retry
            st.stop()
            
    # Now, the rest of the code for displaying the walkthrough can proceed, as
    # st.session_state.triaging_plan will be populated.
    current_step_index = st.session_state.get('current_step_index', 0)
    
    st.progress( (current_step_index + 1) / len(st.session_state.triaging_plan), text=f"Progress: {current_step_index + 1}/{len(st.session_state.triaging_plan)}")
    
    if current_step_index < len(st.session_state.triaging_plan):
        current_step = st.session_state.triaging_plan[current_step_index]
        
        st.info(f"**Current Step:** {current_step['step_name']}")
        st.markdown(current_step['explanation'])
        
        # Display the AI Prediction for the current step
        current_prediction = next((item for item in st.session_state.predictions if item["step_name"] == current_step['step_name']), {})
        if current_prediction:
            st.markdown(f"**AI Prediction:** {current_prediction.get('prediction', 'N/A')}")
            st.markdown(f"**Confidence Score:** {current_prediction.get('confidence_score', 'N/A')}")

        if current_step.get("user_input_required"):
            if current_step.get("kql_query"):
                st.code(current_step['kql_query'])
            user_input = st.text_area(f"Enter your findings for step '{current_step['step_name']}' here:")
            if st.button("Next Step"):
                st.session_state.triaging_output[current_step['step_name']] = user_input
                st.session_state.current_step_index = current_step_index + 1
                st.rerun()
        else:
            if st.button("Next Step"):
                st.session_state.current_step_index = current_step_index + 1
                st.rerun()

    else:
        st.header("Triaging Complete!")
        st.success("All triaging steps have been completed.")
        
        # --- Final Summary and Download ---
        st.subheader("Final Summary of Findings")
        for step, result in st.session_state.triaging_output.items():
            st.markdown(f"**{step}:** {result}")
        
        # Predict final outcome from the last prediction
        final_prediction_data = st.session_state.predictions[-1] if st.session_state.predictions else {}
        final_prediction = final_prediction_data.get('prediction', 'N/A')
        st.info(f"**Final AI Prediction:** Based on all the gathered information, the final outcome is: **{final_prediction}**")

        st.subheader("Download Triaging Template")
        # Placeholder for creating the final template
        final_template_content = "This is a final template with all the details filled in." 
        st.download_button(
            label="Download Completed Template",
            data=final_template_content,
            file_name=f"triaging_template_{selected_incident}.txt",
            mime="text/plain"
        )