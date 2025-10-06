import streamlit as st
import pandas as pd
import os
from src.crew import TriagingCrew
from src.utils import (
    read_all_tracker_sheets, 
    search_alerts_in_data,
    consolidate_incident_data,
    get_triaging_template,
    generate_completed_template
)
import json
import traceback

# --- Page Configuration ---
st.set_page_config(
    page_title="AI-Powered Security Incident Triaging",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Custom CSS ---
st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        margin-bottom: 1rem;
    }
    .step-header {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }
    .metric-card {
        background-color: #ffffff;
        padding: 1rem;
        border-radius: 0.5rem;
        border: 1px solid #e0e0e0;
    }
    </style>
""", unsafe_allow_html=True)

# --- State Management ---
def initialize_session_state():
    """Initialize all session state variables."""
    defaults = {
        "step": 0,
        "alerts": [],
        "all_data": None,
        "consolidated_data": None,
        "selected_alert": None,
        "template_content": None,
        "triaging_plan": None,
        "triaging_output": {},
        "predictions": [],
        "current_step_index": 0,
        "analysis_complete": False
    }
    
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

initialize_session_state()

# --- Load Data on Startup ---
@st.cache_data
def load_tracker_data():
    """Load and cache all tracker sheet data."""
    try:
        df = read_all_tracker_sheets("data")
        return df
    except Exception as e:
        st.error(f"Error loading tracker data: {str(e)}")
        return pd.DataFrame()

# --- Initialize Crew ---
@st.cache_resource
def get_crew():
    """Initialize and cache the CrewAI instance."""
    return TriagingCrew()

crew = get_crew()

# --- App Title ---
st.markdown('<div class="main-header">AI-Powered Security Incident Triaging System</div>', unsafe_allow_html=True)
st.markdown("Automate security alert triaging with AI-powered analysis and step-by-step guidance.")

# --- Sidebar ---
with st.sidebar:
    st.header("Navigation")
    st.write(f"**Current Step:** {st.session_state.step + 1}/5")
    
    if st.session_state.step > 0:
        st.markdown("---")
        if st.button("🔄 Start Over"):
            # Reset all state except cached data
            for key in list(st.session_state.keys()):
                if key not in ['all_data']:
                    del st.session_state[key]
            initialize_session_state()
            st.rerun()
    
    st.markdown("---")
    st.markdown("### About")
    st.markdown("""
    This tool uses AI agents to:
    - Search security alerts
    - Consolidate incident data
    - Retrieve triaging templates
    - Generate investigation plans
    - Predict outcomes
    """)

# ============================================================================
# STEP 0: SEARCH FOR ALERTS
# ============================================================================
if st.session_state.step == 0:
    st.markdown('<div class="step-header"><h2>Step 1: Search for Security Alerts</h2></div>', unsafe_allow_html=True)
    
    # Load data if not already loaded
    if st.session_state.all_data is None:
        with st.spinner("Loading tracker data..."):
            st.session_state.all_data = load_tracker_data()
            
            if st.session_state.all_data.empty:
                st.error("❌ No tracker data found!")
                st.info("Please ensure data files exist in `data/` directory.")
                st.info("Supported formats: .xlsx, .csv")
                st.stop()
            else:
                st.success(f"✅ Loaded {len(st.session_state.all_data)} incidents from tracker sheets")
    
    # Example searches (must come BEFORE the input widget)
    with st.expander("💡 Example Searches"):
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("Sophos"):
                st.session_state.example_query = "Sophos"
                st.rerun()
        with col2:
            if st.button("Atypical Travel"):
                st.session_state.example_query = "Atypical Travel"
                st.rerun()
        with col3:
            if st.button("Privileged Role"):
                st.session_state.example_query = "Privileged Role"
                st.rerun()
    
    # Search interface
    col1, col2 = st.columns([3, 1])
    
    with col1:
        # Use the example query if it exists
        default_value = st.session_state.get('example_query', '')
        search_query = st.text_input(
            "🔍 Enter keywords to search (rule name, incident number, alert type, etc.)",
            value=default_value,
            placeholder="e.g., Sophos, Atypical Travel, Rule#280, AD, Privileged Role...",
            key="search_input"
        )
        # Clear the example query after using it
        if 'example_query' in st.session_state:
            del st.session_state.example_query
    
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        search_button = st.button("Search Alerts", type="primary", use_container_width=True)
        
    if search_button and search_query:
        with st.spinner("🔎 Searching for relevant alerts..."):
            try:
                alerts_list = search_alerts_in_data(
                    st.session_state.all_data, 
                    search_query, 
                    top_n=5
                )
                
                if alerts_list:
                    st.session_state.alerts = alerts_list
                    st.session_state.step = 1
                    st.rerun()
                else:
                    st.warning("⚠️ No relevant alerts found. Try different keywords.")
                    
            except Exception as e:
                st.error(f"❌ Error during search: {str(e)}")
                with st.expander("View Error Details"):
                    st.code(traceback.format_exc())

# ============================================================================
# STEP 1: SELECT AN ALERT
# ============================================================================
elif st.session_state.step == 1:
    st.markdown('<div class="step-header"><h2>Step 2: Select an Alert</h2></div>', unsafe_allow_html=True)
    
    st.markdown(f"**Search Query:** `{st.session_state.get('search_input', 'N/A')}`")
    st.markdown(f"Found **{len(st.session_state.alerts)}** relevant alerts:")
    
    st.markdown("---")
    
    for idx, alert_title in enumerate(st.session_state.alerts):
        with st.container():
            col1, col2 = st.columns([5, 1])
            
            with col1:
                st.markdown(f"### {idx + 1}. {alert_title}")
                
                # Extract and show additional info if available
                try:
                    parts = alert_title.split(' - ')
                    if len(parts) >= 2:
                        rule = parts[0].strip()
                        incident = parts[1].replace("Incident ", "").strip()
                        
                        # Get incident details
                        incident_row = st.session_state.all_data[
                            st.session_state.all_data['incident_no'].astype(str).str.strip() == incident
                        ]
                        
                        if not incident_row.empty:
                            info = incident_row.iloc[0]
                            col_a, col_b, col_c = st.columns(3)
                            with col_a:
                                st.metric("Priority", info.get('priority', 'N/A'))
                            with col_b:
                                st.metric("Type", info.get('alert_incident', 'N/A'))
                            with col_c:
                                st.metric("Connector", info.get('data_connector', 'N/A'))
                except:
                    pass
            
            with col2:
                st.markdown("<br>", unsafe_allow_html=True)
                if st.button("Select →", key=f"select_{idx}", type="primary"):
                    parts = alert_title.split(' - ')
                    rule = parts[0].strip() if parts else "Unknown"
                    incident = parts[1].replace("Incident ", "").strip() if len(parts) > 1 else "Unknown"
                    
                    st.session_state.selected_alert = {
                        'incident': incident,
                        'rule': rule,
                        'description': alert_title
                    }
                    st.session_state.step = 2
                    st.rerun()
            
            st.markdown("---")
    
    if st.button("← Back to Search"):
        st.session_state.step = 0
        st.session_state.alerts = []
        st.rerun()

# ============================================================================
# STEP 2: DATA CONSOLIDATION & TEMPLATE RETRIEVAL
# ============================================================================
elif st.session_state.step == 2:
    st.markdown('<div class="step-header"><h2>Step 3: Data Consolidation & Template Retrieval</h2></div>', unsafe_allow_html=True)
    
    selected_incident = st.session_state.selected_alert.get('incident')
    rule_number = st.session_state.selected_alert.get('rule')
    
    # Show selection
    col1, col2 = st.columns(2)
    with col1:
        st.info(f"**Selected Rule:** {rule_number}")
    with col2:
        st.info(f"**Incident Number:** {selected_incident}")
    
    progress_bar = st.progress(0, text="Initializing...")
    status_text = st.empty()
    
    with st.spinner("Processing..."):
        try:
            # Step 1: Consolidate data
            status_text.text("📊 Consolidating incident data...")
            progress_bar.progress(25, text="Consolidating incident data...")
            
            consolidated = consolidate_incident_data(
                st.session_state.all_data, 
                selected_incident
            )
            
            if not consolidated:
                st.error(f"❌ No data found for incident {selected_incident}")
                if st.button("← Go Back"):
                    st.session_state.step = 1
                    st.rerun()
                st.stop()
            
            st.session_state.consolidated_data = consolidated
            progress_bar.progress(50, text="Data consolidated successfully")
            
            # Step 2: Retrieve template
            status_text.text("📄 Retrieving triaging template...")
            progress_bar.progress(75, text="Retrieving triaging template...")
            
            template = get_triaging_template(rule_number)
            st.session_state.template_content = template
            
            progress_bar.progress(100, text="✅ Ready to start AI analysis!")
            status_text.text("✅ All data prepared successfully!")
            
            # Display preview
            st.markdown("### 📋 Data Preview")
            
            tab1, tab2 = st.tabs(["Consolidated Data", "Triaging Template"])
            
            with tab1:
                # Show key fields in a nice format
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Priority", consolidated.get('priority', 'N/A'))
                    st.metric("MTTD", f"{consolidated.get('mttd_mins', 'N/A')} mins")
                with col2:
                    st.metric("Status", consolidated.get('status', 'N/A'))
                    st.metric("MTTR", f"{consolidated.get('mttr_mins', 'N/A')} mins")
                with col3:
                    st.metric("Classification", consolidated.get('false_true_positive', 'N/A'))
                    st.metric("VIP User", consolidated.get('vip_users', 'N/A'))
                
                with st.expander("View Complete Data"):
                    st.json(consolidated)
            
            with tab2:
                st.text(template[:1000] + "..." if len(template) > 1000 else template)
                with st.expander("View Full Template"):
                    st.text(template)
            
            st.markdown("---")
            
            col1, col2 = st.columns([1, 4])
            with col1:
                if st.button("← Back"):
                    st.session_state.step = 1
                    st.rerun()
            with col2:
                if st.button("Start AI-Powered Triaging →", type="primary", use_container_width=True):
                    st.session_state.step = 3
                    st.rerun()
                    
        except Exception as e:
            progress_bar.empty()
            status_text.empty()
            st.error(f"❌ Error: {str(e)}")
            with st.expander("View Error Details"):
                st.code(traceback.format_exc())
            
            if st.button("← Go Back"):
                st.session_state.step = 1
                st.rerun()

# ============================================================================
# STEP 3: AI-POWERED TRIAGING WALKTHROUGH
# ============================================================================
elif st.session_state.step == 3:
    st.markdown('<div class="step-header"><h2>Step 4: AI-Powered Triaging Walkthrough</h2></div>', unsafe_allow_html=True)
    
    st.markdown(f"**Alert:** {st.session_state.selected_alert.get('description', 'N/A')}")
    
    # Generate triaging plan if not already generated
    if st.session_state.triaging_plan is None:
        st.markdown("### 🤖 AI Agents are Analyzing...")
        
        analysis_status = st.empty()
        analysis_progress = st.progress(0)
        
        with st.spinner("This may take 30-60 seconds..."):
            try:
                analysis_status.info("🧠 AI is learning from historical data and templates...")
                analysis_progress.progress(20)
                
                result = crew.run_analysis_phase(
                    consolidated_data=st.session_state.consolidated_data,
                    template_content=st.session_state.template_content,
                    rule_number=st.session_state.selected_alert.get('rule')
                )
                
                analysis_progress.progress(80)
                analysis_status.info("📝 Generating triaging plan and predictions...")
                
                st.session_state.triaging_plan = result['triaging_plan']
                st.session_state.predictions = result['predictions']
                st.session_state.current_step_index = 0
                
                analysis_progress.progress(100)
                analysis_status.success("✅ AI analysis complete!")
                
                st.rerun()
                
            except Exception as e:
                analysis_progress.empty()
                analysis_status.error(f"❌ Error in AI analysis: {str(e)}")
                with st.expander("View Error Details"):
                    st.code(traceback.format_exc())
                
                st.warning("⚠️ Using fallback triaging plan...")
                st.session_state.triaging_plan = crew._create_minimal_plan(
                    st.session_state.consolidated_data,
                    st.session_state.template_content
                )
                st.session_state.predictions = crew._create_minimal_prediction(
                    st.session_state.consolidated_data
                )
                st.rerun()
    
    # Display triaging walkthrough
    current_step_index = st.session_state.current_step_index
    total_steps = len(st.session_state.triaging_plan)
    
    if total_steps == 0:
        st.error("❌ No triaging steps generated. Please try again.")
        if st.button("← Go Back"):
            st.session_state.step = 2
            st.session_state.triaging_plan = None
            st.rerun()
        st.stop()
    
    # Progress indicator
    progress_percentage = (current_step_index / total_steps) if total_steps > 0 else 0
    st.progress(progress_percentage, text=f"Progress: Step {current_step_index + 1} of {total_steps}")
    
    if current_step_index < total_steps:
        current_step = st.session_state.triaging_plan[current_step_index]
        
        # Step display
        st.markdown(f"## {current_step.get('step_name', 'Investigation Step')}")
        st.markdown(current_step.get('explanation', 'No explanation available.'))
        
        # AI Prediction box
        if st.session_state.predictions:
            with st.expander("🔮 AI Prediction & Guidance", expanded=True):
                prediction = st.session_state.predictions[0]
                
                col1, col2 = st.columns(2)
                with col1:
                    pred_text = prediction.get('prediction', 'N/A')
                    # Color code based on prediction
                    if 'true positive' in pred_text.lower():
                        st.error(f"**Prediction:** {pred_text}")
                    elif 'false positive' in pred_text.lower():
                        st.success(f"**Prediction:** {pred_text}")
                    else:
                        st.info(f"**Prediction:** {pred_text}")
                
                with col2:
                    confidence = prediction.get('confidence_score', 'N/A')
                    st.metric("Confidence Level", confidence)
                
                if 'reasoning' in prediction:
                    st.markdown("**AI Reasoning:**")
                    st.info(prediction['reasoning'])
        
        # KQL Query display
        kql_query = current_step.get('kql_query', '')
        if kql_query and kql_query.strip():
            st.markdown("### 📊 KQL Query")
            st.code(kql_query, language='sql')
            st.caption("Copy this query to run in your SIEM (e.g., Microsoft Sentinel, Azure Log Analytics)")
        
        st.markdown("---")
        
        # User input section
        if current_step.get('user_input_required', True):
            st.markdown("### ✍️ Your Findings")
            user_input = st.text_area(
                f"Document your findings for this step:",
                height=150,
                key=f"input_{current_step_index}",
                placeholder="Enter your investigation findings, observations, and any relevant details..."
            )
            
            col1, col2, col3 = st.columns([1, 1, 3])
            
            with col1:
                if current_step_index > 0:
                    if st.button("← Previous"):
                        st.session_state.current_step_index -= 1
                        st.rerun()
            
            with col2:
                if st.button("Next Step →", type="primary"):
                    if user_input.strip():
                        st.session_state.triaging_output[current_step.get('step_name')] = user_input
                        st.session_state.current_step_index += 1
                        st.rerun()
                    else:
                        st.warning("⚠️ Please enter your findings before proceeding.")
        else:
            # Auto-advance steps that don't require input
            if st.button("Next Step →", type="primary"):
                st.session_state.current_step_index += 1
                st.rerun()
    
    else:
        # All steps completed
        st.session_state.step = 4
        st.rerun()

# ============================================================================
# STEP 4: TRIAGING COMPLETE
# ============================================================================
elif st.session_state.step == 4:
    st.markdown('<div class="step-header"><h2>✅ Triaging Complete!</h2></div>', unsafe_allow_html=True)
    
    st.success("All investigation steps have been completed successfully.")
    
    # Final Summary
    st.markdown("## 📋 Investigation Summary")
    
    for step_name, findings in st.session_state.triaging_output.items():
        with st.expander(f"**{step_name}**", expanded=False):
            st.markdown(findings)
    
    # Final AI Assessment
    if st.session_state.predictions:
        st.markdown("## 🎯 Final AI Assessment")
        
        final_pred = st.session_state.predictions[0]
        
        col1, col2 = st.columns(2)
        with col1:
            prediction = final_pred.get('prediction', 'Unknown')
            if 'true positive' in prediction.lower():
                st.error(f"### {prediction}")
            elif 'false positive' in prediction.lower():
                st.success(f"### {prediction}")
            else:
                st.info(f"### {prediction}")
        
        with col2:
            confidence = final_pred.get('confidence_score', 'N/A')
            st.metric("Confidence Level", confidence, help="AI's confidence in this prediction")
        
        if 'reasoning' in final_pred:
            st.markdown("**AI Reasoning:**")
            st.info(final_pred['reasoning'])
    
    # Download Section
    st.markdown("---")
    st.markdown("## 📥 Export Results")
    
    # Generate final report
    final_template = generate_completed_template(
        st.session_state.consolidated_data,
        st.session_state.triaging_output,
        st.session_state.predictions[0] if st.session_state.predictions else {}
    )
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.download_button(
            label="📄 Download Triaging Report (TXT)",
            data=final_template,
            file_name=f"triaging_report_{st.session_state.selected_alert.get('incident')}.txt",
            mime="text/plain",
            use_container_width=True
        )
    
    with col2:
        # Create JSON export
        json_export = {
            'incident': st.session_state.consolidated_data,
            'investigation': st.session_state.triaging_output,
            'prediction': st.session_state.predictions[0] if st.session_state.predictions else {}
        }
        
        st.download_button(
            label="📊 Download as JSON",
            data=json.dumps(json_export, indent=2),
            file_name=f"triaging_data_{st.session_state.selected_alert.get('incident')}.json",
            mime="application/json",
            use_container_width=True
        )
    
    # Preview report
    with st.expander("📄 Preview Full Report"):
        st.text(final_template)
    
    st.markdown("---")
    
    if st.button("🔄 Start New Triaging", type="primary", use_container_width=True):
        for key in list(st.session_state.keys()):
            if key != 'all_data':
                del st.session_state[key]
        initialize_session_state()
        st.rerun()