# Add these imports at the top of main.py

import streamlit as st
import pandas as pd
import os
import re
import json
import traceback

# Existing imports
from src.crew import TriagingCrew
from src.utils import (
    read_all_tracker_sheets,
    search_alerts_in_data,
    export_rule_incidents_to_excel,
    generate_completed_template,
)

# NEW IMPORTS - Add these
from src.template_parser import TemplateParser
from src.web_llm_enhancer import WebLLMEnhancer
from src.template_generator import EnhancedTemplateGenerator
from src.csv_template_generator import generate_blank_triaging_template_csv

# --- Page Configuration ---
st.set_page_config(
    page_title="AI-Powered Security Incident Triaging",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- Custom CSS ---
st.markdown(
    """
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
    .step-container {
        background-color: #ffffff;
        padding: 1.5rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
        margin-bottom: 1rem;
    }
    .expected-output {
        background-color: #fff3e0;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #ff9800;
        margin: 1rem 0;
    }
    .progressive-prediction {
        background-color: #e3f2fd;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
    </style>
""",
    unsafe_allow_html=True,
)


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
        "progressive_predictions": {},
        "rule_history": {},
        "current_step_index": 0,
        "analysis_complete": False,
        "excel_template_data": None,
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
st.markdown(
    '<div class="main-header">ðŸ›¡ï¸ AI-Powered Security Incident Triaging System</div>',
    unsafe_allow_html=True,
)
st.markdown(
    "Automate security alert triaging with AI-powered analysis and comprehensive template generation."
)

# --- Sidebar ---
with st.sidebar:
    st.header("ðŸ“Š Navigation")
    st.write(f"**Current Step:** {st.session_state.step + 1}/5")

    if st.session_state.step > 0:
        st.markdown("---")
        if st.button("ðŸ”„ Start Over"):
            for key in list(st.session_state.keys()):
                if key not in ["all_data"]:
                    del st.session_state[key]
            initialize_session_state()
            st.rerun()

    st.markdown("---")
    st.markdown("### â„¹ï¸ About")
    st.markdown(
        """
    This tool uses AI agents to:
    - ðŸ” Search security alerts
    - ðŸ“Š Export historical data
    - ðŸ“ Retrieve triaging templates
    - ðŸ¤– Generate investigation plans
    - ðŸŽ¯ Predict outcomes
    - ðŸ“„ Export Excel/CSV templates
    """
    )

# ============================================================================
# STEP 0: SEARCH FOR ALERTS
# ============================================================================
if st.session_state.step == 0:
    st.markdown(
        '<div class="step-header"><h2>Step 1: Search for Security Alerts</h2></div>',
        unsafe_allow_html=True,
    )

    if st.session_state.all_data is None:
        with st.spinner("Loading tracker data..."):
            st.session_state.all_data = load_tracker_data()

            if st.session_state.all_data.empty:
                st.error("âŒ No tracker data found!")
                st.info("Please ensure data files exist in `data/` directory.")
                st.stop()
            else:
                st.success(
                    f"âœ… Loaded {len(st.session_state.all_data)} incidents from tracker sheets"
                )

    with st.expander("ðŸ’¡ Example Searches"):
        col1, col2, col3, col4 = st.columns(4)
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
        with col4:
            if st.button("Passwordless"):
                st.session_state.example_query = "Passwordless"
                st.rerun()

    col1, col2 = st.columns([3, 1])

    with col1:
        default_value = st.session_state.get("example_query", "")
        search_query = st.text_input(
            "ðŸ” Enter keywords to search (rule name, incident number, alert type, etc.)",
            value=default_value,
            placeholder="e.g., Sophos, Atypical Travel, Rule#280, Privileged Role...",
            key="search_input",
        )
        if "example_query" in st.session_state:
            del st.session_state.example_query

    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        search_button = st.button("Search Alerts", type="primary", width="stretch")

    if search_button and search_query:
        with st.spinner("ðŸ”Ž Searching for relevant alerts..."):
            try:
                alerts_list = search_alerts_in_data(
                    st.session_state.all_data, search_query, top_n=5
                )

                if alerts_list:
                    st.session_state.alerts = alerts_list
                    st.session_state.step = 1
                    st.rerun()
                else:
                    st.warning(
                        "âš ï¸ No relevant alerts found. Try different keywords."
                    )

            except Exception as e:
                st.error(f"âŒ Error during search: {str(e)}")

# ============================================================================
# STEP 1: SELECT AN ALERT & EXPORT DATA
# ============================================================================
elif st.session_state.step == 1:
    st.markdown(
        '<div class="step-header"><h2>Step 2: Select an Alert & Export Historical Data</h2></div>',
        unsafe_allow_html=True,
    )

    st.markdown(f"**Search Query:** `{st.session_state.get('search_input', 'N/A')}`")
    st.markdown(f"Found **{len(st.session_state.alerts)}** relevant alerts:")

    st.markdown("---")

    for idx, alert_title in enumerate(st.session_state.alerts):
        with st.container():
            col1, col2, col3 = st.columns([4, 1, 1])

            with col1:
                st.markdown(f"### {idx + 1}. {alert_title}")

                try:
                    parts = alert_title.split(" - ")
                    if len(parts) >= 2:
                        rule = parts[0].strip()
                        incident = parts[1].replace("Incident ", "").strip()

                        incident_row = st.session_state.all_data[
                            st.session_state.all_data["incident_no"]
                            .astype(str)
                            .str.strip()
                            == incident
                        ]

                        if not incident_row.empty:
                            info = incident_row.iloc[0]
                            col_a, col_b, col_c = st.columns(3)
                            with col_a:
                                st.metric("Priority", info.get("priority", "N/A"))
                            with col_b:
                                st.metric("Type", info.get("alert_incident", "N/A"))
                            with col_c:
                                st.metric(
                                    "Connector", info.get("data_connector", "N/A")
                                )
                except:
                    pass

            with col2:
                st.markdown("<br>", unsafe_allow_html=True)
                if st.button(
                    "ðŸ“¥ Export",
                    key=f"export_{idx}",
                    help="Download all incidents for this rule",
                ):
                    try:
                        parts = alert_title.split(" - ")
                        rule = parts[0].strip() if parts else "Unknown"

                        # Generate Excel file
                        excel_data = export_rule_incidents_to_excel(
                            st.session_state.all_data, rule
                        )

                        st.download_button(
                            label="ðŸ’¾ Download Excel",
                            data=excel_data,
                            file_name=f"{rule.replace('#', '_')}_historical_incidents.xlsx",
                            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            key=f"download_{idx}",
                        )
                    except Exception as e:
                        st.error(f"Export error: {str(e)}")

            with col3:
                st.markdown("<br>", unsafe_allow_html=True)
                if st.button("Select â†’", key=f"select_{idx}", type="primary"):
                    parts = alert_title.split(" - ")
                    rule = parts[0].strip() if parts else "Unknown"
                    incident = (
                        parts[1].replace("Incident ", "").strip()
                        if len(parts) > 1
                        else "Unknown"
                    )

                    st.session_state.selected_alert = {
                        "incident": incident,
                        "rule": rule,
                        "description": alert_title,
                    }
                    st.session_state.step = 2
                    st.rerun()

            st.markdown("---")

    if st.button("â† Back to Search"):
        st.session_state.step = 0
        st.session_state.alerts = []
        st.rerun()

# ============================================================================
# UPDATED STEP 2: DATA CONSOLIDATION & TEMPLATE ENHANCEMENT (PARALLEL)
# ============================================================================
elif st.session_state.step == 2:
    st.markdown(
        '<div class="step-header"><h2>Step 3: Template Enhancement & Generation</h2></div>',
        unsafe_allow_html=True,
    )

    selected_incident = st.session_state.selected_alert.get("incident")
    rule_number = st.session_state.selected_alert.get("rule")

    col1, col2 = st.columns(2)
    with col1:
        st.info(f"**Selected Rule:** {rule_number}")
    with col2:
        st.info(f"**Incident Number:** {selected_incident}")

    progress_bar = st.progress(0, text="Initializing...")
    status_text = st.empty()

    with st.spinner("Processing..."):
        try:
            # STEP 1: Find Template
            status_text.text("🔍 Searching for triaging template...")
            progress_bar.progress(20, text="Searching for template...")

            parser = TemplateParser()
            template_dir = "data/triaging_templates"

            # ✅ FIXED: Create directory if missing
            if not os.path.exists(template_dir):
                st.warning(f"⚠️ Template directory not found: {template_dir}")

                col1, col2 = st.columns(2)
                with col1:
                    if st.button("📁 Create Template Directory", type="primary"):
                        os.makedirs(template_dir, exist_ok=True)
                        st.success(
                            "✅ Directory created! Please upload templates and retry."
                        )
                        st.info(
                            "📋 Upload template files (CSV or Excel) to: data/triaging_templates/"
                        )
                        st.stop()

                with col2:
                    if st.button("⬅️ Go Back"):
                        st.session_state.step = 1
                        st.rerun()
                st.stop()

            # Extract rule number
            rule_num_match = re.search(r"#?(\d+)", rule_number)
            rule_num = (
                rule_num_match.group(1)
                if rule_num_match
                else rule_number.replace("#", "").strip()
            )

            # Find matching template
            all_files = os.listdir(template_dir)
            template_files = [
                f
                for f in all_files
                if rule_num in f and (f.endswith(".csv") or f.endswith(".xlsx"))
            ]

            if not template_files:
                st.error(f"❌ No template found for {rule_number}")
                st.info(
                    f"🔍 Looking for files containing '{rule_num}' in: {template_dir}"
                )

                with st.expander("Available Templates", expanded=True):
                    if all_files:
                        st.write("Found templates:")
                        for f in all_files:
                            st.write(f"- {f}")
                    else:
                        st.write("No templates found in directory")

                if st.button("⬅️ Go Back"):
                    st.session_state.step = 1
                    st.rerun()
                st.stop()

            template_path = os.path.join(template_dir, template_files[0])
            st.success(f"✅ Found template: {template_files[0]}")

            # STEP 2: Parse Template (Get ALL steps - PRESERVES ORIGINAL NAMES)
            status_text.text("📋 Parsing template steps...")
            progress_bar.progress(40, text="Parsing template...")

            if template_path.endswith(".csv"):
                original_steps = parser.parse_csv_template(template_path)
            else:
                original_steps = parser.parse_excel_template(template_path)

            if not original_steps:
                st.warning(
                    "⚠️ Template parsing returned no steps. Using fallback generation."
                )
                original_steps = [
                    {
                        "step_name": "Review Alert Details",
                        "explanation": "Gather incident information and review basic alert metadata",
                        "input_required": "Incident number, timestamp",
                        "kql_query": "",
                    }
                ]

            # ✅ SHOW WHAT WAS PARSED (ORIGINAL STEP NAMES PRESERVED)
            st.info(
                f"📋 Successfully parsed {len(original_steps)} steps from template:"
            )
            with st.expander(
                "View Original Steps (Before Enhancement)", expanded=False
            ):
                for i, step in enumerate(original_steps, 1):
                    st.markdown(f"**{i}. {step.get('step_name')}**")
                    st.markdown(
                        f"- Explanation: {step.get('explanation', 'N/A')[:100]}..."
                    )
                    st.markdown(
                        f"- Has KQL: {'Yes' if step.get('kql_query') else 'No'}"
                    )
                    st.markdown("---")

            # STEP 3: Web + LLM Enhancement (PARALLEL PROCESSING)
            status_text.text(
                "🔍 Enhancing template with web research + LLM (parallel processing)..."
            )
            progress_bar.progress(60, text="Enhancing with web + LLM...")

            enhancer = WebLLMEnhancer()

            # ✅ PARALLEL enhancement with progress tracking
            import time

            start_time = time.time()

            # Show enhancement settings
            st.info(
                "⚡ Using parallel processing (5 concurrent workers) for faster enhancement..."
            )

            enhanced_steps = enhancer.enhance_template_steps(
                rule_number=rule_number,
                original_steps=original_steps,
            )

            elapsed = time.time() - start_time

            if not enhanced_steps or len(enhanced_steps) < len(original_steps):
                st.warning(
                    f"⚠️ Enhancement incomplete. Using parsed steps with cleanup."
                )
                # Fallback: Use original steps but clean them
                enhanced_steps = []
                for step in original_steps:
                    enhanced_steps.append(
                        {
                            "step_name": step.get(
                                "step_name", "Investigation Step"
                            ),  # ✅ ORIGINAL NAME KEPT
                            "explanation": step.get(
                                "explanation",
                                "Complete this step and document findings.",
                            ),
                            "input_required": step.get(
                                "input_required", "Investigation data"
                            ),
                            "kql_query": step.get("kql_query", ""),
                        }
                    )

            st.success(
                f"✅ Enhanced {len(enhanced_steps)} steps in {elapsed:.1f}s (avg {elapsed/len(enhanced_steps):.1f}s per step)"
            )

            # ✅ SHOW ENHANCEMENT RESULTS WITH COMPARISON
            st.info("📊 Enhancement Summary:")
            col1, col2, col3, col4, col5 = st.columns(5)
            with col1:
                st.metric("Original Steps", len(original_steps))
            with col2:
                st.metric("Enhanced Steps", len(enhanced_steps))
            with col3:
                kql_count = len([s for s in enhanced_steps if s.get("kql_query")])
                st.metric("Steps with KQL", kql_count)
            with col4:
                st.metric("Processing Time", f"{elapsed:.1f}s")
            with col5:
                st.metric("Avg Time/Step", f"{elapsed/len(enhanced_steps):.1f}s")

            # STEP 4: Generate Clean Excel Template
            status_text.text("📊 Generating Excel template...")
            progress_bar.progress(80, text="Generating Excel template...")

            template_gen = EnhancedTemplateGenerator()
            template_df = template_gen.generate_clean_template(
                rule_number=rule_number, enhanced_steps=enhanced_steps
            )

            # Export to Excel
            excel_file = template_gen.export_to_excel(template_df, rule_number)

            # Store in session state
            st.session_state.enhanced_steps = enhanced_steps
            st.session_state.excel_template_data = excel_file

            progress_bar.progress(100, text="✅ Template ready!")
            status_text.text("✅ Template generation complete!")

            # STEP 5: Display Preview with Before/After Comparison
            st.markdown("---")
            st.markdown("### 📋 Generated Template Preview")

            tab1, tab2, tab3, tab4 = st.tabs(
                [
                    "Excel Preview",
                    "Steps Overview",
                    "Before/After Comparison",
                    "KQL Queries",
                ]
            )

            with tab1:
                st.dataframe(template_df, use_container_width=True, height=400)

                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Steps", len(enhanced_steps))
                with col2:
                    kql_count = len([s for s in enhanced_steps if s.get("kql_query")])
                    st.metric("Steps with KQL", kql_count)
                with col3:
                    exp_count = len([s for s in enhanced_steps if s.get("explanation")])
                    st.metric("Explained Steps", exp_count)

            with tab2:
                for i, step in enumerate(enhanced_steps, 1):
                    with st.expander(
                        f"Step {i}: {step.get('step_name', 'N/A')}", expanded=False
                    ):
                        st.markdown(
                            f"**✅ Step Name (Original):**\n{step.get('step_name', 'N/A')}"
                        )
                        st.markdown(
                            f"**📝 Explanation (Enhanced):**\n{step.get('explanation', 'N/A')}"
                        )
                        st.markdown(
                            f"**📥 Input Required:**\n{step.get('input_required', 'N/A')}"
                        )

                        if step.get("kql_query"):
                            st.markdown("**🔍 KQL Query (Cleaned):**")
                            st.code(step.get("kql_query"), language="kql")
                        else:
                            st.info("No KQL query for this step")

            with tab3:
                st.markdown("### 🔄 Before/After Enhancement Comparison")
                st.info(
                    "This shows how the AI improved the template while keeping original step names"
                )

                for i, (original, enhanced) in enumerate(
                    zip(original_steps, enhanced_steps), 1
                ):
                    with st.expander(
                        f"Step {i}: {original.get('step_name')}", expanded=False
                    ):
                        col1, col2 = st.columns(2)

                        with col1:
                            st.markdown("**🔴 BEFORE (Original)**")
                            st.markdown(f"**Name:** {original.get('step_name')}")
                            st.markdown(f"**Explanation:**")
                            st.text_area(
                                "Original",
                                value=original.get("explanation", "N/A")[:200],
                                height=100,
                                disabled=True,
                                key=f"orig_{i}",
                                label_visibility="collapsed",
                            )
                            st.markdown(
                                f"**Has KQL:** {'Yes' if original.get('kql_query') else 'No'}"
                            )

                        with col2:
                            st.markdown("**🟢 AFTER (Enhanced)**")
                            st.markdown(
                                f"**Name:** {enhanced.get('step_name')} ✅ (Preserved)"
                            )
                            st.markdown(f"**Explanation:**")
                            st.text_area(
                                "Enhanced",
                                value=enhanced.get("explanation", "N/A")[:200],
                                height=100,
                                disabled=True,
                                key=f"enh_{i}",
                                label_visibility="collapsed",
                            )
                            st.markdown(
                                f"**Has KQL:** {'Yes' if enhanced.get('kql_query') else 'No'}"
                            )

                        # Show improvements
                        improvements = []
                        if len(enhanced.get("explanation", "")) > len(
                            original.get("explanation", "")
                        ):
                            improvements.append("📝 Explanation expanded and refined")
                        if enhanced.get("kql_query") and not original.get("kql_query"):
                            improvements.append("🔍 KQL query added")
                        if enhanced.get("kql_query") and original.get("kql_query"):
                            improvements.append("🧹 KQL query cleaned")

                        if improvements:
                            st.success("**Improvements:** " + " • ".join(improvements))

            with tab4:
                st.markdown("### 🔍 KQL Queries (Ready to Use)")
                kql_found = False
                for i, step in enumerate(enhanced_steps, 1):
                    if step.get("kql_query"):
                        kql_found = True
                        st.markdown(f"**Step {i}: {step.get('step_name')}**")
                        st.code(step.get("kql_query"), language="kql")

                        # Copy button simulation (Streamlit doesn't have native copy)
                        col1, col2 = st.columns([4, 1])
                        with col2:
                            st.markdown(f"[Copy to clipboard]")
                        st.markdown("---")

                if not kql_found:
                    st.info("No KQL queries were generated/found in the template.")

            # STEP 6: Download Options
            st.markdown("---")
            st.markdown("### 📥 Download Template")

            col1, col2, col3 = st.columns(3)

            with col1:
                st.download_button(
                    label="📊 Download Excel Template",
                    data=st.session_state.excel_template_data,
                    file_name=f"triaging_template_{rule_number.replace('#', '_')}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    use_container_width=True,
                    type="primary",
                )

            with col2:
                # Generate JSON export
                json_export = {
                    "rule": rule_number,
                    "total_steps": len(enhanced_steps),
                    "enhancement_time_seconds": elapsed,
                    "steps": enhanced_steps,
                    "metadata": {
                        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "parallel_processing": True,
                        "original_step_names_preserved": True,
                        "explanations_enhanced": True,
                        "kql_cleaned": True,
                    },
                }
                st.download_button(
                    label="📄 Download JSON",
                    data=json.dumps(json_export, indent=2),
                    file_name=f"triaging_template_{rule_number.replace('#', '_')}.json",
                    mime="application/json",
                    use_container_width=True,
                )

            with col3:
                # Generate KQL-only export
                kql_export = "\n\n".join(
                    [
                        f"-- Step {i}: {step.get('step_name')}\n{step.get('kql_query')}"
                        for i, step in enumerate(enhanced_steps, 1)
                        if step.get("kql_query")
                    ]
                )
                if kql_export:
                    st.download_button(
                        label="🔍 Download KQL Queries",
                        data=kql_export,
                        file_name=f"kql_queries_{rule_number.replace('#', '_')}.kql",
                        mime="text/plain",
                        use_container_width=True,
                    )
                else:
                    st.button(
                        label="🔍 No KQL Queries",
                        disabled=True,
                        use_container_width=True,
                    )

            st.markdown("---")

            # Enhancement Quality Report
            st.markdown("### 📈 Enhancement Quality Report")

            col1, col2, col3, col4 = st.columns(4)

            with col1:
                st.metric(
                    "Original Names Preserved",
                    "100%",
                    help="All original step names were kept intact",
                )

            with col2:
                enhanced_count = len(
                    [s for s in enhanced_steps if len(s.get("explanation", "")) > 50]
                )
                pct = (
                    (enhanced_count / len(enhanced_steps) * 100)
                    if enhanced_steps
                    else 0
                )
                st.metric(
                    "Explanations Enhanced",
                    f"{pct:.0f}%",
                    help="Percentage of steps with enhanced explanations",
                )

            with col3:
                cleaned_count = len(
                    [
                        s
                        for s in enhanced_steps
                        if s.get("kql_query") and "<USER_EMAIL>" in s.get("kql_query")
                    ]
                )
                st.metric(
                    "KQL Queries Cleaned",
                    cleaned_count,
                    help="Number of KQL queries with placeholders",
                )

            with col4:
                speedup = len(original_steps) / elapsed if elapsed > 0 else 0
                st.metric(
                    "Processing Speed",
                    f"{speedup:.1f} steps/sec",
                    help="Average enhancement speed with parallel processing",
                )

            # Navigation buttons
            st.markdown("---")
            col1, col2, col3 = st.columns([1, 2, 1])

            with col1:
                if st.button("⬅️ Back to Alerts"):
                    st.session_state.step = 1
                    st.rerun()

            with col3:
                if st.button(
                    "🔄 Start New Search", type="primary", use_container_width=True
                ):
                    for key in list(st.session_state.keys()):
                        if key != "all_data":
                            del st.session_state[key]
                    initialize_session_state()
                    st.rerun()

        except Exception as e:
            progress_bar.empty()
            status_text.empty()
            st.error(f"❌ Error: {str(e)}")
            with st.expander("View Error Details"):
                st.code(traceback.format_exc())

            if st.button("⬅️ Go Back"):
                st.session_state.step = 1
                st.rerun()

# ============================================================================
# STEP 4: TRIAGING COMPLETE (ENHANCED WITH REAL-TIME PREDICTION)
# ============================================================================
if st.session_state.step == 4:
    st.markdown(
        '<div class="step-header"><h2>âœ… Triaging Complete!</h2></div>',
        unsafe_allow_html=True,
    )

    st.success("All investigation steps have been completed successfully.")

    # Generate Real-Time Prediction
    if "real_time_prediction" not in st.session_state:
        with st.spinner(
            "ðŸ¤– Generating AI prediction based on your triaging comments..."
        ):
            try:
                real_time_pred = crew.run_real_time_prediction(
                    triaging_comments=st.session_state.triaging_output,
                    rule_number=st.session_state.selected_alert.get("rule"),
                    template_content=st.session_state.template_content,
                    consolidated_data=st.session_state.consolidated_data,
                )
                st.session_state.real_time_prediction = real_time_pred
            except Exception as e:
                st.error(f"Prediction generation failed: {str(e)}")
                st.session_state.real_time_prediction = None

    st.markdown("## ðŸ“‹ Investigation Summary")

    for step_name, findings in st.session_state.triaging_output.items():
        with st.expander(f"**{step_name}**", expanded=False):
            st.markdown(findings)

    # Real-Time AI Prediction Display
    if st.session_state.get("real_time_prediction"):
        st.markdown("## ðŸŽ¯ AI Prediction Based on Your Triaging Comments")

        pred = st.session_state.real_time_prediction

        # Prediction Type with color coding
        pred_type = pred.get("prediction_type", "Unknown")
        if "false positive" in pred_type.lower():
            st.success(f"### ðŸŸ¢ {pred_type}")
        elif "true positive" in pred_type.lower():
            st.error(f"### ðŸ”´ {pred_type}")
        else:
            st.warning(f"### ðŸŸ¡ {pred_type}")

        # Probability Breakdown
        st.markdown("### ðŸ“Š Classification Probabilities")

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            fp_pct = pred.get("false_positive_likelihood", 0)
            st.metric(
                "False Positive",
                f"{fp_pct}%",
                delta=f"{fp_pct - st.session_state.rule_history.get('fp_rate', 50):+.0f}% vs baseline",
            )

        with col2:
            tp_pct = pred.get("true_positive_likelihood", 0)
            st.metric(
                "True Positive",
                f"{tp_pct}%",
                delta=f"{tp_pct - st.session_state.rule_history.get('tp_rate', 50):+.0f}% vs baseline",
            )

        with col3:
            bp_pct = pred.get("benign_positive_likelihood", 0)
            st.metric("Benign Positive", f"{bp_pct}%")

        with col4:
            conf_level = pred.get("confidence_level", "Low")
            conf_color = {"High": "ðŸŸ¢", "Medium": "ðŸŸ¡", "Low": "ðŸ”´"}.get(
                conf_level, "âšª"
            )
            st.metric("Confidence", f"{conf_color} {conf_level}")

        # Visual probability bar
        st.markdown("#### Probability Distribution")
        prob_html = f"""
        <div style="display: flex; width: 100%; height: 40px; border-radius: 8px; overflow: hidden; margin: 10px 0;">
            <div style="width: {fp_pct}%; background-color: #28a745; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold;">
                {fp_pct}% FP
            </div>
            <div style="width: {tp_pct}%; background-color: #dc3545; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold;">
                {tp_pct}% TP
            </div>
            {f'<div style="width: {bp_pct}%; background-color: #ffc107; display: flex; align-items: center; justify-content: center; color: black; font-weight: bold;">{bp_pct}% BP</div>' if bp_pct > 0 else ''}
        </div>
        """
        st.markdown(prob_html, unsafe_allow_html=True)

        # Key Factors
        if pred.get("key_factors"):
            st.markdown("#### ðŸ” Key Factors Supporting This Prediction")
            for i, factor in enumerate(pred["key_factors"], 1):
                st.markdown(f"{i}. {factor}")

        # Reasoning
        if pred.get("reasoning"):
            st.markdown("#### ðŸ’¡ AI Reasoning")
            st.info(pred["reasoning"])

        # Historical Comparison
        if pred.get("historical_comparison"):
            st.markdown("#### ðŸ“ˆ Historical Comparison")
            st.markdown(pred["historical_comparison"])

        # Web Research Findings
        if pred.get("web_research") and pred["web_research"] != "N/A":
            with st.expander("ðŸŒ Web Research Findings", expanded=False):
                st.markdown(pred["web_research"])

    # Original prediction (if exists)
    if st.session_state.predictions:
        st.markdown("## ðŸ¤– Initial AI Assessment (Before Triaging)")

        final_pred = st.session_state.predictions[0]

        col1, col2 = st.columns(2)
        with col1:
            prediction = final_pred.get("prediction", "Unknown")
            if "true positive" in prediction.lower():
                st.error(f"### {prediction}")
            elif "false positive" in prediction.lower():
                st.success(f"### {prediction}")
            else:
                st.info(f"### {prediction}")

        with col2:
            confidence = final_pred.get("confidence_score", "N/A")
            st.metric(
                "Initial Confidence",
                confidence,
                help="AI's confidence before triaging",
            )

        if "reasoning" in final_pred:
            st.markdown("**Initial AI Reasoning:**")
            st.info(final_pred["reasoning"])

    # Display Historical Context
    if st.session_state.rule_history:
        st.markdown("## ðŸ“Š Historical Pattern Summary")

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric(
                "Total Past Incidents",
                st.session_state.rule_history.get("total_incidents", 0),
            )
        with col2:
            st.metric(
                "False Positive Rate",
                f"{st.session_state.rule_history.get('fp_rate', 0)}%",
            )
        with col3:
            st.metric(
                "True Positive Rate",
                f"{st.session_state.rule_history.get('tp_rate', 0)}%",
            )
        with col4:
            st.metric(
                "Data Confidence",
                (
                    "High"
                    if st.session_state.rule_history.get("total_incidents", 0) > 10
                    else "Medium"
                ),
            )

    # Enhanced Download Section
    st.markdown("---")
    st.markdown("## ðŸ“¥ Export Results & Templates")

    # Generate reports
    final_report = generate_completed_template(
        st.session_state.consolidated_data,
        st.session_state.triaging_output,
        st.session_state.predictions[0] if st.session_state.predictions else {},
    )

    # Generate CSV template
    csv_template = generate_blank_triaging_template_csv(
        st.session_state.selected_alert.get("rule"),
        st.session_state.triaging_plan,
        st.session_state.rule_history,
    )

    # Generate Excel template
    if st.session_state.excel_template_data is None:
        with st.spinner("Generating Excel template..."):
            try:
                from src.template_generator import TriagingTemplateGenerator

                template_gen = TriagingTemplateGenerator()

                template_df = template_gen.generate_structured_template(
                    st.session_state.selected_alert.get("rule"),
                    st.session_state.triaging_plan,
                    st.session_state.rule_history,
                )

                excel_file = template_gen.export_to_excel(
                    template_df, st.session_state.selected_alert.get("rule")
                )

                st.session_state.excel_template_data = excel_file
            except Exception as e:
                st.error(f"Error generating Excel template: {str(e)}")
                st.session_state.excel_template_data = None

    # Download buttons
    st.markdown("### ðŸ“„ Available Downloads")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.download_button(
            label="ðŸ“„ Completed Report",
            data=final_report,
            file_name=f"triaging_report_{st.session_state.selected_alert.get('incident')}.txt",
            mime="text/plain",
            width="stretch",
            help="Download the completed investigation report with all findings",
        )

    with col2:
        if st.session_state.excel_template_data:
            st.download_button(
                label="ðŸ“Š Excel Template",
                data=st.session_state.excel_template_data,
                file_name=f"triaging_template_{st.session_state.selected_alert.get('rule').replace('#', '_')}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                width="stretch",
                help="Download professionally formatted Excel template with all investigation steps, KQL queries, and expected outputs",
            )
        else:
            st.button(
                "ðŸ“Š Excel Template",
                disabled=True,
                width="stretch",
                help="Excel template generation failed",
            )

    with col3:
        st.download_button(
            label="ðŸ“‹ CSV Template",
            data=csv_template,
            file_name=f"triaging_template_{st.session_state.selected_alert.get('rule').replace('#', '_')}.csv",
            mime="text/csv",
            width="stretch",
            help="Download CSV template with all investigation details for manual use",
        )

    with col4:
        json_export = {
            "incident": st.session_state.consolidated_data,
            "investigation": st.session_state.triaging_output,
            "prediction": (
                st.session_state.predictions[0] if st.session_state.predictions else {}
            ),
            "rule_history": st.session_state.rule_history,
            "progressive_predictions": st.session_state.progressive_predictions,
        }

        st.download_button(
            label="ðŸ“Š JSON Data",
            data=json.dumps(json_export, indent=2),
            file_name=f"triaging_data_{st.session_state.selected_alert.get('incident')}.json",
            mime="application/json",
            width="stretch",
            help="Download structured data in JSON format for integration",
        )

    # Preview tabs
    with st.expander("ðŸ‘ï¸ Preview Templates & Reports", expanded=False):
        tab1, tab2, tab3 = st.tabs(
            ["Completed Report", "CSV Template", "Excel Preview"]
        )

        with tab1:
            st.text(final_report)

        with tab2:
            st.text(csv_template)

        with tab3:
            if st.session_state.excel_template_data:
                st.success("âœ… Excel template generated successfully!")
                st.info("Excel template contains:")
                st.markdown(
                    """
                - **Step Number** - Sequential numbering
                - **Name** - Clean step names (no markdown)
                - **Explanation** - Detailed instructions (no asterisks)
                - **Input** - Required data/inputs
                - **KQL Query** - Full queries when applicable
                - **Execute** - Empty for manual completion
                - **Output** - Empty for findings
                - **Remarks/Comments** - Empty for manual update
                """
                )

                # Show step count
                step_count = len(st.session_state.triaging_plan)
                st.metric("Total Investigation Steps", step_count)

                # Show steps with KQL queries
                kql_steps = [
                    s for s in st.session_state.triaging_plan if s.get("kql_query")
                ]
                st.metric("Steps with KQL Queries", len(kql_steps))
            else:
                st.error("Excel template not available")

    st.markdown("---")
    st.markdown("### ðŸ“ Template Details")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Investigation Steps",
            len(st.session_state.triaging_plan),
            help="Number of AI-generated investigation steps",
        )

    with col2:
        kql_count = len(
            [s for s in st.session_state.triaging_plan if s.get("kql_query")]
        )
        st.metric(
            "KQL Queries Included", kql_count, help="Number of steps with KQL queries"
        )

    with col3:
        expected_count = len(
            [s for s in st.session_state.triaging_plan if s.get("expected_output")]
        )
        st.metric(
            "Expected Outputs",
            expected_count,
            help="Steps with expected output guidance",
        )

    st.markdown("---")

    if st.button("ðŸ”„ Start New Triaging", type="primary", width="stretch"):
        for key in list(st.session_state.keys()):
            if key != "all_data":
                del st.session_state[key]
        initialize_session_state()
        st.rerun()

# ============================================================================
# STEP 3: AI-POWERED TRIAGING WALKTHROUGH
# ============================================================================
elif st.session_state.step == 3:
    st.markdown(
        '<div class="step-header"><h2>Step 4: AI-Powered Triaging Walkthrough</h2></div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        f"**Alert:** {st.session_state.selected_alert.get('description', 'N/A')}"
    )

    if st.session_state.triaging_plan is None:
        st.markdown("### ðŸ¤– AI Agents are Analyzing...")

        analysis_status = st.empty()
        analysis_progress = st.progress(0)

        with st.spinner("This may take 30-60 seconds..."):
            try:
                analysis_status.info(
                    "ðŸ§  AI is learning from historical data and templates..."
                )
                analysis_progress.progress(20)

                result = crew.run_analysis_phase(
                    consolidated_data=st.session_state.consolidated_data,
                    template_content=st.session_state.template_content,
                    rule_number=st.session_state.selected_alert.get("rule"),
                )

                analysis_progress.progress(80)
                analysis_status.info("ðŸ“ Generating triaging plan and predictions...")

                st.session_state.triaging_plan = result["triaging_plan"]
                st.session_state.predictions = result["predictions"]
                st.session_state.progressive_predictions = result.get(
                    "progressive_predictions", {}
                )
                st.session_state.rule_history = result.get("rule_history", {})
                st.session_state.current_step_index = 0

                analysis_progress.progress(100)
                analysis_status.success("âœ… AI analysis complete!")

                st.rerun()

            except Exception as e:
                analysis_progress.empty()
                analysis_status.error(f"âŒ Error in AI analysis: {str(e)}")
                with st.expander("View Error Details"):
                    st.code(traceback.format_exc())

                st.warning("âš ï¸ Using fallback triaging plan...")
                st.session_state.triaging_plan = crew._create_fallback_steps()
                st.session_state.predictions = crew._create_minimal_prediction(
                    st.session_state.consolidated_data
                )
                st.session_state.progressive_predictions = {}
                st.session_state.rule_history = {}
                st.rerun()

    current_step_index = st.session_state.current_step_index
    total_steps = len(st.session_state.triaging_plan)

    if total_steps == 0:
        st.error("âŒ No triaging steps generated. Please try again.")
        if st.button("â† Go Back"):
            st.session_state.step = 2
            st.session_state.triaging_plan = None
            st.rerun()
        st.stop()

    progress_percentage = (current_step_index / total_steps) if total_steps > 0 else 0
    st.progress(
        progress_percentage,
        text=f"Progress: Step {current_step_index + 1} of {total_steps}",
    )

    if current_step_index < total_steps:
        current_step = st.session_state.triaging_plan[current_step_index]

        # Display the formatted step
        st.markdown(f"***")
        st.markdown(
            f"### {current_step_index + 1}. {current_step.get('step_name')} ðŸ”"
        )
        st.markdown(f"* **Explanation:** {current_step.get('explanation')}")
        st.markdown(f"* **Input Required:** {current_step.get('input_required')}")

        kql_query = current_step.get("kql_query")
        if kql_query and kql_query.strip() != "N/A":
            st.markdown(f"* **KQL Query:**")
            st.code(kql_query, language="kql")
        else:
            st.markdown(f"* **KQL Query:** N/A")

        st.markdown(f"* **Expected Output:** {current_step.get('expected_output')}")
        st.markdown(
            f"* **Decision Point:** {current_step.get('decision_point', 'N/A')}"
        )
        st.markdown(f"***")

        # Progressive Prediction Display
        if st.session_state.progressive_predictions:
            step_name = current_step.get("step_name", "")
            current_prog = st.session_state.progressive_predictions.get(step_name, {})

            if current_prog:
                st.markdown(
                    '<div class="progressive-prediction">', unsafe_allow_html=True
                )
                st.markdown("### ðŸ“Š Progressive Analysis (Updated After Each Step)")

                col1, col2, col3 = st.columns(3)

                with col1:
                    fp_prob = current_prog.get("false_positive_probability", 50)
                    delta_fp = fp_prob - st.session_state.rule_history.get(
                        "fp_rate", 50
                    )
                    st.metric(
                        "False Positive Likelihood",
                        f"{fp_prob:.1f}%",
                        delta=f"{delta_fp:+.1f}% from baseline",
                        delta_color="normal",
                    )

                with col2:
                    tp_prob = current_prog.get("true_positive_probability", 50)
                    delta_tp = tp_prob - st.session_state.rule_history.get(
                        "tp_rate", 50
                    )
                    st.metric(
                        "True Positive Likelihood",
                        f"{tp_prob:.1f}%",
                        delta=f"{delta_tp:+.1f}% from baseline",
                        delta_color="normal",
                    )

                with col3:
                    confidence = current_prog.get("confidence_level", "50%")
                    st.metric("Analysis Confidence", confidence)

                st.markdown("</div>", unsafe_allow_html=True)

        # AI Prediction box
        if st.session_state.predictions:
            with st.expander("ðŸ”® AI Final Prediction & Guidance", expanded=False):
                prediction = st.session_state.predictions[0]

                col1, col2 = st.columns(2)
                with col1:
                    pred_text = prediction.get("prediction", "N/A")
                    if "true positive" in pred_text.lower():
                        st.error(f"**Prediction:** {pred_text}")
                    elif "false positive" in pred_text.lower():
                        st.success(f"**Prediction:** {pred_text}")
                    else:
                        st.info(f"**Prediction:** {pred_text}")

                with col2:
                    confidence = prediction.get("confidence_score", "N/A")
                    st.metric("Overall Confidence", confidence)

                if "reasoning" in prediction:
                    st.markdown("**AI Reasoning:**")
                    st.info(prediction["reasoning"])

        st.markdown("---")

        # User input section
        st.markdown("### âœï¸ Your Findings")

        user_input = st.text_area(
            f"Document your findings for this step:",
            height=150,
            key=f"input_{current_step_index}",
            placeholder="Enter your investigation findings, observations, and any relevant details...",
        )

        col1, col2, col3 = st.columns([1, 1, 3])

        with col1:
            if current_step_index > 0:
                if st.button("â† Previous"):
                    st.session_state.current_step_index -= 1
                    st.rerun()

        with col2:
            if st.button("Next Step â†’", type="primary"):
                if user_input.strip():
                    st.session_state.triaging_output[current_step.get("step_name")] = (
                        user_input
                    )
                    st.session_state.current_step_index += 1
                    st.rerun()
                else:
                    st.warning("âš ï¸ Please enter your findings before proceeding.")

        with col3:
            if st.button(
                "â­ï¸ Skip to End", help="Skip remaining steps and go to summary"
            ):
                for remaining_step in st.session_state.triaging_plan[
                    current_step_index:
                ]:
                    step_name = remaining_step.get("step_name", "Unknown Step")
                    if step_name not in st.session_state.triaging_output:
                        st.session_state.triaging_output[step_name] = "[Skipped]"
                st.session_state.step = 4
                st.rerun()

    else:
        st.session_state.step = 4
        st.rerun()
