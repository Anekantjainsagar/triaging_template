import streamlit as st
from utils.data_loader import get_crew


def render_step_3():
    st.markdown(
        '<div class="step-header"><h2>Step 4: AI-Powered Triaging Walkthrough</h2></div>',
        unsafe_allow_html=True,
    )

    if st.session_state.triaging_plan is None:
        run_ai_analysis()
    else:
        render_triaging_walkthrough()


def run_ai_analysis():
    """Run AI analysis to generate triaging plan."""
    analysis_status = st.empty()
    analysis_progress = st.progress(0)

    with st.spinner("This may take 30-60 seconds..."):
        try:
            crew = get_crew()
            result = crew.run_analysis_phase(
                consolidated_data=st.session_state.consolidated_data,
                template_content=st.session_state.template_content,
                rule_number=st.session_state.selected_alert.get("rule"),
            )

            # Store results
            st.session_state.triaging_plan = result["triaging_plan"]
            st.session_state.predictions = result["predictions"]
            st.session_state.current_step_index = 0

            st.rerun()

        except Exception as e:
            st.error(f"❌ Error in AI analysis: {str(e)}")
            # Implement fallback logic here


def render_triaging_walkthrough():
    """Render the step-by-step triaging interface."""
    current_step_index = st.session_state.current_step_index
    total_steps = len(st.session_state.triaging_plan)

    # Progress bar
    progress_percentage = current_step_index / total_steps if total_steps > 0 else 0
    st.progress(
        progress_percentage, text=f"Step {current_step_index + 1} of {total_steps}"
    )

    if current_step_index < total_steps:
        render_current_step(current_step_index)
    else:
        st.session_state.step = 4
        st.rerun()


def render_current_step(current_step_index):
    """Render the current triaging step."""
    current_step = st.session_state.triaging_plan[current_step_index]

    # Display step information
    st.markdown(f"### {current_step_index + 1}. {current_step.get('step_name')}")
    st.markdown(f"**Explanation:** {current_step.get('explanation')}")

    # KQL Query if available
    kql_query = current_step.get("kql_query")
    if kql_query and kql_query.strip() != "N/A":
        st.code(kql_query, language="kql")

    # User input
    user_input = st.text_area(
        "Document your findings:",
        height=150,
        key=f"input_{current_step_index}",
        placeholder="Enter your investigation findings...",
    )

    # Navigation buttons
    col1, col2, col3 = st.columns([1, 1, 3])

    with col1:
        if current_step_index > 0 and st.button("← Previous"):
            st.session_state.current_step_index -= 1
            st.rerun()

    with col2:
        if st.button("Next Step →", type="primary"):
            if user_input.strip():
                st.session_state.triaging_output[current_step.get("step_name")] = (
                    user_input
                )
                st.session_state.current_step_index += 1
                st.rerun()
            else:
                st.warning("Please enter your findings before proceeding.")

    with col3:
        if st.button("⏩ Skip to End"):
            skip_remaining_steps()
            st.session_state.step = 4
            st.rerun()


def skip_remaining_steps():
    """Mark remaining steps as skipped."""
    for remaining_step in st.session_state.triaging_plan[
        st.session_state.current_step_index :
    ]:
        step_name = remaining_step.get("step_name", "Unknown Step")
        if step_name not in st.session_state.triaging_output:
            st.session_state.triaging_output[step_name] = "[Skipped]"
