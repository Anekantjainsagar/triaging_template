import streamlit as st


def initialize_session_state():
    """Initialize all session state variables."""
    defaults = {
        "step": 0,
        "alerts": [],
        "all_data": None,
        "selected_alert": None,
        "template_content": None,
        "triaging_plan": None,
        "triaging_output": {},
        "predictions": [],
        "analysis_complete": False,
        "excel_template_data": None,
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def reset_session_state():
    """Reset session state while preserving all_data."""
    all_data = st.session_state.get("all_data")

    for key in list(st.session_state.keys()):
        if key != "all_data":
            del st.session_state[key]

    initialize_session_state()
    st.session_state.all_data = all_data


def update_step(step_number):
    """Update the current step."""
    st.session_state.step = step_number
