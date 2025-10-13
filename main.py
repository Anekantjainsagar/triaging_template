import streamlit as st
from components.triaging.step_0_search import render_step_0
from components.triaging.step_1_select import render_step_1
from components.triaging.step_2_template import render_step_2
from components.triaging.step_3_triaging import render_step_3
from components.triaging.step_4_complete import render_step_4
from config.triaging_styles import main_header_style
from utils.state_management import initialize_session_state, reset_session_state


# Page Configuration
st.set_page_config(
    page_title="AI-Powered Security Incident Triaging",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Initialize session state
initialize_session_state()


# Render UI components
def render_header():
    st.markdown(main_header_style, unsafe_allow_html=True)
    st.markdown(
        '<div class="main-header">🔒 AI-Powered Security Incident Triaging System</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        "Automate security alert triaging with AI-powered analysis and comprehensive template generation."
    )


def render_sidebar():
    with st.sidebar:
        st.header("🧭 Navigation")
        st.write(f"**Current Step:** {st.session_state.step + 1}/5")

        if st.session_state.step > 0:
            st.markdown("---")
            if st.button("🔄 Start Over"):
                reset_session_state()
                st.rerun()


render_header()
render_sidebar()


# Main app logic based on current step
if st.session_state.step == 0:
    render_step_0()
elif st.session_state.step == 1:
    render_step_1()
elif st.session_state.step == 2:
    render_step_2()
elif st.session_state.step == 3:
    render_step_3()
elif st.session_state.step == 4:
    render_step_4()
