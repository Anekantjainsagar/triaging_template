import streamlit as st
import traceback

# Backend utilities
from routes.src.crew import TriagingCrew

# Template processing imports
from routes.src.template_parser import TemplateParser
from routes.src.web_llm_enhancer import WebLLMEnhancer
from routes.src.template_generator import EnhancedTemplateGenerator

# Individual step imports
from components.triaging.step2_enhance import show_page as step2_enhance

@st.cache_resource
def get_crew():
    """Initialize and cache the CrewAI instance."""
    return TriagingCrew()


def initialize_triaging_state(rule_number: str):
    """
    ✅ MINIMAL initialization - only what's needed for template enhancement

    Args:
        rule_number: The rule number (e.g., "297" or "Rule#297")
    """

    # ✅ Store ONLY the rule number and alert object
    if "triaging_rule_number" not in st.session_state:
        st.session_state.triaging_rule_number = rule_number

    # 🔧 FIX: Always set/overwrite the alert object (don't check if exists)
    st.session_state.triaging_selected_alert = {
        "rule": rule_number,
        "rule_number": rule_number,
        "incident": f"TEMPLATE_GEN_{rule_number}",
        "description": f"Template Generation for Rule {rule_number}",
    }

    # ✅ Initialize other minimal state
    defaults = {
        "triaging_step": 2,  # Start at template enhancement
        "triaging_plan": None,
        "triaging_output": {},
        "predictions": [],
        "progressive_predictions": {},
        "rule_history": {},
        "current_step_index": 0,
        "analysis_complete": False,
        "original_steps": None,
        "enhanced_steps": None,
        "validation_report": None,
        "real_time_prediction": None,
        "excel_template_data": None,
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

    return True


def display_triaging_workflow(rule_number: str):
    """
    ✅ SIMPLIFIED: Template generation workflow (no historical data needed)

    Args:
        rule_number: Rule number/name (e.g., "297" or "Rule#297")
    """

    st.markdown("## 🔍 AI-Powered Template Enhancement")
    st.markdown("---")

    # ✅ CREATE UNIQUE KEY FOR THIS RULE
    init_key = f"triaging_init_{rule_number}"

    # ✅ INITIALIZE ONCE
    if init_key not in st.session_state:
        st.info("🎯 Initializing template enhancement...")

        if not initialize_triaging_state(rule_number):  # ← Calls initialization
            st.error("❌ Failed to initialize")
            return

        # Mark as initialized
        st.session_state[init_key] = True
        st.success("✅ Ready for template enhancement!")
        st.rerun()  # ← Reruns the entire script
        return

        # ✅ VERIFY STATE EXISTS
        if "triaging_rule_number" not in st.session_state:
            st.error("❌ State lost. Please restart.")
            if st.button("🔄 Restart"):
                if init_key in st.session_state:
                    del st.session_state[init_key]
                st.rerun()
            return

    # ✅ GET RULE NUMBER
    rule_num = st.session_state.triaging_rule_number

    # Display banner
    st.info(f"🎯 **Active Rule:** `{rule_num}` | **Mode:** Template Enhancement Only")

    st.markdown("---")

    # ✅ STEP NAVIGATION
    step_names = [
        "🚀 Enhance Template",  # Step 2
        "💥 CrewAI Walkthrough",  # Step 3
        "✨ Complete Analysis",  # Step 4
    ]

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button(
            step_names[0],
            key="nav_step2",
            width="stretch",
            type="primary" if st.session_state.triaging_step == 2 else "secondary",
        ):
            st.session_state.triaging_step = 2
            st.rerun()

    with col2:
        if st.button(
            step_names[1],
            key="nav_step3",
            width="stretch",
            type="primary" if st.session_state.triaging_step == 3 else "secondary",
            disabled=True,  # Disable for template-only mode
        ):
            st.warning("⚠️ CrewAI walkthrough requires incident data")

    with col3:
        if st.button(
            step_names[2],
            key="nav_step4",
            width="stretch",
            type="primary" if st.session_state.triaging_step == 4 else "secondary",
            disabled=True,  # Disable for template-only mode
        ):
            st.warning("⚠️ Complete analysis requires incident data")

    # Progress indicator
    st.progress(0.33, text=f"Progress: {step_names[0]}")

    st.markdown("---")

    # ✅ DISPLAY TEMPLATE ENHANCEMENT STEP ONLY
    try:
        # Only show template enhancement
        if st.session_state.triaging_step == 2:
            step2_enhance(
                st.session_state,
                TemplateParser,
                WebLLMEnhancer,
                EnhancedTemplateGenerator,
            )
        else:
            st.warning("⚠️ Only template enhancement is available in this mode")
            st.info(
                "💡 To use full triaging workflow, select an incident from the dashboard"
            )

    except Exception as e:
        st.error(f"❌ Error: {str(e)}")
        with st.expander("🔍 View Error Details"):
            st.code(traceback.format_exc())

    # ✅ ACTION BUTTONS
    st.markdown("---")
    col1, col2 = st.columns(2)

    with col1:
        if st.button("🔄 Reset Workflow", key="reset_workflow"):
            # Clear all triaging state including init flag
            keys_to_clear = [
                k
                for k in st.session_state.keys()
                if k.startswith("triaging_") or k == init_key
            ]
            for key in keys_to_clear:
                del st.session_state[
                    key
                ]  # ✅ This is good - deletes, doesn't set to None
            st.success("✅ Reset complete!")
            st.rerun()

    with col2:
        # State inspector
        with st.expander("📊 View State", expanded=False):
            st.json(
                {
                    "rule_number": rule_num,
                    "current_step": st.session_state.triaging_step,
                    "initialized": init_key in st.session_state,
                    "template_found": st.session_state.get("original_steps")
                    is not None,
                    "enhanced": st.session_state.get("enhanced_steps") is not None,
                }
            )


def display_triaging_page():
    """
    Standalone triaging page for template enhancement only
    """
    st.markdown("# 🔍 AI-Powered Template Enhancement")

    st.info(
        "💡 **Template Enhancement Mode** - Generate enhanced triaging templates from existing templates"
    )

    st.markdown("---")
    st.markdown("### 🎯 Enter Rule Number")

    manual_rule = st.text_input(
        "Rule Number:",
        placeholder="e.g., 297 or Rule#297",
        key="manual_rule",
    )

    if st.button("🚀 Start Template Enhancement", type="primary", width="stretch"):
        if not manual_rule:
            st.error("❌ Please provide a rule number")
        else:
            # Initialize and start
            if initialize_triaging_state(manual_rule):
                st.success("✅ Initialized!")
                st.rerun()
            else:
                st.error("❌ Initialization failed")
