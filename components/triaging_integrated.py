# ============================================================================
# FIXED: triaging_integrated.py - Proper state management
# ============================================================================

import streamlit as st
import traceback
import pandas as pd

# Template processing imports
from routes.src.template_parser import TemplateParser
from routes.src.template_generator import EnhancedTemplateGenerator

# Individual step imports
from components.triaging.step2_enhance import show_page as step2_enhance


def initialize_triaging_state(rule_number: str, alert_data: dict = None):
    """
    âœ… FIXED: Accept alert_data directly to avoid state loss

    Args:
        rule_number: The rule number (e.g., "297" or "Rule#297")
        alert_data: Full alert data dict with title, description, etc.
    """

    # âœ… Store FULL alert data, not just rule number
    if alert_data:
        # Use provided alert data
        st.session_state.triaging_selected_alert = {
            "rule": rule_number,
            "rule_number": rule_number,
            "alert_name": alert_data.get("title")
            or alert_data.get("alert_name")
            or rule_number,
            "description": alert_data.get("description")
            or alert_data.get("alert_name")
            or rule_number,
            "incident": alert_data.get("incident_id") or f"ALERT_{id(alert_data)}",
            "severity": alert_data.get("severity", "Unknown"),
            "status": alert_data.get("status", "Unknown"),
            "source": alert_data.get("source", "manual"),
            "is_manual": alert_data.get("source") == "alert_details"
            or alert_data.get("is_manual", False),
            # âœ… CRITICAL: Pass analysis text if available
            "analysis_text": alert_data.get("analysis_text", ""),
        }
    else:
        # Fallback
        st.session_state.triaging_selected_alert = {
            "rule": rule_number,
            "rule_number": rule_number,
            "alert_name": rule_number,
            "incident": f"TEMPLATE_GEN_{rule_number}",
            "description": f"Template Generation for Rule {rule_number}",
            "is_manual": False,
        }

    # âœ… Initialize other minimal state
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


def display_triaging_workflow(rule_number: str, alert_data: dict = None):
    """
    âœ… FIXED: Accept alert_data parameter to preserve state

    Args:
        rule_number: Rule identifier
        alert_data: Full alert data with title, description, analysis, etc.
    """

    st.markdown("## 🔍 AI-Powered Template Enhancement")
    st.markdown("---")

    # âœ… FIXED: Initialize with alert_data if provided
    if alert_data:
        initialize_triaging_state(rule_number, alert_data)

    # Get the alert from session state
    selected_alert = st.session_state.get("triaging_selected_alert", {})
    is_manual = selected_alert.get("is_manual", False)
    alert_name = selected_alert.get("alert_name", rule_number)

    # âœ… DEBUG OUTPUT
    print(f"\n{'='*80}")
    print(f"🔍 TRIAGING WORKFLOW INITIALIZED")
    print(f"{'='*80}")
    print(f"Rule Number: {rule_number}")
    print(f"Alert Name: {alert_name}")
    print(f"Is Manual: {is_manual}")
    print(f"Source: {selected_alert.get('source', 'unknown')}")
    print(f"Alert Data Keys: {selected_alert.keys()}")
    print(f"{'='*80}\n")

    if is_manual:
        st.info(
            "🤖 **Manual Alert Mode** - Generating investigation steps from AI analysis..."
        )

        # âœ… IMPROVED: Better checking and debugging
        analysis_text = st.session_state.get("manual_analysis_text", "").strip()

        # âœ… FALLBACK: Check triaging_selected_alert for analysis
        if not analysis_text:
            analysis_text = selected_alert.get("analysis_text", "").strip()

        print(f"Analysis Text Length: {len(analysis_text)}")
        print(
            f"Analysis Text Preview: {analysis_text[:200] if analysis_text else 'EMPTY'}"
        )

        if not analysis_text or len(analysis_text) < 100:
            st.warning(
                """
                ⚠️ **Analysis Not Ready Yet**
                
                Please:
                1. Go back to **'🤖 AI Threat Analysis'** tab
                2. Wait for analysis to complete
                3. Return to this tab
                
                The system needs the full analysis to generate investigation steps.
                """
            )

            # Provide quick navigation
            st.markdown("---")
            col1, col2, col3 = st.columns(3)
            with col1:
                if st.button("👈 Go to AI Analysis Tab", key="back_to_analysis"):
                    st.rerun()

            return

        # âœ… Analysis is ready - proceed with generation
        print(f"✅ Analysis ready, proceeding with step generation for: {alert_name}")

        try:
            # Initialize template generator
            from routes.src.template_generator import ImprovedTemplateGenerator

            gen = ImprovedTemplateGenerator()

            st.info("⏳ Generating investigation steps from analysis...")

            # Generate template directly from analysis
            with st.spinner("🧠 Analyzing alert and generating steps..."):
                template_df = gen.generate_from_manual_analysis(
                    alert_name=alert_name,
                    analysis_text=analysis_text,
                    rule_number=rule_number,
                )

            # Store in session state
            st.session_state.template_dataframe = template_df
            st.session_state.original_steps = []
            st.session_state.enhanced_steps = []

            # Convert to enhanced steps format for display
            enhanced_steps_with_kql = []
            for idx, row in template_df.iterrows():
                if pd.isna(row["Step"]) or str(row["Step"]).strip() == "":
                    continue

                kql_raw = row.get("KQL Query", "")
                kql_str = str(kql_raw) if pd.notna(kql_raw) else ""
                kql_cleaned = kql_str.strip().lower()
                final_kql = (
                    str(kql_raw).strip()
                    if pd.notna(kql_raw) and kql_cleaned not in ["nan", "none", ""]
                    else ""
                )

                step_dict = {
                    "step_name": (
                        str(row.get("Name", "")) if pd.notna(row.get("Name")) else ""
                    ),
                    "explanation": (
                        str(row.get("Explanation", ""))
                        if pd.notna(row.get("Explanation"))
                        else ""
                    ),
                    "kql_query": final_kql,
                    "kql_explanation": (
                        str(row.get("KQL Explanation", ""))
                        if pd.notna(row.get("KQL Explanation"))
                        and str(row.get("KQL Explanation")).strip().lower()
                        not in ["nan", "none", ""]
                        else ""
                    ),
                    "input_required": "",
                }
                enhanced_steps_with_kql.append(step_dict)

            st.session_state.enhanced_steps = enhanced_steps_with_kql
            st.session_state.excel_template_data = gen.export_to_excel(
                template_df, rule_number
            )

            st.success("✅ Investigation steps generated successfully!")

            # Now display using existing display function
            from components.triaging.step2_enhance import _display_enhancement_results

            _display_enhancement_results(
                st.session_state,
                rule_number,
                None,  # EnhancedTemplateGenerator not needed here
            )

        except Exception as e:
            st.error(f"❌ Error generating steps: {str(e)}")
            print(f"ERROR: {traceback.format_exc()}")
            with st.expander("🔧 View Error Details"):
                st.code(traceback.format_exc())

        return

    # âœ… ORIGINAL FLOW: Template-based triaging
    print(f"DEBUG: Using template-based triaging for {rule_number}")

    init_key = f"triaging_init_{rule_number}"

    if init_key not in st.session_state:
        st.info("🎯 Initializing template enhancement...")

        if not initialize_triaging_state(rule_number, alert_data):
            st.error("❌ Failed to initialize")
            return

        st.session_state[init_key] = True
        st.success("✅ Ready for template enhancement!")
        st.rerun()
        return

    if "triaging_rule_number" not in st.session_state:
        st.error("❌ State lost. Please restart.")
        if st.button("🔄 Restart"):
            if init_key in st.session_state:
                del st.session_state[init_key]
            st.rerun()
        return

    rule_num = st.session_state.triaging_rule_number

    try:
        if st.session_state.triaging_step == 2:
            step2_enhance(
                st.session_state,
                TemplateParser,
                EnhancedTemplateGenerator,
            )
        else:
            st.warning("⚠️ Only template enhancement is available in this mode")
            st.info(
                "💡 To use full triaging workflow, select an incident from the dashboard"
            )

    except Exception as e:
        st.error(f"❌ Error: {str(e)}")
        with st.expander("🔧 View Error Details"):
            st.code(traceback.format_exc())

    # Action buttons
    st.markdown("---")
    col1, col2 = st.columns(2)

    with col1:
        if st.button("🔄 Reset Workflow", key="reset_workflow"):
            keys_to_clear = [
                k
                for k in st.session_state.keys()
                if k.startswith("triaging_") or k == init_key
            ]
            for key in keys_to_clear:
                del st.session_state[key]
            st.success("✅ Reset complete!")
            st.rerun()

    with col2:
        with st.expander("📊 View State", expanded=False):
            st.json(
                {
                    "rule_number": rule_num,
                    "alert_name": alert_name,
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
