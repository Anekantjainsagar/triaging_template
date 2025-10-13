import streamlit as st
import json
from utils.file_handlers import generate_final_report
from src.csv_template_generator import generate_blank_triaging_template_csv


def render_step_4():
    st.markdown(
        '<div class="step-header"><h2>✅ Triaging Complete!</h2></div>',
        unsafe_allow_html=True,
    )

    st.success("All investigation steps have been completed successfully.")

    # Generate real-time prediction
    generate_real_time_prediction()

    # Display investigation summary
    display_investigation_summary()

    # Display AI predictions
    display_ai_predictions()

    # Export section
    display_export_section()

    # New triaging button
    if st.button("🔄 Start New Triaging", type="primary"):
        from utils.state_management import reset_session_state

        reset_session_state()
        st.rerun()


def generate_real_time_prediction():
    """Generate real-time prediction based on triaging comments."""
    if "real_time_prediction" not in st.session_state:
        with st.spinner("🤖 Generating AI prediction..."):
            try:
                from utils.data_loader import get_crew

                crew = get_crew()

                real_time_pred = crew.run_real_time_prediction(
                    triaging_comments=st.session_state.triaging_output,
                    rule_number=st.session_state.selected_alert.get("rule"),
                )
                st.session_state.real_time_prediction = real_time_pred
            except Exception as e:
                st.error(f"Prediction generation failed: {str(e)}")
                st.session_state.real_time_prediction = None


def display_investigation_summary():
    """Display the investigation findings."""
    st.markdown("## 🔮 Investigation Summary")

    for step_name, findings in st.session_state.triaging_output.items():
        with st.expander(f"**{step_name}**", expanded=False):
            st.markdown(findings)


def display_ai_predictions():
    """Display both real-time and initial AI predictions."""
    # Real-time prediction
    if st.session_state.get("real_time_prediction"):
        display_real_time_prediction()

    # Initial prediction
    if st.session_state.predictions:
        display_initial_prediction()


def display_real_time_prediction():
    """Display the real-time AI prediction."""
    pred = st.session_state.real_time_prediction

    st.markdown("## 🎯 AI Prediction Based on Your Triaging")

    # Prediction type with color coding
    pred_type = pred.get("prediction_type", "Unknown")
    if "false positive" in pred_type.lower():
        st.success(f"### 🟢 {pred_type}")
    elif "true positive" in pred_type.lower():
        st.error(f"### 🔴 {pred_type}")
    else:
        st.warning(f"### 🟡 {pred_type}")


def display_initial_prediction():
    """Display the initial AI assessment."""
    st.markdown("## 🤖 Initial AI Assessment")

    final_pred = st.session_state.predictions[0]
    prediction = final_pred.get("prediction", "Unknown")

    if "true positive" in prediction.lower():
        st.error(f"### {prediction}")
    elif "false positive" in prediction.lower():
        st.success(f"### {prediction}")
    else:
        st.info(f"### {prediction}")


def display_export_section():
    """Display the export/download section."""
    st.markdown("---")
    st.markdown("## 📁 Export Results")

    # Generate reports
    final_report = generate_final_report(
        st.session_state.consolidated_data,
        st.session_state.triaging_output,
        st.session_state.predictions,
    )

    csv_template = generate_blank_triaging_template_csv(
        st.session_state.selected_alert.get("rule"),
        st.session_state.triaging_plan,
        st.session_state.rule_history,
    )

    # Download buttons
    col1, col2, col3 = st.columns(3)

    with col1:
        st.download_button(
            label="📄 Completed Report",
            data=final_report,
            file_name=f"triaging_report_{st.session_state.selected_alert.get('incident')}.txt",
            mime="text/plain",
        )

    with col2:
        st.download_button(
            label="📋 CSV Template",
            data=csv_template,
            file_name=f"triaging_template_{st.session_state.selected_alert.get('rule').replace('#', '_')}.csv",
            mime="text/csv",
        )

    with col3:
        json_export = {
            "investigation": st.session_state.triaging_output,
            "prediction": (
                st.session_state.predictions[0] if st.session_state.predictions else {}
            ),
        }

        st.download_button(
            label="📁 JSON Data",
            data=json.dumps(json_export, indent=2),
            file_name=f"triaging_data_{st.session_state.selected_alert.get('incident')}.json",
            mime="application/json",
        )
