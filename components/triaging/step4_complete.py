# step4_complete.py

import streamlit as st
import json
import traceback

def show_page(session_state, crew, generate_completed_template, generate_blank_triaging_template_csv, TriagingTemplateGenerator, traceback):
    st.markdown(
        '<div class="step-header"><h2>✅ Triaging Complete!</h2></div>',
        unsafe_allow_html=True,
    )

    st.success("All investigation steps have been completed successfully.")

    # Generate Real-Time Prediction
    if "real_time_prediction" not in session_state:
        with st.spinner(
            "🧠 Generating AI prediction based on your triaging comments..."
        ):
            try:
                real_time_pred = crew.run_real_time_prediction(
                    triaging_comments=session_state.triaging_output,
                    rule_number=session_state.selected_alert.get("rule"),
                    template_content=session_state.template_content,
                    consolidated_data=session_state.consolidated_data,
                )
                session_state.real_time_prediction = real_time_pred
            except Exception as e:
                st.error(f"Prediction generation failed: {str(e)}")
                session_state.real_time_prediction = None

    st.markdown("## 📝 Investigation Summary")

    for step_name, findings in session_state.triaging_output.items():
        with st.expander(f"**{step_name}**", expanded=False):
            st.markdown(findings)

    # Real-Time AI Prediction Display
    if session_state.get("real_time_prediction"):
        st.markdown("## 🎯 AI Prediction Based on Your Triaging Comments")

        pred = session_state.real_time_prediction

        # Prediction Type with color coding
        pred_type = pred.get("prediction_type", "Unknown")
        if "false positive" in pred_type.lower():
            st.success(f"### 🟢 {pred_type}")
        elif "true positive" in pred_type.lower():
            st.error(f"### 🔴 {pred_type}")
        else:
            st.warning(f"### 🟡 {pred_type}")

        # Probability Breakdown
        st.markdown("### 📊 Classification Probabilities")

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            fp_pct = pred.get("false_positive_likelihood", 0)
            st.metric(
                "False Positive",
                f"{fp_pct}%",
                delta=f"{fp_pct - session_state.rule_history.get('fp_rate', 50):+.0f}% vs baseline",
            )

        with col2:
            tp_pct = pred.get("true_positive_likelihood", 0)
            st.metric(
                "True Positive",
                f"{tp_pct}%",
                delta=f"{tp_pct - session_state.rule_history.get('tp_rate', 50):+.0f}% vs baseline",
            )

        with col3:
            bp_pct = pred.get("benign_positive_likelihood", 0)
            st.metric("Benign Positive", f"{bp_pct}%")

        with col4:
            conf_level = pred.get("confidence_level", "Low")
            conf_color = {"High": "🟢", "Medium": "🟡", "Low": "🔴"}.get(
                conf_level, "⚪"
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
            st.markdown("#### 🔍 Key Factors Supporting This Prediction")
            for i, factor in enumerate(pred["key_factors"], 1):
                st.markdown(f"{i}. {factor}")

        # Reasoning
        if pred.get("reasoning"):
            st.markdown("#### 💡 AI Reasoning")
            st.info(pred["reasoning"])

        # Historical Comparison
        if pred.get("historical_comparison"):
            st.markdown("#### 📈 Historical Comparison")
            st.markdown(pred["historical_comparison"])

        # Web Research Findings
        if pred.get("web_research") and pred["web_research"] != "N/A":
            with st.expander("🌐 Web Research Findings", expanded=False):
                st.markdown(pred["web_research"])

    # Original prediction (if exists)
    if session_state.predictions:
        st.markdown("## 🧠 Initial AI Assessment (Before Triaging)")

        final_pred = session_state.predictions[0]

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
    if session_state.rule_history:
        st.markdown("## 📊 Historical Pattern Summary")

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric(
                "Total Past Incidents",
                session_state.rule_history.get("total_incidents", 0),
            )
        with col2:
            st.metric(
                "False Positive Rate",
                f"{session_state.rule_history.get('fp_rate', 0)}%",
            )
        with col3:
            st.metric(
                "True Positive Rate",
                f"{session_state.rule_history.get('tp_rate', 0)}%",
            )
        with col4:
            st.metric(
                "Data Confidence",
                (
                    "High"
                    if session_state.rule_history.get("total_incidents", 0) > 10
                    else "Medium"
                ),
            )

    # Enhanced Download Section
    st.markdown("---")
    st.markdown("## 💾 Export Results & Templates")

    # Generate reports
    final_report = generate_completed_template(
        session_state.consolidated_data,
        session_state.triaging_output,
        session_state.predictions[0] if session_state.predictions else {},
    )

    # Generate CSV template
    csv_template = generate_blank_triaging_template_csv(
        session_state.selected_alert.get("rule"),
        session_state.triaging_plan,
        session_state.rule_history,
    )

    # Generate Excel template
    if session_state.excel_template_data is None:
        with st.spinner("Generating Excel template..."):
            try:
                template_gen = TriagingTemplateGenerator()

                template_df = template_gen.generate_structured_template(
                    session_state.selected_alert.get("rule"),
                    session_state.triaging_plan,
                    session_state.rule_history,
                )

                excel_file = template_gen.export_to_excel(
                    template_df, session_state.selected_alert.get("rule")
                )

                session_state.excel_template_data = excel_file
            except Exception as e:
                st.error(f"Error generating Excel template: {str(e)}")
                session_state.excel_template_data = None

    # Download buttons
    st.markdown("### 📄 Available Downloads")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.download_button(
            label="📄 Completed Report",
            data=final_report,
            file_name=f"triaging_report_{session_state.selected_alert.get('incident')}.txt",
            mime="text/plain",
            width="stretch",
            help="Download the completed investigation report with all findings",
        )

    with col2:
        if session_state.excel_template_data:
            st.download_button(
                label="📊 Excel Template",
                data=session_state.excel_template_data,
                file_name=f"triaging_template_{session_state.selected_alert.get('rule').replace('#', '_')}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                width="stretch",
                help="Download professionally formatted Excel template with all investigation steps, KQL queries, and expected outputs",
            )
        else:
            st.button(
                "📊 Excel Template",
                disabled=True,
                width="stretch",
                help="Excel template generation failed",
            )

    with col3:
        st.download_button(
            label="📝 CSV Template",
            data=csv_template,
            file_name=f"triaging_template_{session_state.selected_alert.get('rule').replace('#', '_')}.csv",
            mime="text/csv",
            width="stretch",
            help="Download CSV template with all investigation details for manual use",
        )

    with col4:
        json_export = {
            "incident": session_state.consolidated_data,
            "investigation": session_state.triaging_output,
            "prediction": (
                session_state.predictions[0] if session_state.predictions else {}
            ),
            "rule_history": session_state.rule_history,
            "progressive_predictions": session_state.progressive_predictions,
        }

        st.download_button(
            label="📊 JSON Data",
            data=json.dumps(json_export, indent=2),
            file_name=f"triaging_data_{session_state.selected_alert.get('incident')}.json",
            mime="application/json",
            width="stretch",
            help="Download structured data in JSON format for integration",
        )

    # Preview tabs
    with st.expander("👀 Preview Templates & Reports", expanded=False):
        tab1, tab2, tab3 = st.tabs(
            ["Completed Report", "CSV Template", "Excel Preview"]
        )

        with tab1:
            st.text(final_report)

        with tab2:
            st.text(csv_template)

        with tab3:
            if session_state.excel_template_data:
                st.success("✅ Excel template generated successfully!")
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
                step_count = len(session_state.triaging_plan)
                st.metric("Total Investigation Steps", step_count)

                # Show steps with KQL queries
                kql_steps = [
                    s for s in session_state.triaging_plan if s.get("kql_query")
                ]
                st.metric("Steps with KQL Queries", len(kql_steps))
            else:
                st.error("Excel template not available")

    st.markdown("---")
    st.markdown("### 📜 Template Details")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Investigation Steps",
            len(session_state.triaging_plan),
            help="Number of AI-generated investigation steps",
        )

    with col2:
        kql_count = len(
            [s for s in session_state.triaging_plan if s.get("kql_query")]
        )
        st.metric(
            "KQL Queries Included", kql_count, help="Number of steps with KQL queries"
        )

    with col3:
        expected_count = len(
            [s for s in session_state.triaging_plan if s.get("expected_output")]
        )
        st.metric(
            "Expected Outputs",
            expected_count,
            help="Steps with expected output guidance",
        )

    st.markdown("---")

    if st.button("🔄 Start New Triaging", type="primary", width="stretch"):
        for key in list(session_state.keys()):
            if key != "all_data":
                del session_state[key]
        st.session_state.initialize_session_state()
        st.rerun()