# step3_walkthrough.py

import streamlit as st


def show_page(session_state, crew, traceback):
    st.markdown(
        '<div class="step-header"><h2>Step 4: AI-Powered Triaging Walkthrough</h2></div>',
        unsafe_allow_html=True,
    )

    st.markdown(f"**Alert:** {session_state.selected_alert.get('description', 'N/A')}")

    if session_state.triaging_plan is None:
        st.markdown("### 🧠 AI Agents are Analyzing...")

        analysis_status = st.empty()
        analysis_progress = st.progress(0)

        with st.spinner("This may take 30-60 seconds..."):
            try:
                analysis_status.info(
                    "🤖 AI is learning from historical data and templates..."
                )
                analysis_progress.progress(20)

                result = crew.run_analysis_phase(
                    consolidated_data=session_state.consolidated_data,
                    template_content=session_state.template_content,
                    rule_number=session_state.selected_alert.get("rule"),
                )

                analysis_progress.progress(80)
                analysis_status.info("📜 Generating triaging plan and predictions...")

                session_state.triaging_plan = result["triaging_plan"]
                session_state.predictions = result["predictions"]
                session_state.progressive_predictions = result.get(
                    "progressive_predictions", {}
                )
                session_state.rule_history = result.get("rule_history", {})
                session_state.current_step_index = 0

                analysis_progress.progress(100)
                analysis_status.success("✅ AI analysis complete!")

                st.rerun()

            except Exception as e:
                analysis_progress.empty()
                analysis_status.error(f"❌ Error in AI analysis: {str(e)}")
                with st.expander("View Error Details"):
                    st.code(traceback.format_exc())

                st.warning("⚠️ Using fallback triaging plan...")
                session_state.triaging_plan = crew._create_fallback_steps()
                session_state.predictions = crew._create_minimal_prediction(
                    session_state.consolidated_data
                )
                session_state.progressive_predictions = {}
                session_state.rule_history = {}
                st.rerun()

    current_step_index = session_state.current_step_index
    total_steps = len(session_state.triaging_plan)

    if total_steps == 0:
        st.error("❌ No triaging steps generated. Please try again.")
        if st.button("← Go Back"):
            session_state.step = 2
            session_state.triaging_plan = None
            st.rerun()
        st.stop()

    progress_percentage = (current_step_index / total_steps) if total_steps > 0 else 0
    st.progress(
        progress_percentage,
        text=f"Progress: Step {current_step_index + 1} of {total_steps}",
    )

    if current_step_index < total_steps:
        current_step = session_state.triaging_plan[current_step_index]

        # Display the formatted step
        st.markdown(f"***")
        st.markdown(f"### {current_step_index + 1}. {current_step.get('step_name')} 🔍")
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
        if session_state.progressive_predictions:
            step_name = current_step.get("step_name", "")
            current_prog = session_state.progressive_predictions.get(step_name, {})

            if current_prog:
                st.markdown(
                    '<div class="progressive-prediction">', unsafe_allow_html=True
                )
                st.markdown("### 📊 Progressive Analysis (Updated After Each Step)")

                col1, col2, col3 = st.columns(3)

                with col1:
                    fp_prob = current_prog.get("false_positive_probability", 50)
                    delta_fp = fp_prob - session_state.rule_history.get("fp_rate", 50)
                    st.metric(
                        "False Positive Likelihood",
                        f"{fp_prob:.1f}%",
                        delta=f"{delta_fp:+.1f}% from baseline",
                        delta_color="normal",
                    )

                with col2:
                    tp_prob = current_prog.get("true_positive_probability", 50)
                    delta_tp = tp_prob - session_state.rule_history.get("tp_rate", 50)
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
        if session_state.predictions:
            with st.expander("🔮 AI Final Prediction & Guidance", expanded=False):
                prediction = session_state.predictions[0]

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
        st.markdown("### ✍️ Your Findings")

        user_input = st.text_area(
            f"Document your findings for this step:",
            height=150,
            key=f"input_{current_step_index}",
            placeholder="Enter your investigation findings, observations, and any relevant details...",
        )

        col1, col2, col3 = st.columns([1, 1, 3])

        with col1:
            if current_step_index > 0:
                if st.button("← Previous"):
                    session_state.current_step_index -= 1
                    st.rerun()

        with col2:
            if st.button("Next Step ➡️", type="primary"):
                if user_input.strip():
                    session_state.triaging_output[current_step.get("step_name")] = (
                        user_input
                    )
                    session_state.current_step_index += 1
                    st.rerun()
                else:
                    st.warning("⚠️ Please enter your findings before proceeding.")

        with col3:
            if st.button(
                "⏹️ Skip to End", help="Skip remaining steps and go to summary"
            ):
                for remaining_step in session_state.triaging_plan[current_step_index:]:
                    step_name = remaining_step.get("step_name", "Unknown Step")
                    if step_name not in session_state.triaging_output:
                        session_state.triaging_output[step_name] = "[Skipped]"
                session_state.step = 4
                st.rerun()

    else:
        session_state.step = 4
        st.rerun()
