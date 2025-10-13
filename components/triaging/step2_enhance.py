# step2_enhance.py

import streamlit as st
import os
import re
import json
import time
import traceback  # Added for error logging


def show_page(session_state, TemplateParser, WebLLMEnhancer, EnhancedTemplateGenerator):
    st.markdown(
        '<div class="step-header"><h2>Step 3: Template Enhancement & Generation</h2></div>',
        unsafe_allow_html=True,
    )

    selected_incident = session_state.selected_alert.get("incident")
    rule_number = session_state.selected_alert.get("rule")

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

            if not os.path.exists(template_dir):
                st.warning(f"⚠️ Template directory not found: {template_dir}")
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("📁 Create Template Directory", type="primary"):
                        os.makedirs(template_dir, exist_ok=True)
                        st.success(
                            "✅ Directory created! Please upload templates and retry."
                        )
                        st.stop()
                with col2:
                    if st.button("⬅️ Go Back"):
                        session_state.step = 1
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
                    session_state.step = 1
                    st.rerun()
                st.stop()

            template_path = os.path.join(template_dir, template_files[0])
            st.success(f"✅ Found template: {template_files[0]}")

            # STEP 2: Parse Template - GET ORIGINAL STEPS (NO MODIFICATION)
            status_text.text("📋 Extracting original steps from template...")
            progress_bar.progress(40, text="Parsing template...")

            if template_path.endswith(".csv"):
                original_steps = parser.parse_csv_template(template_path)
            else:
                original_steps = parser.parse_excel_template(template_path)

            if not original_steps:
                st.warning("⚠️ Template parsing returned no steps. Using fallback.")
                original_steps = [
                    {
                        "step_name": "Review Alert Details",
                        "explanation": "Gather incident information and review basic alert metadata",
                        "input_required": "Incident number, timestamp",
                        "kql_query": "",
                    }
                ]

            # ✅ SHOW ORIGINAL STEPS AS-IS
            st.success(
                f"✅ Extracted {len(original_steps)} original steps from template"
            )

            with st.expander("📋 View Original Steps (Unmodified)", expanded=False):
                for i, step in enumerate(original_steps, 1):
                    st.markdown(f"**{i}. {step.get('step_name')}**")
                    st.markdown(f"- **Explanation:** {step.get('explanation', 'N/A')}")
                    st.markdown(
                        f"- **Input Required:** {step.get('input_required', 'N/A')}"
                    )
                    st.markdown(
                        f"- **Has KQL:** {'Yes' if step.get('kql_query') else 'No'}"
                    )
                    if step.get("kql_query"):
                        st.code(step.get("kql_query")[:200] + "...", language="kql")
                    st.markdown("---")

            # STEP 3: Enhancement (ONLY explanations, WITH validation)
            status_text.text(
                "🔧 Enhancing explanations + validating KQL (parallel processing)..."
            )
            progress_bar.progress(60, text="Enhancing with validation...")

            enhancer = WebLLMEnhancer()
            start_time = time.time()

            st.info(
                "⚡ Processing with validation: Names preserved, Explanations enhanced, KQL validated..."
            )

            # ✅ ENHANCE WITH VALIDATION
            enhanced_steps = enhancer.enhance_template_steps(
                rule_number=rule_number,
                original_steps=original_steps,
            )

            elapsed = time.time() - start_time

            # ✅ RUN VALIDATION REPORT
            validation_report = enhancer.validate_enhanced_steps(
                original_steps, enhanced_steps
            )
            enhancer.print_validation_report(validation_report)

            # ✅ SHOW VALIDATION RESULTS IN UI
            st.success(
                f"✅ Enhanced and validated {len(enhanced_steps)} steps in {elapsed:.1f}s"
            )

            # Validation metrics
            st.markdown("### 🔍 Quality Validation Results")

            col1, col2, col3, col4, col5 = st.columns(5)

            with col1:
                names_pct = (
                    (
                        validation_report["names_preserved"]
                        / validation_report["total_original"]
                        * 100
                    )
                    if validation_report["total_original"] > 0
                    else 0
                )
                st.metric(
                    "Names Preserved",
                    f"{names_pct:.0f}%",
                    delta="✅" if names_pct == 100 else "⚠️",
                )

            with col2:
                st.metric(
                    "Explanations Enhanced", validation_report["explanations_improved"]
                )

            with col3:
                st.metric(
                    "KQL Relevant",
                    validation_report["kql_relevant"],
                    delta=f"-{validation_report['kql_removed']} removed",
                )

            with col4:
                leak_status = (
                    "✅ Clean"
                    if validation_report["prompt_leaks_found"] == 0
                    else f"⚠️ {validation_report['prompt_leaks_found']} found"
                )
                st.metric("Prompt Leaks", leak_status)

            with col5:
                issue_status = (
                    "✅ None"
                    if len(validation_report["issues"]) == 0
                    else f"⚠️ {len(validation_report['issues'])}"
                )
                st.metric("Issues", issue_status)

            # Show issues if any
            if validation_report["issues"]:
                with st.expander("⚠️ View Validation Issues", expanded=True):
                    for issue in validation_report["issues"]:
                        st.warning(issue)

            # STEP 4: Generate Excel Template
            status_text.text("📊 Generating Excel template...")
            progress_bar.progress(80, text="Generating Excel...")

            template_gen = EnhancedTemplateGenerator()
            template_df = template_gen.generate_clean_template(
                rule_number=rule_number, enhanced_steps=enhanced_steps
            )

            # --- FIX: Ensure 'Step' column is a consistent type to avoid PyArrow error ---
            template_df["Step"] = template_df["Step"].astype(str)

            excel_file = template_gen.export_to_excel(template_df, rule_number)

            session_state.original_steps = original_steps  # Store for comparison
            session_state.enhanced_steps = enhanced_steps
            session_state.validation_report = validation_report
            session_state.excel_template_data = excel_file

            progress_bar.progress(100, text="✅ Complete!")
            status_text.text("✅ Template generation complete!")

            # STEP 5: Display with Before/After + Validation
            st.markdown("---")
            st.markdown("### 📋 Enhanced Template Preview")

            tab1, tab2, tab3, tab4, tab5 = st.tabs(
                [
                    "Excel Preview",
                    "Before/After Comparison",
                    "Validation Report",
                    "Steps Overview",
                    "KQL Queries",
                ]
            )

            with tab1:
                st.dataframe(template_df, width="stretch", height=400)

                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Steps", len(enhanced_steps))
                with col2:
                    kql_count = len([s for s in enhanced_steps if s.get("kql_query")])
                    st.metric("Relevant KQL", kql_count)
                with col3:
                    exp_count = len(
                        [
                            s
                            for s in enhanced_steps
                            if len(s.get("explanation", "")) > 30
                        ]
                    )
                    st.metric("Quality Explanations", exp_count)

            with tab2:
                st.markdown("### 📊 Before/After Enhancement")
                st.info("Shows original template vs enhanced version with validation")

                for i, (original, enhanced) in enumerate(
                    zip(original_steps, enhanced_steps), 1
                ):
                    with st.expander(
                        f"Step {i}: {original.get('step_name')}", expanded=False
                    ):

                        # Validation status for this step
                        step_issues = [
                            issue
                            for issue in validation_report["issues"]
                            if f"Step {i}" in issue
                        ]
                        if step_issues:
                            for issue in step_issues:
                                st.error(issue)
                        else:
                            st.success("✅ No issues")

                        col1, col2 = st.columns(2)

                        with col1:
                            st.markdown("**🔴 ORIGINAL**")
                            st.markdown(f"**Name:** {original.get('step_name')}")
                            st.text_area(
                                "Explanation",
                                value=original.get("explanation", "N/A"),
                                height=120,
                                disabled=True,
                                key=f"orig_exp_{i}",
                                label_visibility="collapsed",
                            )
                            if original.get("kql_query"):
                                st.code(original.get("kql_query")[:150], language="kql")
                            else:
                                st.info("No KQL")

                        with col2:
                            st.markdown("**🟢 ENHANCED**")
                            st.markdown(
                                f"**Name:** {enhanced.get('step_name')} {'✅' if original.get('step_name') == enhanced.get('step_name') else '⚠️ CHANGED'}"
                            )
                            st.text_area(
                                "Explanation",
                                value=enhanced.get("explanation", "N/A"),
                                height=120,
                                disabled=True,
                                key=f"enh_exp_{i}",
                                label_visibility="collapsed",
                            )
                            if enhanced.get("kql_query"):
                                kql_status = (
                                    "✅ Validated"
                                    if enhancer._is_kql_relevant(
                                        enhanced.get("kql_query"),
                                        enhanced.get("step_name"),
                                        enhanced.get("explanation"),
                                    )
                                    else "⚠️ Not Relevant"
                                )
                                st.markdown(f"**KQL Status:** {kql_status}")
                                st.code(enhanced.get("kql_query")[:150], language="kql")
                            else:
                                st.info(
                                    "No KQL"
                                    if not original.get("kql_query")
                                    else "❌ KQL Removed (not relevant)"
                                )

                        # Show changes
                        changes = []
                        if original.get("step_name") != enhanced.get("step_name"):
                            changes.append("⚠️ Step name changed (should be preserved)")
                        if len(enhanced.get("explanation", "")) > len(
                            original.get("explanation", "")
                        ):
                            changes.append("📝 Explanation enhanced")
                        if not enhanced.get("kql_query") and original.get("kql_query"):
                            changes.append("🗑️ KQL removed (validation failed)")
                        if enhanced.get("kql_query") and not original.get("kql_query"):
                            changes.append("➕ KQL added")

                        if changes:
                            st.markdown("**Changes:**")
                            for change in changes:
                                st.markdown(f"- {change}")

            with tab3:
                st.markdown("### 🔍 Detailed Validation Report")

                # Summary
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("**✅ Passed Checks:**")
                    st.markdown(
                        f"- Names Preserved: {validation_report['names_preserved']}/{validation_report['total_original']}"
                    )
                    st.markdown(
                        f"- Explanations Improved: {validation_report['explanations_improved']}"
                    )
                    st.markdown(
                        f"- KQL Queries Relevant: {validation_report['kql_relevant']}"
                    )

                with col2:
                    st.markdown("**⚠️ Issues Found:**")
                    st.markdown(
                        f"- Prompt Leaks: {validation_report['prompt_leaks_found']}"
                    )
                    st.markdown(f"- KQL Removed: {validation_report['kql_removed']}")
                    st.markdown(f"- Total Issues: {len(validation_report['issues'])}")

                # Detailed issues
                if validation_report["issues"]:
                    st.markdown("---")
                    st.markdown("**Issue Details:**")
                    for i, issue in enumerate(validation_report["issues"], 1):
                        st.markdown(f"{i}. {issue}")
                else:
                    st.success(
                        "🎉 No validation issues found! All steps are correctly processed."
                    )

            with tab4:
                st.markdown("### 📝 All Enhanced Steps")
                for i, step in enumerate(enhanced_steps, 1):
                    with st.expander(
                        f"Step {i}: {step.get('step_name')}", expanded=False
                    ):
                        st.markdown(f"**Explanation:** {step.get('explanation')}")
                        st.markdown(f"**Input Required:** {step.get('input_required')}")
                        if step.get("kql_query"):
                            st.markdown("**KQL Query:**")
                            st.code(step.get("kql_query"), language="kql")

            with tab5:
                st.markdown("### 🔍 Validated KQL Queries Only")
                kql_found = False
                for i, step in enumerate(enhanced_steps, 1):
                    if step.get("kql_query"):
                        kql_found = True
                        is_relevant = enhancer._is_kql_relevant(
                            step.get("kql_query"),
                            step.get("step_name"),
                            step.get("explanation"),
                        )

                        status = (
                            "✅ Validated"
                            if is_relevant
                            else "⚠️ Warning: May not be relevant"
                        )
                        st.markdown(f"**Step {i}: {step.get('step_name')}** - {status}")
                        st.code(step.get("kql_query"), language="kql")
                        st.markdown("---")

                if not kql_found:
                    st.info("No KQL queries found in enhanced template")

            # STEP 6: Download Options
            st.markdown("---")
            st.markdown("### 📥 Download Enhanced Template")

            col1, col2, col3 = st.columns(3)

            with col1:
                st.download_button(
                    label="📊 Download Excel Template",
                    data=session_state.excel_template_data,
                    file_name=f"triaging_template_{rule_number.replace('#', '_')}_enhanced.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    width="stretch",
                    type="primary",
                )

            with col2:
                # JSON export with validation report
                json_export = {
                    "rule": rule_number,
                    "total_steps": len(enhanced_steps),
                    "steps": enhanced_steps,
                    "validation": validation_report,
                    "metadata": {
                        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "enhancement_time_seconds": elapsed,
                        "names_preserved": validation_report["names_preserved"]
                        == validation_report["total_original"],
                        "all_kql_validated": validation_report["kql_removed"] == 0,
                    },
                }
                st.download_button(
                    label="📄 Download JSON + Validation",
                    data=json.dumps(json_export, indent=2),
                    file_name=f"triaging_template_{rule_number.replace('#', '_')}_validated.json",
                    mime="application/json",
                    width="stretch",
                )

            with col3:
                # KQL-only export (validated queries only)
                kql_export = "\n\n".join(
                    [
                        f"-- Step {i}: {step.get('step_name')}\n-- Status: {'Validated' if enhancer._is_kql_relevant(step.get('kql_query'), step.get('step_name'), step.get('explanation')) else 'Warning: Check relevance'}\n{step.get('kql_query')}"
                        for i, step in enumerate(enhanced_steps, 1)
                        if step.get("kql_query")
                    ]
                )
                if kql_export:
                    st.download_button(
                        label="🔍 Download KQL Queries",
                        data=kql_export,
                        file_name=f"kql_queries_{rule_number.replace('#', '_')}_validated.kql",
                        mime="text/plain",
                        width="stretch",
                    )
                else:
                    st.button("🔍 No KQL Queries", disabled=True, width="stretch")

            st.markdown("---")

            # Final quality metrics
            st.markdown("### 📈 Final Quality Metrics")

            col1, col2, col3, col4 = st.columns(4)

            with col1:
                preservation_rate = (
                    (
                        validation_report["names_preserved"]
                        / validation_report["total_original"]
                        * 100
                    )
                    if validation_report["total_original"] > 0
                    else 0
                )
                st.metric(
                    "Name Preservation",
                    f"{preservation_rate:.0f}%",
                    help="Percentage of original step names preserved",
                )

            with col2:
                improvement_rate = (
                    (
                        validation_report["explanations_improved"]
                        / len(enhanced_steps)
                        * 100
                    )
                    if enhanced_steps
                    else 0
                )
                st.metric(
                    "Explanation Enhancement",
                    f"{improvement_rate:.0f}%",
                    help="Percentage of explanations improved",
                )

            with col3:
                if (
                    validation_report["kql_relevant"] + validation_report["kql_removed"]
                    > 0
                ):
                    relevance_rate = (
                        validation_report["kql_relevant"]
                        / (
                            validation_report["kql_relevant"]
                            + validation_report["kql_removed"]
                        )
                        * 100
                    )
                else:
                    relevance_rate = 100
                st.metric(
                    "KQL Relevance",
                    f"{relevance_rate:.0f}%",
                    help="Percentage of KQL queries that passed validation",
                )

            with col4:
                quality_score = (
                    preservation_rate + improvement_rate + relevance_rate
                ) / 3
                st.metric(
                    "Overall Quality Score",
                    f"{quality_score:.0f}%",
                    help="Combined quality metric",
                )

            # Navigation
            st.markdown("---")
            col1, col2, col3 = st.columns([1, 2, 1])

            with col1:
                if st.button("⬅️ Back to Alerts"):
                    session_state.step = 1
                    st.rerun()

            with col3:
                if st.button("🔄 Start New Search", type="primary", width="stretch"):
                    for key in list(session_state.keys()):
                        if key != "all_data":
                            del session_state[key]
                    st.session_state.initialize_session_state()
                    st.rerun()

        except Exception as e:
            progress_bar.empty()
            status_text.empty()
            st.error(f"❌ Error: {str(e)}")
            with st.expander("View Error Details"):
                st.code(traceback.format_exc())

            if st.button("⬅️ Go Back"):
                session_state.step = 1
                st.rerun()
