# step2_enhance.py - OPTIMIZED VERSION

import streamlit as st
import os
import re
import json
import time
import traceback
import hashlib


def _get_enhancement_cache_key(rule_number: str, template_path: str) -> str:
    """Create unique cache key for template enhancement"""
    return f"enhanced_template_{rule_number}_{hashlib.md5(template_path.encode()).hexdigest()}"


def show_page(session_state, TemplateParser, WebLLMEnhancer, EnhancedTemplateGenerator):
    st.markdown(
        '<div class="step-header"><h2>Step 2: Template Enhancement & Generation</h2></div>',
        unsafe_allow_html=True,
    )

    # Get alert information with fallback
    selected_alert = getattr(session_state, "triaging_selected_alert", None)
    if selected_alert is None:
        st.error("❌ No alert selected. Please go back and select an incident.")
        return

    selected_incident = selected_alert.get("incident", "Unknown")
    rule_number = selected_alert.get(
        "rule_number", selected_alert.get("rule", "Unknown")
    )

    col1, col2 = st.columns(2)
    with col1:
        st.info(f"**Selected Rule:** {rule_number}")
    with col2:
        st.info(f"**Incident Number:** {selected_incident}")

    # Extract rule number for file matching
    rule_num_match = re.search(r"#?(\d+)", rule_number)
    rule_num = (
        rule_num_match.group(1)
        if rule_num_match
        else rule_number.replace("#", "").strip()
    )

    # Find template
    template_dir = "data/triaging_templates"

    if not os.path.exists(template_dir):
        st.warning(f"⚠️ Template directory not found: {template_dir}")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("📁 Create Template Directory", type="primary"):
                os.makedirs(template_dir, exist_ok=True)
                st.success("✅ Directory created! Please upload templates and retry.")
                st.stop()
        with col2:
            if st.button("⬅️ Go Back"):
                session_state.triaging_step = 1
                st.rerun()
        st.stop()

    all_files = os.listdir(template_dir)
    template_files = [
        f
        for f in all_files
        if rule_num in f and (f.endswith(".csv") or f.endswith(".xlsx"))
    ]

    if not template_files:
        st.error(f"❌ No template found for {rule_number}")
        st.info(f"🔍 Looking for files containing '{rule_num}' in: {template_dir}")
        with st.expander("Available Templates", expanded=True):
            if all_files:
                st.write("Found templates:")
                for f in all_files:
                    st.write(f"- {f}")
            else:
                st.write("No templates found in directory")
        if st.button("⬅️ Go Back"):
            session_state.triaging_step = 1
            st.rerun()
        st.stop()

    template_path = os.path.join(template_dir, template_files[0])

    # ✅ CREATE CACHE KEY FOR THIS TEMPLATE
    cache_key = _get_enhancement_cache_key(rule_number, template_path)

    # ✅ CHECK IF ENHANCEMENT ALREADY EXISTS
    if cache_key in st.session_state:
        st.success(f"✅ Using cached enhancement for: {template_files[0]}")

        # Restore cached data
        cached_data = st.session_state[cache_key]
        session_state.original_steps = cached_data["original_steps"]
        session_state.enhanced_steps = cached_data["enhanced_steps"]
        session_state.validation_report = cached_data["validation_report"]
        session_state.excel_template_data = cached_data["excel_template_data"]

        # Display cached results (skip to display section)
        _display_enhancement_results(
            session_state,
            template_files[0],
            rule_number,
            cached_data["elapsed_time"],
            EnhancedTemplateGenerator,
            WebLLMEnhancer,
        )
        return

    # ✅ IF NOT CACHED, RUN ENHANCEMENT (ONLY ONCE)
    st.info(f"🔄 Processing template: {template_files[0]}")

    progress_bar = st.progress(0, text="Initializing...")
    status_text = st.empty()

    with st.spinner("Processing..."):
        try:
            # STEP 1: Parse Template
            status_text.text("📋 Extracting original steps from template...")
            progress_bar.progress(20, text="Parsing template...")

            parser = TemplateParser()

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

            st.success(
                f"✅ Extracted {len(original_steps)} original steps from template"
            )
            progress_bar.progress(40, text="Steps extracted...")

            # STEP 2: Enhancement with Validation
            status_text.text(
                "🔧 Enhancing explanations + validating KQL (parallel processing)..."
            )
            progress_bar.progress(60, text="Enhancing with validation...")

            enhancer = WebLLMEnhancer()
            start_time = time.time()

            st.info(
                "⚡ Processing with validation: Names preserved, Explanations enhanced, KQL validated..."
            )

            # Enhance with validation
            enhanced_steps = enhancer.enhance_template_steps(
                rule_number=rule_number,
                original_steps=original_steps,
            )

            elapsed = time.time() - start_time

            # Run validation report
            validation_report = enhancer.validate_enhanced_steps(
                original_steps, enhanced_steps
            )

            progress_bar.progress(80, text="Generating Excel...")

            # STEP 3: Generate Excel Template
            status_text.text("📊 Generating Excel template...")

            template_gen = EnhancedTemplateGenerator()
            template_df = template_gen.generate_clean_template(
                rule_number=rule_number, enhanced_steps=enhanced_steps
            )

            # Fix PyArrow error
            template_df["Step"] = template_df["Step"].astype(str)

            excel_file = template_gen.export_to_excel(template_df, rule_number)

            # ✅ CACHE ALL RESULTS
            st.session_state[cache_key] = {
                "original_steps": original_steps,
                "enhanced_steps": enhanced_steps,
                "validation_report": validation_report,
                "excel_template_data": excel_file,
                "elapsed_time": elapsed,
            }

            # Store in session state for current use
            session_state.original_steps = original_steps
            session_state.enhanced_steps = enhanced_steps
            session_state.validation_report = validation_report
            session_state.excel_template_data = excel_file

            progress_bar.progress(100, text="✅ Complete!")
            status_text.text("✅ Template generation complete!")

            # Clear progress indicators
            time.sleep(1)
            progress_bar.empty()
            status_text.empty()

            # Display results
            _display_enhancement_results(
                session_state,
                template_files[0],
                rule_number,
                elapsed,
                EnhancedTemplateGenerator,
                WebLLMEnhancer,
            )

        except Exception as e:
            progress_bar.empty()
            status_text.empty()
            st.error(f"❌ Error: {str(e)}")
            with st.expander("View Error Details"):
                st.code(traceback.format_exc())

            if st.button("⬅️ Go Back"):
                session_state.triaging_step = 1
                session_state.triaging_initialized = False
                st.rerun()


def _display_enhancement_results(
    session_state,
    template_filename,
    rule_number,
    elapsed_time,
    EnhancedTemplateGenerator,
    WebLLMEnhancer,
):
    """Display enhancement results (separated to avoid code duplication)"""

    original_steps = session_state.original_steps
    enhanced_steps = session_state.enhanced_steps
    validation_report = session_state.validation_report

    st.success(
        f"✅ Enhanced and validated {len(enhanced_steps)} steps in {elapsed_time:.1f}s"
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
        st.metric("Explanations Enhanced", validation_report["explanations_improved"])

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

    st.markdown("---")
    st.markdown("### 📋 Enhanced Template Preview")

    # Generate template_df for display
    template_gen = EnhancedTemplateGenerator()
    template_df = template_gen.generate_clean_template(
        rule_number=rule_number, enhanced_steps=enhanced_steps
    )
    template_df["Step"] = template_df["Step"].astype(str)

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
        st.dataframe(template_df, use_container_width=True, height=400)

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Steps", len(enhanced_steps))
        with col2:
            kql_count = len([s for s in enhanced_steps if s.get("kql_query")])
            st.metric("Relevant KQL", kql_count)
        with col3:
            exp_count = len(
                [s for s in enhanced_steps if len(s.get("explanation", "")) > 30]
            )
            st.metric("Quality Explanations", exp_count)

    with tab2:
        st.markdown("### 📊 Before/After Enhancement")

        for i, (original, enhanced) in enumerate(
            zip(original_steps, enhanced_steps), 1
        ):
            with st.expander(f"Step {i}: {original.get('step_name')}", expanded=False):
                # Validation status
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
                        enhancer = WebLLMEnhancer()
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

    with tab3:
        st.markdown("### 🔍 Detailed Validation Report")

        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**✅ Passed Checks:**")
            st.markdown(
                f"- Names Preserved: {validation_report['names_preserved']}/{validation_report['total_original']}"
            )
            st.markdown(
                f"- Explanations Improved: {validation_report['explanations_improved']}"
            )
            st.markdown(f"- KQL Queries Relevant: {validation_report['kql_relevant']}")

        with col2:
            st.markdown("**⚠️ Issues Found:**")
            st.markdown(f"- Prompt Leaks: {validation_report['prompt_leaks_found']}")
            st.markdown(f"- KQL Removed: {validation_report['kql_removed']}")
            st.markdown(f"- Total Issues: {len(validation_report['issues'])}")

        if validation_report["issues"]:
            st.markdown("---")
            st.markdown("**Issue Details:**")
            for i, issue in enumerate(validation_report["issues"], 1):
                st.markdown(f"{i}. {issue}")
        else:
            st.success("🎉 No validation issues found!")

    with tab4:
        st.markdown("### 📝 All Enhanced Steps")
        for i, step in enumerate(enhanced_steps, 1):
            with st.expander(f"Step {i}: {step.get('step_name')}", expanded=False):
                st.markdown(f"**Explanation:** {step.get('explanation')}")
                st.markdown(f"**Input Required:** {step.get('input_required')}")
                if step.get("kql_query"):
                    st.markdown("**KQL Query:**")
                    st.code(step.get("kql_query"), language="kql")

    with tab5:
        st.markdown("### 🔎 Validated KQL Queries Only")
        enhancer = WebLLMEnhancer()
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
                    "✅ Validated" if is_relevant else "⚠️ Warning: May not be relevant"
                )
                st.markdown(f"**Step {i}: {step.get('step_name')}** - {status}")
                st.code(step.get("kql_query"), language="kql")
                st.markdown("---")

        if not kql_found:
            st.info("No KQL queries found in enhanced template")

    # Download Options
    st.markdown("---")
    st.markdown("### 📥 Download Enhanced Template")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.download_button(
            label="📊 Download Excel Template",
            data=session_state.excel_template_data,
            file_name=f"triaging_template_{rule_number.replace('#', '_')}_enhanced.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            use_container_width=True,
            type="primary",
        )

    with col2:
        json_export = {
            "rule": rule_number,
            "total_steps": len(enhanced_steps),
            "steps": enhanced_steps,
            "validation": validation_report,
            "metadata": {
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "enhancement_time_seconds": elapsed_time,
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
            use_container_width=True,
        )

    with col3:
        kql_export = "\n\n".join(
            [
                f"-- Step {i}: {step.get('step_name')}\n{step.get('kql_query')}"
                for i, step in enumerate(enhanced_steps, 1)
                if step.get("kql_query")
            ]
        )
        if kql_export:
            st.download_button(
                label="🔎 Download KQL Queries",
                data=kql_export,
                file_name=f"kql_queries_{rule_number.replace('#', '_')}_validated.kql",
                mime="text/plain",
                use_container_width=True,
            )
        else:
            st.button("🔎 No KQL Queries", disabled=True, use_container_width=True)

    # Navigation
    st.markdown("---")
    col1, col2, col3 = st.columns([1, 2, 1])

    with col1:
        if st.button("⬅️ Back to Alerts"):
            session_state.triaging_step = 1
            session_state.triaging_initialized = False
            st.rerun()

    with col3:
        if st.button("🔄 Start New Search", type="primary", use_container_width=True):
            # Clear triaging-related state
            for key in list(session_state.keys()):
                if key.startswith("triaging_") or key in [
                    "template_content",
                    "progressive_predictions",
                    "rule_history",
                    "excel_template_data",
                    "original_steps",
                    "enhanced_steps",
                    "validation_report",
                ]:
                    del session_state[key]
            st.rerun()
