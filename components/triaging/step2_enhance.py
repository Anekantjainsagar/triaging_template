# step2_enhance.py - FIXED DUPLICATE GENERATION

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
        '<div class="step-header"><h2>Step 2: Fast AI Template Enhancement</h2></div>',
        unsafe_allow_html=True,
    )

    st.info(
        "🚀 Parallel processing with LLM + Web Intelligence for fast, professional templates"
    )

    # Get alert information
    selected_alert = session_state.get("triaging_selected_alert", None)

    if selected_alert is None:
        rule_number = session_state.get("triaging_rule_number", None)
        if rule_number:
            st.warning("⚠️ Alert object reconstructed...")
            selected_alert = {
                "rule": rule_number,
                "rule_number": rule_number,
                "incident": f"TEMPLATE_GEN_{rule_number}",
                "description": f"Template Generation for Rule {rule_number}",
            }
            session_state["triaging_selected_alert"] = selected_alert
        else:
            st.error("❌ No alert selected. Please go back and select an incident.")
            return

    rule_number = selected_alert.get(
        "rule_number", selected_alert.get("rule", "Unknown")
    )

    col1, col2 = st.columns(2)
    with col1:
        st.info(f"**Selected Rule:** {rule_number}")
    with col2:
        st.info(f"**Mode:** Fast Enhancement")

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
                st.success("✅ Directory created! Please upload templates.")
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

    # ✅ CREATE CACHE KEY
    cache_key = _get_enhancement_cache_key(rule_number, template_path)

    # ✅ CHECK CACHE FIRST
    if cache_key in st.session_state:
        st.success(f"⚡ Using cached enhancement for: {template_files[0]}")

        cached_data = st.session_state[cache_key]
        session_state.original_steps = cached_data["original_steps"]
        session_state.enhanced_steps = cached_data["enhanced_steps"]
        session_state.validation_report = cached_data["validation_report"]
        session_state.excel_template_data = cached_data["excel_template_data"]
        # ✅ FIX #4: STORE PRE-GENERATED DATAFRAME
        session_state.template_dataframe = cached_data["template_dataframe"]

        _display_enhancement_results(
            session_state,
            template_files[0],
            rule_number,
            cached_data["elapsed_time"],
            EnhancedTemplateGenerator,
        )
        return

    # ✅ RUN ENHANCEMENT (ONLY ONCE)
    st.info(f"📄 Processing template: {template_files[0]}")

    # Create progress tracking
    progress_container = st.container()

    with progress_container:
        progress_bar = st.progress(0)
        status_text = st.empty()
        step_status = st.empty()

    try:
        # STEP 1: Parse Template
        status_text.text("📋 Parsing original template...")
        progress_bar.progress(10)

        parser = TemplateParser()

        if template_path.endswith(".csv"):
            original_steps = parser.parse_csv_template(template_path)
        else:
            original_steps = parser.parse_excel_template(template_path)

        if not original_steps:
            st.error("❌ Template parsing failed - no steps extracted")
            st.stop()

        st.success(f"✅ Extracted {len(original_steps)} original steps")
        progress_bar.progress(20)

        # STEP 2: FAST Enhancement with Parallel Processing
        status_text.text("🚀 Enhancing with parallel AI processing...")
        step_status.info(f"⚡ Processing {len(original_steps)} steps in parallel...")
        progress_bar.progress(30)

        enhancer = WebLLMEnhancer()
        start_time = time.time()

        # This now runs in PARALLEL
        enhanced_steps = enhancer.enhance_template_steps(
            rule_number=rule_number,
            original_steps=original_steps,
        )

        elapsed = time.time() - start_time

        progress_bar.progress(60)
        st.success(f"⚡ Enhanced {len(enhanced_steps)} steps in {elapsed:.1f}s")

        # Get validation report
        validation_report = enhancer.validate_enhanced_steps(
            original_steps, enhanced_steps
        )

        progress_bar.progress(70)

        # STEP 3: Generate Professional Excel Template
        status_text.text("📊 Generating professional Excel template...")
        progress_bar.progress(80)

        template_gen = EnhancedTemplateGenerator()

        # ✅ FIX #4: GENERATE DATAFRAME ONLY ONCE HERE
        template_df = template_gen.generate_clean_template(
            rule_number=rule_number, enhanced_steps=enhanced_steps
        )

        # Fix PyArrow error
        template_df["Step"] = template_df["Step"].astype(str)

        excel_file = template_gen.export_to_excel(template_df, rule_number)

        progress_bar.progress(95)

        # ✅ CACHE ALL RESULTS INCLUDING DATAFRAME
        st.session_state[cache_key] = {
            "original_steps": original_steps,
            "enhanced_steps": enhanced_steps,
            "validation_report": validation_report,
            "excel_template_data": excel_file,
            "template_dataframe": template_df,  # ✅ CACHE THE DF
            "elapsed_time": elapsed,
        }

        # Store in session state
        session_state.original_steps = original_steps
        session_state.enhanced_steps = enhanced_steps
        session_state.validation_report = validation_report
        session_state.excel_template_data = excel_file
        session_state.template_dataframe = template_df  # ✅ STORE DF

        progress_bar.progress(100)
        status_text.text("✅ Enhancement complete!")

        # Clear progress
        time.sleep(0.5)
        progress_bar.empty()
        status_text.empty()
        step_status.empty()

        # Display results
        _display_enhancement_results(
            session_state,
            template_files[0],
            rule_number,
            elapsed,
            EnhancedTemplateGenerator,
        )

    except Exception as e:
        progress_bar.empty()
        status_text.empty()
        step_status.empty()

        st.error(f"❌ Error: {str(e)}")

        with st.expander("🔍 View Error Details"):
            st.code(traceback.format_exc())

        if st.button("⬅️ Go Back"):
            session_state.triaging_step = 1
            st.rerun()


def _display_enhancement_results(
    session_state,
    template_filename,
    rule_number,
    elapsed_time,
    EnhancedTemplateGenerator,
):
    """Display enhancement results"""

    original_steps = session_state.original_steps
    enhanced_steps = session_state.enhanced_steps
    validation_report = session_state.validation_report

    st.success(
        f"✅ Generated professional template with {len(enhanced_steps)} steps in {elapsed_time:.1f}s"
    )

    # Validation metrics
    st.markdown("### 📊 Enhancement Quality Report")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Steps Processed", validation_report["total_enhanced"], delta="✅")

    with col2:
        improved = validation_report["names_improved"]
        kept = validation_report["names_kept"]
        st.metric("Step Names", f"{improved} improved", delta=f"{kept} kept")

    with col3:
        enhanced_exp = validation_report["explanations_enhanced"]
        kept_exp = validation_report["explanations_kept"]
        st.metric("Explanations", f"{enhanced_exp} enhanced", delta=f"{kept_exp} kept")

    with col4:
        cleaned = validation_report.get("kql_cleaned", 0)
        st.metric("KQL Queries", f"{cleaned} cleaned", delta="✅")

    # Show issues if any
    if validation_report.get("issues"):
        with st.expander("⚠️ View Enhancement Issues", expanded=False):
            for issue in validation_report["issues"]:
                st.warning(issue)

    st.markdown("---")
    st.markdown("### 📋 Enhanced Template Preview")

    # ✅ FIX #4: USE CACHED DATAFRAME - NO REGENERATION
    if (
        hasattr(session_state, "template_dataframe")
        and session_state.template_dataframe is not None
    ):
        template_df = session_state.template_dataframe
    else:
        # Fallback: generate if not cached (shouldn't happen)
        template_gen = EnhancedTemplateGenerator()
        template_df = template_gen.generate_clean_template(
            rule_number=rule_number, enhanced_steps=enhanced_steps
        )
        template_df["Step"] = template_df["Step"].astype(str)
        session_state.template_dataframe = template_df

    tab1, tab2, tab3 = st.tabs(
        ["📊 Final Template", "📄 Before/After", "📈 Validation"]
    )

    with tab1:
        st.dataframe(template_df, width="stretch", height=500)

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Steps", len(enhanced_steps))
        with col2:
            kql_count = len([s for s in enhanced_steps if s.get("kql_query")])
            st.metric("KQL Queries", kql_count)
        with col3:
            improved_names = validation_report["names_improved"]
            st.metric("Improved Names", improved_names)
        with col4:
            enhanced_exp = validation_report["explanations_enhanced"]
            st.metric("Enhanced Explanations", enhanced_exp)

    with tab2:
        st.markdown("### 📄 Before/After Enhancement")

        for i, (original, enhanced) in enumerate(
            zip(original_steps, enhanced_steps), 1
        ):
            with st.expander(f"Step {i}: {enhanced.get('step_name')}", expanded=False):

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

                with col2:
                    st.markdown("**🟢 ENHANCED**")
                    name_changed = original.get("step_name") != enhanced.get(
                        "step_name"
                    )
                    status = "✨ Improved" if name_changed else "✅ Kept"
                    st.markdown(f"**Name:** {enhanced.get('step_name')} ({status})")
                    st.text_area(
                        "Explanation",
                        value=enhanced.get("explanation", "N/A"),
                        height=120,
                        disabled=True,
                        key=f"enh_exp_{i}",
                        label_visibility="collapsed",
                    )

    with tab3:
        st.markdown("### 📈 Detailed Validation Report")

        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**✅ Enhancements:**")
            st.markdown(f"- Step Names Improved: {validation_report['names_improved']}")
            st.markdown(f"- Step Names Kept: {validation_report['names_kept']}")
            st.markdown(
                f"- Explanations Enhanced: {validation_report['explanations_enhanced']}"
            )
            st.markdown(
                f"- Explanations Kept: {validation_report['explanations_kept']}"
            )

        with col2:
            st.markdown("**🧹 Cleanup:**")
            st.markdown(
                f"- KQL Queries Cleaned: {validation_report.get('kql_cleaned', 0)}"
            )
            st.markdown(f"- Issues Found: {len(validation_report.get('issues', []))}")

        if not validation_report.get("issues"):
            st.success("🎉 No validation issues! Template quality is excellent.")

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
            width="stretch",
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
            },
        }
        st.download_button(
            label="📄 Download JSON Report",
            data=json.dumps(json_export, indent=2),
            file_name=f"triaging_template_{rule_number.replace('#', '_')}_report.json",
            mime="application/json",
            width="stretch",
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
                file_name=f"kql_queries_{rule_number.replace('#', '_')}.kql",
                mime="text/plain",
                width="stretch",
            )
        else:
            st.button("🔎 No KQL Queries", disabled=True, width="stretch")

    # Navigation
    st.markdown("---")
    col1, col2, col3 = st.columns([1, 2, 1])

    with col1:
        if st.button("⬅️ Back"):
            session_state.triaging_step = 1
            st.rerun()

    with col3:
        if st.button("🔄 New Search", type="primary", width="stretch"):
            # Clear state
            for key in list(session_state.keys()):
                if key.startswith("triaging_") or key.startswith("enhanced_template_"):
                    del session_state[key]
            st.rerun()
