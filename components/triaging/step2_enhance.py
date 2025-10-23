# step2_enhance.py - UPDATED WITH REMARKS DOWNLOAD
import streamlit as st
import os
import re
import time
import traceback
import hashlib
import pandas as pd
from io import BytesIO


def _get_enhancement_cache_key(rule_number: str, template_path: str) -> str:
    """Create unique cache key for template enhancement"""
    return f"enhanced_template_{rule_number}_{hashlib.md5(template_path.encode()).hexdigest()}"


def _export_template_with_remarks(template_df, remarks_dict, rule_number):
    """Export template with remarks column added"""
    # Create a copy of the dataframe
    export_df = template_df.copy()

    # Add remarks column
    remarks_list = []
    step_counter = 1

    for idx, row in export_df.iterrows():
        # Skip header row
        if pd.isna(row["Step"]) or str(row["Step"]).strip() == "":
            remarks_list.append("")
        else:
            remark_key = f"remark_step_{step_counter}_{rule_number}"
            remark = remarks_dict.get(remark_key, "")
            remarks_list.append(remark)
            step_counter += 1

    export_df["Remarks/Comments"] = remarks_list

    # Export to Excel with formatting
    output = BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        export_df.to_excel(writer, index=False, sheet_name="Triaging Steps")

        worksheet = writer.sheets["Triaging Steps"]

        # Set column widths
        worksheet.column_dimensions["A"].width = 8
        worksheet.column_dimensions["B"].width = 30
        worksheet.column_dimensions["C"].width = 50
        worksheet.column_dimensions["D"].width = 60
        worksheet.column_dimensions["E"].width = 40
        worksheet.column_dimensions["F"].width = 50

        # Format header row
        from openpyxl.styles import Font, PatternFill, Alignment

        header_fill = PatternFill(
            start_color="4472C4", end_color="4472C4", fill_type="solid"
        )
        header_font = Font(bold=True, color="FFFFFF")

        for cell in worksheet[1]:
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(horizontal="center", vertical="center")

        # Wrap text for all cells
        for row in worksheet.iter_rows(min_row=2):
            for cell in row:
                cell.alignment = Alignment(wrap_text=True, vertical="top")

    output.seek(0)
    return output.getvalue()


def show_page(session_state, TemplateParser, WebLLMEnhancer, EnhancedTemplateGenerator):
    # Get alert information
    selected_alert = session_state.get("triaging_selected_alert", None)

    if selected_alert is None:
        rule_number = session_state.get("triaging_rule_number", None)
        if rule_number:
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
        if st.button("📁 Create Template Directory", type="primary"):
            os.makedirs(template_dir, exist_ok=True)
            st.success("✅ Directory created! Please upload templates.")
            st.stop()
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
        st.stop()

    template_path = os.path.join(template_dir, template_files[0])

    # ✅ CREATE CACHE KEY
    cache_key = _get_enhancement_cache_key(rule_number, template_path)

    # ✅ CHECK CACHE FIRST
    if cache_key in st.session_state:
        cached_data = st.session_state[cache_key]
        session_state.original_steps = cached_data["original_steps"]
        session_state.enhanced_steps = cached_data["enhanced_steps"]
        session_state.excel_template_data = cached_data["excel_template_data"]
        session_state.template_dataframe = cached_data["template_dataframe"]

        _display_enhancement_results(
            session_state,
            rule_number,
            EnhancedTemplateGenerator,
        )
        return

    # ✅ RUN ENHANCEMENT (ONLY ONCE)
    st.info(f"📄 Processing template: {template_files[0]}")

    # Create progress tracking
    progress_bar = st.progress(0, text="📄 Starting enhancement...")

    try:
        # STEP 1: Parse Template
        progress_bar.progress(10, text="📋 Parsing original template...")

        parser = TemplateParser()

        if template_path.endswith(".csv"):
            original_steps = parser.parse_csv_template(template_path)
        else:
            original_steps = parser.parse_excel_template(template_path)

        if not original_steps:
            st.error("❌ Template parsing failed - no steps extracted")
            st.stop()

        progress_bar.progress(20, text=f"✅ Extracted {len(original_steps)} steps")

        # STEP 2: Enhancement (this doesn't add KQL yet)
        progress_bar.progress(30, text="🚀 Enhancing with AI...")

        enhancer = WebLLMEnhancer()
        start_time = time.time()

        enhanced_steps = enhancer.enhance_template_steps(
            rule_number=rule_number,
            original_steps=original_steps,
        )

        elapsed = time.time() - start_time

        progress_bar.progress(50, text=f"⚡ Enhanced {len(enhanced_steps)} steps")

        # STEP 3: Generate Full Template with KQL
        progress_bar.progress(60, text="🔎 Generating KQL queries...")

        template_gen = EnhancedTemplateGenerator()

        template_df = template_gen.generate_clean_template(
            rule_number=rule_number, enhanced_steps=enhanced_steps
        )

        template_df["Step"] = template_df["Step"].astype(str)

        progress_bar.progress(80, text="📊 Finalizing Excel template...")

        excel_file = template_gen.export_to_excel(template_df, rule_number)

        progress_bar.progress(90, text="💾 Converting to display format...")

        # ✅ CONVERT DataFrame back to dictionary format with KQL included
        enhanced_steps_with_kql = []

        for idx, row in template_df.iterrows():
            # Skip header row
            if pd.isna(row["Step"]) or str(row["Step"]).strip() == "":
                continue

            # Extract KQL
            kql_raw = row["KQL Query"]
            kql_str = str(kql_raw) if pd.notna(kql_raw) else ""
            kql_cleaned = kql_str.strip().lower()

            if pd.notna(kql_raw) and kql_cleaned not in ["nan", "none", ""]:
                final_kql = str(kql_raw)
            else:
                final_kql = ""

            step_dict = {
                "step_name": str(row["Name"]) if pd.notna(row["Name"]) else "",
                "explanation": (
                    str(row["Explanation"]) if pd.notna(row["Explanation"]) else ""
                ),
                "kql_query": final_kql,
                "kql_explanation": (
                    str(row["KQL Explanation"])
                    if pd.notna(row["KQL Explanation"])
                    and str(row["KQL Explanation"]).strip().lower()
                    not in ["nan", "none", ""]
                    else ""
                ),
                "input_required": "",
            }

            enhanced_steps_with_kql.append(step_dict)

        progress_bar.progress(95, text="💾 Caching results...")

        # ✅ CACHE WITH KQL INCLUDED
        st.session_state[cache_key] = {
            "original_steps": original_steps,
            "enhanced_steps": enhanced_steps_with_kql,
            "excel_template_data": excel_file,
            "template_dataframe": template_df,
            "elapsed_time": elapsed,
        }

        # Store in session state
        session_state.original_steps = original_steps
        session_state.enhanced_steps = enhanced_steps_with_kql
        session_state.excel_template_data = excel_file
        session_state.template_dataframe = template_df

        progress_bar.progress(100, text="✅ Enhancement complete!")

        time.sleep(0.5)
        progress_bar.empty()

        # Display results
        _display_enhancement_results(
            session_state,
            rule_number,
            EnhancedTemplateGenerator,
        )

    except Exception as e:
        progress_bar.empty()
        st.error(f"❌ Error: {str(e)}")
        with st.expander("🔍 View Error Details"):
            st.code(traceback.format_exc())


def _display_enhancement_results(
    session_state,
    rule_number,
    EnhancedTemplateGenerator,
):
    """Display enhancement results with sequential navigation"""

    enhanced_steps = session_state.enhanced_steps

    st.success(f"✅ Successfully generated {len(enhanced_steps)} enhanced steps")
    st.markdown("---")

    # Initialize remarks and current step in session state
    if "step_remarks" not in st.session_state:
        st.session_state.step_remarks = {}
    if "current_open_step" not in st.session_state:
        st.session_state.current_open_step = 1

    # ✅ TWO MAIN TABS
    tab1, tab2 = st.tabs(["📋 Triaging Steps", "📊 Excel Template"])

    # TAB 1: Sequential Step Navigation
    with tab1:
        # Display current step
        current_idx = st.session_state.current_open_step - 1
        if 0 <= current_idx < len(enhanced_steps):
            step = enhanced_steps[current_idx]
            step_num = current_idx + 1

            step_name = step.get("step_name", f"Step {step_num}")
            explanation = step.get("explanation", "No explanation provided")

            kql_query = step.get("kql_query", "")
            kql_explanation = step.get("kql_explanation", "")

            # Clean up KQL query
            if kql_query:
                kql_query = str(kql_query).strip()
                if kql_query.lower() in ["nan", "none", "n/a", ""]:
                    kql_query = ""

            # Display Step Header
            st.markdown(f"### Step {step_num} of {len(enhanced_steps)}: {step_name}")
            st.write(explanation)

            # ✅ KQL Query Section (if exists)
            if kql_query and len(kql_query) > 5:
                st.markdown("##### 🔎 KQL Query")
                if kql_explanation and str(kql_explanation).strip() not in [
                    "nan",
                    "none",
                    "n/a",
                    "",
                ]:
                    st.write(kql_explanation)
                st.code(kql_query, language="kql")

                # ✅ Execute Button
                col_space, col_execute = st.columns([4, 1])
                with col_execute:
                    if st.button(
                        "▶️ Execute",
                        key=f"execute_step_{step_num}",
                        type="primary",
                        help="Execute this KQL query",
                        width="stretch",
                    ):
                        st.info("🚀 Query execution would be triggered here")
                        # TODO: Add your execution logic here

                # ✅ Output Section (Empty for now)
                st.markdown("##### 📊 Output")
                st.info("Output will be displayed here after query execution")

            # ✅ Remarks/Comments Input
            st.markdown("##### 💬 Remarks/Comments")

            # Get existing remark
            remark_key = f"remark_step_{step_num}_{rule_number}"
            existing_remark = st.session_state.step_remarks.get(remark_key, "")

            # Text area for remarks
            remark = st.text_area(
                "Add your remarks or comments for this step:",
                value=existing_remark,
                height=120,
                key=f"remark_input_{step_num}",
                placeholder="Enter any observations, notes, or comments about this step...",
                label_visibility="collapsed",
            )

            # Save remark to session state
            if remark != existing_remark:
                st.session_state.step_remarks[remark_key] = remark

            st.markdown("---")

            # ✅ Navigation Buttons
            col1, col2, col3 = st.columns([1, 2, 1])

            with col1:
                if st.session_state.current_open_step > 1:
                    if st.button("⬅️ Previous", key="prev_btn", width="stretch"):
                        st.session_state.current_open_step -= 1
                        st.rerun()

            with col3:
                if st.session_state.current_open_step < len(enhanced_steps):
                    if st.button(
                        "Next ➡️",
                        key="next_btn",
                        type="primary",
                        width="stretch",
                    ):
                        st.session_state.current_open_step += 1
                        st.rerun()

        # ✅ SHOW DOWNLOAD BUTTON WHEN ALL STEPS REVIEWED
        if st.session_state.current_open_step == len(enhanced_steps):
            st.markdown("---")
            st.success("🎉 All steps reviewed!")

            st.info(
                "📝 Click below to download the complete template with all your remarks"
            )

            # Generate template with remarks
            template_df = session_state.template_dataframe
            remarks_dict = st.session_state.step_remarks

            excel_with_remarks = _export_template_with_remarks(
                template_df, remarks_dict, rule_number
            )

            # Center the download button
            col1, col2, col3 = st.columns([1, 2, 1])
            with col2:
                st.download_button(
                    label="📥 Download Complete Template with Remarks",
                    data=excel_with_remarks,
                    file_name=f"triaging_template_{rule_number.replace('#', '_')}_with_remarks.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    type="primary",
                    width="stretch",
                )

    # TAB 2: Excel Template Preview & Download
    with tab2:
        st.markdown("### 📊 Excel Template Preview")

        # Use cached dataframe
        if (
            hasattr(session_state, "template_dataframe")
            and session_state.template_dataframe is not None
        ):
            template_df = session_state.template_dataframe
        else:
            # Fallback
            template_gen = EnhancedTemplateGenerator()
            template_df = template_gen.generate_clean_template(
                rule_number=rule_number, enhanced_steps=enhanced_steps
            )
            template_df["Step"] = template_df["Step"].astype(str)
            session_state.template_dataframe = template_df

        # Display dataframe
        st.dataframe(template_df, width="stretch", height=500)

        st.markdown("---")

        # Download Buttons
        col1, col2 = st.columns(2)

        with col1:
            st.download_button(
                label="📥 Download Base Template",
                data=session_state.excel_template_data,
                file_name=f"triaging_template_{rule_number.replace('#', '_')}_base.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                width="stretch",
            )

        with col2:
            # Generate template with remarks
            remarks_dict = st.session_state.step_remarks
            excel_with_remarks = _export_template_with_remarks(
                template_df, remarks_dict, rule_number
            )

            st.download_button(
                label="📥 Download with Remarks",
                data=excel_with_remarks,
                file_name=f"triaging_template_{rule_number.replace('#', '_')}_with_remarks.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                width="stretch",
                type="primary",
            )
