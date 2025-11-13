# step2_enhance.py - UPDATED WITH KQL EXECUTION
import streamlit as st
import os
import re
import time
import traceback
import hashlib
import pandas as pd
from io import BytesIO
from routes.src.virustotal_integration import IPReputationChecker
from routes.src.template_generator import ImprovedTemplateGenerator
from components.triaging.kql_executor import KQLExecutor  # NEW IMPORT


def contains_ip_not_vip(text):
    """Check if text contains 'ip' but not as part of 'vip'"""
    if "ip" not in text:
        return False
    import re

    ip_patterns = [
        r"\bip\b",
        r"ip\s+address",
        r"ip\s+reputation",
        r"source\s+ip",
    ]
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in ip_patterns)


def _save_step_data(step_num: int, rule_number: str, data_type: str):
    """Helper to save step data immediately"""
    if data_type == "remark":
        remark_key = f"remark_step_{step_num}_{rule_number}"
        input_key = f"remark_input_{step_num}"
        if input_key in st.session_state:
            st.session_state.step_remarks[remark_key] = st.session_state[input_key]

    elif data_type == "output":
        output_key = f"output_step_{step_num}_{rule_number}"
        input_key = f"output_input_{step_num}"
        if input_key in st.session_state:
            st.session_state.step_outputs[output_key] = st.session_state[input_key]


def _extract_all_ips_from_outputs(step_num: int, rule_number: str) -> list:
    """
    Extract ALL IPs (IPv4 and IPv6) from previous investigation steps

    Args:
        step_num: Current step number
        rule_number: Rule identifier

    Returns:
        List of unique IP addresses
    """
    import re

    all_ips = []

    # Check all previous steps
    for prev_step in range(1, step_num):
        prev_output_key = f"output_step_{prev_step}_{rule_number}"
        prev_output = st.session_state.step_outputs.get(prev_output_key, "")

        if not prev_output:
            continue

        # IPv4 pattern (strict)
        ipv4_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ipv4_matches = re.findall(ipv4_pattern, prev_output)

        # IPv6 pattern (comprehensive)
        ipv6_pattern = r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b"
        ipv6_matches = re.findall(ipv6_pattern, prev_output)

        all_ips.extend(ipv4_matches)
        all_ips.extend(ipv6_matches)

    # Remove duplicates while preserving order
    seen = set()
    unique_ips = []
    for ip in all_ips:
        if ip not in seen:
            seen.add(ip)
            unique_ips.append(ip)

    return unique_ips


def _execute_kql_query(step_num: int, rule_number: str, kql_query: str):
    """
    Execute KQL query and save results to output

    Args:
        step_num: Current step number
        rule_number: Rule identifier
        kql_query: KQL query to execute
    """
    output_key = f"output_step_{step_num}_{rule_number}"

    try:
        # Initialize executor
        if "kql_executor" not in st.session_state:
            st.session_state.kql_executor = KQLExecutor()

        executor = st.session_state.kql_executor

        # Show execution progress
        with st.spinner("🔄 Executing KQL query..."):
            success, formatted_output, raw_results = executor.execute_query(kql_query)

        if success:
            # Save to output
            st.session_state.step_outputs[output_key] = formatted_output
            st.success("✅ Query executed successfully!")

            # Show preview
            with st.expander("📊 View Results Preview", expanded=True):
                st.text(
                    formatted_output[:1000]
                    + ("..." if len(formatted_output) > 1000 else "")
                )

            return True
        else:
            st.error(f"❌ Query execution failed: {formatted_output}")
            return False

    except Exception as e:
        st.error(f"❌ Execution error: {str(e)}")
        return False


def _unlock_predictions(excel_data: bytes, filename: str, rule_number: str):
    """Callback to unlock predictions tab AND immediately upload file"""
    st.session_state.triaging_complete = True
    st.session_state.predictions_excel_data = excel_data
    st.session_state.predictions_excel_filename = filename
    st.session_state.predictions_rule_number = rule_number

    success = _upload_to_predictions_api(excel_data, filename)

    if success:
        st.session_state.predictions_uploaded = True
        st.session_state.show_predictions_unlock_message = True
        print(f"✅ Successfully uploaded {filename} to predictions API")
    else:
        st.session_state.predictions_uploaded = False
        st.session_state.show_predictions_unlock_message = True
        print(f"❌ Failed to upload {filename} to predictions API")


def _upload_to_predictions_api(excel_data: bytes, filename: str):
    """Upload Excel file to predictions API immediately"""
    try:
        import os
        from api_client.predictions_api_client import get_predictions_client

        final_api_key = os.getenv("GOOGLE_API_KEY")
        predictions_api_url = os.getenv(
            "PREDICTIONS_API_URL", "http://localhost:8000/predictions"
        )

        client = get_predictions_client(predictions_api_url, final_api_key)

        file_obj = BytesIO(excel_data)

        with st.spinner("📤 Uploading to predictions API..."):
            upload_result = client.upload_excel_bytes(file_obj, filename)

        if upload_result.get("success"):
            st.session_state.predictions_uploaded = True
            st.session_state.predictions_upload_result = upload_result
            st.session_state.predictions_file_data = excel_data
            st.session_state.predictions_filename = filename
            print(f"✅ Successfully uploaded {upload_result.get('total_rows', 0)} rows")
            return True
        else:
            st.session_state.predictions_upload_error = upload_result.get(
                "error", "Unknown error"
            )
            print(f"❌ Upload failed: {upload_result.get('error')}")
            return False

    except Exception as e:
        st.session_state.predictions_upload_error = str(e)
        print(f"❌ Upload exception: {str(e)}")
        return False


def _get_enhancement_cache_key(rule_number: str, template_path: str) -> str:
    """Create unique cache key for template enhancement"""
    return f"enhanced_template_{rule_number}_{hashlib.md5(template_path.encode()).hexdigest()}"


def _get_manual_cache_key(alert_name: str) -> str:
    """Create unique cache key for manual generation"""
    return f"manual_template_{hashlib.md5(alert_name.encode()).hexdigest()}"


def _export_template_with_remarks_and_outputs(
    template_df, remarks_dict, outputs_dict, rule_number
):
    """Export template with remarks AND outputs columns added"""
    export_df = template_df.copy()

    remarks_list = []
    outputs_list = []
    step_counter = 1

    for idx, row in export_df.iterrows():
        if pd.isna(row["Step"]) or str(row["Step"]).strip() == "":
            remarks_list.append("")
            outputs_list.append("")
        else:
            remark_key = f"remark_step_{step_counter}_{rule_number}"
            remark = remarks_dict.get(remark_key, "")
            remarks_list.append(remark)

            output_key = f"output_step_{step_counter}_{rule_number}"
            output = outputs_dict.get(output_key, "")
            outputs_list.append(output)

            step_counter += 1

    export_df["Output"] = outputs_list
    export_df["Remarks/Comments"] = remarks_list

    output = BytesIO()

    try:
        intelligent_gen = ImprovedTemplateGenerator()
        return intelligent_gen.export_to_excel(export_df, rule_number).getvalue()
    except Exception as e:
        print(f"⚠️ Fallback Excel export used due to error: {e}")
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            export_df.to_excel(writer, index=False, sheet_name="Triaging Steps")
        output.seek(0)
        return output.getvalue()


def show_page(session_state, TemplateParser, EnhancedTemplateGenerator):
    """Main page function"""

    selected_alert = session_state.get("triaging_selected_alert", None)

    if selected_alert is None:
        rule_number = session_state.get("triaging_rule_number", None)
        if rule_number:
            selected_alert = {
                "rule": rule_number,
                "rule_number": rule_number,
                "incident": f"TEMPLATE_GEN_{rule_number}",
                "description": f"Template Generation for Rule {rule_number}",
                "is_manual": False,
            }
            session_state["triaging_selected_alert"] = selected_alert
        else:
            st.error("❌ No alert selected. Please go back and select an incident.")
            return

    rule_number = selected_alert.get(
        "rule_number", selected_alert.get("rule", "Unknown")
    )
    alert_name = selected_alert.get("alert_name", rule_number)
    is_manual = selected_alert.get("is_manual", False)

    rule_num_match = re.search(r"#?(\d+)", rule_number)
    rule_num = (
        rule_num_match.group(1)
        if rule_num_match
        else rule_number.replace("#", "").strip()
    )

    template_dir = "data/triaging_templates"
    template_files = []
    template_path = ""

    if not is_manual:
        if os.path.exists(template_dir):
            all_files = os.listdir(template_dir)
            template_files = [
                f
                for f in all_files
                if rule_num in f and (f.endswith(".csv") or f.endswith(".xlsx"))
            ]
            if template_files:
                template_path = os.path.join(template_dir, template_files[0])

    # GENERATE FROM MANUAL INPUT
    if is_manual or not template_files:
        if is_manual:
            st.info(f"🤖 Generating investigation steps for: **{alert_name}**")
            cache_key = _get_manual_cache_key(alert_name)
        else:
            st.info(
                f"⚠️ No template file found for {rule_number}. Generating dynamic template."
            )
            cache_key = _get_manual_cache_key(rule_number)

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

        progress_bar = st.progress(0, text="📄 Starting intelligent generation...")
        try:
            original_steps = []

            progress_bar.progress(30, text="🧠 Analyzing with AI intelligence...")

            intelligent_gen = ImprovedTemplateGenerator()

            rule_context = selected_alert.get("description", alert_name)

            progress_bar.progress(40, text="📡 Gathering threat intelligence...")

            start_time = time.time()

            template_df = intelligent_gen.generate_intelligent_template(
                rule_number=rule_number,
                original_steps=original_steps,
                rule_context=rule_context,
            )

            elapsed = time.time() - start_time
            progress_bar.progress(80, text="📊 Finalizing template...")

            enhanced_steps_with_kql = []

            for idx, row in template_df.iterrows():
                if pd.isna(row["Step"]) or str(row["Step"]).strip() == "":
                    continue

                kql_raw = row["KQL Query"]
                kql_str = str(kql_raw) if pd.notna(kql_raw) else ""
                kql_cleaned = kql_str.strip().lower()

                final_kql = (
                    str(kql_raw).strip()
                    if pd.notna(kql_raw) and kql_cleaned not in ["nan", "none", ""]
                    else ""
                )

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

            progress_bar.progress(90, text="💾 Caching results...")

            excel_file = intelligent_gen.export_to_excel(template_df, rule_number)

            st.session_state[cache_key] = {
                "original_steps": original_steps,
                "enhanced_steps": enhanced_steps_with_kql,
                "excel_template_data": excel_file,
                "template_dataframe": template_df,
                "elapsed_time": elapsed,
            }

            session_state.original_steps = original_steps
            session_state.enhanced_steps = enhanced_steps_with_kql
            session_state.excel_template_data = excel_file
            session_state.template_dataframe = template_df

            progress_bar.progress(100, text="✅ Generation complete!")
            time.sleep(0.5)
            progress_bar.empty()

            st.success(f"🎉 Dynamic template generated in {elapsed:.1f}s!")

            _display_enhancement_results(
                session_state,
                rule_number,
                EnhancedTemplateGenerator,
            )

            return

        except Exception as e:
            progress_bar.empty()
            st.error(f"❌ Error during dynamic template generation: {str(e)}")
            with st.expander("🔍 View Error Details"):
                st.code(traceback.format_exc())
            return

    # ENHANCE EXISTING TEMPLATE
    if template_files:
        st.info(f"📄 Processing existing template: {template_files[0]}")
        cache_key = _get_enhancement_cache_key(rule_number, template_path)

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

        progress_bar = st.progress(0, text="📄 Starting intelligent enhancement...")

        try:
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

            progress_bar.progress(30, text="🧠 Analyzing with AI intelligence...")

            intelligent_gen = ImprovedTemplateGenerator()

            progress_bar.progress(40, text="📡 Gathering threat intelligence...")

            start_time = time.time()

            template_df = intelligent_gen.generate_intelligent_template(
                rule_number=rule_number, original_steps=original_steps
            )

            elapsed = time.time() - start_time

            progress_bar.progress(80, text="📊 Finalizing template...")

            enhanced_steps_with_kql = []

            for idx, row in template_df.iterrows():
                if pd.isna(row["Step"]) or str(row["Step"]).strip() == "":
                    continue

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

            progress_bar.progress(90, text="💾 Caching results...")

            excel_file = intelligent_gen.export_to_excel(template_df, rule_number)

            st.session_state[cache_key] = {
                "original_steps": original_steps,
                "enhanced_steps": enhanced_steps_with_kql,
                "excel_template_data": excel_file,
                "template_dataframe": template_df,
                "elapsed_time": elapsed,
            }

            session_state.original_steps = original_steps
            session_state.enhanced_steps = enhanced_steps_with_kql
            session_state.excel_template_data = excel_file
            session_state.template_dataframe = template_df

            progress_bar.progress(100, text="✅ Enhancement complete!")

            time.sleep(0.5)
            progress_bar.empty()

            st.success(f"🎉 Intelligent template generated in {elapsed:.1f}s!")

            _display_enhancement_results(
                session_state,
                rule_number,
                EnhancedTemplateGenerator,
            )

        except Exception as e:
            progress_bar.empty()
            st.error(f"❌ Error during template enhancement: {str(e)}")
            with st.expander("🔍 View Error Details"):
                st.code(traceback.format_exc())


def _display_enhancement_results(
    session_state,
    rule_number,
    EnhancedTemplateGenerator,
):
    """Display enhancement results with accordion navigation and completion tracking"""

    enhanced_steps = session_state.enhanced_steps

    st.success(f"✅ Successfully generated {len(enhanced_steps)} enhanced steps")
    st.markdown("---")

    if "step_remarks" not in st.session_state:
        st.session_state.step_remarks = {}
    if "step_outputs" not in st.session_state:
        st.session_state.step_outputs = {}
    if "completed_steps" not in st.session_state:
        st.session_state.completed_steps = set()
    if "current_open_step" not in st.session_state:
        st.session_state.current_open_step = 1

    tab1, tab2 = st.tabs(["📋 Triaging Steps", "📊 Excel Template"])

    with tab1:
        if st.session_state.get("predictions_upload_error"):
            st.error(f"❌ Upload failed: {st.session_state.predictions_upload_error}")
            if st.button("🔄 Retry Upload"):
                del st.session_state.predictions_upload_error
                if st.session_state.get("predictions_excel_data"):
                    _upload_to_predictions_api(
                        st.session_state.predictions_excel_data,
                        st.session_state.predictions_excel_filename,
                    )
                st.rerun()

        if st.session_state.get("show_predictions_unlock_message", False):
            if st.session_state.get("predictions_uploaded"):
                st.success(
                    "✅ Predictions tab unlocked! Switch to the **🔮 Predictions & MITRE** tab to continue."
                )
            else:
                st.warning(
                    "⚠️ Template downloaded but upload to predictions API failed. Check the error above."
                )
            del st.session_state.show_predictions_unlock_message

        for idx, step in enumerate(enhanced_steps):
            step_num = idx + 1
            step_name = step.get("step_name", f"Step {step_num}")

            is_completed = step_num in st.session_state.completed_steps
            is_expanded = (
                step_num == st.session_state.current_open_step and not is_completed
            )
            is_locked = (
                step_num > 1 and (step_num - 1) not in st.session_state.completed_steps
            )

            if is_completed:
                status_icon = "✅"
            elif is_locked:
                status_icon = "🔒"
            else:
                status_icon = "⏳"

            with st.expander(
                f"{status_icon} Step {step_num}: {step_name}", expanded=is_expanded
            ):
                if is_locked:
                    st.warning("🔒 Complete the previous step to unlock this one")
                else:
                    explanation = step.get("explanation", "No explanation provided")
                    st.write(explanation)

                    kql_query = step.get("kql_query", "")
                    kql_explanation = step.get("kql_explanation", "")

                    if kql_query:
                        kql_query = str(kql_query).strip()
                        if kql_query.lower() in ["nan", "none", "n/a", ""]:
                            kql_query = ""

                    step_name_lower = step_name.lower()
                    explanation_lower = explanation.lower()

                    is_ip_reputation_step = (
                        ("virustotal" in step_name_lower)
                        or ("virustotal" in explanation_lower)
                        or ("virus total" in step_name_lower)
                        or ("virus total" in explanation_lower)
                        or (
                            contains_ip_not_vip(step_name_lower)
                            and "reputation" in step_name_lower
                        )
                    )

                    # ✅ KQL QUERY SECTION WITH EXECUTE BUTTON - ENHANCED VERSION
                    if (
                        kql_query and len(kql_query.strip()) > 10
                    ):  # Increased minimum length
                        st.markdown("##### 🔍 KQL Query")

                        # Display query info
                        if kql_explanation and str(kql_explanation).strip() not in [
                            "nan",
                            "none",
                            "n/a",
                            "",
                        ]:
                            st.write(kql_explanation)

                        # Show the actual query with syntax highlighting
                        # st.code(kql_query, language="kql")

                        # Debug info - show query details
                        with st.expander("🔧 Query Details", expanded=False):
                            st.write(f"Query length: {len(kql_query)} characters")
                            st.write(
                                f"Workspace ID configured: {'✅' if os.getenv('LOG_ANALYTICS_WORKSPACE_ID') else '❌'}"
                            )

                        # ✅ EXECUTE BUTTON with enhanced feedback
                        col1, col2, col3 = st.columns([2, 1, 2])
                        with col2:
                            execute_clicked = st.button(
                                "▶️ Execute Query",
                                key=f"execute_kql_{step_num}",
                                type="primary",
                                width="stretch",
                            )

                        # Handle execution when button is clicked
                        if execute_clicked:
                            # Validate workspace configuration first
                            if not os.getenv("LOG_ANALYTICS_WORKSPACE_ID"):
                                st.error(
                                    "❌ Log Analytics Workspace ID not configured. Please check your environment variables."
                                )
                            else:
                                # Execute the query
                                success = _execute_kql_query(
                                    step_num, rule_number, kql_query
                                )

                                if success:
                                    st.success(
                                        "✅ Query executed successfully! Results saved below."
                                    )
                                else:
                                    st.error(
                                        "❌ Query execution failed. Check the error details above."
                                    )

                        # ✅ OUTPUT SECTION - ALWAYS DISPLAYED WHEN KQL QUERY EXISTS
                        st.markdown("##### 📊 Output")
                        output_key = f"output_step_{step_num}_{rule_number}"
                        existing_output = st.session_state.step_outputs.get(
                            output_key, ""
                        )

                        # Enhanced text area with better placeholder
                        placeholder_text = (
                            "KQL query results will appear here after execution..."
                        )
                        if existing_output:
                            placeholder_text = (
                                f"Results loaded ({len(existing_output)} characters)"
                            )

                        manual_output = st.text_area(
                            "Query Results:",
                            value=existing_output,
                            height=200,
                            key=f"output_input_{step_num}",
                            placeholder=placeholder_text,
                            on_change=lambda sn=step_num: _save_step_data(
                                sn, rule_number, "output"
                            ),
                            label_visibility="collapsed",
                        )

                        # Always save the output
                        st.session_state.step_outputs[output_key] = manual_output

                        if manual_output and manual_output != existing_output:
                            st.success(
                                f"✅ Output updated ({len(manual_output)} characters)"
                            )

                    # IP REPUTATION SECTION - ONLY IF NOT KQL QUERY
                    elif is_ip_reputation_step:
                        st.markdown("##### 📊 Output")
                        output_key = f"output_step_{step_num}_{rule_number}"
                        existing_output = st.session_state.step_outputs.get(
                            output_key, ""
                        )

                        st.info("🛡️ **Comprehensive IP Reputation Check**")
                        st.markdown("---")

                        # Extract ALL IPs from previous steps
                        default_ips = _extract_all_ips_from_outputs(
                            step_num, rule_number
                        )

                        if default_ips:
                            st.success(
                                f"✅ Auto-detected {len(default_ips)} IP address(es) from previous steps"
                            )

                            ipv4_ips = [ip for ip in default_ips if ":" not in ip]
                            ipv6_ips = [ip for ip in default_ips if ":" in ip]

                            col1, col2 = st.columns(2)
                            with col1:
                                if ipv4_ips:
                                    st.info(f"🌐 IPv4: {len(ipv4_ips)} address(es)")
                            with col2:
                                if ipv6_ips:
                                    st.info(f"🌐 IPv6: {len(ipv6_ips)} address(es)")

                        st.markdown("##### 🔍 Enter IP Addresses to Check")
                        st.caption(
                            "Enter multiple IPs (one per line, comma-separated, or space-separated)"
                        )
                        st.caption("✅ Supports: IPv4, IPv6, Private IPs, Public IPs")

                        default_text = "\n".join(default_ips) if default_ips else ""

                        ip_input = st.text_area(
                            "IP Addresses:",
                            value=default_text,
                            placeholder="Enter IPs here:\n192.168.1.1\n10.0.0.5\n2001:0db8:85a3:0000:0000:8a2e:0370:7334\n\nOr comma-separated: 192.168.1.1, 8.8.8.8",
                            key=f"vt_ip_step_{step_num}",
                            height=200,
                            label_visibility="collapsed",
                        )

                        col1, col2, col3 = st.columns([2, 2, 1])

                        with col1:
                            if default_ips:
                                st.caption(f"ℹ️ {len(default_ips)} IP(s) auto-detected")

                        with col3:
                            check_button = st.button(
                                "🔍 Check All IPs",
                                key=f"vt_check_step_{step_num}",
                                type="primary",
                                width="stretch",
                            )

                        if check_button and ip_input:
                            import re

                            ip_list = re.split(r"[,\n\s]+", ip_input)
                            ip_list = [ip.strip() for ip in ip_list if ip.strip()]

                            if not ip_list:
                                st.error(
                                    "❌ No valid IP addresses found. Please enter at least one IP."
                                )
                            else:
                                st.info(
                                    f"🔍„ Processing {len(ip_list)} IP address(es)..."
                                )

                                if "ip_checker" not in st.session_state:
                                    st.session_state.ip_checker = IPReputationChecker()

                                checker = st.session_state.ip_checker

                                progress_bar = st.progress(0)
                                status_text = st.empty()

                                results = checker.check_multiple_ips(
                                    ip_list, method="auto"
                                )

                                progress_bar.progress(100)
                                status_text.empty()
                                progress_bar.empty()

                                formatted_output_excel = ""

                                for ip, result in results.items():
                                    if result.get("formatted_output_excel"):
                                        formatted_output_excel += (
                                            result["formatted_output_excel"] + "\n\n"
                                        )

                                st.session_state.step_outputs[output_key] = (
                                    formatted_output_excel.strip()
                                )

                                st.markdown("---")
                                st.success(
                                    f"✅ Completed checking {len(ip_list)} IP address(es)!"
                                )
                                st.markdown("---")

                                high_risk = sum(
                                    1
                                    for r in results.values()
                                    if r.get("risk_level") == "HIGH"
                                )
                                medium_risk = sum(
                                    1
                                    for r in results.values()
                                    if r.get("risk_level") == "MEDIUM"
                                )
                                low_risk = sum(
                                    1
                                    for r in results.values()
                                    if r.get("risk_level") in ["LOW", "CLEAN"]
                                )
                                skipped = sum(
                                    1
                                    for r in results.values()
                                    if r.get("skip_check", False)
                                )

                                col1, col2, col3, col4 = st.columns(4)

                                with col1:
                                    if high_risk > 0:
                                        st.metric("🔍´ High Risk", high_risk)
                                    else:
                                        st.metric("High Risk", high_risk)

                                with col2:
                                    if medium_risk > 0:
                                        st.metric("🟡 Suspicious", medium_risk)
                                    else:
                                        st.metric("Suspicious", medium_risk)

                                with col3:
                                    st.metric("🟢 Clean", low_risk)

                                with col4:
                                    st.metric("ℹ️ Skipped", skipped)

                                st.markdown("### 🔍‹ Detailed Results")

                                for ip, result in results.items():
                                    ip_type = result.get("ip_type", "Unknown")

                                    if result.get("skip_check"):
                                        with st.expander(
                                            f"ℹ️ {ip} ({ip_type}) - Skipped",
                                            expanded=False,
                                        ):
                                            st.info(result.get("message", ""))
                                        continue

                                    if result.get("success"):
                                        risk_level = result.get("risk_level", "UNKNOWN")

                                        if risk_level == "HIGH":
                                            icon = "🔍´"
                                            expanded = True
                                        elif risk_level == "MEDIUM":
                                            icon = "🟡"
                                            expanded = True
                                        elif risk_level in ["LOW", "CLEAN"]:
                                            icon = "🟢"
                                            expanded = False
                                        else:
                                            icon = "⚪"
                                            expanded = False

                                        with st.expander(
                                            f"{icon} {ip} ({ip_type}) - {risk_level}",
                                            expanded=expanded,
                                        ):
                                            formatted_output_ui = result.get(
                                                "formatted_output", ""
                                            )
                                            st.markdown(formatted_output_ui)

                                            if risk_level == "HIGH":
                                                st.error(
                                                    "🚨 **HIGH RISK IP** - Immediate action recommended"
                                                )
                                            elif risk_level == "MEDIUM":
                                                st.warning(
                                                    "⚠️ **SUSPICIOUS IP** - Further investigation needed"
                                                )
                                            elif risk_level in ["LOW", "CLEAN"]:
                                                st.success(
                                                    "✅ **CLEAN IP** - No significant threats detected"
                                                )

                                    else:
                                        with st.expander(
                                            f"❌ {ip} ({ip_type}) - Check Failed",
                                            expanded=True,
                                        ):
                                            st.error(
                                                f"Error: {result.get('error', 'Unknown error')}"
                                            )
                                            if result.get("manual_check"):
                                                st.markdown(
                                                    result.get("formatted_output", "")
                                                )

                                st.markdown("---")
                                st.markdown("### 📈 Overall Assessment")

                                if high_risk > 0:
                                    st.error(
                                        f"⚠️ **CRITICAL**: {high_risk} high-risk IP(s) detected. Immediate investigation required!"
                                    )
                                elif medium_risk > 0:
                                    st.warning(
                                        f"⚠️ **CAUTION**: {medium_risk} suspicious IP(s) found. Further investigation recommended."
                                    )
                                else:
                                    st.success(
                                        "✅ All checked IPs appear clean or are private addresses."
                                    )

                                st.info(
                                    "💾 All results have been saved to the Output field for Excel export."
                                )

                        if existing_output:
                            with st.expander(
                                "🔍‹ View Saved Output (Excel Format)",
                                expanded=False,
                            ):
                                st.text(existing_output)

                    # Remarks Section
                    st.markdown("##### 💬 Remarks/Comments")
                    remark_key = f"remark_step_{step_num}_{rule_number}"
                    existing_remark = st.session_state.step_remarks.get(remark_key, "")

                    remark = st.text_area(
                        "Add remarks:",
                        value=existing_remark,
                        height=120,
                        key=f"remark_input_{step_num}",
                        placeholder="Enter observations or comments...",
                        label_visibility="collapsed",
                        on_change=lambda sn=step_num: _save_step_data(
                            sn, rule_number, "remark"
                        ),
                    )
                    st.session_state.step_remarks[remark_key] = remark

                    st.markdown("---")

                    if not is_completed:
                        if st.button(
                            "✅ Mark as Complete",
                            key=f"complete_step_{step_num}",
                            type="primary",
                            width="stretch",
                        ):
                            st.session_state.completed_steps.add(step_num)
                            st.session_state.current_open_step = step_num + 1
                            st.rerun()

        # Final Download Section
        if len(st.session_state.completed_steps) == len(enhanced_steps):
            st.markdown("---")
            st.success("🎉 All steps completed!")

            excel_key = f"final_excel_{rule_number}"
            if excel_key not in st.session_state:
                template_df = session_state.template_dataframe
                excel_with_data = _export_template_with_remarks_and_outputs(
                    template_df,
                    st.session_state.step_remarks,
                    st.session_state.step_outputs,
                    rule_number,
                )
                filename = (
                    f"triaging_template_{rule_number.replace('#', '_')}_complete.xlsx"
                )
                st.session_state[excel_key] = excel_with_data
                st.session_state.final_excel_filename = filename
            else:
                excel_with_data = st.session_state[excel_key]
                filename = st.session_state.final_excel_filename

            col1, col2, col3 = st.columns([1, 2, 1])
            with col2:
                st.download_button(
                    label="📥 Download & Proceed to Predictions",
                    data=excel_with_data,
                    file_name=filename,
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    type="primary",
                    width="stretch",
                    key="download_and_proceed",
                    on_click=lambda: _unlock_predictions(
                        excel_with_data, filename, rule_number
                    ),
                )

            if st.session_state.get("show_predictions_unlock_message"):
                if st.session_state.get("predictions_uploaded"):
                    st.success(
                        "✅ Template uploaded to predictions API! Switch to Predictions tab."
                    )
                else:
                    st.error(
                        f"❌ Upload failed: {st.session_state.get('predictions_upload_error', 'Unknown error')}"
                    )
                    if st.button("🔄 Retry Upload"):
                        success = _upload_to_predictions_api(excel_with_data, filename)
                        if success:
                            st.session_state.predictions_uploaded = True
                            st.rerun()

    # TAB 2: Excel Template Preview & Download
    with tab2:
        st.markdown("### 📊 Excel Template Preview")

        if (
            hasattr(session_state, "template_dataframe")
            and session_state.template_dataframe is not None
        ):
            template_df = session_state.template_dataframe
        else:
            st.warning("Template not generated yet")
            return

        st.dataframe(template_df, width="stretch", height=500)

        st.markdown("---")

        col1, col2 = st.columns(2)

        with col1:
            st.download_button(
                label="📥 Download Base Template",
                data=session_state.excel_template_data,
                file_name=f"triaging_template_{rule_number.replace('#', '_')}_base.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                width="stretch",
                key="download_base_excel",
            )

        with col2:
            complete_excel_key = f"complete_excel_{rule_number}"
            if complete_excel_key not in st.session_state:
                remarks_dict = st.session_state.step_remarks
                outputs_dict = st.session_state.step_outputs
                st.session_state[complete_excel_key] = (
                    _export_template_with_remarks_and_outputs(
                        template_df, remarks_dict, outputs_dict, rule_number
                    )
                )

            st.download_button(
                label="📥 Download Complete Template",
                data=st.session_state[complete_excel_key],
                file_name=f"triaging_template_{rule_number.replace('#', '_')}_complete.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                width="stretch",
                type="primary",
                key="download_complete_excel",
            )
