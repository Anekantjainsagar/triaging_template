import streamlit as st
import traceback
import pandas as pd
import hashlib
import json
from datetime import datetime
import os
import re
from io import BytesIO

from components.triaging.kql_executor import KQLExecutor
from routes.src.virustotal_integration import IPReputationChecker


def get_stable_cache_key(alert_name: str, rule_number: str, is_manual: bool) -> str:
    """Generate stable cache key"""
    data = f"{alert_name}_{rule_number}_{is_manual}"
    hash_key = hashlib.md5(data.encode()).hexdigest()
    return f"triaging_cache_{hash_key}"


def get_step_state_key(rule_number: str) -> str:
    """Get key for storing step completion state"""
    return f"step_state_{rule_number}"


class TriagingStateManager:
    """Manages triaging state with persistent caching"""

    def __init__(self, rule_number: str):
        self.rule_number = rule_number
        self.state_key = get_step_state_key(rule_number)

        if self.state_key not in st.session_state:
            st.session_state[self.state_key] = {
                "completed_steps": set(),
                "current_open_step": 1,
                "step_remarks": {},
                "step_outputs": {},
                "template_generated": False,
                "last_updated": datetime.now().isoformat(),
            }

    def mark_step_complete(self, step_num: int):
        """Mark a step as complete"""
        state = st.session_state[self.state_key]
        state["completed_steps"].add(step_num)
        state["current_open_step"] = step_num + 1
        state["last_updated"] = datetime.now().isoformat()
        st.session_state[self.state_key] = state

    def save_step_data(self, step_num: int, remark: str = None, output: str = None):
        """Save step data"""
        state = st.session_state[self.state_key]

        if remark is not None:
            state["step_remarks"][f"step_{step_num}"] = remark

        if output is not None:
            state["step_outputs"][f"step_{step_num}"] = output

        state["last_updated"] = datetime.now().isoformat()
        st.session_state[self.state_key] = state

    def get_step_data(self, step_num: int):
        """Retrieve step data"""
        state = st.session_state[self.state_key]
        return {
            "remark": state["step_remarks"].get(f"step_{step_num}", ""),
            "output": state["step_outputs"].get(f"step_{step_num}", ""),
            "completed": step_num in state["completed_steps"],
        }

    def is_step_completed(self, step_num: int) -> bool:
        """Check if step is completed"""
        return step_num in st.session_state[self.state_key]["completed_steps"]

    def get_current_open_step(self) -> int:
        """Get currently open step number"""
        return st.session_state[self.state_key]["current_open_step"]

    def is_all_complete(self, total_steps: int) -> bool:
        """Check if all steps are complete"""
        return len(st.session_state[self.state_key]["completed_steps"]) == total_steps

    def get_all_remarks(self) -> dict:
        """Get all remarks"""
        return st.session_state[self.state_key]["step_remarks"]

    def get_all_outputs(self) -> dict:
        """Get all outputs"""
        return st.session_state[self.state_key]["step_outputs"]

    def reset(self):
        """Reset all state"""
        if self.state_key in st.session_state:
            del st.session_state[self.state_key]


class TemplateCacheManager:
    """Manages template generation caching"""

    @staticmethod
    def get_cached_template(cache_key: str):
        """Get cached template if exists"""
        if cache_key in st.session_state:
            cached = st.session_state[cache_key]
            if all(
                k in cached for k in ["enhanced_steps", "template_df", "excel_data"]
            ):
                return cached
        return None

    @staticmethod
    def cache_template(
        cache_key: str,
        enhanced_steps: list,
        template_df: pd.DataFrame,
        excel_data: bytes,
    ):
        """Cache template generation results"""
        st.session_state[cache_key] = {
            "enhanced_steps": enhanced_steps,
            "template_df": template_df,
            "excel_data": excel_data,
            "cached_at": datetime.now().isoformat(),
        }

    @staticmethod
    def has_cache(cache_key: str) -> bool:
        """Check if cache exists"""
        return cache_key in st.session_state


def contains_ip_not_vip(text):
    """Check if text contains 'ip' but not as part of 'vip'"""
    if "ip" not in text:
        return False

    ip_patterns = [r"\bip\b", r"ip\s+address", r"ip\s+reputation", r"source\s+ip"]
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in ip_patterns)


def _execute_kql_query(
    step_num: int, rule_number: str, kql_query: str, state_mgr: TriagingStateManager
):
    """Execute KQL query and save results"""
    try:
        if "kql_executor" not in st.session_state:
            st.session_state.kql_executor = KQLExecutor()

        executor = st.session_state.kql_executor

        with st.spinner("🔄 Executing KQL query..."):
            success, formatted_output, raw_results = executor.execute_query(kql_query)

        if success:
            output_key = f"output_{rule_number}_{step_num}"

            # Save to state manager
            state_mgr.save_step_data(step_num, output=formatted_output)

            # Save to session state for immediate display
            st.session_state[output_key] = formatted_output

            return True, formatted_output
        else:
            st.error(f"❌ Query execution failed: {formatted_output}")
            return False, None

    except Exception as e:
        st.error(f"❌ Execution error: {str(e)}")
        return False, None


def _extract_ips_from_entities(alert_data: dict) -> list:
    """
    Extract ALL IP addresses directly from alert entities

    Returns:
        List of unique IP addresses (IPv4 and IPv6)
    """
    all_ips = []

    if not alert_data:
        return all_ips

    # Extract from entities
    entities = alert_data.get("entities", {})
    entities_list = (
        entities.get("entities", [])
        if isinstance(entities, dict)
        else (entities if isinstance(entities, list) else [])
    )

    for entity in entities_list:
        kind = entity.get("kind", "").lower()
        if kind == "ip":
            props = entity.get("properties", {})
            ip_address = props.get("address", "")
            if ip_address:
                all_ips.append(ip_address)

    # Remove duplicates while preserving order
    seen = set()
    unique_ips = []
    for ip in all_ips:
        if ip not in seen:
            seen.add(ip)
            unique_ips.append(ip)

    return unique_ips


def display_triaging_workflow(rule_number: str, alert_data: dict = None):
    """Main triaging workflow with proper caching"""

    st.markdown("## 📋 AI-Powered Template Enhancement")
    st.markdown("---")

    # Extract alert info
    alert_name = alert_data.get("title") or alert_data.get("alert_name") or rule_number
    is_manual = alert_data.get("source") == "alert_details" or alert_data.get(
        "is_manual", False
    )

    # Generate stable cache key
    cache_key = get_stable_cache_key(alert_name, rule_number, is_manual)

    # Initialize state manager
    state_mgr = TriagingStateManager(rule_number)

    # Check cache first
    cached_template = TemplateCacheManager.get_cached_template(cache_key)

    if cached_template:
        st.success("✅ Using cached template (no API calls needed)")
        enhanced_steps = cached_template["enhanced_steps"]
        template_df = cached_template["template_df"]
        excel_data = cached_template["excel_data"]
    else:
        st.info("🤖 Generating investigation template...")

        try:
            with st.spinner("⏳ This may take 30-60 seconds..."):
                from routes.src.template_generator import ImprovedTemplateGenerator

                gen = ImprovedTemplateGenerator()
                analysis_text = alert_data.get("analysis_text", "")

                if is_manual:
                    template_df = gen.generate_from_manual_analysis(
                        alert_name=alert_name,
                        analysis_text=analysis_text,
                        rule_number=rule_number,
                        alert_data=alert_data,
                    )
                else:
                    template_df = gen.generate_intelligent_template(
                        rule_number=rule_number,
                        original_steps=[],
                        rule_context=alert_name,
                    )

                    if alert_data:
                        template_df = gen.inject_alert_data_into_template(
                            template_df, alert_data
                        )

                # Convert to enhanced steps format
                enhanced_steps = []
                for idx, row in template_df.iterrows():
                    if (
                        pd.isna(row.get("Step"))
                        or str(row.get("Step", "")).strip() == ""
                    ):
                        continue

                    kql_query = row.get("KQL Query", "")
                    if pd.notna(kql_query):
                        kql_query = str(kql_query).strip()
                        if kql_query.lower() in ["nan", "none", ""]:
                            kql_query = ""
                    else:
                        kql_query = ""

                    enhanced_steps.append(
                        {
                            "step_name": (
                                str(row.get("Name", ""))
                                if pd.notna(row.get("Name"))
                                else ""
                            ),
                            "explanation": (
                                str(row.get("Explanation", ""))
                                if pd.notna(row.get("Explanation"))
                                else ""
                            ),
                            "kql_query": kql_query,
                            "kql_explanation": (
                                str(row.get("KQL Explanation", ""))
                                if pd.notna(row.get("KQL Explanation"))
                                else ""
                            ),
                        }
                    )

                # Export to Excel
                excel_data = gen.export_to_excel(template_df, rule_number).getvalue()

                # Cache the results
                TemplateCacheManager.cache_template(
                    cache_key, enhanced_steps, template_df, excel_data
                )

                st.success(
                    f"✅ Template generated and cached! ({len(enhanced_steps)} steps)"
                )

        except Exception as e:
            st.error(f"❌ Error generating template: {str(e)}")
            with st.expander("🔍 View Error Details"):
                st.code(traceback.format_exc())
            return

    # Display interactive steps
    display_interactive_steps(
        enhanced_steps, template_df, excel_data, rule_number, state_mgr, alert_data
    )


def display_interactive_steps(
    enhanced_steps: list,
    template_df: pd.DataFrame,
    excel_data: bytes,
    rule_number: str,
    state_mgr: TriagingStateManager,
    alert_data: dict = None,
):
    """Display steps with accordion navigation and KQL execution"""

    st.markdown("---")
    st.markdown(f"### 📋 {len(enhanced_steps)} Investigation Steps")

    tab1, tab2 = st.tabs(["📋 Triaging Steps", "📊 Excel Template"])

    with tab1:
        for idx, step in enumerate(enhanced_steps):
            step_num = idx + 1
            step_name = step.get("step_name", f"Step {step_num}")

            is_completed = state_mgr.is_step_completed(step_num)
            is_current = step_num == state_mgr.get_current_open_step()
            is_locked = step_num > 1 and not state_mgr.is_step_completed(step_num - 1)

            if is_completed:
                status_icon = "✅"
            elif is_locked:
                status_icon = "🔒"
            else:
                status_icon = "⏳"

            with st.expander(
                f"{status_icon} Step {step_num}: {step_name}",
                expanded=(is_current and not is_completed and not is_locked),
            ):
                if is_locked:
                    st.warning("🔒 Complete the previous step to unlock this one")
                    continue

                st.write(step.get("explanation", "No explanation provided"))

                kql_query = step.get("kql_query", "")

                # KQL Query section
                if kql_query and len(kql_query.strip()) > 10:
                    st.markdown("##### 🔎 KQL Query")

                    kql_explanation = step.get("kql_explanation", "")
                    if kql_explanation:
                        st.write(kql_explanation)

                    st.code(kql_query, language="kql")

                    col1, col2, col3 = st.columns([2, 1, 2])
                    with col2:
                        execute_clicked = st.button(
                            "▶️ Execute Query",
                            key=f"execute_kql_{step_num}",
                            type="primary",
                            use_container_width=True,
                        )

                    if execute_clicked:
                        if not os.getenv("LOG_ANALYTICS_WORKSPACE_ID"):
                            st.error("❌ Log Analytics Workspace ID not configured.")
                        else:
                            success, output = _execute_kql_query(
                                step_num, rule_number, kql_query, state_mgr
                            )

                            if success:
                                st.success("✅ Query executed successfully!")

                                # Display output in highlighted container
                                st.markdown("##### 📊 Query Results")
                                st.markdown(
                                    """
                                    <div style="
                                        background-color: #f0f7ff;
                                        border-left: 4px solid #1976d2;
                                        padding: 15px;
                                        border-radius: 5px;
                                        font-family: 'Courier New', monospace;
                                        font-size: 13px;
                                        max-height: 400px;
                                        overflow-y: auto;
                                        white-space: pre-wrap;
                                        word-wrap: break-word;
                                    ">""",
                                    unsafe_allow_html=True,
                                )
                                st.text(output)
                                st.markdown("</div>", unsafe_allow_html=True)

                                # Provide editable text area below
                                st.markdown("##### ✏️ Edit Output (if needed)")
                                output_key = f"output_{rule_number}_{step_num}"
                                edited_output = st.text_area(
                                    "Modify results:",
                                    value=output,
                                    height=150,
                                    key=f"edit_{output_key}",
                                    label_visibility="collapsed",
                                )

                                if edited_output != output:
                                    state_mgr.save_step_data(
                                        step_num, output=edited_output
                                    )
                                    st.info("💾 Changes saved")

                    else:
                        # Show existing output if any
                        step_data = state_mgr.get_step_data(step_num)
                        existing_output = step_data["output"]

                        if existing_output:
                            st.markdown("##### 📊 Saved Results")
                            st.markdown(
                                """
                                <div style="
                                    background-color: #f0f7ff;
                                    border-left: 4px solid #1976d2;
                                    padding: 15px;
                                    border-radius: 5px;
                                    font-family: 'Courier New', monospace;
                                    font-size: 13px;
                                    max-height: 400px;
                                    overflow-y: auto;
                                    white-space: pre-wrap;
                                    word-wrap: break-word;
                                ">""",
                                unsafe_allow_html=True,
                            )
                            st.text(existing_output)
                            st.markdown("</div>", unsafe_allow_html=True)

                # IP Reputation section
                elif _is_ip_reputation_step(step):
                    st.markdown("##### 🛡️ IP Reputation Check")

                    # Extract IPs directly from entities
                    entity_ips = (
                        _extract_ips_from_entities(alert_data) if alert_data else []
                    )

                    if entity_ips:
                        st.success(
                            f"✅ Found {len(entity_ips)} IP address(es) from alert entities"
                        )

                        with st.expander("🔍 View Detected IPs", expanded=True):
                            for ip in entity_ips:
                                st.code(ip)

                    st.markdown("##### 📝 Enter Additional IPs (optional)")

                    default_text = "\n".join(entity_ips) if entity_ips else ""

                    ip_input = st.text_area(
                        "IP Addresses:",
                        value=default_text,
                        placeholder="IPs auto-filled from entities. Add more if needed.",
                        key=f"vt_ip_step_{step_num}",
                        height=150,
                        label_visibility="collapsed",
                    )

                    col1, col2, col3 = st.columns([2, 2, 1])
                    with col3:
                        check_button = st.button(
                            "🔍 Check All IPs",
                            key=f"vt_check_step_{step_num}",
                            type="primary",
                            use_container_width=True,
                        )

                    if check_button and ip_input:
                        _process_ip_reputation_check(
                            ip_input, step_num, rule_number, state_mgr
                        )

                # Remarks section
                st.markdown("##### 💬 Remarks/Comments")

                step_data = state_mgr.get_step_data(step_num)
                remark_key = f"remark_{rule_number}_{step_num}"

                remark_text = st.text_area(
                    "Add remarks:",
                    value=step_data["remark"],
                    height=120,
                    key=remark_key,
                    placeholder="Enter observations or comments...",
                    label_visibility="collapsed",
                )

                if remark_text != step_data["remark"]:
                    state_mgr.save_step_data(step_num, remark=remark_text)
                    st.info("💾 Remark auto-saved")

                st.markdown("---")

                if not is_completed:
                    if st.button(
                        f"✅ Mark Step {step_num} as Complete",
                        key=f"complete_{rule_number}_{step_num}",
                        type="primary",
                    ):
                        state_mgr.mark_step_complete(step_num)
                        st.success(f"✅ Step {step_num} marked as complete!")
                        st.rerun()

        # Final download section
        if state_mgr.is_all_complete(len(enhanced_steps)):
            st.markdown("---")
            st.success("🎉 All steps completed!")

            final_excel = generate_final_excel(
                template_df,
                state_mgr.get_all_remarks(),
                state_mgr.get_all_outputs(),
                rule_number,
            )

            filename = f"triaging_complete_{rule_number.replace('#', '_')}.xlsx"

            col1, col2, col3 = st.columns([1, 2, 1])
            with col2:
                st.download_button(
                    label="📥 Download Complete Template & Unlock Predictions",
                    data=final_excel,
                    file_name=filename,
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    type="primary",
                    on_click=lambda: unlock_predictions(
                        final_excel, filename, rule_number
                    ),
                )

    with tab2:
        st.markdown("### 📊 Excel Template Preview")
        st.dataframe(template_df, width="stretch", height=500)

        st.markdown("---")

        st.download_button(
            label="📥 Download Base Template",
            data=excel_data,
            file_name=f"triaging_base_{rule_number.replace('#', '_')}.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )


def _is_ip_reputation_step(step: dict) -> bool:
    """Check if step is an IP reputation step"""
    step_name_lower = step.get("step_name", "").lower()
    explanation_lower = step.get("explanation", "").lower()

    return (
        ("virustotal" in step_name_lower)
        or ("virustotal" in explanation_lower)
        or ("virus total" in step_name_lower)
        or ("virus total" in explanation_lower)
        or (contains_ip_not_vip(step_name_lower) and "reputation" in step_name_lower)
    )


def _process_ip_reputation_check(
    ip_input: str, step_num: int, rule_number: str, state_mgr: TriagingStateManager
):
    """Process IP reputation check and display results"""
    import re

    ip_list = re.split(r"[,\n\s]+", ip_input)
    ip_list = [ip.strip() for ip in ip_list if ip.strip()]

    if not ip_list:
        st.error("❌ No valid IP addresses found.")
        return

    st.info(f"🔍 Processing {len(ip_list)} IP address(es)...")

    if "ip_checker" not in st.session_state:
        st.session_state.ip_checker = IPReputationChecker()

    checker = st.session_state.ip_checker

    progress_bar = st.progress(0)
    results = checker.check_multiple_ips(ip_list, method="auto")
    progress_bar.progress(100)
    progress_bar.empty()

    # Aggregate output for Excel
    formatted_output_excel = ""
    for ip, result in results.items():
        if result.get("formatted_output_excel"):
            formatted_output_excel += result["formatted_output_excel"] + "\n\n"

    # Save to state
    state_mgr.save_step_data(step_num, output=formatted_output_excel.strip())

    st.markdown("---")
    st.success(f"✅ Completed checking {len(ip_list)} IP address(es)!")

    # Display summary metrics
    high_risk = sum(1 for r in results.values() if r.get("risk_level") == "HIGH")
    medium_risk = sum(1 for r in results.values() if r.get("risk_level") == "MEDIUM")
    low_risk = sum(
        1 for r in results.values() if r.get("risk_level") in ["LOW", "CLEAN"]
    )
    skipped = sum(1 for r in results.values() if r.get("skip_check", False))

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("🔴 High Risk", high_risk)
    with col2:
        st.metric("🟡 Suspicious", medium_risk)
    with col3:
        st.metric("🟢 Clean", low_risk)
    with col4:
        st.metric("ℹ️ Skipped", skipped)

    st.info("💾 All results have been saved to the Output field for Excel export.")


def generate_final_excel(
    template_df: pd.DataFrame, remarks: dict, outputs: dict, rule_number: str
) -> bytes:
    """Generate final Excel with remarks and outputs"""
    from io import BytesIO

    export_df = template_df.copy()

    remarks_list = []
    outputs_list = []

    for idx, row in export_df.iterrows():
        if pd.isna(row.get("Step")) or str(row.get("Step", "")).strip() == "":
            remarks_list.append("")
            outputs_list.append("")
        else:
            step_num = idx + 1
            remarks_list.append(remarks.get(f"step_{step_num}", ""))
            outputs_list.append(outputs.get(f"step_{step_num}", ""))

    export_df["Output"] = outputs_list
    export_df["Remarks/Comments"] = remarks_list

    output = BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        export_df.to_excel(writer, index=False, sheet_name="Triaging Steps")

    output.seek(0)
    return output.getvalue()


def unlock_predictions(excel_data: bytes, filename: str, rule_number: str):
    """Unlock predictions tab and upload data"""
    st.session_state.triaging_complete = True
    st.session_state.predictions_excel_data = excel_data
    st.session_state.predictions_excel_filename = filename
    st.session_state.predictions_rule_number = rule_number

    try:
        from api_client.predictions_api_client import get_predictions_client
        import os
        from io import BytesIO

        api_key = os.getenv("GOOGLE_API_KEY")
        api_url = os.getenv("PREDICTIONS_API_URL", "http://localhost:8000")

        client = get_predictions_client(api_url, api_key)

        file_obj = BytesIO(excel_data)
        upload_result = client.upload_excel_bytes(file_obj, filename)

        if upload_result.get("success"):
            st.session_state.predictions_uploaded = True
            st.success("✅ Template uploaded to predictions API!")
        else:
            st.session_state.predictions_uploaded = False
            st.error(f"❌ Upload failed: {upload_result.get('error')}")

    except Exception as e:
        st.session_state.predictions_uploaded = False
        st.error(f"❌ Upload error: {str(e)}")

