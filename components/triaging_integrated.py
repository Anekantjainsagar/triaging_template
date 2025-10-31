# ============================================================================
# COMPREHENSIVE FIX: Proper Caching and State Management
# ============================================================================

import streamlit as st
import traceback
import pandas as pd
import hashlib
import json
from datetime import datetime

# ============================================================================
# 1. IMPROVED CACHE KEY GENERATION
# ============================================================================


def get_stable_cache_key(alert_name: str, rule_number: str, is_manual: bool) -> str:
    """Generate stable cache key that persists across reruns"""
    # Create a deterministic hash
    data = f"{alert_name}_{rule_number}_{is_manual}"
    hash_key = hashlib.md5(data.encode()).hexdigest()
    return f"triaging_cache_{hash_key}"


def get_step_state_key(rule_number: str) -> str:
    """Get key for storing step completion state"""
    return f"step_state_{rule_number}"


# ============================================================================
# 2. PERSISTENT STATE MANAGER
# ============================================================================


class TriagingStateManager:
    """Manages triaging state with persistent caching"""

    def __init__(self, rule_number: str):
        self.rule_number = rule_number
        self.state_key = get_step_state_key(rule_number)

        # Initialize state if not exists
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
        """Mark a step as complete WITHOUT rerunning"""
        state = st.session_state[self.state_key]
        state["completed_steps"].add(step_num)
        state["current_open_step"] = step_num + 1
        state["last_updated"] = datetime.now().isoformat()
        # Force state update
        st.session_state[self.state_key] = state

    def save_step_data(self, step_num: int, remark: str = None, output: str = None):
        """Save step data WITHOUT rerunning"""
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
        """Check if all steps are completed"""
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


# ============================================================================
# 3. TEMPLATE CACHE MANAGER
# ============================================================================


class TemplateCacheManager:
    """Manages template generation caching"""

    @staticmethod
    def get_cached_template(cache_key: str):
        """Get cached template if exists"""
        if cache_key in st.session_state:
            cached = st.session_state[cache_key]
            # Verify cache is valid
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


# ============================================================================
# 4. FIXED TRIAGING WORKFLOW
# ============================================================================


def display_triaging_workflow(rule_number: str, alert_data: dict = None):
    """
    FIXED: Triaging workflow with proper caching and NO unnecessary reruns
    Now properly passes alert_data to template generator for KQL injection

    Args:
        rule_number: Rule identifier
        alert_data: Full alert data dictionary (with entities and timestamps)
    """

    st.markdown("## 🔍 AI-Powered Template Enhancement")
    st.markdown("---")

    # Extract alert info
    alert_name = alert_data.get("title") or alert_data.get("alert_name") or rule_number
    is_manual = alert_data.get("source") == "alert_details" or alert_data.get(
        "is_manual", False
    )

    # ✅ DEBUG: Check if we have alert_data for KQL injection
    st.info(f"🔍 Alert Data Status: {'✅ Available' if alert_data else '❌ Missing'}")
    if alert_data:
        entities = alert_data.get("entities", {})
        entities_list = (
            entities.get("entities", []) if isinstance(entities, dict) else entities
        )
        st.info(f"📊 Entities found: {len(entities_list)}")

        # Show extracted entities for debugging
        if entities_list:
            with st.expander("🔍 View Extracted Entities", expanded=False):
                for entity in entities_list[:5]:  # Show first 5
                    kind = entity.get("kind", "Unknown")
                    props = entity.get("properties", {})
                    if kind == "Account":
                        account_name = props.get("accountName", "")
                        upn_suffix = props.get("upnSuffix", "")
                        st.write(
                            f"👤 {account_name}@{upn_suffix}"
                            if upn_suffix
                            else f"👤 {account_name}"
                        )
                    elif kind == "Ip":
                        st.write(f"🌐 {props.get('address', '')}")
                    elif kind == "Host":
                        st.write(f"💻 {props.get('hostName', '')}")

    # Generate stable cache key
    cache_key = get_stable_cache_key(alert_name, rule_number, is_manual)

    # Initialize state manager
    state_mgr = TriagingStateManager(rule_number)

    # ===== STEP 1: Check Cache First =====
    cached_template = TemplateCacheManager.get_cached_template(cache_key)

    if cached_template:
        st.success("✅ Using cached template (no API calls needed)")

        # Use cached data
        enhanced_steps = cached_template["enhanced_steps"]
        template_df = cached_template["template_df"]
        excel_data = cached_template["excel_data"]

    else:
        # ===== STEP 2: Generate Template (Only Once) =====
        st.info("🤖 Generating investigation template...")

        try:
            with st.spinner("⏳ This may take 30-60 seconds..."):
                # Import generator
                from routes.src.template_generator import ImprovedTemplateGenerator

                gen = ImprovedTemplateGenerator()

                # ✅ CRITICAL FIX: Pass alert_data for KQL injection
                analysis_text = alert_data.get("analysis_text", "")

                if is_manual:
                    # For manual alerts, use generate_from_manual_analysis with alert_data
                    template_df = gen.generate_from_manual_analysis(
                        alert_name=alert_name,
                        analysis_text=analysis_text,
                        rule_number=rule_number,
                        alert_data=alert_data,  # ✅ PASS alert_data HERE
                    )
                else:
                    # For template-based alerts, generate and then inject
                    template_df = gen.generate_intelligent_template(
                        rule_number=rule_number,
                        original_steps=[],
                        rule_context=alert_name,
                    )

                    # ✅ INJECT ALERT DATA into the generated template
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

                # ===== CACHE THE RESULTS =====
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

    # ===== STEP 3: Display Interactive Steps =====
    display_interactive_steps(
        enhanced_steps, template_df, excel_data, rule_number, state_mgr
    )


# ============================================================================
# 5. INTERACTIVE STEPS DISPLAY (NO RERUNS)
# ============================================================================


def display_interactive_steps(
    enhanced_steps: list,
    template_df: pd.DataFrame,
    excel_data: bytes,
    rule_number: str,
    state_mgr: TriagingStateManager,
):
    """Display steps with accordion navigation WITHOUT unnecessary reruns"""

    st.markdown("---")
    st.markdown(f"### 📋 {len(enhanced_steps)} Investigation Steps")

    # Create tabs
    tab1, tab2 = st.tabs(["📋 Triaging Steps", "📊 Excel Template"])

    with tab1:
        # Display each step in accordion
        for idx, step in enumerate(enhanced_steps):
            step_num = idx + 1
            step_name = step.get("step_name", f"Step {step_num}")

            # Get step state
            is_completed = state_mgr.is_step_completed(step_num)
            is_current = step_num == state_mgr.get_current_open_step()
            is_locked = step_num > 1 and not state_mgr.is_step_completed(step_num - 1)

            # Status icon
            if is_completed:
                status_icon = "✅"
            elif is_locked:
                status_icon = "🔒"
            else:
                status_icon = "⏳"

            # Display step accordion
            with st.expander(
                f"{status_icon} Step {step_num}: {step_name}",
                expanded=(is_current and not is_completed and not is_locked),
            ):

                if is_locked:
                    st.warning("🔒 Complete the previous step to unlock this one")
                    continue

                # Step explanation
                st.write(step.get("explanation", "No explanation provided"))

                # KQL Query section
                kql_query = step.get("kql_query", "")
                if kql_query and len(kql_query) > 5:
                    st.markdown("##### 🔎 KQL Query")

                    kql_explanation = step.get("kql_explanation", "")
                    if kql_explanation:
                        st.write(kql_explanation)

                    st.code(kql_query, language="kql")

                    # Output section
                    st.markdown("##### 📊 Output")

                    # Get saved output
                    step_data = state_mgr.get_step_data(step_num)

                    # Create unique key for this specific step's output
                    output_key = f"output_{rule_number}_{step_num}"

                    output_text = st.text_area(
                        "Enter the KQL query output:",
                        value=step_data["output"],
                        height=200,
                        key=output_key,
                        placeholder="Paste the query results here...",
                    )

                    # Save on change (no rerun)
                    if output_text != step_data["output"]:
                        state_mgr.save_step_data(step_num, output=output_text)
                        st.info("💾 Output auto-saved")

                # Remarks section
                st.markdown("##### 💬 Remarks/Comments")

                step_data = state_mgr.get_step_data(step_num)

                # Create unique key for this specific step's remark
                remark_key = f"remark_{rule_number}_{step_num}"

                remark_text = st.text_area(
                    "Add remarks:",
                    value=step_data["remark"],
                    height=120,
                    key=remark_key,
                    placeholder="Enter observations or comments...",
                    label_visibility="collapsed",
                )

                # Save on change (no rerun)
                if remark_text != step_data["remark"]:
                    state_mgr.save_step_data(step_num, remark=remark_text)
                    st.info("💾 Remark auto-saved")

                st.markdown("---")

                # Complete button
                if not is_completed:
                    if st.button(
                        f"✅ Mark Step {step_num} as Complete",
                        key=f"complete_{rule_number}_{step_num}",
                        type="primary",
                    ):
                        state_mgr.mark_step_complete(step_num)
                        st.success(f"✅ Step {step_num} marked as complete!")
                        st.rerun()  # Only rerun after completion

        # Final download section
        if state_mgr.is_all_complete(len(enhanced_steps)):
            st.markdown("---")
            st.success("🎉 All steps completed!")

            # Generate final Excel with all data
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
        # Excel preview
        st.markdown("### 📊 Excel Template Preview")
        st.dataframe(template_df, use_container_width=True, height=500)

        st.markdown("---")

        st.download_button(
            label="📥 Download Base Template",
            data=excel_data,
            file_name=f"triaging_base_{rule_number.replace('#', '_')}.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )


# ============================================================================
# 6. HELPER FUNCTIONS
# ============================================================================


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

    # Trigger upload
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


# ============================================================================
# USAGE EXAMPLE
# ============================================================================
"""
# In your main.py, replace the existing call with:

from components.triaging_fixed import display_triaging_workflow_fixed

# Then in your display_ai_analysis function:
with tab3:
    if triaging_cache_key in st.session_state:
        st.success("✅ Triaging already completed!")
        # Show cached download
    else:
        display_triaging_workflow_fixed(
            rule_number,
            alert_data=enhanced_alert_data
        )
"""
