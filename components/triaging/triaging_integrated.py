import streamlit as st
import traceback
import pandas as pd
import hashlib
from datetime import datetime
import os
import re
import time

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
    """Execute KQL query and save results with enhanced table display"""
    try:
        if "kql_executor" not in st.session_state:
            st.session_state.kql_executor = KQLExecutor()

        executor = st.session_state.kql_executor

        with st.spinner("🔄 Executing KQL query..."):
            success, formatted_output, raw_results, dataframe = executor.execute_query(
                kql_query
            )

        if success:
            output_key = f"output_{rule_number}_{step_num}"
            df_key = f"dataframe_{rule_number}_{step_num}"

            # Save to state manager
            state_mgr.save_step_data(step_num, output=formatted_output)

            # Save to session state for immediate display
            st.session_state[output_key] = formatted_output
            st.session_state[df_key] = dataframe

            # Force state update to persist
            st.session_state[state_mgr.state_key]["step_outputs"][
                f"step_{step_num}"
            ] = formatted_output
            st.session_state[state_mgr.state_key][
                "last_updated"
            ] = datetime.now().isoformat()

            print(f"✅ Output saved for step {step_num}: {len(formatted_output)} chars")

            return True, formatted_output, dataframe
        else:
            st.error(f"❌ Query execution failed: {formatted_output}")
            return False, None, None

    except Exception as e:
        st.error(f"❌ Execution error: {str(e)}")
        return False, None, None


def _extract_users_from_entities(alert_data: dict) -> list:
    """
    Extract user accounts from alert entities

    Returns:
        List of unique user email addresses
    """
    all_users = []

    if not alert_data:
        return all_users

    # Extract from entities
    entities = alert_data.get("entities", {})
    entities_list = (
        entities.get("entities", [])
        if isinstance(entities, dict)
        else (entities if isinstance(entities, list) else [])
    )

    for entity in entities_list:
        kind = entity.get("kind", "").lower()
        if kind == "account":
            props = entity.get("properties", {})
            account_name = props.get("accountName", "")
            upn_suffix = props.get("upnSuffix", "")

            if account_name and upn_suffix:
                all_users.append(f"{account_name}@{upn_suffix}")
            elif account_name:
                all_users.append(account_name)

    # Remove duplicates while preserving order
    seen = set()
    unique_users = []
    for user in all_users:
        if user not in seen:
            seen.add(user)
            unique_users.append(user)

    return unique_users


def _is_vip_user_check_step(step: dict) -> bool:
    """Check if step is a VIP user verification step"""
    input_required = step.get("input_required", "")
    step_name_lower = step.get("step_name", "").lower()
    explanation_lower = step.get("explanation", "").lower()

    # Check for input_required flag first
    if input_required == "vip_user_list":
        return True

    # Fallback: Check step name/explanation
    vip_indicators = [
        "vip",
        "high-priority",
        "privileged account",
        "executive account",
        "verify user account status",
    ]

    return any(
        indicator in step_name_lower or indicator in explanation_lower
        for indicator in vip_indicators
    )


def _generate_vip_kql_query(
    vip_users: list, entity_users: list, alert_data: dict
) -> str:
    from datetime import timedelta

    # ✅ EXTRACT timeGenerated FROM alert_data (from full_alert.properties)
    props = alert_data.get("full_alert", {})
    props = props.get("properties", {})
    time_generated_str = props.get("timeGenerated")

    if time_generated_str:
        try:
            # Parse the timeGenerated datetime
            from datetime import datetime

            reference_datetime_obj = datetime.fromisoformat(
                time_generated_str.replace("Z", "+00:00")
            )
            reference_datetime = reference_datetime_obj.strftime("%Y-%m-%d %H:%M:%S")

            # Calculate 7-day lookback
            start_dt = reference_datetime_obj - timedelta(days=7)
            start_dt_str = start_dt.strftime("%Y-%m-%d %H:%M:%S")

        except Exception as e:
            # Fallback to current time if parsing fails
            from datetime import datetime

            reference_datetime_obj = datetime.utcnow()
            reference_datetime = reference_datetime_obj.strftime("%Y-%m-%d %H:%M:%S")
            start_dt = reference_datetime_obj - timedelta(days=7)
            start_dt_str = start_dt.strftime("%Y-%m-%d %H:%M:%S")
    else:
        # Fallback: use current time if timeGenerated not found
        from datetime import datetime

        reference_datetime_obj = datetime.utcnow()
        reference_datetime = reference_datetime_obj.strftime("%Y-%m-%d %H:%M:%S")
        start_dt = reference_datetime_obj - timedelta(days=7)
        start_dt_str = start_dt.strftime("%Y-%m-%d %H:%M:%S")

    # Format VIP users for datatable
    vip_users_formatted = ",\n    ".join([f'"{user}"' for user in vip_users])

    # Format entity users for filter
    entity_users_formatted = ", ".join([f'"{user}"' for user in entity_users])

    # ✅ BUILD STRUCTURED KQL QUERY WITH 7-DAY LOOKBACK
    kql_query = f"""// VIP User Verification Query
// Alert Time Generated: {reference_datetime}Z
// Query Time Range: {start_dt_str}Z to {reference_datetime}Z (7 days)
// Analyst-provided VIP users: {len(vip_users)} user(s)
// Alert-affected users: {len(entity_users)} user(s)

let VIPUsers = datatable(UserPrincipalName:string)
[
    {vip_users_formatted}
];
SigninLogs
| where TimeGenerated > datetime({start_dt_str}Z) and TimeGenerated <= datetime({reference_datetime}Z)
| where UserPrincipalName in ({entity_users_formatted})
| extend IsVIP = iff(UserPrincipalName in (VIPUsers), "⭐ VIP ACCOUNT", "Regular User")
| summarize
TotalSignIns = count(),
    UniqueIPAddresses = dcount(IPAddress),
    UniqueCountries = dcount(tostring(LocationDetails.countryOrRegion)),
    HighRiskSignIns = countif(RiskLevelAggregated == "high"),
    MediumRiskSignIns = countif(RiskLevelAggregated == "medium"),
    FailedAttempts = countif(ResultType != "0"),
    SuccessfulSignIns = countif(ResultType == "0")
    by UserPrincipalName, UserDisplayName, IsVIP
| extend
    VIPRiskScore = (HighRiskSignIns * 10) + (MediumRiskSignIns * 5) + (FailedAttempts * 2) + (UniqueCountries * 3)
| extend
    AccountClassification = case(
        VIPRiskScore > 30, "🔴 Critical - Executive at High Risk",
        VIPRiskScore > 15, "🟠 High - VIP Requires Attention",
        VIPRiskScore > 5, "🟡 Medium - Monitor Closely", 
        "🟢 Low - Normal Activity"
    )
| project-reorder UserPrincipalName, UserDisplayName, IsVIP, AccountClassification, VIPRiskScore
| order by VIPRiskScore desc"""

    return kql_query


def _process_vip_user_check(
    vip_input: str,
    entity_users: list,
    step_num: int,
    rule_number: str,
    state_mgr: TriagingStateManager,
    alert_data: dict,
):
    """
    Process VIP user verification step with full emoji support

    Flow:
    1. Parse VIP user input (comma/newline separated emails)
    2. Check if any alert entities are VIP users
    3. Show template query first
    4. Generate customized KQL query with VIP list + entity users
    5. Display query and execute button
    6. Save results to state
    """
    import re

    # ===================================================================
    # STEP 1: Parse VIP user list from user input
    # ===================================================================
    # Split by comma, newline, or space
    vip_list = re.split(r"[,\n\s]+", vip_input)

    # Clean up: remove empty strings and keep only valid emails
    vip_list = [user.strip() for user in vip_list if user.strip() and "@" in user]

    if not vip_list:
        st.error(
            "❌ No valid email addresses found in VIP list. Please enter at least one email."
        )
        return

    st.success(f"✅ Parsed {len(vip_list)} VIP user(s) from input")

    # ===================================================================
    # STEP 2: Display parsed VIP users
    # ===================================================================
    with st.expander("📋 VIP Users Entered", expanded=True):
        for vip_user in vip_list:
            st.code(vip_user)

    # ===================================================================
    # STEP 3: Check if any entity users are VIP
    # ===================================================================
    # Compare entity users (from alert) with VIP list
    vip_matches = [user for user in entity_users if user in vip_list]

    if vip_matches:
        st.error(
            f"🚨 **CRITICAL ALERT:** {len(vip_matches)} VIP account(s) detected in this incident!"
        )
        for vip_user in vip_matches:
            st.error(f"⭐ VIP Account Affected: **{vip_user}**")
    else:
        st.success("✅ No VIP accounts detected among affected users.")

    st.markdown("---")

    # ===================================================================
    # STEP 5: Generate Customized Query
    # ===================================================================
    st.info("🔨 Generating customized KQL query with your VIP list...")

    # Generate the customized query
    kql_query = _generate_vip_kql_query(vip_list, entity_users, alert_data)

    st.markdown("##### ✏️ Edit Query Before Execution")
    st.caption("You can modify the generated query if needed")
    
    # Make the KQL query editable
    query_edit_key = f"vip_editable_kql_{rule_number}_{step_num}"
    if query_edit_key not in st.session_state:
        st.session_state[query_edit_key] = kql_query
    
    edited_kql_query = st.text_area(
        "Editable KQL Query:",
        value=st.session_state[query_edit_key],
        height=300,
        key=f"vip_kql_editor_{step_num}",
        help="✏️ Modify this query as needed before execution",
        label_visibility="collapsed"
    )
    
    # Update session state when query changes
    st.session_state[query_edit_key] = edited_kql_query
    
    st.markdown("---")

    # ===================================================================
    # STEP 7: Execute Button
    # ===================================================================
    col1, col2, col3 = st.columns([2, 1, 2])
    with col2:
        execute_clicked = st.button(
            "▶️ Execute Query",
            key=f"exec_vip_kql_{step_num}",
            type="primary",
            width="stretch",
        )

    # ===================================================================
    # STEP 8: Execute Query if Button Clicked
    # ===================================================================
    if execute_clicked:
        # Validate workspace configuration
        if not os.getenv("LOG_ANALYTICS_WORKSPACE_ID"):
            st.error(
                "❌ Log Analytics Workspace ID not configured. Please check your environment variables."
            )
        else:
            # Execute the EDITED KQL query (not the original)
            success, output, dataframe = _execute_kql_query(
                step_num, rule_number, edited_kql_query, state_mgr
            )

            if success:
                st.success("✅ VIP user verification query executed successfully!")
                _display_query_results(
                    output, dataframe, step_num, rule_number, state_mgr
                )
            else:
                st.error("❌ Query execution failed. Check the error details above.")

    # ===================================================================
    # STEP 11: Show Existing Output if Already Executed
    # ===================================================================
    else:
        # Check if this step was already executed before
        step_data = state_mgr.get_step_data(step_num)
        existing_output = step_data["output"]

        if existing_output:
            df_key = f"dataframe_{rule_number}_{step_num}"
            existing_df = st.session_state.get(df_key)
            _display_query_results(
                existing_output,
                existing_df,
                step_num,
                rule_number,
                state_mgr,
                is_existing=True,
            )
            st.info("💡 Click 'Execute Query' above to run again with updated data")


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


def display_triaging_workflow_cached(
    rule_number: str, alert_data: dict, cache_key: str, analysis_key: str
):
    # ✅ DEBUG: Show what we're passing to triaging
    st.info(f"🚀 Starting triaging for: {alert_data.get('title', 'Unknown Alert')}")

    # ✅ ENHANCEMENT: Extract technical overview from alert analysis if available
    if analysis_key in st.session_state and st.session_state[analysis_key]:
        analysis_result = st.session_state[analysis_key]
        if analysis_result.get("success") and analysis_result.get("analysis"):
            analysis_text = analysis_result.get("analysis", "")
            
            # Extract technical overview section
            technical_overview = ""
            if "## 1. TECHNICAL OVERVIEW" in analysis_text:
                sections = analysis_text.split("##")
                for section in sections:
                    if "1. TECHNICAL OVERVIEW" in section:
                        # Clean up the technical overview
                        technical_overview = section.replace("1. TECHNICAL OVERVIEW", "").strip()
                        break
            
            # Add technical overview to alert_data
            if technical_overview:
                alert_data["technical_overview"] = technical_overview
                alert_data["analysis_text"] = analysis_text
                st.success(f"✅ Technical overview extracted ({len(technical_overview)} chars)")

    # Call the original triaging workflow with enhanced alert_data
    display_triaging_workflow(rule_number, alert_data=alert_data)

    # ✅ MONITOR FOR COMPLETION
    # When triaging completes and Excel is generated, cache it
    if st.session_state.get("triaging_complete"):
        if f"excel_cache_{analysis_key}" not in st.session_state:
            # Store the Excel data in permanent cache
            excel_data = st.session_state.get("predictions_excel_data")
            excel_filename = st.session_state.get("predictions_excel_filename")

            if excel_data and excel_filename:
                st.session_state[f"excel_cache_{analysis_key}"] = excel_data
                st.session_state[f"excel_filename_{analysis_key}"] = excel_filename
                st.session_state[cache_key] = True  # Mark as done

                st.success(
                    "✅ Template cached! You can now switch tabs without losing progress."
                )
                st.info("💡 Refresh the page to see the cached version")



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
    
    col1, col2 = st.columns([3, 1])
    with col1:
        st.markdown(f"### 📋 {len(enhanced_steps)} Investigation Steps")
    with col2:
        auto_execute = st.button(
            "⚡ AUTO-EXECUTE ALL STEPS",
            type="primary",
            help="Automatically execute all KQL queries, VIP checks, and IP reputation checks",
            key=f"auto_execute_{rule_number}"
        )
    
    if auto_execute:
        # Execute all steps automatically
        entity_users = _extract_users_from_entities(alert_data) if alert_data else []
        entity_ips = _extract_ips_from_entities(alert_data) if alert_data else []
        default_vip_users = ["ceo@company.com", "cfo@company.com", "admin@company.com"]
        
        # Create containers for progress display
        progress_container = st.container()
        status_container = st.container()
        
        with progress_container:
            # st.markdown("### 🚀 **Executing Investigation Steps**")
            progress_bar = st.progress(0)
            current_step_text = st.empty()
        
        with status_container:
            step_status = st.empty()
        
        for idx, step in enumerate(enhanced_steps):
            step_num = idx + 1
            step_name = step.get("step_name", f"Step {step_num}")
            
            # Update progress
            progress = idx / len(enhanced_steps)
            progress_bar.progress(progress)
            current_step_text.info(f"🔄 **Step {step_num}/{len(enhanced_steps)}:** {step_name}")
            
            # VIP check
            if _is_vip_user_check_step(step) and entity_users:
                step_status.info("🔍 Checking VIP users...")
                kql_query = _generate_vip_kql_query(default_vip_users, entity_users, alert_data)
                success, output, dataframe = _execute_kql_query(step_num, rule_number, kql_query, state_mgr)
                if success:
                    vip_matches = [user for user in entity_users if user in default_vip_users]
                    vip_analysis = f"\nVIP Analysis: {len(vip_matches)} VIP matches found" if vip_matches else "\nVIP Analysis: No VIP users affected"
                    combined_output = output + vip_analysis
                    state_mgr.save_step_data(step_num, output=combined_output, remark="Auto-executed")
                    st.session_state[f"dataframe_{rule_number}_{step_num}"] = dataframe
                    step_status.success(f"✅ VIP check complete - {len(vip_matches)} matches found" if vip_matches else "✅ VIP check complete - No VIP users affected")
            
            # IP reputation check
            elif _is_ip_reputation_step(step) and entity_ips:
                step_status.info(f"🔍 Checking {len(entity_ips)} IP addresses...")
                if "ip_checker" not in st.session_state:
                    st.session_state.ip_checker = IPReputationChecker()
                results = st.session_state.ip_checker.check_multiple_ips(entity_ips, method="auto")
                output_excel = "\n\n".join([r.get("formatted_output_excel", "") for r in results.values() if r.get("formatted_output_excel")])
                state_mgr.save_step_data(step_num, output=output_excel, remark="Auto-executed")
                st.session_state[f"ip_results_{rule_number}_{step_num}"] = results
                
                high_risk = sum(1 for r in results.values() if r.get("risk_level") == "HIGH")
                vpn_count = sum(1 for r in results.values() if r.get("vpn_detection", {}).get("is_vpn", False))
                step_status.success(f"✅ IP check complete - {high_risk} high risk, {vpn_count} VPN detected")
            
            # KQL query steps
            elif step.get("kql_query") and len(step.get("kql_query", "").strip()) > 10:
                step_status.info("🔍 Executing KQL query...")
                success, output, dataframe = _execute_kql_query(step_num, rule_number, step.get("kql_query"), state_mgr)
                if success:
                    state_mgr.save_step_data(step_num, remark="Auto-executed")
                    result_count = len(dataframe) if dataframe is not None and not dataframe.empty else 0
                    step_status.success(f"✅ Query complete - {result_count} results")
                else:
                    step_status.error("❌ Query failed")
            
            else:
                step_status.info("📝 Marking for manual review...")
                state_mgr.save_step_data(step_num, remark="Auto-reviewed - manual verification needed")
                step_status.success("✅ Marked for manual review")
            
            # Mark complete
            state_mgr.mark_step_complete(step_num)
            time.sleep(0.5)  # Brief pause to show progress
        
        # Final progress update
        progress_bar.progress(1.0)
        current_step_text.success(f"🎉 **All {len(enhanced_steps)} steps completed successfully!**")
        step_status.success("✅ Investigation complete - All results saved to Excel template")
        
        time.sleep(2)
        progress_container.empty()
        status_container.empty()
        st.rerun()
    
    st.markdown("---")

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

                # ✅ NEW: Check if this is a VIP user check step
                if _is_vip_user_check_step(step):
                    st.markdown("##### 👤 VIP User Verification")

                    # Extract users from alert
                    entity_users = (
                        _extract_users_from_entities(alert_data) if alert_data else []
                    )

                    if entity_users:
                        st.success(
                            f"✅ Found {len(entity_users)} user account(s) from alert entities"
                        )
                        with st.expander("👥 View Affected Users", expanded=True):
                            for user in entity_users:
                                st.code(user)
                    else:
                        st.warning(
                            "⚠️ No user accounts found in alert entities. Please verify manually."
                        )

                    st.markdown("---")

                    # ===================================================================
                    # ✅ FIX: Use session state to persist VIP input across reruns
                    # ===================================================================
                    vip_input_key = f"vip_input_{rule_number}_{step_num}"
                    vip_processed_key = f"vip_processed_{rule_number}_{step_num}"

                    # Initialize session state for this step
                    if vip_input_key not in st.session_state:
                        st.session_state[vip_input_key] = (
                            "ceo@company.com, cfo@company.com, admin@company.com"
                        )

                    if vip_processed_key not in st.session_state:
                        st.session_state[vip_processed_key] = False

                    # ===================================================================
                    # STEP 1: VIP Input Form (only show if not processed yet)
                    # ===================================================================
                    if not st.session_state[vip_processed_key]:
                        st.markdown("##### 🔐 Enter VIP/Executive User List")
                        st.caption(
                            "Enter VIP user email addresses (one per line, comma-separated, or space-separated)"
                        )
                        st.caption(
                            "✅ Example: ceo@company.com, cfo@company.com, admin@company.com"
                        )

                        # VIP user input text area
                        vip_input = st.text_area(
                            "VIP Users:",
                            placeholder="Enter VIP user emails:\nceo@company.com\nadmin@company.com\nexecutive@company.com",
                            key=f"vip_users_textarea_{step_num}",
                            height=150,
                            label_visibility="collapsed",
                            value=st.session_state[vip_input_key],  # ✅ Persist value
                        )

                        # Update session state when input changes
                        st.session_state[vip_input_key] = vip_input

                        col1, col2, col3 = st.columns([2, 2, 1])
                        with col3:
                            check_button = st.button(
                                "🔍 Generate & Process",
                                key=f"vip_check_step_{step_num}",
                                type="primary",
                                width="stretch",
                            )

                        if check_button:
                            if not vip_input:
                                st.error(
                                    "❌ Please enter at least one VIP user email address."
                                )
                            elif not entity_users:
                                st.error(
                                    "❌ No affected users found. Cannot generate query."
                                )
                            else:
                                # Mark as processed
                                st.session_state[vip_processed_key] = True
                                st.rerun()  # Rerun to show results

                    # ===================================================================
                    # STEP 2: Show Results and Execute Query (after processing)
                    # ===================================================================
                    else:
                        # Retrieve the saved VIP input
                        vip_input = st.session_state[vip_input_key]

                        if vip_input and entity_users:
                            # Call the processing function
                            _process_vip_user_check(
                                vip_input,
                                entity_users,
                                step_num,
                                rule_number,
                                state_mgr,
                                alert_data,
                            )

                            # Add a "Reset" button to go back and change VIP list
                            st.markdown("---")
                            col1, col2, col3 = st.columns([2, 2, 1])
                            with col3:
                                if st.button(
                                    "🔄 Change VIP List",
                                    key=f"reset_vip_{step_num}",
                                    width="stretch",
                                ):
                                    st.session_state[vip_processed_key] = False
                                    st.session_state[vip_input_key] = ""
                                    st.rerun()
                    
                    # Show auto-executed results if available
                    step_data = state_mgr.get_step_data(step_num)
                    if step_data["output"] and not st.session_state.get(vip_processed_key, False):
                        st.markdown("##### 📊 Auto-Executed Results")
                        df_key = f"dataframe_{rule_number}_{step_num}"
                        existing_df = st.session_state.get(df_key)
                        _display_query_results(
                            step_data["output"],
                            existing_df,
                            step_num,
                            rule_number,
                            state_mgr,
                            is_existing=True,
                        )

                # KQL Query section
                elif kql_query and len(kql_query.strip()) > 10:
                    st.markdown("##### 🔎 KQL Query")

                    kql_explanation = step.get("kql_explanation", "")
                    if kql_explanation:
                        st.write(kql_explanation)

                    # Editable KQL Query - ALWAYS EDITABLE
                    query_key = f"editable_kql_{rule_number}_{step_num}"
                    if query_key not in st.session_state:
                        st.session_state[query_key] = kql_query

                    # Make query editable for ALL steps including VIP
                    edited_query = st.text_area(
                        "KQL Query (editable):",
                        value=st.session_state[query_key],
                        height=200,
                        key=f"kql_editor_{step_num}",
                        help="✏️ You can modify this query before execution",
                        disabled=False  # Ensure it's always editable
                    )

                    # Update session state when query changes
                    st.session_state[query_key] = edited_query

                    col1, col2, col3 = st.columns([2, 1, 2])
                    with col2:
                        execute_clicked = st.button(
                            "▶️ Execute Query",
                            key=f"execute_kql_{step_num}",
                            type="primary",
                            width="stretch",
                        )

                    if execute_clicked:
                        if not os.getenv("LOG_ANALYTICS_WORKSPACE_ID"):
                            st.error("❌ Log Analytics Workspace ID not configured.")
                        else:
                            success, output, dataframe = _execute_kql_query(
                                step_num, rule_number, edited_query, state_mgr
                            )

                            if success:
                                st.success("✅ Query executed successfully!")
                                _display_query_results(
                                    output, dataframe, step_num, rule_number, state_mgr
                                )

                    else:
                        # Show existing output if any
                        step_data = state_mgr.get_step_data(step_num)
                        existing_output = step_data["output"]
                        df_key = f"dataframe_{rule_number}_{step_num}"
                        existing_df = st.session_state.get(df_key)

                        if existing_output:
                            _display_query_results(
                                existing_output,
                                existing_df,
                                step_num,
                                rule_number,
                                state_mgr,
                                is_existing=True,
                            )

                # IP Reputation section with VPN detection
                elif _is_ip_reputation_step(step):

                    # Extract IPs directly from entities
                    entity_ips = (
                        _extract_ips_from_entities(alert_data) if alert_data else []
                    )

                    if entity_ips:
                        st.success(
                            f"✅ Found {len(entity_ips)} IP address(es) from alert entities"
                        )

                    st.markdown("##### 📝 Enter Additional IPs (optional)")
                    st.caption(
                        "🔐 VPN, Proxy, and Tor detection included automatically"
                    )

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
                            "🔍 Check IPs + VPN",
                            key=f"vt_check_step_{step_num}",
                            type="primary",
                            width="stretch",
                        )

                    if check_button and ip_input:
                        _process_ip_reputation_check(
                            ip_input, step_num, rule_number, state_mgr
                        )
                    
                    # Show auto-executed IP results if available
                    step_data = state_mgr.get_step_data(step_num)
                    ip_results_key = f"ip_results_{rule_number}_{step_num}"
                    if step_data["output"] and ip_results_key in st.session_state:
                        st.markdown("##### 📊 Auto-Executed IP Results")
                        results = st.session_state[ip_results_key]
                        
                        # Display summary metrics
                        high_risk = sum(1 for r in results.values() if r.get("risk_level") == "HIGH")
                        medium_risk = sum(1 for r in results.values() if r.get("risk_level") == "MEDIUM")
                        vpn_detected = sum(1 for r in results.values() if r.get("vpn_detection", {}).get("is_vpn", False))
                        
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("🔴 High Risk", high_risk)
                        with col2:
                            st.metric("🟡 Medium Risk", medium_risk)
                        with col3:
                            st.metric("🔒 VPN Detected", vpn_detected)
                        with col4:
                            st.metric("📊 Total IPs", len(results))
                        
                        # Show detailed results in expanders
                        for ip, result in results.items():
                            if result.get("formatted_output"):
                                with st.expander(f"🔍 {ip} - {result.get('risk_level', 'Unknown')}", expanded=False):
                                    st.text(result["formatted_output"])

                # Remarks section
                st.markdown("##### 💬 Remarks/Comments")

                step_data = state_mgr.get_step_data(step_num)
                remark_key = f"remark_{rule_number}_{step_num}"

                remark_text = st.text_area(
                    "Add remarks:",
                    value=step_data["remark"],
                    height=70,
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

        # ===================================================================
        # CRITICAL FIX 5: Add explicit save button before download
        # ===================================================================
        if state_mgr.is_all_complete(len(enhanced_steps)):
            st.markdown("---")
            st.success("🎉 All steps completed!")

            # Initialize session state for report preparation
            report_prepared_key = f"report_prepared_{rule_number}"
            if report_prepared_key not in st.session_state:
                st.session_state[report_prepared_key] = False

            # NEW: Add explicit "Prepare Download" button
            col1, col2, col3 = st.columns([1, 2, 1])
            with col2:
                if st.button(
                    "📋 Prepare Final Report",
                    type="secondary",
                    width="stretch",
                    key=f"prepare_report_{rule_number}",
                ):
                    st.info("💾 Saving all outputs to final report...")

                    # Force save all outputs
                    all_outputs = state_mgr.get_all_outputs()
                    all_remarks = state_mgr.get_all_remarks()

                    print(f"\n📊 Final Report Preparation:")
                    print(f"   Total outputs: {len(all_outputs)}")
                    for key, value in all_outputs.items():
                        if value:
                            print(f"   ✅ {key}: {len(value)} chars")

                    # Mark as prepared
                    st.session_state[report_prepared_key] = True
                    st.success("✅ Report prepared! You can now download.")
                    st.rerun()

            st.markdown("---")

            # Only show download button if report is prepared
            if st.session_state[report_prepared_key]:
                # Generate final Excel
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
    """Check if step is an IP reputation step (includes VPN detection)"""
    step_name_lower = step.get("step_name", "").lower()
    explanation_lower = step.get("explanation", "").lower()

    return (
        ("virustotal" in step_name_lower)
        or ("virustotal" in explanation_lower)
        or ("virus total" in step_name_lower)
        or ("virus total" in explanation_lower)
        or ("vpn" in step_name_lower)
        or ("vpn" in explanation_lower)
        or ("proxy" in step_name_lower)
        or ("proxy" in explanation_lower)
        or (contains_ip_not_vip(step_name_lower) and "reputation" in step_name_lower)
    )


def _process_ip_reputation_check(
    ip_input: str, step_num: int, rule_number: str, state_mgr: TriagingStateManager
):
    """Process IP reputation check and display results with VPN detection"""
    import re

    ip_list = re.split(r"[,\n\s]+", ip_input)
    ip_list = [ip.strip() for ip in ip_list if ip.strip()]

    if not ip_list:
        st.error("❌ No valid IP addresses found.")
        return

    st.info(f"🔍 Processing {len(ip_list)} IP address(es) with VPN detection...")

    if "ip_checker" not in st.session_state:
        st.session_state.ip_checker = IPReputationChecker()

    checker = st.session_state.ip_checker

    progress_bar = st.progress(0)
    results = checker.check_multiple_ips(ip_list, method="auto")
    progress_bar.progress(100)
    progress_bar.empty()

    # Display detailed results for each IP - CLOSED BY DEFAULT
    st.markdown("### 📊 Detailed Results")
    for ip, result in results.items():
        if result.get("formatted_output"):
            with st.expander(
                f"🔍 {ip} - {result.get('risk_level', 'Unknown')}", expanded=False  # CLOSED BY DEFAULT
            ):
                st.text(result["formatted_output"])
        elif result.get("skip_check"):
            with st.expander(
                f"ℹ️ {ip} - {result.get('ip_type', 'Skipped')}", expanded=False
            ):
                st.info(result.get("message", "No check needed"))

    # Aggregate output for Excel
    formatted_output_excel = ""
    for ip, result in results.items():
        if result.get("formatted_output_excel"):
            formatted_output_excel += result["formatted_output_excel"] + "\n\n"

    # Save to state
    state_mgr.save_step_data(step_num, output=formatted_output_excel.strip())

    st.success(
        f"✅ Completed checking {len(ip_list)} IP address(es) with VPN detection!"
    )
    st.markdown("---")

    # Display summary metrics including VPN detection
    high_risk = sum(1 for r in results.values() if r.get("risk_level") == "HIGH")
    medium_risk = sum(1 for r in results.values() if r.get("risk_level") == "MEDIUM")
    low_risk = sum(
        1 for r in results.values() if r.get("risk_level") in ["LOW", "CLEAN"]
    )
    skipped = sum(1 for r in results.values() if r.get("skip_check", False))

    # VPN detection metrics
    vpn_detected = sum(
        1 for r in results.values() if r.get("vpn_detection", {}).get("is_vpn", False)
    )
    tor_detected = sum(
        1 for r in results.values() if r.get("vpn_detection", {}).get("is_tor", False)
    )
    proxy_detected = sum(
        1 for r in results.values() if r.get("vpn_detection", {}).get("is_proxy", False)
    )

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("🔴 High Risk", high_risk)
    with col2:
        st.metric("🟡 Suspicious", medium_risk)
    with col3:
        st.metric("🟢 Clean", low_risk)
    with col4:
        st.metric("ℹ️ Skipped", skipped)

    # VPN metrics row (always show)
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("🔒 VPN Detected", vpn_detected)
    with col2:
        st.metric("🕵️ Tor Detected", tor_detected)
    with col3:
        st.metric("🌐 Proxy Detected", proxy_detected)
    with col4:
        total_anonymous = vpn_detected + tor_detected + proxy_detected
        st.metric("⚠️ Total Anonymous", total_anonymous)

    st.info(
        "💾 All results including VPN detection have been saved to the Output field for Excel export."
    )


def generate_final_excel(
    template_df: pd.DataFrame, remarks: dict, outputs: dict, rule_number: str
) -> bytes:
    """
    Generate final Excel with remarks and outputs

    FIXED: Ensures all outputs including last step are saved correctly
    """
    from io import BytesIO

    export_df = template_df.copy()

    remarks_list = []
    outputs_list = []

    # Process each row in the template
    for idx, row in export_df.iterrows():
        # Skip header rows (rows without a valid Step number)
        if pd.isna(row.get("Step")) or str(row.get("Step", "")).strip() == "":
            remarks_list.append("")
            outputs_list.append("")
        else:
            step_num = idx + 1

            # Retrieve remark and output from state
            remark_key = f"step_{step_num}"
            output_key = f"step_{step_num}"

            # Get remark (prioritize from remarks dict, fallback to existing in df)
            remark = remarks.get(remark_key, "")
            if not remark and "Remarks/Comments" in row:
                remark = str(row.get("Remarks/Comments", ""))

            # Get output (prioritize from outputs dict, fallback to existing in df)
            output = outputs.get(output_key, "")
            if not output and "Output" in row:
                output = str(row.get("Output", ""))

            # Debug print to verify data
            if output:
                print(f"   ✅ Step {step_num}: Output saved ({len(output)} chars)")
            else:
                print(f"   ⚠️ Step {step_num}: No output")

            remarks_list.append(remark)
            outputs_list.append(output)

    # Update DataFrame with collected data
    export_df["Output"] = outputs_list
    export_df["Remarks/Comments"] = remarks_list

    # Generate Excel file
    output = BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        export_df.to_excel(writer, index=False, sheet_name="Triaging Steps")

        # Apply formatting
        workbook = writer.book
        worksheet = writer.sheets["Triaging Steps"]

        # Auto-adjust column widths for better readability
        for column_cells in worksheet.columns:
            length = max(len(str(cell.value or "")) for cell in column_cells)
            worksheet.column_dimensions[column_cells[0].column_letter].width = min(
                length + 2, 100
            )

    output.seek(0)
    print(f"\n✅ Excel generated with {len(outputs_list)} rows")
    return output.getvalue()


def _display_query_results(
    output: str,
    dataframe: pd.DataFrame,
    step_num: int,
    rule_number: str,
    state_mgr: TriagingStateManager,
    is_existing: bool = False,
):
    """
    Display query results in enhanced tabular format with editable output
    """
    if is_existing:
        st.markdown("##### 📊 Saved Results (from previous execution)")
    else:
        st.markdown("##### 📊 Query Results")

    # Display results count
    if dataframe is not None and not dataframe.empty:
        st.info(f"Results: {len(dataframe)} row(s) returned")

        # Display as scrollable table
        st.dataframe(dataframe, width="stretch", height=200, hide_index=True)

        # Option to view raw text format
        with st.expander("📄 View Raw Text Format", expanded=False):
            st.text(output)
    else:
        # Fallback to text display if no dataframe
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


def unlock_predictions(excel_data: bytes, filename: str, rule_number: str):
    """
    Unlock predictions tab and upload data

    FIXED: Ensures all step data is persisted before generating final Excel
    """
    # Force save all pending state changes
    state_key = get_step_state_key(rule_number)
    if state_key in st.session_state:
        print(f"📊 Final state verification:")
        state = st.session_state[state_key]

        # Log all saved outputs
        outputs = state.get("step_outputs", {})
        for step_key, output in outputs.items():
            if output:
                print(f"   ✅ {step_key}: {len(output)} chars saved")
            else:
                print(f"   ⚠️ {step_key}: NO OUTPUT")

    # Mark triaging as complete
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
