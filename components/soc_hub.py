import hashlib
import streamlit as st
from sentinel.backend import *
from api_client.analyzer_api_client import get_analyzer_client

from components.alert_analysis.main import display_ai_threat_analysis_tab
from components.alert_analysis.historical_analysis import (
    display_historical_analysis_tab,
)
from components.triaging.triaging_integrated import display_triaging_workflow_cached
from components.predictions.predictions_page import display_predictions_tab_integrated


def display_entities_summary(alert_data):
    entities = alert_data.get("entities", {})

    if not entities:
        return

    # Get entities list
    if isinstance(entities, dict):
        entities_list = entities.get("entities", [])
    else:
        entities_list = entities

    if not entities_list:
        return

    st.markdown(
        """
    <div style="
        background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%);
        border-left: 5px solid #1976d2;
        padding: 20px;
        margin: 20px 0;
        border-radius: 10px;
        box-shadow: 0 4px 15px rgba(0,0,0,0.1);
    ">
        <h3 style="color: #1565c0; margin: 0 0 15px 0;">🔍 Associated Entities</h3>
    </div>
    """,
        unsafe_allow_html=True,
    )

    # Group entities by type
    entities_by_type = {}
    for entity in entities_list:
        kind = entity.get("kind", "Unknown")
        if kind not in entities_by_type:
            entities_by_type[kind] = []
        entities_by_type[kind].append(entity)

    # Sort entity types by priority
    priority_order = [
        "Account",
        "Ip",
        "Host",
        "MailMessage",
        "CloudApplication",
        "File",
        "Process",
        "Url",
    ]

    sorted_types = sorted(
        entities_by_type.keys(),
        key=lambda x: priority_order.index(x) if x in priority_order else 999,
    )

    # Display entities in columns
    if len(sorted_types) <= 2:
        cols = st.columns(len(sorted_types))
    else:
        cols = st.columns(3)

    col_idx = 0
    for entity_type in sorted_types:
        entities = entities_by_type[entity_type]

        with cols[col_idx % len(cols)]:
            # Entity type header
            type_emoji = {
                "Account": "👥",
                "Ip": "🌐",
                "Host": "💻",
                "File": "📄",
                "Process": "⚙️",
                "MailMessage": "📧",
                "Url": "🔗",
                "CloudApplication": "☁️",
            }.get(entity_type, "📌")

            st.markdown(f"**{type_emoji} {entity_type}** ({len(entities)})")

            # Display each entity
            for entity in entities:
                formatted = format_entity_display(entity)
                st.markdown(formatted)

                # Add additional details in expander for complex entities
                if entity_type in ["Account", "Host", "Ip"]:
                    props = entity.get("properties", {})
                    details = []

                    if entity_type == "Account":
                        sid = props.get("sid")
                        if sid:
                            details.append(f"SID: {sid}")

                    elif entity_type == "Ip":
                        location = props.get("location", {})
                        if location:
                            city = location.get("city")
                            state = location.get("state")
                            if city or state:
                                details.append(
                                    f"📍 {city}, {state}"
                                    if city and state
                                    else city or state
                                )

                    elif entity_type == "Host":
                        domain = props.get("dnsDomain")
                        if domain:
                            details.append(f"🌐 Domain: {domain}")

                    if details:
                        with st.expander("ℹ️ Details", expanded=False):
                            for detail in details:
                                st.caption(detail)

            st.markdown("---")

        col_idx += 1

    st.markdown("<br>", unsafe_allow_html=True)


def display_ai_analysis(alert_data):
    """Display AI analysis with proper state passing to triaging and predictions tab"""

    # VALIDATE alert_data STRUCTURE
    if not alert_data:
        st.error("❌ No alert data provided")
        return

    # EXTRACT AND VALIDATE alert name
    alert_name = (
        alert_data.get("title")
        or alert_data.get("alert_name")
        or alert_data.get("rule_name")
        or alert_data.get("name")
    )

    if not alert_name or alert_name == "undefined":
        st.error("❌ Alert name is undefined or missing")
        return

    st.markdown("---")
    st.title("🤖 SOC Hub - AI-Powered Analysis")

    # ✅ FIXED: Get timeGenerated from properties first, then fallback
    props = alert_data.get("full_alert", {})
    props = props.get("properties", {})
    time_generated = props.get("timeGenerated")

    if time_generated:
        st.markdown(
            f"""
            <div style="
                background: linear-gradient(135deg, #e8f5e9 0%, #c8e6c9 100%);
                border-left: 5px solid #388e3c;
                padding: 12px 20px;
                margin: 15px 0;
                border-radius: 8px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.06);
            ">
                <h4 style="color: #2e7d32; margin: 0;">
                    ⏰ Time Generated: <strong>{format_datetime(time_generated)}</strong>
                </h4>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Display alert info
    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown(f"### {alert_name}")
        description = alert_data.get("description", "No description available")
        st.markdown(f"**Description:** {description}")
    with col2:
        severity = alert_data.get("severity", "Unknown")
        status = alert_data.get("status", "Unknown")
        st.markdown(f"**Severity:** `{severity}`")
        st.markdown(f"**Status:** `{status}`")

    # ✅ NEW: Display entities summary at the top
    display_entities_summary(alert_data)

    st.markdown("---")

    api_client = get_analyzer_client()
    is_healthy, health_data = check_api_status()

    if not is_healthy:
        st.error("❌ SOC Analysis API Not Available")
        return

    # ✅ CREATE UNIQUE CACHE KEY FOR THIS ALERT
    sanitized_name = (
        alert_name.replace(" ", "_").replace("/", "_").replace("\\", "_").lower()
    )
    analysis_key = (
        f"analysis_{sanitized_name}_{hashlib.md5(alert_name.encode()).hexdigest()}"
    )

    # ✅ PREVENT RERUN: Store alert in session state only once
    alert_cache_key = f"alert_data_{analysis_key}"
    if alert_cache_key not in st.session_state:
        st.session_state[alert_cache_key] = alert_data

    # Initialize if needed
    if analysis_key not in st.session_state:
        st.session_state[f"{analysis_key}_in_progress"] = False

    # Create tab structure
    print(alert_data)
    source = alert_data.get("source", "unknown")
    is_manual = source == "alert_details"
    has_historical_data = alert_data.get("historical_data") is not None
    print("I'm here till now")
    print(is_manual, has_historical_data)

    # ✅ FIXED: Always show 4 tabs if triaging is complete OR if we have historical data
    predictions_enabled = st.session_state.get("triaging_complete", False)

    # ✅ CACHE KEY FOR TRIAGING STATE
    triaging_cache_key = f"triaging_done_{analysis_key}"

    if is_manual or not has_historical_data:
        if predictions_enabled:
            # Show 3 tabs: AI Analysis, Triaging, Predictions
            tab1, tab2, tab3 = st.tabs(
                ["🤖 AI Threat Analysis", "📋 AI Triaging", "🔮 Predictions & MITRE"]
            )
        else:
            # Show 2 tabs: AI Analysis, Triaging
            tab1, tab2 = st.tabs(["🤖 AI Threat Analysis", "📋 AI Triaging"])

        with tab1:
            display_ai_threat_analysis_tab(
                alert_name,
                api_client,
                analysis_key,
                st.session_state.get(alert_cache_key, alert_data),
            )

        with tab2:
            # ✅ CHECK IF TRIAGING ALREADY DONE FOR THIS ALERT
            if triaging_cache_key in st.session_state:
                st.success("✅ Triaging already completed for this alert!")

                # Show download button for cached template
                cached_excel = st.session_state.get(f"excel_cache_{analysis_key}")
                cached_filename = st.session_state.get(f"excel_filename_{analysis_key}")

                if cached_excel and cached_filename:
                    st.info("📥 Download your completed template below:")
                    st.download_button(
                        label="📥 Download Completed Template",
                        data=cached_excel,
                        file_name=cached_filename,
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        type="primary",
                        width="stretch",
                    )
                    st.info(
                        "💡 Switch to the **🔮 Predictions & MITRE** tab to continue analysis"
                    )
                else:
                    st.warning("⚠️ Template data not found in cache. Please regenerate.")
            else:
                # ✅ RUN TRIAGING WORKFLOW ONLY ONCE
                rule_number = alert_data.get("rule_number", f"ALERT_{id(alert_data)}")
                enhanced_alert_data = st.session_state.get(
                    alert_cache_key, alert_data
                ).copy()
                enhanced_alert_data["rule_number"] = rule_number
                enhanced_alert_data["alert_name"] = alert_name

                # ✅ NEW: Pass analysis text to template generator for manual analysis
                if analysis_key in st.session_state:
                    result = st.session_state[analysis_key]
                    if result.get("success"):
                        enhanced_alert_data["analysis_text"] = result.get(
                            "analysis", ""
                        )

                # ✅ DEBUG: Show what we're passing
                st.info(
                    f"📊 Passing to triaging: {len(enhanced_alert_data.get('entities', {}).get('entities', []))} entities"
                )

                # ✅ ADD THIS DIAGNOSTIC SECTION
                print(f"\n🔍 PRE-TRIAGING DIAGNOSTIC:")
                print(f"   rule_number: {rule_number}")
                print(f"   enhanced_alert_data keys: {list(enhanced_alert_data.keys())}")
                print(f"   Has entities: {'entities' in enhanced_alert_data}")

                if 'entities' in enhanced_alert_data:
                    entities = enhanced_alert_data['entities']
                    print(f"   entities type: {type(entities)}")
                    if isinstance(entities, dict):
                        entities_list = entities.get('entities', [])
                        print(f"   entities count: {len(entities_list)}")
                        
                        # Count entity types
                        account_count = sum(1 for e in entities_list if e.get('kind', '').lower() == 'account')
                        ip_count = sum(1 for e in entities_list if e.get('kind', '').lower() == 'ip')
                        print(f"   Account entities: {account_count}")
                        print(f"   IP entities: {ip_count}")

                # Then call the function
                display_triaging_workflow_cached(
                    rule_number,
                    alert_data=enhanced_alert_data,
                    cache_key=triaging_cache_key,
                    analysis_key=analysis_key,
                )

        # ✅ FIXED: Add predictions tab if enabled
        if predictions_enabled:
            with tab3:
                display_predictions_tab_integrated()

    else:
        print("I'm in else tab")
        # Has historical data - Always show 4 tabs if predictions enabled
        if predictions_enabled:
            tab1, tab2, tab3, tab4 = st.tabs(
                [
                    "🤖 AI Threat Analysis",
                    "📊 Historical Analysis",
                    "📋 AI Triaging",
                    "🔮 Predictions & MITRE",
                ]
            )
        else:
            tab1, tab2, tab3 = st.tabs(
                [
                    "🤖 AI Threat Analysis",
                    "📊 Historical Analysis",
                    "📋 AI Triaging",
                ]
            )

        with tab1:
            display_ai_threat_analysis_tab(
                alert_name,
                api_client,
                analysis_key,
                st.session_state.get(alert_cache_key, alert_data),
            )

        with tab2:
            historical_data = alert_data.get("historical_data")
            if historical_data is not None and not historical_data.empty:
                display_historical_analysis_tab(historical_data)
            else:
                st.info("✅ No historical data available for this alert")

        with tab3:
            # ✅ CHECK IF TRIAGING ALREADY DONE FOR THIS ALERT
            if triaging_cache_key in st.session_state:
                st.success("✅ Triaging already completed for this alert!")

                # Show download button for cached template
                cached_excel = st.session_state.get(f"excel_cache_{analysis_key}")
                cached_filename = st.session_state.get(f"excel_filename_{analysis_key}")

                if cached_excel and cached_filename:
                    st.info("📥 Download your completed template below:")
                    st.download_button(
                        label="📥 Download Completed Template",
                        data=cached_excel,
                        file_name=cached_filename,
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        type="primary",
                        width="stretch",
                    )
                    st.info(
                        "💡 Switch to the **🔮 Predictions & MITRE** tab to continue analysis"
                    )
                else:
                    st.warning("⚠️ Template data not found in cache. Please regenerate.")
            else:
                # ✅ RUN TRIAGING WORKFLOW ONLY ONCE
                rule_number = alert_data.get("rule_number", f"ALERT_{id(alert_data)}")
                enhanced_alert_data = st.session_state.get(
                    alert_cache_key, alert_data
                ).copy()
                enhanced_alert_data["rule_number"] = rule_number
                enhanced_alert_data["alert_name"] = alert_name

                # ✅ NEW: Pass analysis text to template generator for manual analysis
                if analysis_key in st.session_state:
                    result = st.session_state[analysis_key]
                    if result.get("success"):
                        enhanced_alert_data["analysis_text"] = result.get(
                            "analysis", ""
                        )

                display_triaging_workflow_cached(
                    rule_number,
                    alert_data=enhanced_alert_data,  # ✅ Now contains full alert_data with entities
                    cache_key=triaging_cache_key,
                    analysis_key=analysis_key,
                )

        # ✅ FIXED: Add predictions tab if enabled
        if predictions_enabled:
            with tab4:
                display_predictions_tab_integrated()
