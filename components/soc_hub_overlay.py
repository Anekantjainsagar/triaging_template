# [file name]: soc_hub_overlay.py (INTEGRATED WITH EXISTING COMPONENTS)
import os
import json
import hashlib
import streamlit as st
from datetime import datetime
from sentinel.backend import *
from sentinel.utils import *
from api_client.analyzer_api_client import get_analyzer_client

# ✅ REUSE EXISTING COMPONENTS FROM alert_analysis
from components.alert_analysis.main import display_ai_threat_analysis_tab
from components.alert_analysis.historical_analysis import (
    display_historical_analysis_tab,
)
from components.triaging.triaging_integrated import display_triaging_workflow_cached
from components.predictions.predictions_page import display_predictions_tab_integrated


def prepare_alert_from_log(log_data, error_info=None):
    """
    Prepare comprehensive alert data from log entry for SOC Hub analysis
    Enhanced to include all entities: Account, IP, Location, and Application
    """

    # Extract title from failure reason
    title = (
        str(log_data.get("Status", {}).get("errorCode", "N/A"))
        + " - "
        + log_data.get("Status", {}).get("failureReason", "Sign-in Failure")
    )

    # Build comprehensive description with bullet points
    description_parts = []
    if error_info:
        # Split error_info into bullet points
        error_lines = error_info.split("\n")
        for line in error_lines:
            if line.strip():
                # Remove "Description: " prefix if present
                cleaned_line = line.replace("Description: ", "").strip()
                # Add bullet point if not already present
                if cleaned_line and not cleaned_line.startswith("•"):
                    description_parts.append(f"• {cleaned_line}")
                elif cleaned_line:
                    description_parts.append(cleaned_line)

    error_code = log_data.get("Status", {}).get("errorCode", "N/A")

    # Join with HTML line breaks for proper rendering
    description = "<br>".join(description_parts)

    # ================================================================
    # ENHANCED: Extract comprehensive entity information
    # ================================================================
    entities = {"entities": []}

    # 1. ADD ACCOUNT ENTITY (Email)
    user_principal = log_data.get("UserPrincipalName", "")
    user_display_name = log_data.get("UserDisplayName", "")
    user_id = log_data.get("UserId", "")

    if user_principal:
        entities["entities"].append(
            {
                "kind": "Account",
                "properties": {
                    "accountName": (
                        user_principal.split("@")[0]
                        if "@" in user_principal
                        else user_principal
                    ),
                    "upnSuffix": (
                        user_principal.split("@")[1] if "@" in user_principal else ""
                    ),
                    "userPrincipalName": user_principal,
                    "friendlyName": user_display_name or user_principal,
                    "aadUserId": user_id,
                    "displayName": user_display_name,
                },
            }
        )

    # 2. ADD IP ENTITY (with enhanced location data)
    ip_address = log_data.get("IPAddress")
    location_details = log_data.get("LocationDetails", {})

    if ip_address and ip_address != "N/A":
        # Extract comprehensive geolocation
        location_info = {}
        if isinstance(location_details, dict):
            location_info = {
                "city": location_details.get("city", ""),
                "state": location_details.get("state", ""),
                "countryName": location_details.get("countryOrRegion", ""),
                "countryCode": location_details.get("countryOrRegion", ""),
            }

            # Add coordinates if available
            geo_coords = location_details.get("geoCoordinates", {})
            if isinstance(geo_coords, dict):
                location_info["latitude"] = geo_coords.get("latitude")
                location_info["longitude"] = geo_coords.get("longitude")

        entities["entities"].append(
            {
                "kind": "Ip",
                "properties": {
                    "address": ip_address,
                    "location": location_info,
                    "asn": log_data.get("AutonomousSystemNumber"),
                },
            }
        )

    # 3. ADD CLOUD APPLICATION ENTITY
    app_name = log_data.get("AppDisplayName", "")
    app_id = log_data.get("AppId", "")

    if app_name:
        entities["entities"].append(
            {
                "kind": "CloudApplication",
                "properties": {
                    "name": app_name,
                    "displayName": app_name,
                    "appId": app_id,
                },
            }
        )

    # 4. ADD DEVICE/HOST ENTITY (if available)
    device_detail = log_data.get("DeviceDetail", {})
    if isinstance(device_detail, dict) and device_detail.get("deviceId"):
        entities["entities"].append(
            {
                "kind": "Host",
                "properties": {
                    "hostName": device_detail.get("displayName", "Unknown Device"),
                    "deviceId": device_detail.get("deviceId"),
                    "oSFamily": device_detail.get("operatingSystem", ""),
                    "isCompliant": device_detail.get("isCompliant", False),
                    "isManaged": device_detail.get("isManaged", False),
                    "trustType": device_detail.get("trustType", ""),
                },
            }
        )

    # ================================================================
    # Compile location string for context
    # ================================================================
    location_parts = []
    if isinstance(location_details, dict):
        city = location_details.get("city", "")
        state = location_details.get("state", "")
        country = location_details.get("countryOrRegion", "")

        if city:
            location_parts.append(city)
        if state:
            location_parts.append(state)
        if country:
            location_parts.append(country)

    location_str = (
        ", ".join(location_parts) if location_parts else log_data.get("Location", "N/A")
    )

    # ================================================================
    # Construct comprehensive alert data structure
    # ================================================================

    alert_data = {
        "title": title,
        "alert_name": title,  # ✅ Add alert_name for compatibility
        "description": description,
        "severity": "Medium",
        "status": "Active",
        "rule_number": f"SIGNIN_{error_code}",
        "source": "signin_logs",  # ✅ Mark as sign-in log source
        "is_manual": False,  # ✅ Not manual entry
        "full_alert": {
            "properties": {
                "timeGenerated": log_data.get("TimeGenerated", ""),
                "alertDisplayName": title,
                "description": description,
                "severity": "Medium",
            }
        },
        "entities": entities,
        "additional_context": {
            "user_principal": user_principal,
            "user_display_name": user_display_name,
            "user_id": user_id,
            "ip_address": ip_address,
            "location": location_str,
            "location_details": location_details,
            "error_code": error_code,
            "result_type": error_code,
            "result_description": log_data.get("ResultDescription", "N/A"),
            "app_display_name": app_name,
            "app_id": app_id,
            "device_info": device_detail,
            "authentication_details": log_data.get("AuthenticationDetails", []),
            "conditional_access": log_data.get("ConditionalAccessPolicies", []),
            "risk_info": {
                "risk_state": log_data.get("RiskState", "N/A"),
                "risk_level": log_data.get("RiskLevelDuringSignIn", "N/A"),
                "risk_detail": log_data.get("RiskDetail", "N/A"),
                "is_risky": log_data.get("IsRisky", False),
            },
            "raw_log": log_data,
        },
    }

    return alert_data


def display_entities_summary(alert_data):
    """
    Display comprehensive entities summary with proper formatting
    ✅ REUSED from soc_hub.py
    """
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

    # Priority order for display
    priority_order = [
        "Account",
        "Ip",
        "Host",
        "CloudApplication",
        "MailMessage",
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
            # Entity type header with emoji
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

                # Add detailed view for key entity types
                if entity_type in ["Account", "Host", "Ip"]:
                    props = entity.get("properties", {})
                    details = []

                    if entity_type == "Account":
                        user_id = props.get("aadUserId")
                        display_name = props.get("displayName")
                        if user_id:
                            details.append(f"User ID: {user_id}")
                        if display_name:
                            details.append(f"Display Name: {display_name}")

                    elif entity_type == "Ip":
                        location = props.get("location", {})
                        if location:
                            city = location.get("city")
                            state = location.get("state")
                            country = location.get("countryName")

                            location_str = []
                            if city:
                                location_str.append(city)
                            if state:
                                location_str.append(state)
                            if country:
                                location_str.append(country)

                            if location_str:
                                details.append(f"📍 {', '.join(location_str)}")

                            # Add coordinates if available
                            lat = location.get("latitude")
                            lon = location.get("longitude")
                            if lat and lon:
                                details.append(f"Coordinates: {lat}, {lon}")

                        asn = props.get("asn")
                        if asn:
                            details.append(f"ASN: {asn}")

                    elif entity_type == "Host":
                        device_id = props.get("deviceId")
                        os_family = props.get("oSFamily")
                        if device_id:
                            details.append(f"Device ID: {device_id}")
                        if os_family:
                            details.append(f"OS: {os_family}")

                    if details:
                        with st.expander("ℹ️ Details", expanded=False):
                            for detail in details:
                                st.caption(detail)

            st.markdown("---")

        col_idx += 1

    st.markdown("<br>", unsafe_allow_html=True)


def display_soc_hub_overlay():
    """
    Display SOC Hub overlay - FULLY INTEGRATED with existing alert_analysis components
    ✅ Reuses: display_ai_threat_analysis_tab, display_triaging_workflow_cached, display_predictions_tab_integrated
    """

    # Header with back button
    col1, col2 = st.columns([6, 1])
    with col1:
        st.markdown(
            '<div class="main-header">🤖 SOC Hub - AI-Powered Analysis</div>',
            unsafe_allow_html=True,
        )
    with col2:
        if st.button(
            "⬅️ Back", key="back_soc_hub", type="primary", use_container_width=True
        ):
            st.session_state.show_soc_hub = False
            st.rerun()

    st.markdown("---")

    # Check if we have alert data
    if "soc_alert_data" not in st.session_state or not st.session_state.soc_alert_data:
        st.error("❌ No alert data available for analysis")
        st.info("Please select a log entry and click 'Analyze in SOC Hub' first")
        return

    alert_data = st.session_state.soc_alert_data

    # ================================================================
    # Validate alert structure
    # ================================================================
    alert_name = (
        alert_data.get("title")
        or alert_data.get("alert_name")
        or alert_data.get("rule_name")
        or "Sign-in Failure"
    )

    rule_number = alert_data.get("rule_number", f"SIGNIN_{id(alert_data)}")

    # ================================================================
    # Display Basic Alert Info
    # ================================================================

    # Display alert information
    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown(f"### {alert_name}")
        description = alert_data.get("description", "No description available")
        time_generated = (
            alert_data.get("full_alert", {}).get("properties", {}).get("timeGenerated")
        )
        st.markdown(description, unsafe_allow_html=True)
        st.markdown(f"**Time Generated:** {format_datetime(time_generated)}")
    with col2:
        severity = alert_data.get("severity", "Unknown")
        status = alert_data.get("status", "Unknown")
        st.markdown(f"**Severity:** `{severity}`")
        st.markdown(f"**Status:** `{status}`")

    # ================================================================
    # Display Entities Summary (shows email, IP, location)
    # ================================================================
    display_entities_summary(alert_data)

    st.markdown("---")

    # ================================================================
    # Check API Health
    # ================================================================
    api_client = get_analyzer_client()
    is_healthy, health_data = check_api_status()

    if not is_healthy:
        st.error("❌ SOC Analysis API Not Available")
        st.warning(
            "AI-powered analysis features require the backend API to be running."
        )

        with st.expander("Error Details", expanded=False):
            if "error" in health_data:
                st.error(f"Error: {health_data['error']}")
        return

    # ================================================================
    # Create unique cache key for this alert
    # ================================================================
    sanitized_name = (
        alert_name.replace(" ", "_").replace("/", "_").replace("\\", "_").lower()
    )
    analysis_key = (
        f"analysis_{sanitized_name}_{hashlib.md5(alert_name.encode()).hexdigest()}"
    )

    # Store alert in session state cache
    alert_cache_key = f"alert_data_{analysis_key}"
    if alert_cache_key not in st.session_state:
        st.session_state[alert_cache_key] = alert_data

    # ================================================================
    # ✅ TAB STRUCTURE - REUSING EXISTING COMPONENTS
    # ================================================================
    predictions_enabled = st.session_state.get("triaging_complete", False)
    triaging_cache_key = f"triaging_done_{analysis_key}"

    # Determine tab structure based on state
    if predictions_enabled:
        tab1, tab2, tab3 = st.tabs(
            ["🤖 AI Threat Analysis", "📋 AI Triaging", "🔮 Predictions & MITRE"]
        )
    else:
        tab1, tab2 = st.tabs(["🤖 AI Threat Analysis", "📋 AI Triaging"])

    # ================================================================
    # TAB 1: AI Threat Analysis
    # ✅ REUSING: display_ai_threat_analysis_tab from components.alert_analysis.main
    # ================================================================
    with tab1:
        display_ai_threat_analysis_tab(
            alert_name,
            api_client,
            analysis_key,
            st.session_state.get(alert_cache_key, alert_data),
        )

    # ================================================================
    # TAB 2: AI Triaging
    # ✅ REUSING: display_triaging_workflow_cached from components.triaging.triaging_integrated
    # ================================================================
    with tab2:
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
                    use_container_width=True,
                )
                st.info(
                    "💡 Switch to the **🔮 Predictions & MITRE** tab to continue analysis"
                )
            else:
                st.warning("⚠️ Template data not found in cache. Please regenerate.")
        else:
            # Enhance alert data for triaging
            enhanced_alert_data = st.session_state.get(
                alert_cache_key, alert_data
            ).copy()
            enhanced_alert_data["rule_number"] = rule_number
            enhanced_alert_data["alert_name"] = alert_name

            # Pass analysis text if available
            if analysis_key in st.session_state:
                result = st.session_state[analysis_key]
                if result.get("success"):
                    enhanced_alert_data["analysis_text"] = result.get("analysis", "")

            # Display triaging workflow
            display_triaging_workflow_cached(
                rule_number,
                alert_data=enhanced_alert_data,
                cache_key=triaging_cache_key,
                analysis_key=analysis_key,
            )

    # ================================================================
    # TAB 3: Predictions & MITRE (only if triaging complete)
    # ✅ REUSING: display_predictions_tab_integrated from components.predictions.predictions_page
    # ================================================================
    if predictions_enabled:
        with tab3:
            # Set the alert data in the expected session state key
            st.session_state.soc_analysis_data = alert_data

            display_predictions_tab_integrated()
