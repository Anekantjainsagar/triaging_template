import math
import json
import streamlit as st
from soc_utils import *
from datetime import datetime
import hashlib
import time

# Import SOC analysis components
from api_client.analyzer_api_client import get_analyzer_client
from components.triaging_integrated import display_triaging_workflow
from routes.src.entity_prediction import display_entity_predictions_panel
from components.historical_analysis import display_historical_analysis_tab
from components.ip_analysis import analyze_ip_entities_parallel

# Page configuration
st.set_page_config(
    page_title="Microsoft Sentinel - SOC Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for better styling
st.markdown(
    """
    <style>
    .incident-card {
        border: 1px solid #ddd;
        border-radius: 8px;
        padding: 15px;
        margin-bottom: 15px;
        background-color: #f9f9f9;
        cursor: pointer;
        transition: all 0.3s ease;
    }
    .incident-card:hover {
        box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        transform: translateY(-2px);
    }
    .severity-high {
        color: #d32f2f;
        font-weight: bold;
    }
    .severity-medium {
        color: #f57c00;
        font-weight: bold;
    }
    .severity-low {
        color: #fbc02d;
        font-weight: bold;
    }
    .severity-informational {
        color: #1976d2;
        font-weight: bold;
    }
    .status-badge {
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 12px;
        font-weight: bold;
    }
    .status-new {
        background-color: #e3f2fd;
        color: #1976d2;
    }
    .status-active {
        background-color: #fff3e0;
        color: #f57c00;
    }
    .status-closed {
        background-color: #e8f5e9;
        color: #388e3c;
    }
    .alert-card {
        background-color: #fff3e0;
        border-left: 4px solid #f57c00;
        padding: 12px;
        margin: 8px 0;
        border-radius: 4px;
    }
    .entity-badge {
        display: inline-block;
        padding: 4px 8px;
        margin: 2px;
        border-radius: 4px;
        background-color: #e3f2fd;
        color: #1565c0;
        font-size: 12px;
    }
    .pagination-info {
        text-align: center;
        padding: 20px;
        font-size: 16px;
        color: #666;
    }
    .threat-intel-box {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 20px;
        border-radius: 10px;
        margin: 15px 0;
        box-shadow: 0 4px 15px rgba(0,0,0,0.1);
    }
    .analysis-section {
        background-color: #f8f9fa;
        border-left: 4px solid #007bff;
        padding: 15px;
        margin: 10px 0;
        border-radius: 5px;
    }
    analysis-container {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 25px;
        border-radius: 12px;
        margin: 20px 0;
        box-shadow: 0 8px 25px rgba(0,0,0,0.15);
    }
    
    .analysis-section {
        background-color: rgba(255, 255, 255, 0.95);
        color: #333;
        border-left: 5px solid #667eea;
        padding: 20px;
        margin: 15px 0;
        border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.08);
    }
    
    .analysis-section h2 {
        color: #667eea;
        font-size: 1.4em;
        margin-bottom: 15px;
        border-bottom: 2px solid #667eea;
        padding-bottom: 10px;
    }
    
    .analysis-section h3 {
        color: #764ba2;
        font-size: 1.2em;
        margin-top: 15px;
        margin-bottom: 10px;
    }
    
    .mitre-technique {
        background-color: #fff3e0;
        border-left: 4px solid #f57c00;
        padding: 12px;
        margin: 10px 0;
        border-radius: 6px;
    }
    
    .threat-actor {
        background-color: #ffebee;
        border-left: 4px solid #d32f2f;
        padding: 12px;
        margin: 10px 0;
        border-radius: 6px;
    }
    
    .action-item {
        background-color: #e8f5e9;
        border-left: 4px solid #388e3c;
        padding: 10px;
        margin: 8px 0;
        border-radius: 6px;
    }
    
    .risk-badge-critical {
        background-color: #d32f2f;
        color: white;
        padding: 6px 16px;
        border-radius: 20px;
        font-weight: bold;
        display: inline-block;
        margin: 5px 0;
    }
    
    .risk-badge-high {
        background-color: #f57c00;
        color: white;
        padding: 6px 16px;
        border-radius: 20px;
        font-weight: bold;
        display: inline-block;
        margin: 5px 0;
    }
    
    .risk-badge-medium {
        background-color: #fbc02d;
        color: #333;
        padding: 6px 16px;
        border-radius: 20px;
        font-weight: bold;
        display: inline-block;
        margin: 5px 0;
    }
    </style>
""",
    unsafe_allow_html=True,
)

# ============================================================================
# Session State Initialization
# ============================================================================


def initialize_session_state():
    """Initialize all session state variables and auto-load incidents"""
    defaults = {
        "current_page": "overview",
        "incidents": [],
        "selected_incident": None,
        "current_page_num": 1,
        "soc_analysis_data": None,
        "selected_rule_data": None,
        # Triaging-specific states
        "triaging_step": 2,
        "triaging_alerts": [],
        "triaging_selected_alert": None,
        "triaging_template_content": None,
        "triaging_plan": None,
        "triaging_output": {},
        "triaging_predictions": [],
        "progressive_predictions": {},
        "triaging_initialized": False,
        "rule_history": {},
        "current_step_index": 0,
        "analysis_complete": False,
        "excel_template_data": None,
        "original_steps": None,
        "enhanced_steps": None,
        "validation_report": None,
        "real_time_prediction": None,
        "triaging_complete": False,
        "predictions_excel_data": None,
        "predictions_excel_filename": None,
        "predictions_uploaded": False,
        "auto_loaded": False,  # New flag to track auto-load
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

    # Auto-load incidents from file on first run
    if not st.session_state.auto_loaded and not st.session_state.incidents:
        try:
            incidents = load_incidents_from_file()
            if incidents:
                st.session_state.incidents = incidents
                st.session_state.auto_loaded = True
        except Exception as e:
            pass


initialize_session_state()

# ============================================================================
# API Status Check
# ============================================================================


@st.cache_data(ttl=60)
def check_api_status():
    """Check if backend API is running"""
    try:
        api_client = get_analyzer_client()
        health = api_client.health_check()

        if health.get("status") == "healthy":
            return True, health
        else:
            return False, health
    except Exception as e:
        return False, {"status": "error", "error": str(e)}


# ============================================================================
# ✅ FIXED: Add Predictions Tab Display Function from soc.py
# ============================================================================

def display_predictions_tab_integrated():
    """Display predictions analysis tab with parallel automated entity-level predictions"""

    if not st.session_state.get("triaging_complete", False):
        st.warning(
            "⚠️ Complete the AI Triaging workflow first to unlock predictions analysis"
        )
        return

    st.markdown("### 🔮 True/False Positive Analyzer with MITRE ATT&CK")

    # Get alert data
    alert_data = st.session_state.get("soc_analysis_data")
    if not alert_data:
        st.error("❌ No alert data found. Please run AI analysis first.")
        return

    # Verify triaging data is uploaded
    excel_data = st.session_state.get("predictions_excel_data")
    excel_filename = st.session_state.get("predictions_excel_filename")

    if not excel_data:
        st.error("❌ No triaging data found. Please complete triaging first.")
        return

    # Initialize API client
    import os
    final_api_key = os.getenv("GOOGLE_API_KEY")
    predictions_api_url = os.getenv("PREDICTIONS_API_URL", "http://localhost:8000")

    from api_client.predictions_api_client import get_predictions_client

    try:
        client = get_predictions_client(predictions_api_url, final_api_key)

        # Upload data if not already uploaded
        if not st.session_state.get("predictions_uploaded"):
            st.info("📤 Uploading triaging template to analysis engine...")

            with st.spinner("Uploading investigation data..."):
                from components.triaging.step2_enhance import _upload_to_predictions_api
                upload_success = _upload_to_predictions_api(excel_data, excel_filename)

            if upload_success:
                st.success("✅ Template uploaded successfully!")
                st.session_state.predictions_uploaded = True
            else:
                st.error(
                    f"❌ Upload failed: {st.session_state.get('predictions_upload_error', 'Unknown error')}"
                )
                return
        else:
            st.success("✅ Template already uploaded to predictions API")

        # Verify upload
        preview_result = client.get_upload_preview()
        if preview_result.get("success"):
            st.success(
                f"✅ Data verified: {preview_result.get('total_rows', 0)} investigation steps loaded"
            )

        st.markdown("---")

        # ✅ CHECK TESTING MODE
        testing_mode = os.getenv("TESTING", "false").lower() == "true"

        # Extract entities
        entities = alert_data.get("entities", {})
        entities_list = (
            entities.get("entities", [])
            if isinstance(entities, dict)
            else (entities if isinstance(entities, list) else [])
        )

        # Separate Account and IP entities
        account_entities = [e for e in entities_list if e.get("kind") == "Account"]
        ip_entities = [e for e in entities_list if e.get("kind") == "Ip"]

        # ✅ CONDITIONAL: If TESTING=true, skip tabs and show account analysis directly
        if testing_mode:
            # Only show account analysis (no tabs)
            st.markdown("---")
            
            if account_entities:
                st.markdown(f"### 👤 Analyzing {len(account_entities)} Account(s)")
                st.info("🤖 Running parallel analysis for all accounts...")
                analyze_entities_parallel(account_entities, client)
            else:
                st.warning("⚠️ No account entities found in this alert")

        else:
            # ✅ PRODUCTION: Show all tabs
            # Create tabs for different entity types
            tab_list = ["📊 Summary"]
            if account_entities:
                tab_list.append("👤 Account Analysis")
            if ip_entities:
                tab_list.append("🌐 IP Analysis")

            tabs = st.tabs(tab_list)

            # Summary tab
            with tabs[0]:
                st.markdown("### 📊 Analysis Overview")
                
                col1, col2 = st.columns(2)
                with col1:
                    if account_entities:
                        st.metric("👤 Account Entities", len(account_entities))
                with col2:
                    if ip_entities:
                        st.metric("🌐 IP Entities", len(ip_entities))

                st.info("🤖 Running parallel analysis for all entities...")

            # Account analysis tab
            if account_entities and len(tabs) > 1:
                with tabs[1]:
                    st.markdown(f"### 👤 Analyzing {len(account_entities)} Account(s)")
                    st.info("🤖 Running parallel analysis for all accounts...")
                    analyze_entities_parallel(account_entities, client)

            # IP analysis tab (NEW)
            if ip_entities:
                ip_tab_index = 2 if account_entities else 1
                if len(tabs) > ip_tab_index:
                    with tabs[ip_tab_index]:
                        st.markdown(f"### 🌐 Analyzing {len(ip_entities)} IP Address(es)")
                        st.info("🤖 Running parallel analysis for all IPs...")
                        analyze_ip_entities_parallel(ip_entities, client)

    except Exception as e:
        st.error(f"❌ Error: {str(e)}")
        with st.expander("View Full Error"):
            import traceback
            st.code(traceback.format_exc())

def analyze_entities_parallel(account_entities: list, client):
    """Analyze multiple entities in parallel using threading"""
    import concurrent.futures
    import hashlib

    # Build username list
    usernames = []
    for entity in account_entities:
        props = entity.get("properties", {})
        account_name = props.get("accountName", "")
        upn_suffix = props.get("upnSuffix", "")

        if account_name and upn_suffix:
            username = f"{account_name}@{upn_suffix}"
        else:
            username = props.get("friendlyName", "Unknown")

        usernames.append(username)

    # Progress tracking
    progress_bar = st.progress(0)
    status_text = st.empty()

    # Results container
    results = {}

    def analyze_single_entity(username: str):
        """Analyze single entity"""
        cache_key = (
            f"entity_prediction_{username}_{hashlib.md5(username.encode()).hexdigest()}"
        )

        # Check cache first
        if cache_key in st.session_state:
            return username, st.session_state[cache_key]

        try:
            complete_analysis = client.analyze_complete(username)

            if complete_analysis.get("success"):
                st.session_state[cache_key] = complete_analysis
                return username, complete_analysis
            else:
                error_msg = complete_analysis.get("error", "Unknown error")
                if "No investigation data found" in error_msg or "404" in str(
                    error_msg
                ):
                    return username, {"error": "no_data", "username": username}
                else:
                    return username, {"error": error_msg, "username": username}
        except Exception as e:
            error_str = str(e)
            if "404" in error_str or "No investigation data" in error_str:
                return username, {"error": "no_data", "username": username}
            else:
                return username, {"error": str(e), "username": username}

    # Execute parallel analysis
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(analyze_single_entity, username): username
            for username in usernames
        }

        completed = 0
        total = len(futures)

        for future in concurrent.futures.as_completed(futures):
            username = futures[future]
            try:
                username, result = future.result()
                results[username] = result
                completed += 1

                progress_bar.progress(completed / total)
                status_text.text(f"Analyzed {completed}/{total} accounts...")

            except Exception as e:
                results[username] = {"error": str(e), "username": username}
                completed += 1
                progress_bar.progress(completed / total)

    progress_bar.empty()
    status_text.empty()

    st.success("✅ Parallel analysis complete!")
    st.markdown("---")

    # Display results for each account
    for username in usernames:
        result = results.get(username, {})

        if "error" in result:
            if result["error"] == "no_data":
                with st.expander(f"👤 {username} - ℹ️ No Data", expanded=False):
                    st.info(
                        f"No specific investigation data found for {username}. "
                        "This account may not have been directly involved in the investigation steps."
                    )
            else:
                with st.expander(f"👤 {username} - ❌ Error", expanded=False):
                    st.error(f"Analysis failed: {result['error']}")
        else:
            display_entity_analysis_full(username, result)


def display_entity_analysis_full(username: str, complete_analysis: dict):
    """Display complete analysis with full MITRE visualization like predictions_page.py"""

    initial = complete_analysis.get("initial_analysis", {})
    classification = initial.get("classification", "UNKNOWN")

    # Determine if expanded by default (first TRUE POSITIVE)
    is_expanded = "TRUE POSITIVE" in classification

    # Accordion header
    if "TRUE POSITIVE" in classification:
        header = f"👤 {username} - 🚨 TRUE POSITIVE"
    elif "FALSE POSITIVE" in classification:
        header = f"👤 {username} - ✅ FALSE POSITIVE"
    else:
        header = f"👤 {username} - ℹ️ {classification}"

    with st.expander(header, expanded=is_expanded):
        # Import display utilities from predictions_page
        from frontend.utils.predictions.display_utils import (
            display_mitre_analysis,
            display_analysis_results,
        )

        # Display initial analysis results (same as predictions_page)
        display_analysis_results(complete_analysis, username)

        # Display MITRE analysis with full visualization
        if complete_analysis.get("mitre_attack_analysis"):
            st.markdown("---")
            display_mitre_analysis(
                complete_analysis["mitre_attack_analysis"],
                username,
            )

        # Download section
        st.markdown("---")
        st.markdown("### 📥 Download Options")

        col1, col2, col3 = st.columns(3)

        with col1:
            # Full JSON report
            import json
            from datetime import datetime

            report_json = json.dumps(complete_analysis, indent=2)
            st.download_button(
                label="📄 Full Analysis (JSON)",
                data=report_json,
                file_name=f"complete_analysis_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                key=f"download_full_{username}",
                use_container_width=True,
            )

        with col2:
            # Executive summary
            exec_summary = complete_analysis.get("executive_summary", {})

            if exec_summary and isinstance(exec_summary, dict):
                subtechniques_text = ""
                if exec_summary.get("key_sub_techniques_observed"):
                    subtechniques_text = f"\n\nKEY SUB-TECHNIQUES OBSERVED:\n{chr(10).join([f'- {st}' for st in exec_summary.get('key_sub_techniques_observed', [])])}"

                summary_text = f"""SECURITY INVESTIGATION REPORT
                                        
User: {username}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

CLASSIFICATION: {complete_analysis.get('initial_analysis', {}).get('classification', 'N/A')}
RISK LEVEL: {complete_analysis.get('initial_analysis', {}).get('risk_level', 'N/A')}

EXECUTIVE SUMMARY:
{exec_summary.get('one_line_summary', 'N/A')}

ATTACK SOPHISTICATION:
{exec_summary.get('attack_sophistication', 'N/A')}

BUSINESS IMPACT:
{exec_summary.get('business_impact', 'N/A')}

IMMEDIATE ACTIONS:
{chr(10).join([f"- {action}" for action in exec_summary.get('immediate_actions', [])])}

PRIORITY: {exec_summary.get('investigation_priority', 'N/A')}
{subtechniques_text}
"""
            else:
                summary_text = f"""SECURITY INVESTIGATION REPORT
                                        
User: {username}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

CLASSIFICATION: {complete_analysis.get('initial_analysis', {}).get('classification', 'N/A')}
RISK LEVEL: {complete_analysis.get('initial_analysis', {}).get('risk_level', 'N/A')}
CONFIDENCE: {complete_analysis.get('initial_analysis', {}).get('confidence_score', 'N/A')}%

SUMMARY:
{complete_analysis.get('initial_analysis', {}).get('summary', 'Analysis completed - see detailed report for findings')}
"""

            st.download_button(
                label="📋 Executive Summary (TXT)",
                data=summary_text,
                file_name=f"executive_summary_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain",
                key=f"download_summary_{username}",
                use_container_width=True,
            )

        with col3:
            # MITRE Navigator layer
            if complete_analysis.get("mitre_attack_analysis"):
                navigator_data = complete_analysis["mitre_attack_analysis"].get(
                    "mitre_navigator_layer", {}
                )
                if navigator_data:
                    navigator_json = json.dumps(navigator_data, indent=2)
                    st.download_button(
                        label="🗺️ MITRE Navigator Layer",
                        data=navigator_json,
                        file_name=f"mitre_layer_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json",
                        key=f"download_mitre_{username}",
                        use_container_width=True,
                    )

        # Display sub-technique coverage summary
        if complete_analysis.get("mitre_attack_analysis"):
            coverage = complete_analysis["mitre_attack_analysis"].get(
                "sub_technique_coverage"
            )

            if coverage and isinstance(coverage, dict):
                st.markdown("---")
                st.markdown("### 📊 Analysis Coverage")

                col1, col2, col3 = st.columns(3)

                with col1:
                    st.metric(
                        "Total Techniques Mapped",
                        coverage.get("total_techniques_mapped", 0),
                    )

                with col2:
                    st.metric(
                        "With Sub-Techniques",
                        coverage.get("techniques_with_sub_techniques", 0),
                    )

                with col3:
                    st.metric(
                        "Sub-Technique Coverage",
                        coverage.get("sub_technique_percentage", "0%"),
                    )


def display_entity_analysis_results(username: str, complete_analysis: dict):
    """Display analysis results for a single entity"""

    initial = complete_analysis.get("initial_analysis", {})

    # Classification header
    classification = initial.get("classification", "UNKNOWN")
    if "TRUE POSITIVE" in classification:
        st.error(f"🚨 **Classification:** {classification}")
    elif "FALSE POSITIVE" in classification:
        st.success(f"✅ **Classification:** {classification}")
    else:
        st.info(f"ℹ️ **Classification:** {classification}")

    # Metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Risk Level", initial.get("risk_level", "UNKNOWN"))
    with col2:
        st.metric("Confidence", f"{initial.get('confidence_score', 0)}%")
    with col3:
        timestamp = complete_analysis.get("analysis_timestamp", "N/A")
        st.caption(
            f"🕐 Analyzed: {timestamp[:19] if len(timestamp) > 19 else timestamp}"
        )

    st.markdown("---")

    # Key Findings
    key_findings = initial.get("key_findings", [])
    if key_findings:
        st.markdown("### 🔍 Key Findings")
        for finding in key_findings:
            severity = finding.get("severity", "Medium")
            severity_color = {
                "Critical": "🔴",
                "High": "🟠",
                "Medium": "🟡",
                "Low": "🟢",
            }.get(severity, "⚪")

            st.markdown(
                f"""
            **{severity_color} {finding.get('category', 'Finding')}** ({severity})
            - **Details:** {finding.get('details', 'N/A')}
            - **Evidence:** {finding.get('evidence', 'N/A')}
            - **Impact:** {finding.get('impact', 'N/A')}
            """
            )

    # MITRE Analysis
    mitre = complete_analysis.get("mitre_attack_analysis", {})
    if mitre:
        st.markdown("---")
        st.markdown("### 🎯 MITRE ATT&CK Analysis")

        overall = mitre.get("overall_assessment", {})
        if overall:
            col1, col2 = st.columns(2)
            with col1:
                st.info(f"**Attack Stage:** {overall.get('attack_stage', 'Unknown')}")
            with col2:
                st.info(
                    f"**Sophistication:** {overall.get('threat_sophistication', 'Unknown')}"
                )

        # Techniques observed
        techniques = mitre.get("mitre_techniques_observed", [])
        if techniques:
            st.markdown("#### 📋 Techniques Observed")
            for tech in techniques[:5]:  # Show top 5
                st.markdown(
                    f"""
                - **{tech.get('technique', 'Unknown')}** ({tech.get('technique_id', 'N/A')})
                  - Sub-technique: {tech.get('sub_technique', 'N/A')}
                  - Severity: {tech.get('severity', 'N/A')}
                """
                )

    # Executive Summary
    exec_summary = complete_analysis.get("executive_summary", {})
    if exec_summary:
        st.markdown("---")
        st.markdown("### 📋 Executive Summary")
        st.write(exec_summary.get("one_line_summary", "No summary available"))

        actions = exec_summary.get("immediate_actions", [])
        if actions:
            st.markdown("**Immediate Actions:**")
            for action in actions:
                st.markdown(f"- {action}")

    # Download button
    st.markdown("---")
    import json
    from datetime import datetime

    report_json = json.dumps(complete_analysis, indent=2)
    st.download_button(
        label="📥 Download Complete Analysis (JSON)",
        data=report_json,
        file_name=f"analysis_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json",
        key=f"download_{username}",
    )


def display_cached_entity_analysis(username: str, complete_analysis: dict):
    """Display cached analysis results"""
    with st.expander(f"👤 {username} - ✅ Analysis Complete", expanded=False):
        display_entity_analysis_results(username, complete_analysis)


# ============================================================================
# UPDATED: display_ai_analysis function with 4 tabs + PROPER CACHING
# ============================================================================


def format_entity_display(entity):
    """
    Format entity for display based on entity type

    Args:
        entity: Entity dictionary from alert data

    Returns:
        Formatted string representation of the entity
    """
    kind = entity.get("kind", "Unknown")
    props = entity.get("properties", {})

    if kind == "Account":
        account_name = props.get("accountName", "")
        upn_suffix = props.get("upnSuffix", "")
        friendly_name = props.get("friendlyName", "")

        # Format as accountName@upnSuffix
        if account_name and upn_suffix:
            primary = f"{account_name}@{upn_suffix}"
        elif account_name:
            primary = account_name
        else:
            primary = friendly_name or "Unknown Account"

        # Add friendly name if different
        if friendly_name and friendly_name != account_name:
            return f"👤 **{primary}** (Friendly: {friendly_name})"
        else:
            return f"👤 **{primary}**"

    elif kind == "Ip":
        address = props.get("address", "Unknown IP")
        location = props.get("location", {})
        country = location.get("countryName", "") if location else ""

        if country:
            return f"🌐 **{address}** ({country})"
        else:
            return f"🌐 **{address}**"

    elif kind == "Host":
        hostname = props.get("hostName") or props.get("netBiosName") or "Unknown Host"
        os = props.get("oSFamily", "")

        if os:
            return f"💻 **{hostname}** (OS: {os})"
        else:
            return f"💻 **{hostname}**"

    elif kind == "Url":
        url = props.get("url", "Unknown URL")
        return f"🔗 **{url}**"

    elif kind == "File":
        filename = props.get("name") or props.get("fileName") or "Unknown File"
        file_hash = props.get("fileHashValue", "")

        if file_hash:
            return f"📄 **{filename}** (Hash: {file_hash[:16]}...)"
        else:
            return f"📄 **{filename}**"

    elif kind == "Process":
        process_name = props.get("processName") or props.get(
            "commandLine", "Unknown Process"
        )
        process_id = props.get("processId", "")

        if process_id:
            return f"⚙️ **{process_name}** (PID: {process_id})"
        else:
            return f"⚙️ **{process_name}**"

    elif kind == "MailMessage":
        sender = props.get("sender", "Unknown Sender")
        recipient = props.get("recipient", "Unknown Recipient")
        subject = props.get("subject", "No Subject")

        mail_info = f"📧 **From:** {sender}"
        if recipient:
            mail_info += f" | **To:** {recipient}"
        mail_info += f" | **Subject:** {subject}"
        return mail_info

    elif kind == "CloudApplication":
        app_name = props.get("name") or props.get("displayName") or "Unknown App"
        return f"☁️ **{app_name}**"

    else:
        # Generic display for unknown entity types
        name = (
            props.get("name")
            or props.get("displayName")
            or props.get("friendlyName")
            or f"Unknown {kind}"
        )
        return f"📋 **{name}**"


def display_entities_summary(alert_data):
    """
    Display a comprehensive summary of entities associated with the alert

    Args:
        alert_data: Full alert data including entities
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
    source = alert_data.get("source", "unknown")
    is_manual = source == "alert_details"
    has_historical_data = alert_data.get("historical_data") is not None

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

                display_triaging_workflow_cached(
                    rule_number,
                    alert_data=enhanced_alert_data,
                    cache_key=triaging_cache_key,
                    analysis_key=analysis_key,
                )

            st.info(
                """
                **Want Historical Analysis?** If you have historical incident data for this alert, 
                go back and search using the exact rule name from your SOC tracker.
                """
            )

        # ✅ FIXED: Add predictions tab if enabled
        if predictions_enabled:
            with tab3:
                display_predictions_tab_integrated()

    else:
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


# ============================================================================
# ✅ NEW: Cached Triaging Workflow Wrapper
# ============================================================================


def display_triaging_workflow_cached(
    rule_number: str, alert_data: dict, cache_key: str, analysis_key: str
):
    # ✅ DEBUG: Show what we're passing to triaging
    st.info(f"🚀 Starting triaging for: {alert_data.get('title', 'Unknown Alert')}")

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


def display_ai_threat_analysis_tab(alert_name, api_client, analysis_key, alert_data):
    """Display AI threat analysis for an alert"""

    if analysis_key in st.session_state and st.session_state[analysis_key]:
        result = st.session_state[analysis_key]
        if result.get("success"):
            analysis = result.get("analysis", "")

            st.markdown('<div class="threat-intel-box">', unsafe_allow_html=True)
            st.markdown("### 📋 Comprehensive Threat Intelligence Report")
            st.markdown("</div>", unsafe_allow_html=True)

            # Display sections...
            sections = analysis.split("## ")
            for section in sections:
                if not section.strip():
                    continue
                st.markdown(f"## {section}")

            # Download button
            st.markdown("---")
            col1, col2, col3 = st.columns([1, 1, 1])
            with col2:
                st.download_button(
                    label="📥 Download Analysis Report",
                    data=analysis,
                    file_name=f"threat_analysis_{alert_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                    mime="text/markdown",
                    width="stretch",
                    type="primary",
                )
    else:
        # Run analysis
        progress_placeholder = st.empty()

        with progress_placeholder.container():
            progress_bar = st.progress(0)
            status_text = st.empty()

            status_text.text("🚀 Initializing AI analysis engine...")
            progress_bar.progress(20)
            time.sleep(0.3)

            status_text.text("🔍 Analyzing threat patterns...")
            progress_bar.progress(50)
            time.sleep(0.3)

            status_text.text("🌐 Researching threat intelligence...")
            progress_bar.progress(75)

            # Call API
            result = api_client.analyze_alert(alert_name)

            progress_bar.progress(95)
            status_text.text("📊 Finalizing analysis...")
            time.sleep(0.2)
            progress_bar.progress(100)

            time.sleep(0.5)
            progress_placeholder.empty()

        # Cache and display
        st.session_state[analysis_key] = result

        if result.get("success"):
            st.rerun()
        else:
            st.error(f"❌ Analysis failed: {result.get('error')}")


def clean_and_format_markdown(text):
    """
    Clean and properly format markdown text for display

    Args:
        text: Raw markdown text that may have formatting issues

    Returns:
        Properly formatted markdown text
    """
    if not text:
        return ""

    # Remove excessive asterisks and clean up bold/italic markers
    # Fix patterns like *word*- or **word*-
    text = re.sub(r"\*+([^\*]+?)\*+-", r"**\1** -", text)
    text = re.sub(r"\*+([^\*]+?)\*+:", r"**\1**:", text)

    # Fix improperly closed bold markers
    text = re.sub(r"\*\*([^\*]+?)\*([^*])", r"**\1**\2", text)

    # Ensure proper spacing after list markers
    text = re.sub(r"^\*([^\s])", r"* \1", text, flags=re.MULTILINE)
    text = re.sub(r"^-([^\s])", r"- \1", text, flags=re.MULTILINE)

    # Fix numbered lists
    text = re.sub(r"^(\d+)\.([^\s])", r"\1. \2", text, flags=re.MULTILINE)

    # Ensure proper heading formatting
    text = re.sub(r"^##([^\s])", r"## \1", text, flags=re.MULTILINE)
    text = re.sub(r"^###([^\s])", r"### \1", text, flags=re.MULTILINE)

    # Add spacing around sections
    text = re.sub(r"\n(##[^#])", r"\n\n\1", text)

    # Clean up multiple consecutive newlines
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()


def parse_analysis_sections(analysis_text):
    """
    Parse analysis text into structured sections

    Args:
        analysis_text: Raw analysis text

    Returns:
        List of section dictionaries with title and content
    """
    sections = []

    # Split by ## headers
    parts = re.split(r"\n##\s+", analysis_text)

    # First part might be intro text before any section
    if parts[0].strip() and not parts[0].startswith("#"):
        sections.append(
            {
                "title": "Overview",
                "content": clean_and_format_markdown(parts[0].strip()),
                "level": 2,
            }
        )

    # Process remaining sections
    for part in parts[1:]:
        lines = part.split("\n", 1)
        if len(lines) >= 2:
            title = lines[0].strip()
            content = clean_and_format_markdown(lines[1].strip())
            sections.append({"title": title, "content": content, "level": 2})
        elif len(lines) == 1:
            sections.append({"title": lines[0].strip(), "content": "", "level": 2})

    return sections


def display_analysis_section(section):
    """
    Display a single analysis section with proper formatting

    Args:
        section: Dictionary with 'title' and 'content' keys
    """
    title = section["title"]
    content = section["content"]

    # Determine section styling based on title
    if any(keyword in title.upper() for keyword in ["MITRE", "ATT&CK", "TECHNIQUE"]):
        border_color = "#f57c00"
        bg_color = "#fff3e0"
        icon = "🎯"
    elif any(keyword in title.upper() for keyword in ["THREAT", "ACTOR", "ADVERSARY"]):
        border_color = "#d32f2f"
        bg_color = "#ffebee"
        icon = "⚠️"
    elif any(keyword in title.upper() for keyword in ["BUSINESS", "IMPACT", "RISK"]):
        border_color = "#f57c00"
        bg_color = "#fff3e0"
        icon = "💼"
    elif any(
        keyword in title.upper() for keyword in ["ACTION", "RECOMMENDATION", "RESPONSE"]
    ):
        border_color = "#388e3c"
        bg_color = "#e8f5e9"
        icon = "✅"
    else:
        border_color = "#667eea"
        bg_color = "#f8f9fa"
        icon = "📋"

    # Display section with custom styling
    st.markdown(
        f"""
    <div style="
        background-color: {bg_color};
        border-left: 5px solid {border_color};
        padding: 20px;
        margin: 15px 0;
        border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.08);
    ">
        <h2 style="
            color: {border_color};
            font-size: 1.4em;
            margin-bottom: 15px;
            border-bottom: 2px solid {border_color};
            padding-bottom: 10px;
        ">{icon} {title}</h2>
    </div>
    """,
        unsafe_allow_html=True,
    )

    # Display content with proper markdown
    if content:
        st.markdown(content)

    st.markdown("<br>", unsafe_allow_html=True)


def display_risk_badge(risk_level):
    """
    Display a styled risk level badge

    Args:
        risk_level: String like 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    """
    risk_colors = {
        "CRITICAL": ("#d32f2f", "white"),
        "HIGH": ("#f57c00", "white"),
        "MEDIUM": ("#fbc02d", "#333"),
        "LOW": ("#388e3c", "white"),
    }

    bg_color, text_color = risk_colors.get(risk_level.upper(), ("#757575", "white"))

    st.markdown(
        f"""
    <span style="
        background-color: {bg_color};
        color: {text_color};
        padding: 6px 16px;
        border-radius: 20px;
        font-weight: bold;
        display: inline-block;
        margin: 5px 0;
    ">{risk_level.upper()}</span>
    """,
        unsafe_allow_html=True,
    )


# ============================================================================
# Alert Display Functions
# ============================================================================


def display_alert(alert, entities_data):
    """Display alert details with entities in accordion format"""
    props = alert.get("properties", {})

    alert_name = props.get("alertDisplayName", "Unknown Alert")
    severity = props.get("severity", "Unknown")
    status = props.get("status", "Unknown")
    description = props.get("description", "")
    time_generated = props.get("timeGenerated", "")

    accordion_title = f"{alert_name} – {severity} • {status}"

    with st.expander(accordion_title, expanded=False):
        st.markdown(f'<div class="alert-card">', unsafe_allow_html=True)

        # Time Generated at the top
        if time_generated:
            st.markdown(f"**⏰ Time Generated:** {format_datetime(time_generated)}")
            st.divider()

        # Severity and Status badges
        col1, col2, col3 = st.columns([1, 1, 1])
        with col1:
            st.markdown(
                f'<span class="{get_severity_color(severity)}">Severity: {severity}</span>',
                unsafe_allow_html=True,
            )
        with col2:
            st.markdown(f"*Status: {status}*")
        with col3:
            if st.button(
                "🚀 Analyze in SOC Hub",
                key=f"soc_analysis_{alert_name}_{id(alert)}",
                help="Open this alert in SOC Hub for AI-powered analysis",
                type="primary",
            ):
                alert_data = {
                    "title": alert_name,
                    "description": description or alert_name,
                    "severity": severity,
                    "status": status,
                    "full_alert": alert,
                    "entities": entities_data,
                    "source": "alert_details",
                }
                st.session_state.soc_analysis_data = alert_data
                st.session_state.current_page = "soc_analysis"
                st.rerun()

        st.divider()

        if description:
            st.markdown(f"**Description:** _{description}_")

        # Time information
        start_time = props.get("startTimeUtc")
        end_time = props.get("endTimeUtc")

        col1, col2 = st.columns(2)
        with col1:
            if start_time:
                st.markdown(f"**Started:** {format_datetime(start_time)}")
        with col2:
            if end_time:
                st.markdown(f"**Ended:** {format_datetime(end_time)}")

        st.divider()

        # Tactics and Techniques
        tactics = props.get("tactics", [])
        techniques = props.get("techniques", [])

        if tactics or techniques:
            st.markdown("**MITRE ATT&CK:**")
            if tactics:
                st.markdown(f"Tactics: {', '.join(tactics)}")
            if techniques:
                st.markdown(f"Techniques: {', '.join(techniques)}")

        st.divider()

        # 🔍 Associated Entities
        if entities_data and "entities" in entities_data:
            alert_entities = entities_data["entities"]
            if alert_entities:
                st.markdown(
                    """
                    <div style="
                        background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%);
                        border-left: 5px solid #1976d2;
                        padding: 15px;
                        margin: 15px 0;
                        border-radius: 8px;
                        box-shadow: 0 2px 10px rgba(0,0,0,0.08);
                    ">
                        <h4 style="color: #1565c0; margin: 0;">🔍 Associated Entities</h4>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                entities_by_type = {}
                for entity in alert_entities:
                    kind = entity.get("kind", "Unknown")
                    if kind not in entities_by_type:
                        entities_by_type[kind] = []
                    entities_by_type[kind].append(entity)

                for entity_type, entities in entities_by_type.items():
                    with st.expander(
                        f"📋 {entity_type} ({len(entities)})", expanded=False
                    ):
                        for entity in entities:
                            st.markdown(f"- {format_entity_display(entity)}")

        st.markdown("</div>", unsafe_allow_html=True)


def display_incident_overview(incident, index):
    """Display incident as a clickable card in overview"""
    props = incident.get("properties", {})

    title = props.get("title", "Untitled Incident")
    severity = props.get("severity", "Unknown")
    status = props.get("status", "Unknown")
    incident_number = props.get("incidentNumber", "N/A")
    created = props.get("createdTimeUtc")

    additional_data = props.get("additionalData", {})
    alert_count = additional_data.get("alertsCount", 0)

    with st.container():
        if index == 0 or (index % 50 == 0):
            col1, col2, col3, col4, col5, col6 = st.columns([1, 4, 1.5, 1.5, 1.5, 1.5])
            with col1:
                st.caption("incident #")
            with col2:
                st.caption("title")
            with col3:
                st.caption("severity")
            with col4:
                st.caption("status")
            with col5:
                st.caption("alerts")
            with col6:
                st.caption("action")

        col1, col2, col3, col4, col5, col6 = st.columns([1, 4, 1.5, 1.5, 1.5, 1.5])

        with col1:
            st.markdown(f"**#{incident_number}**")

        with col2:
            st.markdown(f"**{title}**")

        with col3:
            st.markdown(
                f'<span class="{get_severity_color(severity)}">{severity}</span>',
                unsafe_allow_html=True,
            )

        with col4:
            st.markdown(
                f'<span class="status-badge {get_status_class(status)}">{status}</span>',
                unsafe_allow_html=True,
            )

        with col5:
            st.markdown(f"**{alert_count}**")

        with col6:
            if st.button("View Details", key=f"view_{index}"):
                st.session_state.selected_incident = incident
                st.session_state.current_page = "detail"
                st.rerun()

        if created:
            st.caption(f"Created: {format_datetime(created)}")

        st.divider()


def display_incident_detail(incident):
    """Display full incident details on detail page"""
    props = incident.get("properties", {})

    title = props.get("title", "Untitled Incident")
    severity = props.get("severity", "Unknown")
    status = props.get("status", "Unknown")
    incident_number = props.get("incidentNumber", "N/A")
    incident_id = incident.get("name")
    description = props.get("description", "")

    # Back button
    if st.button("← Back to Incidents List"):
        st.session_state.current_page = "overview"
        st.rerun()

    st.title(f"🔍 Incident #{incident_number}")
    st.markdown(f"## {title}")

    st.divider()

    # Main incident info
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(f"**Severity:**")
        st.markdown(
            f'<span class="{get_severity_color(severity)}">{severity}</span>',
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(f"**Status:**")
        st.markdown(
            f'<span class="status-badge {get_status_class(status)}">{status}</span>',
            unsafe_allow_html=True,
        )

    with col3:
        st.markdown(f"**Classification:**")
        st.write(props.get("classification", "N/A"))

    with col4:
        st.markdown(f"**Provider:**")
        st.write(props.get("providerName", "N/A"))

    st.divider()

    # Timeline
    st.markdown("### 📅 Timeline")
    col1, col2 = st.columns(2)

    with col1:
        created = props.get("createdTimeUtc")
        first_activity = props.get("firstActivityTimeUtc")
        if created:
            st.write(f"**Created:** {format_datetime(created)}")
        if first_activity:
            st.write(f"**First Activity:** {format_datetime(first_activity)}")

    with col2:
        last_activity = props.get("lastActivityTimeUtc")
        last_modified = props.get("lastModifiedTimeUtc")
        if last_activity:
            st.write(f"**Last Activity:** {format_datetime(last_activity)}")
        if last_modified:
            st.write(f"**Last Modified:** {format_datetime(last_modified)}")

    st.divider()

    # Fetch and display alerts
    additional_data = props.get("additionalData", {})
    alert_count = additional_data.get("alertsCount", 0)

    st.markdown(f"### 🚨 Alerts ({alert_count})")

    if alert_count > 0:
        cache_key = f"incident_details_{incident_id}"

        if cache_key not in st.session_state:
            with st.spinner("Loading alerts and entities..."):
                details = fetch_incident_details(incident_id)
                if details:
                    st.session_state[cache_key] = details

        if cache_key in st.session_state:
            details = st.session_state[cache_key]

            alerts = details.get("alerts", {}).get("value", [])
            entities_data = details.get("entities", {})

            if alerts:
                for idx, alert in enumerate(alerts):
                    display_alert(alert, entities_data)
                    if idx < len(alerts) - 1:
                        st.markdown("---")
            else:
                st.info(
                    f"This incident has {alert_count} alert(s), but details couldn't be loaded."
                )
        else:
            st.warning("Failed to load incident details. Please try again.")
    else:
        st.write("No alerts associated with this incident.")

    # Tactics and Techniques
    if additional_data.get("tactics") or additional_data.get("techniques"):
        st.markdown("### 🎯 MITRE ATT&CK")
        if additional_data.get("tactics"):
            st.write(f"**Tactics:** {', '.join(additional_data['tactics'])}")
        if additional_data.get("techniques"):
            st.write(f"**Techniques:** {', '.join(additional_data['techniques'])}")

    # Owner information
    owner = props.get("owner", {})
    if owner.get("assignedTo"):
        st.markdown("### 👤 Owner")
        st.write(f"**Assigned To:** {owner.get('assignedTo')}")
        if owner.get("email"):
            st.write(f"**Email:** {owner.get('email')}")


# ============================================================================
# Main Application
# ============================================================================


def main():
    """Main Streamlit application"""

    # Navigation sidebar
    with st.sidebar:
        st.title("🛡️ Navigation")
        st.markdown("---")

        # Page selection
        st.markdown("### 📋 Pages")
        if st.button("📊 Incidents Dashboard", width="stretch"):
            st.session_state.current_page = "overview"
            st.rerun()

        if st.button("🤖 SOC Analysis Hub", width="stretch"):
            if not st.session_state.soc_analysis_data:
                st.warning("⚠️ Please select an incident or alert first")
            else:
                st.session_state.current_page = "soc_analysis"
                st.rerun()

        st.markdown("---")

        # API Status Check
        st.markdown("### 📡 Backend Status")
        is_healthy, health_data = check_api_status()

        if is_healthy:
            st.success("✅ API Connected")
            with st.expander("API Info", expanded=False):
                st.write(f"**Status:** {health_data.get('status')}")
                st.write(
                    f"**SOC Analyzer:** {'✅' if health_data.get('soc_analyzer_loaded') else '❌'}"
                )
                st.write(
                    f"**Alert Analyzer:** {'✅' if health_data.get('alert_analyzer_loaded') else '❌'}"
                )
        else:
            st.error("❌ API Not Connected")
            st.caption("AI features require backend API")

        st.markdown("---")
        st.markdown("### 🔧 Actions")

        if st.button("🗑️ Clear Cache", width="stretch"):
            keys_to_remove = [
                key
                for key in st.session_state.keys()
                if key.startswith("incident_details_")
                or key.startswith("analysis_")
                or key.startswith("triaging_")
            ]
            for key in keys_to_remove:
                del st.session_state[key]
            st.success("Cache cleared!")
            st.rerun()

    # Route to appropriate page
    if (
        st.session_state.current_page == "soc_analysis"
        and st.session_state.soc_analysis_data
    ):
        display_ai_analysis(st.session_state.soc_analysis_data)
    elif (
        st.session_state.current_page == "detail" and st.session_state.selected_incident
    ):
        display_incident_detail(st.session_state.selected_incident)
    else:
        display_overview_page()


def display_overview_page():
    """Display the incidents overview page with pagination"""
    st.title("🛡️ Microsoft Sentinel - SOC Intelligence Dashboard")
    st.markdown("---")

    # Sidebar for filters and options
    with st.sidebar:
        st.header("⚙️ Data Source")

        data_source = st.radio(
            "Select Source",
            ["Load from File", "Fetch from Azure"],
            help="Choose to load incidents from a local file or fetch directly from Azure",
        )

        if data_source == "Fetch from Azure":
            st.markdown("### ⏱️ Time Range")

            timespan_option = st.selectbox(
                "Select Timespan",
                [
                    "Last 7 days",
                    "Last 30 days",
                    "Last 90 days",
                    "Last 180 days",
                    "Last 365 days",
                    "Custom",
                ],
                index=2,
            )

            timespan_map = {
                "Last 7 days": 7,
                "Last 30 days": 30,
                "Last 90 days": 90,
                "Last 180 days": 180,
                "Last 365 days": 365,
            }

            if timespan_option == "Custom":
                custom_days = st.number_input(
                    "Enter number of days", min_value=1, max_value=365, value=90
                )
                timespan_days = custom_days
            else:
                timespan_days = timespan_map[timespan_option]

            st.markdown("### 📊 Status Filter (Azure Fetch)")
            azure_status_filter = st.multiselect(
                "Filter by Status",
                options=["New", "Active", "Closed"],
                default=[],
                help="Leave empty to fetch all statuses",
            )

            if st.button("🔄 Fetch Incidents", type="primary"):
                incidents = fetch_incidents_from_azure(
                    timespan_days=timespan_days,
                    status_filters=azure_status_filter if azure_status_filter else None,
                )
                st.session_state.incidents = incidents
                st.session_state.current_page_num = 1

                if incidents:
                    with open(
                        "sentinel_all_incidents.json", "w", encoding="utf-8"
                    ) as f:
                        json.dump({"value": incidents}, f, indent=4, ensure_ascii=False)
                    st.success("💾 Incidents saved to sentinel_all_incidents.json")
        else:
            if st.button("📂 Load from File", type="primary"):
                incidents = load_incidents_from_file()
                st.session_state.incidents = incidents
                st.session_state.current_page_num = 1
                if incidents:
                    st.success(f"✅ Loaded {len(incidents)} incidents from file")

        st.markdown("---")
        st.header("🔍 Filters")

    incidents = st.session_state.incidents

    if not incidents:
        st.warning(
            "No incidents loaded. Please load incidents from file or fetch from Azure."
        )
        return

    # Filters in sidebar
    with st.sidebar:
        st.markdown("### ⏱️ Time Range Filter")
        time_filter = st.selectbox(
            "Filter by Creation Time",
            [
                "All Time",
                "Last 7 days",
                "Last 30 days",
                "Last 90 days",
                "Last 180 days",
                "Last 365 days",
            ],
            index=0,
        )

        time_filter_map = {
            "All Time": 0,
            "Last 7 days": 7,
            "Last 30 days": 30,
            "Last 90 days": 90,
            "Last 180 days": 180,
            "Last 365 days": 365,
        }

        time_filter_days = time_filter_map[time_filter]

        severity_filter = st.multiselect(
            "Severity",
            options=["High", "Medium", "Low", "Informational"],
            default=["High", "Medium", "Low", "Informational"],
        )

        status_filter = st.multiselect(
            "Status",
            options=["New", "Active", "Closed"],
            default=["New", "Active", "Closed"],
        )

        search_term = st.text_input("🔎 Search in title", "")
        incident_number_search = st.text_input(
            "🔢 Search by Incident Number", "", placeholder="e.g., 26"
        )

    # Apply filters
    filtered_incidents = incidents

    if time_filter_days > 0:
        filtered_incidents = apply_time_filter(filtered_incidents, time_filter_days)

    if severity_filter:
        filtered_incidents = [
            inc
            for inc in filtered_incidents
            if inc.get("properties", {}).get("severity") in severity_filter
        ]

    if status_filter:
        filtered_incidents = [
            inc
            for inc in filtered_incidents
            if inc.get("properties", {}).get("status") in status_filter
        ]

    if search_term:
        filtered_incidents = [
            inc
            for inc in filtered_incidents
            if search_term.lower() in inc.get("properties", {}).get("title", "").lower()
        ]

    if incident_number_search:
        try:
            search_number = int(incident_number_search)
            filtered_incidents = [
                inc
                for inc in filtered_incidents
                if inc.get("properties", {}).get("incidentNumber") == search_number
            ]
        except ValueError:
            st.sidebar.warning("Please enter a valid incident number")

    # Display statistics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Incidents", len(filtered_incidents))

    with col2:
        high_severity = len(
            [
                i
                for i in filtered_incidents
                if i.get("properties", {}).get("severity") == "High"
            ]
        )
        st.metric("High Severity", high_severity)

    with col3:
        active_incidents = len(
            [
                i
                for i in filtered_incidents
                if i.get("properties", {}).get("status") in ["New", "Active"]
            ]
        )
        st.metric("Active", active_incidents)

    with col4:
        closed_incidents = len(
            [
                i
                for i in filtered_incidents
                if i.get("properties", {}).get("status") == "Closed"
            ]
        )
        st.metric("Closed", closed_incidents)

    st.markdown("---")

    # Sort options
    col1, col2 = st.columns([3, 1])
    with col2:
        sort_by = st.selectbox(
            "Sort by",
            [
                "Incident Number (Desc)",
                "Incident Number (Asc)",
                "Severity",
                "Alert Count (Desc)",
                "Alert Count (Asc)",
                "Created Time (Recent)",
                "Created Time (Oldest)",
            ],
        )

    # Sort incidents
    if sort_by == "Incident Number (Desc)":
        filtered_incidents = sorted(
            filtered_incidents,
            key=lambda x: x.get("properties", {}).get("incidentNumber", 0),
            reverse=True,
        )
    elif sort_by == "Incident Number (Asc)":
        filtered_incidents = sorted(
            filtered_incidents,
            key=lambda x: x.get("properties", {}).get("incidentNumber", 0),
        )
    elif sort_by == "Severity":
        severity_order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
        filtered_incidents = sorted(
            filtered_incidents,
            key=lambda x: severity_order.get(
                x.get("properties", {}).get("severity", "Low"), 4
            ),
        )
    elif sort_by == "Alert Count (Desc)":
        filtered_incidents = sorted(
            filtered_incidents,
            key=lambda x: x.get("properties", {})
            .get("additionalData", {})
            .get("alertsCount", 0),
            reverse=True,
        )
    elif sort_by == "Alert Count (Asc)":
        filtered_incidents = sorted(
            filtered_incidents,
            key=lambda x: x.get("properties", {})
            .get("additionalData", {})
            .get("alertsCount", 0),
        )
    elif sort_by == "Created Time (Recent)":
        filtered_incidents = sorted(
            filtered_incidents,
            key=lambda x: x.get("properties", {}).get("createdTimeUtc", ""),
            reverse=True,
        )
    elif sort_by == "Created Time (Oldest)":
        filtered_incidents = sorted(
            filtered_incidents,
            key=lambda x: x.get("properties", {}).get("createdTimeUtc", ""),
        )

    # Pagination
    ITEMS_PER_PAGE = 50
    total_incidents = len(filtered_incidents)
    total_pages = (
        math.ceil(total_incidents / ITEMS_PER_PAGE) if total_incidents > 0 else 1
    )

    # Ensure current page is within bounds
    if st.session_state.current_page_num > total_pages:
        st.session_state.current_page_num = total_pages
    if st.session_state.current_page_num < 1:
        st.session_state.current_page_num = 1

    # Calculate pagination indices
    start_idx = (st.session_state.current_page_num - 1) * ITEMS_PER_PAGE
    end_idx = min(start_idx + ITEMS_PER_PAGE, total_incidents)

    # Get current page incidents
    current_page_incidents = filtered_incidents[start_idx:end_idx]

    # Display incidents
    st.markdown("## Incidents")

    if not filtered_incidents:
        st.info("No incidents match the selected filters.")
    else:
        # Pagination controls at top
        col1, col2, col3, col4, col5 = st.columns([1, 1, 2, 1, 1])

        with col1:
            if st.button("⏮️ First", disabled=(st.session_state.current_page_num == 1)):
                st.session_state.current_page_num = 1
                st.rerun()

        with col2:
            if st.button(
                "◀️ Previous", disabled=(st.session_state.current_page_num == 1)
            ):
                st.session_state.current_page_num -= 1
                st.rerun()

        with col3:
            st.markdown(
                f'<div class="pagination-info">Page {st.session_state.current_page_num} of {total_pages} | Showing {start_idx + 1}-{end_idx} of {total_incidents} incidents</div>',
                unsafe_allow_html=True,
            )

        with col4:
            if st.button(
                "Next ▶️", disabled=(st.session_state.current_page_num == total_pages)
            ):
                st.session_state.current_page_num += 1
                st.rerun()

        with col5:
            if st.button(
                "Last ⏭️", disabled=(st.session_state.current_page_num == total_pages)
            ):
                st.session_state.current_page_num = total_pages
                st.rerun()

        st.markdown("---")

        # Display incidents for current page
        for idx, incident in enumerate(current_page_incidents):
            display_incident_overview(incident, idx)

        # Pagination controls at bottom
        if total_pages > 1:
            st.markdown("---")
            col1, col2, col3, col4, col5 = st.columns([1, 1, 2, 1, 1])

            with col1:
                if st.button(
                    "⏮️ First2", disabled=(st.session_state.current_page_num == 1)
                ):
                    st.session_state.current_page_num = 1
                    st.rerun()

            with col2:
                if st.button(
                    "◀️ Previous2", disabled=(st.session_state.current_page_num == 1)
                ):
                    st.session_state.current_page_num -= 1
                    st.rerun()

            with col3:
                st.markdown(
                    f'<div class="pagination-info">Page {st.session_state.current_page_num} of {total_pages} | Showing {start_idx + 1}-{end_idx} of {total_incidents} incidents</div>',
                    unsafe_allow_html=True,
                )

            with col4:
                if st.button(
                    "Next2 ▶️",
                    disabled=(st.session_state.current_page_num == total_pages),
                ):
                    st.session_state.current_page_num += 1
                    st.rerun()

            with col5:
                if st.button(
                    "Last2 ⏭️",
                    disabled=(st.session_state.current_page_num == total_pages),
                ):
                    st.session_state.current_page_num = total_pages
                    st.rerun()


if __name__ == "__main__":
    main()
