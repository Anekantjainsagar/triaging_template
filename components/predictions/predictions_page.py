import os
import json
import hashlib
import traceback
import streamlit as st
import concurrent.futures
from datetime import datetime
from components.predictions.ip_analysis import analyze_ip_entities_parallel
from api_client.predictions_api_client import get_predictions_client
from components.triaging.step2_enhance import _upload_to_predictions_api
from components.predictions.utils.display_utils import (
    display_mitre_analysis,
    display_analysis_results,
)
from components.predictions.enhanced_predictions_page import display_predictions_tab_enhanced


def analyze_entities_parallel(account_entities: list, client):
    """Analyze multiple entities in parallel using threading"""

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
            report_json = json.dumps(complete_analysis, indent=2)
            st.download_button(
                label="📄 Full Analysis (JSON)",
                data=report_json,
                file_name=f"complete_analysis_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                key=f"download_full_{username}",
                width="stretch",
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
                width="stretch",
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
                        width="stretch",
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


def display_predictions_tab_integrated():
    """Display predictions analysis tab with enhanced UI and better structure"""
    # Use the enhanced version
    display_predictions_tab_enhanced()
