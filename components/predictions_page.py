import os
import json
import streamlit as st
from datetime import datetime
from dotenv import load_dotenv

from frontend.config.styles import apply_predictions_css
from frontend.utils.predictions.display_utils import (
    display_mitre_analysis,
    display_analysis_results,
)
from api_client.predictions_api_client import (
    get_predictions_client,
    validate_api_connection,
    export_analysis_json,
)

load_dotenv()
apply_predictions_css()


def display_predictions_page():
    """Main predictions page component with API integration"""

    final_api_key = os.getenv("GOOGLE_API_KEY")
    predictions_api_url = os.getenv("PREDICTIONS_API_URL", "http://localhost:8000")

    st.markdown(
        "<h1 class='main-header'>🔍 True/False Positive Analyzer with MITRE ATT&CK</h1>",
        unsafe_allow_html=True,
    )
    st.markdown(
        "**Advanced Threat Investigation with MITRE ATT&CK Framework Integration (Including Sub-Techniques)**"
    )

    # Initialize API client
    try:
        client = get_predictions_client(predictions_api_url, final_api_key)
    except Exception as e:
        st.error(f"Failed to initialize API client: {str(e)}")
        return

    # Check API connection
    st.markdown("---")
    with st.spinner("Checking API connection..."):
        is_connected, message = validate_api_connection(predictions_api_url)
        if is_connected:
            st.success(message)
        else:
            st.error(
                f"{message} - Make sure the API is running on {predictions_api_url}"
            )
            st.info("Start the API with: `python predictions_api_backend.py`")
            return

    # File upload section
    st.markdown("---")
    st.subheader("📤 Upload Investigation Data")
    uploaded_file = st.file_uploader(
        "Upload Excel file containing investigation data",
        type=["xlsx", "xls"],
        help="Upload the Excel file with columns: Step, Name, Explanation, KQL Query, Execute, Output, Remarks/Comments",
    )

    if uploaded_file:
        st.success("✅ File uploaded successfully!")

        # Upload to API
        with st.spinner("Uploading file to analysis server..."):
            upload_result = client.upload_excel_bytes(uploaded_file, uploaded_file.name)

        if upload_result.get("success"):
            st.success(
                f"📊 Loaded {upload_result.get('total_rows', 0)} investigation steps"
            )

            # Show preview
            with st.expander("👁️ Preview Investigation Data"):
                preview_data = upload_result.get("preview_data", [])
                if preview_data:
                    st.dataframe(preview_data, width="stretch")
                else:
                    st.info("No preview data available")

            # Username input
            st.markdown("---")
            st.subheader("👤 User Analysis")
            username = st.text_input(
                "Enter username/email to analyze",
                placeholder="e.g., sarah.mitchell@abc.com",
                help="Enter the exact username or email address from the investigation",
            )

            # Analysis options
            col1, col2 = st.columns(2)
            with col1:
                analysis_type = st.radio(
                    "Select analysis type:",
                    [
                        "Complete Analysis",
                        "Initial Classification Only",
                        "MITRE Mapping Only",
                    ],
                    help="Choose the scope of analysis to perform",
                )

            with col2:
                show_cache_info = st.checkbox("Show cache info", value=False)
                if show_cache_info:
                    cache_info = client.cache_info()
                    st.metric("Cached Analyses", cache_info.get("cached_analyses", 0))

            if st.button(
                "🔍 Analyze Investigation Data",
                type="primary",
                width="stretch",
                disabled=not final_api_key,
            ):
                if not final_api_key:
                    st.error(
                        "❌ API key not configured. Please set GOOGLE_API_KEY in environment variables."
                    )
                elif not username:
                    st.warning("⚠️ Please enter a username to analyze")
                else:
                    # Determine which analysis to run
                    if analysis_type == "Complete Analysis":
                        perform_complete_analysis(client, username, final_api_key)
                    elif analysis_type == "Initial Classification Only":
                        perform_initial_analysis(client, username, final_api_key)
                    else:
                        perform_mitre_analysis(client, username, final_api_key)

        else:
            st.error(f"❌ Upload failed: {upload_result.get('error', 'Unknown error')}")

    else:
        st.info("📂 Please upload an Excel file to begin analysis")

    # API Statistics sidebar
    with st.sidebar:
        st.markdown("---")
        st.subheader("📊 API Statistics")

        if st.button("Refresh Statistics", key="refresh_stats"):
            st.rerun()

        try:
            # FIXED: Call get_statistics() method directly
            stats = client.get_statistics()

            # Check if the call was successful
            if stats.get("success"):
                st.metric("Total Analyses", stats.get("total_analyses", 0))

                classifications = stats.get("classifications", {})
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("True Positives", classifications.get("TRUE POSITIVE", 0))
                with col2:
                    st.metric(
                        "False Positives", classifications.get("FALSE POSITIVE", 0)
                    )

                if stats.get("last_analysis_time"):
                    st.caption(f"Last analysis: {stats.get('last_analysis_time')}")
            else:
                st.warning("Unable to fetch statistics")

        except Exception as e:
            st.error(f"Could not fetch statistics: {str(e)}")

        st.markdown("---")
        if st.button("Clear Cache", key="clear_cache"):
            with st.spinner("Clearing cache..."):
                result = client.clear_cache()
                if result.get("success"):
                    st.success("✅ Cache cleared successfully")
                else:
                    st.error("Failed to clear cache")


def perform_initial_analysis(client, username: str):
    """Perform initial classification analysis only"""

    with st.spinner(f"🤖 Performing initial analysis for {username}..."):
        result = client.analyze_initial(username)

    if result.get("success"):
        st.success("✅ Initial analysis complete!")

        # Display results
        initial = result
        col1, col2, col3 = st.columns(3)

        with col1:
            classification = initial.get("classification", "UNKNOWN")
            if "TRUE POSITIVE" in classification:
                st.error(f"🚨 **Classification:** {classification}")
            elif "FALSE POSITIVE" in classification:
                st.success(f"✅ **Classification:** {classification}")
            else:
                st.info(f"ℹ️ **Classification:** {classification}")

        with col2:
            st.metric("Risk Level", initial.get("risk_level", "UNKNOWN"))

        with col3:
            st.metric("Confidence", f"{initial.get('confidence_score', 0)}%")

        st.markdown("---")
        st.subheader("📋 Executive Summary")
        st.write(initial.get("summary", "No summary available"))

        # Download button
        st.markdown("---")
        analysis_json = export_analysis_json(initial)
        st.download_button(
            label="📥 Download Analysis (JSON)",
            data=analysis_json,
            file_name=f"initial_analysis_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            width="stretch",
        )
    else:
        st.error(f"❌ Analysis failed: {result.get('error', 'Unknown error')}")


def perform_mitre_analysis(client, username: str):
    """Perform MITRE ATT&CK analysis only"""

    with st.spinner(f"🤖 Performing MITRE ATT&CK analysis for {username}..."):
        result = client.analyze_mitre(username)

    if result.get("success"):
        st.success("✅ MITRE analysis complete!")

        mitre_data = result.get("mitre_analysis", {})

        # Display MITRE analysis
        if mitre_data:
            display_mitre_analysis(mitre_data, username)
        else:
            st.warning("⚠️ No MITRE analysis data available")

        # Download button
        st.markdown("---")
        analysis_json = export_analysis_json(result)
        st.download_button(
            label="📥 Download MITRE Analysis (JSON)",
            data=analysis_json,
            file_name=f"mitre_analysis_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            width="stretch",
        )
    else:
        st.error(f"❌ Analysis failed: {result.get('error', 'Unknown error')}")


def perform_complete_analysis(client, username: str):
    """Perform complete investigation analysis"""

    with st.spinner(
        f"🤖 AI analyzing investigation with MITRE ATT&CK framework for {username}..."
    ):
        complete_analysis = client.analyze_complete(username)

    if complete_analysis.get("success"):
        st.success("✅ Complete analysis finished!")

        # Display initial analysis results
        display_analysis_results(complete_analysis, username)

        # Display MITRE analysis with sub-techniques
        if complete_analysis.get("mitre_attack_analysis"):
            display_mitre_analysis(
                complete_analysis["mitre_attack_analysis"],
                username,
            )

        # Download section
        st.markdown("---")
        st.markdown("### 📥 Download Complete Report")

        col1, col2, col3 = st.columns(3)

        with col1:
            # Full JSON report
            report_json = json.dumps(complete_analysis, indent=2)
            st.download_button(
                label="📄 Full Analysis (JSON)",
                data=report_json,
                file_name=f"complete_analysis_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
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
                        width="stretch",
                    )

        # Display sub-technique coverage summary
        if complete_analysis.get("mitre_attack_analysis"):
            coverage = complete_analysis["mitre_attack_analysis"].get(
                "sub_technique_coverage"
            )

            if coverage and isinstance(coverage, dict):
                st.markdown("---")
                st.markdown("### 📊 Analysis Summary")

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

                # Check coverage percentage
                try:
                    coverage_pct = coverage.get("sub_technique_percentage", "0%")
                    if isinstance(coverage_pct, str):
                        coverage_value = float(coverage_pct.rstrip("%"))
                        if coverage_value < 50:
                            st.warning(
                                "⚠️ Low sub-technique coverage detected. Consider reviewing the analysis for more specific sub-technique identification."
                            )
                except (ValueError, AttributeError):
                    pass

    else:
        st.error(
            f"❌ Analysis failed: {complete_analysis.get('error', 'Unknown error')}"
        )
