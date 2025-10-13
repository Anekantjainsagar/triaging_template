import os
import json
import streamlit as st
from datetime import datetime
from dotenv import load_dotenv

# Import backend
from config.styles import apply_predictions_css
from backend.predictions_backend import InvestigationAnalyzer, parse_excel_data
from utils.predictions.display_utils import display_mitre_analysis, display_analysis_results

load_dotenv()

apply_predictions_css()


def display_predictions_page():
    """Main predictions page component"""

    final_api_key = os.getenv("GOOGLE_API_KEY")

    st.markdown(
        "<h1 class='main-header'>🔐 True/False Positive Analyzer with MITRE ATT&CK</h1>",
        unsafe_allow_html=True,
    )
    st.markdown(
        "**Advanced Threat Investigation with MITRE ATT&CK Framework Integration (Including Sub-Techniques)**"
    )

    # File upload
    st.markdown("---")
    st.subheader("📁 Upload Investigation Data")
    uploaded_file = st.file_uploader(
        "Upload Excel file containing investigation data",
        type=["xlsx", "xls"],
        help="Upload the Excel file with columns: Step, Name, Explanation, KQL Query, Execute, Output, Remarks/Comments",
    )

    if uploaded_file:
        st.success("✅ File uploaded successfully!")

        # Parse the Excel file
        with st.spinner("Parsing Excel data..."):
            df = parse_excel_data(uploaded_file)

        if df is not None:
            st.info(f"📊 Loaded {len(df)} investigation steps from the Excel file")

            # Show preview
            with st.expander("👁️ Preview Investigation Data"):
                st.dataframe(df, width="stretch")

            # Username input
            st.markdown("---")
            st.subheader("👤 User Analysis")
            username = st.text_input(
                "Enter username/email to analyze",
                placeholder="e.g., sarah.mitchell@abc.com",
                help="Enter the exact username or email address from the investigation",
            )

            if st.button(
                "🔍 Analyze with MITRE ATT&CK Framework",
                type="primary",
                width="stretch",
                disabled=not final_api_key,
            ):
                if not final_api_key:
                    st.error(
                        "❌ API key not configured. Please set GOOGLE_API_KEY in environment variables."
                    )
                elif username:
                    # Check if username exists
                    if not any(
                        df.astype(str)
                        .apply(lambda x: x.str.contains(username, case=False, na=False))
                        .any()
                    ):
                        st.error(
                            f"❌ The email/username '{username}' does not exist in the uploaded document."
                        )
                        st.stop()

                    with st.spinner(
                        f"🤖 AI analyzing investigation with MITRE ATT&CK framework (including sub-techniques) for {username}..."
                    ):
                        # Initialize analyzer
                        analyzer = InvestigationAnalyzer(final_api_key)

                        # Extract investigation steps
                        investigation_steps = analyzer.extract_investigation_steps(
                            df, username
                        )

                        if not investigation_steps:
                            st.warning(
                                f"⚠️ No investigation data found for user: {username}"
                            )
                            st.info(
                                "💡 Tip: Check the spelling and ensure the username appears in the investigation outputs"
                            )
                        else:
                            st.info(
                                f"📋 Found {len(investigation_steps)} relevant investigation steps"
                            )

                            # Perform complete analysis
                            complete_analysis = analyzer.perform_complete_analysis(
                                username, investigation_steps
                            )

                            if complete_analysis.get("status") == "success":
                                # Display initial analysis
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
                                    report_json = json.dumps(
                                        complete_analysis, indent=2
                                    )
                                    st.download_button(
                                        label="📄 Full Analysis (JSON)",
                                        data=report_json,
                                        file_name=f"complete_analysis_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                                        mime="application/json",
                                        width="stretch",
                                    )

                                with col2:
                                    # Executive summary with null checks
                                    exec_summary = complete_analysis.get(
                                        "executive_summary"
                                    )

                                    if exec_summary and isinstance(exec_summary, dict):
                                        # Include sub-techniques in summary
                                        subtechniques_text = ""
                                        if exec_summary.get(
                                            "key_sub_techniques_observed"
                                        ):
                                            subtechniques_text = f"\n\nKEY SUB-TECHNIQUES OBSERVED:\n{chr(10).join([f'- {st}' for st in exec_summary.get('key_sub_techniques_observed', [])])}"

                                        summary_text = f"""SECURITY INVESTIGATION REPORT
                                        
User: {username}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

CLASSIFICATION: {complete_analysis['initial_analysis'].get('classification', 'N/A')}
RISK LEVEL: {complete_analysis['initial_analysis'].get('risk_level', 'N/A')}

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
                                        # Fallback summary if executive_summary is missing
                                        summary_text = f"""SECURITY INVESTIGATION REPORT
                                        
User: {username}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

CLASSIFICATION: {complete_analysis['initial_analysis'].get('classification', 'N/A')}
RISK LEVEL: {complete_analysis['initial_analysis'].get('risk_level', 'N/A')}
CONFIDENCE: {complete_analysis['initial_analysis'].get('confidence_score', 'N/A')}%

SUMMARY:
{complete_analysis['initial_analysis'].get('summary', 'Analysis completed - see detailed report for findings')}

RECOMMENDATIONS:
{chr(10).join([f"- {rec}" for rec in complete_analysis['initial_analysis'].get('recommendations', [])])}
"""

                                    st.download_button(
                                        label="📋 Executive Summary (TXT)",
                                        data=summary_text,
                                        file_name=f"executive_summary_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                                        mime="text/plain",
                                        width="stretch",
                                    )

                                with col3:
                                    # MITRE Navigator layer with sub-techniques
                                    if complete_analysis.get("mitre_attack_analysis"):
                                        navigator_data = complete_analysis[
                                            "mitre_attack_analysis"
                                        ].get("mitre_navigator_layer", {})
                                        if navigator_data:
                                            navigator_json = json.dumps(
                                                navigator_data, indent=2
                                            )
                                            st.download_button(
                                                label="🗺️ MITRE Navigator Layer",
                                                data=navigator_json,
                                                file_name=f"mitre_layer_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                                                mime="application/json",
                                                width="stretch",
                                            )

                                # Display sub-technique coverage summary
                                if complete_analysis.get("mitre_attack_analysis"):
                                    coverage = complete_analysis[
                                        "mitre_attack_analysis"
                                    ].get("sub_technique_coverage")

                                    if coverage and isinstance(coverage, dict):
                                        st.markdown("---")
                                        st.markdown("### 📊 Analysis Summary")

                                        col1, col2, col3 = st.columns(3)

                                        with col1:
                                            st.metric(
                                                "Total Techniques Mapped",
                                                coverage.get(
                                                    "total_techniques_mapped", 0
                                                ),
                                            )

                                        with col2:
                                            st.metric(
                                                "With Sub-Techniques",
                                                coverage.get(
                                                    "techniques_with_sub_techniques", 0
                                                ),
                                            )

                                        with col3:
                                            st.metric(
                                                "Sub-Technique Coverage",
                                                coverage.get(
                                                    "sub_technique_percentage", "0%"
                                                ),
                                            )

                                        # Check coverage percentage
                                        try:
                                            coverage_pct = coverage.get(
                                                "sub_technique_percentage", "0%"
                                            )
                                            if isinstance(coverage_pct, str):
                                                coverage_value = float(
                                                    coverage_pct.rstrip("%")
                                                )
                                                if coverage_value < 50:
                                                    st.warning(
                                                        "⚠️ Low sub-technique coverage detected. Consider reviewing the analysis for more specific sub-technique identification."
                                                    )
                                        except (ValueError, AttributeError):
                                            pass
                            else:
                                st.error(
                                    "❌ Analysis failed. Please check the logs and try again."
                                )
                else:
                    st.warning("⚠️ Please enter a username to analyze")
    else:
        st.info("👆 Please upload an Excel file to begin analysis")
