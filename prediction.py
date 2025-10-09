import streamlit as st
import pandas as pd
import json
from datetime import datetime
from typing import Dict, List, Any
import google.generativeai as genai
import os
from dotenv import load_dotenv

load_dotenv()

# Page configuration
st.set_page_config(
    page_title="Privileged Role Investigation Analyzer", page_icon="🔐", layout="wide"
)

# Custom CSS for better styling
st.markdown(
    """
    <style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f2937;
        margin-bottom: 1rem;
    }
    .risk-critical {
        background-color: #fee2e2;
        border-left: 4px solid #dc2626;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .risk-high {
        background-color: #fed7aa;
        border-left: 4px solid #ea580c;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .risk-medium {
        background-color: #fef3c7;
        border-left: 4px solid #f59e0b;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .risk-low {
        background-color: #d1fae5;
        border-left: 4px solid #10b981;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .step-card {
        background-color: #f9fafb;
        border-radius: 0.5rem;
        padding: 1rem;
        margin: 0.5rem 0;
        border-left: 3px solid #3b82f6;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def parse_excel_data(uploaded_file) -> pd.DataFrame:
    """Parse the uploaded Excel file and return the dataframe"""
    try:
        df = pd.read_excel(uploaded_file)
        return df
    except Exception as e:
        st.error(f"Error parsing Excel file: {str(e)}")
        return None


def extract_investigation_steps(df: pd.DataFrame, username: str) -> List[Dict]:
    """Extract investigation steps with their outputs for the specific user"""

    investigation_steps = []

    for idx, row in df.iterrows():
        step_data = {
            "step_number": row.get("Step", idx + 1),
            "step_name": row.get("Name", "Unknown Step"),
            "explanation": row.get("Explanation", ""),
            "kql_query": row.get("KQL Query", ""),
            "output": row.get("Output", ""),
            "remarks": row.get("Remarks/Comments", ""),
        }

        # Check if this step's output contains the username
        output_str = str(step_data["output"]).lower()
        if username.lower() in output_str or pd.notna(step_data["output"]):
            investigation_steps.append(step_data)

    return investigation_steps


def build_enhanced_analysis_prompt(
    username: str, investigation_steps: List[Dict], full_df: pd.DataFrame
) -> str:
    """Build an enhanced prompt focusing on step-by-step pattern analysis"""

    # Format investigation steps for the prompt
    steps_formatted = ""
    for i, step in enumerate(investigation_steps, 1):
        steps_formatted += f"""
### STEP {step['step_number']}: {step['step_name']}
**Purpose**: {step['explanation']}
**Output Data**:
{step['output']}
**Remarks**: {step['remarks']}
---
"""

    prompt = f"""You are an elite cybersecurity analyst specializing in privileged access investigations and advanced threat detection.

# INVESTIGATION TARGET: {username}

# CRITICAL ANALYSIS FRAMEWORK:
You must analyze the investigation data step-by-step and determine the classification based on PATTERN RECOGNITION across all investigation phases.

# INVESTIGATION STEPS AND OUTPUTS:
{steps_formatted}

---

# PATTERN-BASED CLASSIFICATION CRITERIA:

## TRUE POSITIVE Indicators:
✓ **Privileged Role Assignment** to high-risk roles (Global Admin, Privileged Role Admin, Security Admin)
✓ **Temporal Anomalies**: Sign-ins before role assignment, impossible geographic travel times
✓ **Geographic Impossibilities**: Sign-ins from multiple distant locations within short timeframes
✓ **Unknown Device Access**: Sign-ins from unrecognized/untrusted devices after privilege escalation
✓ **Unknown Location Access**: Sign-ins from unknown/suspicious geographic locations
✓ **MFA Failure Rate**: >10% MFA failure rate or multiple authentication failures
✓ **Suspicious IP Addresses**: Sign-ins from non-corporate IP ranges after privilege assignment
✓ **Behavioral Anomalies**: Sudden change in access patterns after role assignment
✓ **Off-Hours Activity**: Privileged access during unusual hours

## FALSE POSITIVE Indicators:
✓ Role assignment by authorized administrator from corporate network
✓ All sign-ins from known corporate locations and trusted devices
✓ High MFA success rate (>95%)
✓ Consistent geographic and temporal patterns
✓ No unusual access patterns or behavioral changes
✓ Legitimate business justification evident in remarks

## BENIGN POSITIVE Indicators:
✓ Standard role assignments to lower-privilege roles
✓ Normal sign-in patterns with no anomalies
✓ 100% MFA success rate
✓ All access from trusted, corporate-managed devices
✓ Expected geographic locations only
✓ No security concerns identified in any investigation step

---

# ANALYSIS METHODOLOGY:

1. **Initial Assessment Analysis**: Review role assignment details
   - What role was assigned? (Critical/High/Medium/Low risk)
   - Who assigned it and from where?
   - Was this expected or unusual?

2. **User Account Analysis**: Review user details
   - Account age, department, job title
   - Does the role match their position?

3. **Role Assignment Deep Dive**: Examine assignment metadata
   - Source IP analysis (corporate vs external)
   - Timing analysis (business hours vs off-hours)
   - Initiator legitimacy

4. **Activity Pattern Analysis**: Review sign-in logs
   - Geographic consistency
   - Device trust status
   - Temporal feasibility of access patterns

5. **Authentication Analysis**: Examine MFA statistics
   - Success/failure rates
   - Authentication methods used

6. **Cross-Step Correlation**: Identify patterns across ALL steps
   - Timeline correlation between privilege assignment and suspicious activity
   - Geographic impossibilities
   - Device consistency

7. **Risk Scoring**: Calculate overall risk based on cumulative indicators

---

# OUTPUT FORMAT (STRICT JSON):

{{
    "classification": "TRUE POSITIVE | FALSE POSITIVE | BENIGN POSITIVE",
    "risk_level": "CRITICAL | HIGH | MEDIUM | LOW",
    "confidence_score": 85,
    "summary": "2-3 sentence executive summary explaining the classification decision based on pattern analysis",
    "pattern_analysis": {{
        "privilege_escalation_risk": "Description of role assignment risk",
        "temporal_anomalies": "Any time-based inconsistencies or impossibilities",
        "geographic_anomalies": "Location-based concerns or inconsistencies",
        "authentication_concerns": "MFA and authentication issues",
        "device_trust_issues": "Unknown or untrusted device access",
        "behavioral_deviations": "Unusual patterns in user behavior"
    }},
    "key_findings": [
        {{
            "step_reference": "Step name where finding was identified",
            "category": "Privileged Role Assignment | Suspicious Activity | Authentication | Geographic Anomaly | Device Trust",
            "severity": "Critical | High | Medium | Low",
            "details": "Specific finding with exact data from output",
            "evidence": "Direct quote or data point from investigation output",
            "impact": "Security implication of this finding"
        }}
    ],
    "risk_indicators": [
        "Specific measurable risk indicators from investigation outputs"
    ],
    "timeline_correlation": [
        {{
            "event_sequence": "Description of correlated events",
            "timestamps": "Relevant timestamps showing the pattern",
            "significance": "Why this correlation indicates TRUE/FALSE/BENIGN POSITIVE"
        }}
    ],
    "step_by_step_analysis": [
        {{
            "step": "Step name",
            "finding": "What this step revealed",
            "contribution_to_classification": "How this step supports the final classification"
        }}
    ],
    "recommendations": [
        "Specific actionable recommendations prioritized by urgency"
    ],
    "justification": "Detailed explanation of why this classification was chosen based on the complete pattern analysis"
}}

---

# CRITICAL ANALYSIS RULES:

1. **Evidence-Based Only**: Base classification ONLY on data present in the investigation outputs
2. **Pattern Recognition**: Look for PATTERNS across multiple steps, not isolated incidents
3. **Temporal Logic**: Check if timeline makes logical sense (no impossible scenarios)
4. **Geographic Feasibility**: Validate if geographic patterns are physically possible
5. **Privilege Context**: Weight findings higher if they occur AFTER privilege escalation
6. **MFA Threshold**: <90% MFA success rate is HIGH RISK for privileged accounts
7. **Unknown = Suspicious**: Unknown devices/locations after privilege assignment = TRUE POSITIVE indicator
8. **Correlation is Key**: Multiple weak indicators together can indicate TRUE POSITIVE
9. **Be Decisive**: Choose one classification with high confidence based on evidence
10. **Specificity Required**: Reference exact data points from outputs to support findings

---

# EXAMPLE CLASSIFICATION LOGIC:

**TRUE POSITIVE Example:**
"User assigned Global Administrator at 15:34:34, followed by sign-in from unknown location (203.0.113.45) at 14:34:34 with unknown device. Temporal impossibility (sign-in timestamp before role assignment) + unknown device + geographic anomaly + 20% MFA failure rate = **TRUE POSITIVE: Account Compromise**"

**FALSE POSITIVE Example:**
"User assigned Security Administrator role by IT Manager during business hours from corporate IP. All subsequent sign-ins from known corporate offices in Seattle with trusted devices. 100% MFA success rate. Normal pattern = **FALSE POSITIVE: Legitimate Administrative Action**"

**BENIGN POSITIVE Example:**
"User assigned standard User Administrator role. All access from corporate network, trusted devices only. 100% MFA success. No anomalies detected in any investigation step = **BENIGN POSITIVE: Normal Operations**"

---

Now analyze the investigation data for **{username}** and provide your assessment in VALID JSON format only (no markdown, no code blocks, no explanations outside the JSON structure)."""

    return prompt


def analyze_with_gemini(
    username: str, investigation_steps: List[Dict], full_df: pd.DataFrame, api_key: str
) -> Dict[str, Any]:
    """Use to analyze the investigation data with enhanced pattern recognition"""
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-2.0-flash-exp")

        # Build enhanced prompt
        prompt = build_enhanced_analysis_prompt(username, investigation_steps, full_df)

        # Generate response
        response = model.generate_content(prompt)
        content = response.text.strip()

        # Clean up response - remove markdown code blocks if present
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0]
        elif "```" in content:
            content = content.split("```")[1].split("```")[0]

        content = content.strip()

        # Parse JSON
        result = json.loads(content)
        return result

    except json.JSONDecodeError as e:
        st.error(f"JSON parsing error: {str(e)}")
        if "content" in locals():
            st.error(f"Raw response preview: {content[:500]}")
        return None
    except Exception as e:
        st.error(f"Error calling API: {str(e)}")
        return None


def display_analysis_results(analysis: Dict[str, Any], username: str):
    """Display the enhanced analysis results with pattern focus"""

    # Header
    st.markdown(
        f"<h2>🔍 Investigation Assessment for: <code>{username}</code></h2>",
        unsafe_allow_html=True,
    )
    st.markdown("---")

    # Classification and Risk Level
    col1, col2, col3 = st.columns(3)

    with col1:
        classification = analysis.get("classification", "UNKNOWN")
        if "TRUE POSITIVE" in classification:
            st.error(f"🚨 **Classification:** {classification}")
        elif "FALSE POSITIVE" in classification:
            st.success(f"✅ **Classification:** {classification}")
        else:
            st.info(f"ℹ️ **Classification:** {classification}")

    with col2:
        risk_level = analysis.get("risk_level", "UNKNOWN")
        risk_colors = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        icon = risk_colors.get(risk_level, "⚪")
        st.metric("Risk Level", f"{icon} {risk_level}")

    with col3:
        confidence = analysis.get("confidence_score", 0)
        st.metric("Confidence Score", f"{confidence}%")

    st.markdown("---")

    # Executive Summary
    if "summary" in analysis:
        st.subheader("📋 Executive Summary")
        st.write(analysis["summary"])
        st.markdown("---")

    # Pattern Analysis
    if "pattern_analysis" in analysis:
        st.subheader("🔬 Pattern Analysis")
        pattern = analysis["pattern_analysis"]

        col1, col2 = st.columns(2)

        with col1:
            if pattern.get("privilege_escalation_risk"):
                st.markdown("**⬆️ Privilege Escalation Risk:**")
                st.write(pattern["privilege_escalation_risk"])

            if pattern.get("temporal_anomalies"):
                st.markdown("**⏰ Temporal Anomalies:**")
                st.write(pattern["temporal_anomalies"])

            if pattern.get("geographic_anomalies"):
                st.markdown("**🌍 Geographic Anomalies:**")
                st.write(pattern["geographic_anomalies"])

        with col2:
            if pattern.get("authentication_concerns"):
                st.markdown("**🔐 Authentication Concerns:**")
                st.write(pattern["authentication_concerns"])

            if pattern.get("device_trust_issues"):
                st.markdown("**💻 Device Trust Issues:**")
                st.write(pattern["device_trust_issues"])

            if pattern.get("behavioral_deviations"):
                st.markdown("**📊 Behavioral Deviations:**")
                st.write(pattern["behavioral_deviations"])

        st.markdown("---")

    # Key Findings
    if "key_findings" in analysis and analysis["key_findings"]:
        st.subheader("🔍 Key Findings by Investigation Step")
        for idx, finding in enumerate(analysis["key_findings"], 1):
            severity = finding.get("severity", "Unknown").upper()

            if severity == "CRITICAL":
                css_class = "risk-critical"
                emoji = "🔴"
            elif severity == "HIGH":
                css_class = "risk-high"
                emoji = "🟠"
            elif severity == "MEDIUM":
                css_class = "risk-medium"
                emoji = "🟡"
            else:
                css_class = "risk-low"
                emoji = "🟢"

            st.markdown(
                f"""
            <div class="{css_class}">
                <h4>{emoji} Finding #{idx}: {finding.get('category', 'Unknown Category')} ({severity})</h4>
                <p><strong>📍 Step Reference:</strong> {finding.get('step_reference', 'N/A')}</p>
                <p><strong>📝 Details:</strong> {finding.get('details', 'No details provided')}</p>
                <p><strong>🔬 Evidence:</strong> {finding.get('evidence', 'No evidence provided')}</p>
                <p><strong>⚠️ Impact:</strong> {finding.get('impact', 'No impact assessment')}</p>
            </div>
            """,
                unsafe_allow_html=True,
            )

        st.markdown("---")

    # Timeline Correlation
    if "timeline_correlation" in analysis and analysis["timeline_correlation"]:
        st.subheader("⏱️ Timeline Correlation Analysis")
        for correlation in analysis["timeline_correlation"]:
            st.markdown(
                f"""
            <div class="step-card">
                <p><strong>Event Sequence:</strong> {correlation.get('event_sequence', 'N/A')}</p>
                <p><strong>Timestamps:</strong> {correlation.get('timestamps', 'N/A')}</p>
                <p><strong>Significance:</strong> {correlation.get('significance', 'N/A')}</p>
            </div>
            """,
                unsafe_allow_html=True,
            )
        st.markdown("---")

    # Step-by-Step Analysis
    if "step_by_step_analysis" in analysis and analysis["step_by_step_analysis"]:
        st.subheader("📊 Step-by-Step Contribution to Classification")
        for step_analysis in analysis["step_by_step_analysis"]:
            with st.expander(f"📌 {step_analysis.get('step', 'Unknown Step')}"):
                st.markdown(f"**Finding:** {step_analysis.get('finding', 'N/A')}")
                st.markdown(
                    f"**Classification Contribution:** {step_analysis.get('contribution_to_classification', 'N/A')}"
                )
        st.markdown("---")

    # Risk Indicators
    if "risk_indicators" in analysis and analysis["risk_indicators"]:
        st.subheader("⚠️ Risk Indicators")
        for indicator in analysis["risk_indicators"]:
            st.markdown(f"- {indicator}")
        st.markdown("---")

    # Recommendations
    if "recommendations" in analysis and analysis["recommendations"]:
        st.subheader("✅ Recommended Actions")
        for idx, rec in enumerate(analysis["recommendations"], 1):
            if idx == 1 and "TRUE POSITIVE" in analysis.get("classification", ""):
                st.error(f"**🚨 URGENT #{idx}:** {rec}")
            elif idx <= 3:
                st.warning(f"**⚠️ High Priority #{idx}:** {rec}")
            else:
                st.info(f"**📋 #{idx}:** {rec}")
        st.markdown("---")

    # Justification
    if "justification" in analysis:
        st.subheader("📖 Classification Justification")
        st.write(analysis["justification"])


# Main App
def main():
    final_api_key = os.getenv("GOOGLE_API_KEY")

    st.markdown(
        "<h1 class='main-header'>🔐 Privileged Role Investigation Analyzer</h1>",
        unsafe_allow_html=True,
    )
    st.markdown("**AI-Powered Security Assessment with Pattern Recognition**")

    # File upload
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
            st.subheader("👤 User Analysis")
            username = st.text_input(
                "Enter username/email to analyze",
                placeholder="e.g., john.doe@abc.com",
                help="Enter the exact username or email address from the investigation",
            )

            if st.button(
                "🔍 Analyze User with Pattern Recognition",
                type="primary",
                width="stretch",
                disabled=not final_api_key,
            ):
                if not final_api_key:
                    st.error("❌ Some error occured")
                elif username:
                    with st.spinner(
                        f"🤖 AI analyzing investigation patterns for {username}..."
                    ):
                        # Extract investigation steps
                        investigation_steps = extract_investigation_steps(df, username)

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

                            # Show extracted steps
                            with st.expander("📊 Extracted Investigation Steps"):
                                for step in investigation_steps:
                                    st.markdown(
                                        f"**Step {step['step_number']}: {step['step_name']}**"
                                    )
                                    st.text(
                                        f"Output preview: {str(step['output'])[:200]}..."
                                    )
                                    st.markdown("---")

                            analysis = analyze_with_gemini(
                                username, investigation_steps, df, final_api_key
                            )

                            if analysis:
                                st.markdown("---")
                                display_analysis_results(analysis, username)

                                # Download report button
                                st.markdown("---")
                                col1, col2 = st.columns(2)

                                with col1:
                                    report_json = json.dumps(analysis, indent=2)
                                    st.download_button(
                                        label="📥 Download Full Analysis (JSON)",
                                        data=report_json,
                                        file_name=f"analysis_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                                        mime="application/json",
                                        width="stretch",
                                    )

                                with col2:
                                    # Create a summary report
                                    summary = f"""PRIVILEGED ROLE INVESTIGATION SUMMARY
                                    
User: {username}
Classification: {analysis.get('classification', 'N/A')}
Risk Level: {analysis.get('risk_level', 'N/A')}
Confidence: {analysis.get('confidence_score', 0)}%

Summary: {analysis.get('summary', 'N/A')}

Key Recommendations:
{chr(10).join([f"{i+1}. {rec}" for i, rec in enumerate(analysis.get('recommendations', [])[:5])])}

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
                                    st.download_button(
                                        label="📄 Download Summary Report (TXT)",
                                        data=summary,
                                        file_name=f"summary_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                                        mime="text/plain",
                                        width="stretch",
                                    )
                            else:
                                st.error(
                                    "❌ Analysis failed. Please check your API key and try again."
                                )
                else:
                    st.warning("⚠️ Please enter a username to analyze")
    else:
        st.info("👆 Please upload an Excel file to begin analysis")


if __name__ == "__main__":
    main()
