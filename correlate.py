import json
import google.generativeai as genai
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


def analyze_security_data_with_llm(json_data):
    """Use LLM to analyze JSON security data and generate alerts"""

    # Configure Gemini
    api_key = os.getenv("GOOGLE_API_KEY")
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-2.0-flash-exp")

    # Prepare the prompt for security analysis
    prompt = f"""
    Analyze this security log data and generate security alerts in EXACTLY the same format as the example below.

    CRITICAL: You MUST use the EXACT same format, emojis, and structure as the example.

    EXAMPLE FORMAT:
    
    ### ALERT-001: Device Isolation Script Detected
    **Severity:** 🟡 MEDIUM  
    **Category:** Defense Evasion / System Configuration  
    **MITRE ATT&CK:** T1562.004 (Disable or Modify System Firewall)

    **Description:**
    [Description here]

    **Evidence:**
    - **Timestamp:** [timestamp]
    - **Action Type:** [type]
    - **File SHA256:** [hash]
    - **Script Name:** [name]
    - **Key Components:**
      - [component 1]
      - [component 2]

    **Risk Assessment:**
    [Risk assessment]

    **Recommendations:**
    - ✅ [Recommendation 1]
    - ✅ [Recommendation 2]

    NOW ANALYZE THIS ACTUAL DATA:

    {json.dumps(json_data, indent=2)}

    Generate 4-6 security alerts following the EXACT format above. Focus on:
    1. Script executions
    2. File operations  
    3. Network connections
    4. Process activities
    5. Authentication events
    6. System configurations

    Make sure each alert has:
    - ALERT-XXX numbering
    - Proper severity emojis (🟡 MEDIUM, 🟢 LOW)
    - MITRE ATT&CK mappings where applicable
    - Specific evidence from the logs
    - Actionable recommendations with ✅ emoji
    """

    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Error generating analysis: {str(e)}"


def generate_complete_report(json_data):
    """Generate complete security report using LLM"""

    api_key = os.getenv("GOOGLE_API_KEY")
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-2.0-flash-exp")

    # First, let the LLM extract metadata
    metadata_prompt = f"""
    Extract key metadata from this security log data and return as a structured summary:

    {json.dumps(json_data, indent=2)[:10000]}  # Limit size for context

    Provide a summary with:
    - Total events count
    - Devices found with their status
    - Time range
    - Key event categories
    - Notable patterns

    Return in concise bullet points.
    """

    try:
        # Get metadata summary
        metadata_response = model.generate_content(metadata_prompt)

        # Now generate security alerts
        security_alerts = analyze_security_data_with_llm(json_data)

        # Generate final report
        report_prompt = f"""
        Create a comprehensive security analysis report using this metadata and security alerts.

        METADATA SUMMARY:
        {metadata_response.text}

        SECURITY ALERTS:
        {security_alerts}

        Generate a complete report in this EXACT format:

        # Security Analysis Report
        **Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        **Analysis Period:** [from metadata]
        **Device:** [from metadata]

        ---

        ## 🎯 Executive Summary

        **Total Events Analyzed:** [number]
        **Alerts Generated:** [number]  
        **Highest Severity:** [level]
        **Devices Monitored:** [number]

        [Brief summary]

        ---

        ## 🚨 Security Alerts

        [Include all the security alerts exactly as generated above]

        ---

        ## 📊 Event Timeline

        [Create timeline from the data]

        ---

        ## 🛡️ Recommendations

        [Overall recommendations]

        ---

        **Report End**

        Use the exact same emojis, formatting, and structure as the example.
        """

        final_report = model.generate_content(report_prompt)
        return final_report.text

    except Exception as e:
        return f"Error generating report: {str(e)}"


# Usage example
if __name__ == "__main__":
    # Load your JSON data
    with open(
        "sentinel_logs1\sentinel_logs_2025-11-07 06-00-07-00\sentinel_endpoint_security_20251107_0600_0700.json",
        "r",
    ) as f:
        security_data = json.load(f)

    # Generate complete report using LLM only
    report = generate_complete_report(security_data)
    print(report)

    # Save to file
    with open("security_analysis_report.md", "w") as f:
        f.write(report)
