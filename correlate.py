import json
import google.generativeai as genai
import os
import time
import re
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


def configure_gemini():
    """Configure Gemini API"""
    api_key = os.getenv("GOOGLE_API_KEY")
    genai.configure(api_key=api_key)
    return genai.GenerativeModel("gemini-2.5-flash")


def safe_api_call(model, prompt, delay=3, max_retries=3):
    """Make API call with automatic retry and rate limiting"""

    for attempt in range(max_retries):
        try:
            # Add delay before each call
            if attempt > 0:
                print(f"    🔄 Retry attempt {attempt + 1}/{max_retries}")

            time.sleep(delay)
            response = model.generate_content(prompt)
            # print(response)
            return response.text

        except Exception as e:
            error_msg = str(e)
            print(error_msg)

            # Check for rate limit error
            if "429" in error_msg or "quota" in error_msg.lower():
                # Try to extract wait time from error message
                wait_time = 60  # Default
                try:
                    # Look for "retry in XX.XXs" pattern
                    match = re.search(r"retry in (\d+)\.?\d*s", error_msg)
                    if match:
                        wait_time = int(float(match.group(1))) + 5
                except:
                    pass

                if attempt < max_retries - 1:
                    print(f"    ⚠️  Rate limit hit. Waiting {wait_time} seconds...")
                    time.sleep(wait_time)
                    continue
                else:
                    print(f"    ❌ Failed after {max_retries} retries")
                    raise
            else:
                # Non-rate-limit error
                print(f"    ❌ API Error: {str(e)[:100]}")
                raise

    raise Exception(f"Failed after {max_retries} retries")


def extract_report_metadata(json_data, model):
    """Extract metadata from the entire dataset"""

    metadata_prompt = f"""
    Analyze this security log data and extract key metadata.
    
    Data: {json.dumps(json_data, indent=2)[:15000]}
    
    Extract and return in this EXACT format:
    
    TOTAL_EVENTS: [total count across all tables]
    DEVICES: [comma-separated list of device names]
    TIME_RANGE: [earliest to latest timestamp in format "YYYY-MM-DD HH:MM - HH:MM UTC"]
    EVENT_CATEGORIES: [comma-separated list of non-empty table names]
    PRIMARY_DEVICE: [main device being monitored]
    
    Be precise and extract actual values from the data.
    """

    try:
        return safe_api_call(model, metadata_prompt, delay=2)
    except Exception as e:
        return f"Error extracting metadata: {str(e)[:200]}"


def analyze_table_for_alerts(table_name, table_data, model, alert_start_number):
    """Analyze a single table and generate alerts"""

    if not table_data or len(table_data) == 0:
        return None, alert_start_number

    prompt = f"""
    You are a security analyst. Analyze this specific security event table and generate relevant security alerts.
    
    TABLE NAME: {table_name}
    TABLE DATA: {json.dumps(table_data, indent=2)}
    
    INSTRUCTIONS:
    - Generate as many security alerts as necessary based on the events in this table
    - Create separate alerts for each distinct security concern
    - Analyze each event carefully for potential threats
    - Start alert numbering from ALERT-{alert_start_number:03d}
    - Use this EXACT format for each alert:
    
    ### ALERT-XXX: [Alert Title]
    **Severity:** [🔴 HIGH / 🟡 MEDIUM / 🟢 LOW]
    **Category:** [Category Name]
    **MITRE ATT&CK:** [Technique ID and name if applicable, or "N/A"]
    
    **Description:**
    [2-3 sentences describing what was detected and why it matters]
    
    **Evidence:**
    - **Timestamp:** [actual timestamp from data]
    - **Action Type:** [from data]
    - **[Other Key Field]:** [value from data]
    - **Key Components:**
      - [specific detail 1]
      - [specific detail 2]
    
    **Risk Assessment:**
    [1-2 sentences about the actual risk level and context]

    ---
    
    IMPORTANT:
    - Only generate alerts if there are actual security-relevant events
    - Use actual data from the logs (timestamps, IDs, commands, etc.)
    - If the table shows normal operations, still create an alert but mark it as LOW severity
    - Focus on: suspicious activities, patterns, anomalies, misconfigurations, or notable system events
    - For table: {table_name}, consider what security insights this data provides
    
    If this table has no security-relevant events, return exactly: "NO_ALERTS"
    """

    try:
        content = safe_api_call(model, prompt, delay=4)
        content = content.strip()

        if "NO_ALERTS" in content:
            return None, alert_start_number

        # Count how many alerts were generated
        alert_count = content.count("### ALERT-")

        return content, alert_start_number + alert_count

    except Exception as e:
        print(f"    ❌ Error: {str(e)[:100]}")
        return None, alert_start_number


def generate_event_timeline(json_data, model):
    """Generate timeline from all events"""

    timeline_prompt = f"""
    Create a chronological event timeline from this security data.
    
    Data: {json.dumps(json_data, indent=2)[:20000]}
    
    Generate a timeline in this EXACT format:
    
    ```
    HH:MM:SS - [Brief description of event type and key detail]
    HH:MM:SS - [Brief description of event type and key detail]
    ```
    
    - Include 8-12 most significant events
    - Use actual timestamps from the data
    - Keep descriptions concise (max 80 characters)
    - Order chronologically
    - Focus on security-relevant events
    """

    try:
        return safe_api_call(model, timeline_prompt, delay=3)
    except Exception as e:
        return f"Timeline generation failed: {str(e)[:200]}"


def generate_complete_report(json_data):
    """Generate complete security report by analyzing each table separately"""

    model = configure_gemini()

    print("🔍 Extracting metadata...")
    metadata = extract_report_metadata(json_data, model)

    print("📊 Analyzing security events table by table...")
    all_alerts = []
    alert_number = 1

    # Define table processing order
    table_order = [
        "DeviceEvents",
        "DeviceFileEvents",
        "DeviceProcessEvents",
        "DeviceNetworkEvents",
        "DeviceLogonEvents",
        "DeviceRegistryEvents",
        "DeviceImageLoadEvents",
        "DeviceFileCertificateInfo",
        "DeviceInfo",
        "DeviceNetworkInfo",
    ]

    for table_name in table_order:
        if table_name in json_data:
            table_data = json_data[table_name]
            print(f"  → Analyzing {table_name} ({len(table_data)} events)...")

            alerts, alert_number = analyze_table_for_alerts(
                table_name, table_data, model, alert_number
            )

            if alerts:
                all_alerts.append(alerts)
                print(f"    ✓ Generated alerts")
            else:
                print(f"    ⊘ No alerts generated")

    # Combine all alerts
    combined_alerts = (
        "\n\n".join(all_alerts) if all_alerts else "No security alerts generated."
    )

    print("⏱️ Generating event timeline...")
    timeline = generate_event_timeline(json_data, model)


    print("📝 Assembling final report...")

    # Generate executive summary
    exec_summary_prompt = f"""
    Create an executive summary based on this metadata and alerts.
    
    METADATA:
    {metadata}
    
    ALERTS GENERATED: {len(all_alerts)}
    
    Generate in this EXACT format:
    
    **Total Events Analyzed:** [number]
    **Alerts Generated:** [number]
    **Highest Severity:** [HIGH/MEDIUM/LOW]
    **Devices Monitored:** [number]
    
    [2-3 sentence summary of key findings]
    """

    try:
        exec_summary = safe_api_call(model, exec_summary_prompt, delay=3)
    except:
        exec_summary = f"**Total Events Analyzed:** [See metadata]\n**Alerts Generated:** {len(all_alerts)}"

    # Parse metadata for report header
    device_name_prompt = f"""
    From this metadata, extract ONLY the primary device name:
    {metadata}
    
    Return ONLY the device name, nothing else.
    """

    time_range_prompt = f"""
    From this metadata, extract ONLY the time range:
    {metadata}
    
    Return in format: YYYY-MM-DD HH:MM - HH:MM UTC
    """

    try:
        device_name = safe_api_call(model, device_name_prompt, delay=3).strip()
        time_range = safe_api_call(model, time_range_prompt, delay=3).strip()
    except:
        device_name = "Unknown Device"
        time_range = "Unknown Time Range"

    # Assemble final report
    report = f"""# Security Analysis Report
**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Analysis Period:** {time_range}
**Device:** {device_name}

---

## 🎯 Executive Summary

{exec_summary}

---

## 🚨 Security Alerts

{combined_alerts}

---

## 📊 Event Timeline

{timeline}

---

**Report End**

*This analysis was generated by AI-powered security log analyzer. Always validate findings with manual investigation and consult with security team for critical decisions.*
"""

    return report


# Usage example
if __name__ == "__main__":
    print("🚀 Starting Security Analysis Report Generation")
    print("=" * 60)

    # Load your JSON data
    json_file_path = "sentinel_logs1\sentinel_logs_2025-11-07 06-00-07-00\cleaned_sentinel_endpoint_security_20251107_0600_0700.json"

    print(f"📁 Loading data from: {json_file_path}")
    with open(json_file_path, "r", encoding="utf-8") as f:
        security_data = json.load(f)

    print(
        f"✓ Loaded {sum(len(v) if isinstance(v, list) else 0 for v in security_data.values())} total events"
    )
    print()

    # Generate complete report
    report = generate_complete_report(security_data)

    # Save to file with UTF-8 encoding for emoji support
    output_file = "endpoint_analysis_report.md"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(report)

    print()
    print("=" * 60)
    print(f"✅ Report generated successfully: {output_file}")
    print()
    print("Preview:")
    print("-" * 60)
    print(report[:500] + "...")
