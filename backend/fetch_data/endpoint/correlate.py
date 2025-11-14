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


def parse_alert_to_json(alert_text):
    """Parse a single alert markdown text into structured JSON with improved key components extraction"""
    alert_data = {
        "alert_id": "",
        "title": "",
        "severity": "",
        "category": "",
        "mitre_attack": "",
        "description": "",
        "evidence": {},
        "risk_assessment": "",
    }

    try:
        # Extract alert ID and title
        title_match = re.search(r"### ALERT-(\d+): (.+)", alert_text)
        if title_match:
            alert_data["alert_id"] = f"ALERT-{title_match.group(1)}"
            alert_data["title"] = title_match.group(2).strip()

        # Extract severity
        severity_match = re.search(r"\*\*Severity:\*\* ([^\n]+)", alert_text)
        if severity_match:
            severity_text = severity_match.group(1).strip()
            if "🔴" in severity_text or "HIGH" in severity_text:
                alert_data["severity"] = "HIGH"
            elif "🟡" in severity_text or "MEDIUM" in severity_text:
                alert_data["severity"] = "MEDIUM"
            elif "🟢" in severity_text or "LOW" in severity_text:
                alert_data["severity"] = "LOW"

        # Extract category
        category_match = re.search(r"\*\*Category:\*\* (.+)", alert_text)
        if category_match:
            alert_data["category"] = category_match.group(1).strip()

        # Extract MITRE ATT&CK
        mitre_match = re.search(r"\*\*MITRE ATT&CK:\*\* (.+)", alert_text)
        if mitre_match:
            alert_data["mitre_attack"] = mitre_match.group(1).strip()

        # Extract description
        desc_match = re.search(
            r"\*\*Description:\*\*\s*(.+?)(?=\*\*Evidence:\*\*)", alert_text, re.DOTALL
        )
        if desc_match:
            alert_data["description"] = desc_match.group(1).strip()

        # Extract evidence section - COMPLETELY REWRITTEN
        evidence_section = re.search(
            r"\*\*Evidence:\*\*(.+?)(?=\*\*Risk Assessment:\*\*)", alert_text, re.DOTALL
        )

        if evidence_section:
            evidence_text = evidence_section.group(1).strip()

            # Split by lines and process each bullet point
            lines = evidence_text.split("\n")
            current_field = None
            key_components = []

            for line in lines:
                line = line.strip()

                # Match main bullet points: - **FieldName:** value
                main_bullet = re.match(r"^-\s+\*\*([^:]+):\*\*\s*(.*)$", line)

                if main_bullet:
                    field_name = main_bullet.group(1).strip()
                    field_value = main_bullet.group(2).strip()

                    if field_name == "Key Components":
                        # Starting key components section
                        current_field = "Key Components"
                        if field_value:  # If there's content on same line
                            key_components.append(field_value)
                    else:
                        # Regular field
                        current_field = None
                        alert_data["evidence"][field_name] = field_value

                # Match nested bullet points under Key Components: - value or  - value
                elif current_field == "Key Components":
                    nested_bullet = re.match(r"^\s*-\s+(.+)$", line)
                    if nested_bullet:
                        component = nested_bullet.group(1).strip()
                        if component:
                            key_components.append(component)

            # Add key components if any were found
            if key_components:
                alert_data["evidence"]["Key Components"] = key_components

        # Extract Risk Assessment
        risk_match = re.search(
            r"\*\*Risk Assessment:\*\*\s*(.+?)(?=---|###|$)", alert_text, re.DOTALL
        )
        if risk_match:
            alert_data["risk_assessment"] = risk_match.group(1).strip()

    except Exception as e:
        print(f"    ⚠️  Error parsing alert: {str(e)[:100]}")

    return alert_data


def analyze_table_for_alerts(table_name, table_data, model, alert_start_number):
    """Analyze a single table and generate alerts"""

    if not table_data or len(table_data) == 0:
        return None, alert_start_number, []

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
            return None, alert_start_number, []

        # Parse alerts into JSON
        alert_sections = re.split(r"(?=### ALERT-)", content)
        parsed_alerts = []

        for section in alert_sections:
            if section.strip() and "### ALERT-" in section:
                alert_json = parse_alert_to_json(section)
                if alert_json["alert_id"]:
                    parsed_alerts.append(alert_json)

        # Count how many alerts were generated
        alert_count = len(parsed_alerts)

        return content, alert_start_number + alert_count, parsed_alerts

    except Exception as e:
        print(f"    ❌ Error: {str(e)[:100]}")
        return None, alert_start_number, []


def generate_complete_report(json_data):
    """Generate complete security report by analyzing each table separately"""

    model = configure_gemini()

    print("🔍 Extracting metadata...")
    metadata = extract_report_metadata(json_data, model)

    print("📊 Analyzing security events table by table...")
    all_alerts = []
    all_alerts_json = []
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

            alerts, alert_number, alerts_json = analyze_table_for_alerts(
                table_name, table_data, model, alert_number
            )

            if alerts:
                all_alerts.append(alerts)
                all_alerts_json.extend(alerts_json)
                print(f"    ✓ Generated {len(alerts_json)} alert(s)")
            else:
                print(f"    ⊘ No alerts generated")

    # Combine all alerts
    combined_alerts = (
        "\n\n".join(all_alerts) if all_alerts else "No security alerts generated."
    )

    print("📝 Assembling final report...")

    # Generate executive summary
    exec_summary_prompt = f"""
    Create an executive summary based on this metadata and alerts.
    
    METADATA:
    {metadata}
    
    ALERTS GENERATED: {len(all_alerts_json)}
    
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
        exec_summary = f"**Total Events Analyzed:** [See metadata]\n**Alerts Generated:** {len(all_alerts_json)}"

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

    # Calculate severity distribution
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for alert in all_alerts_json:
        severity = alert.get("severity", "LOW")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    highest_severity = "LOW"
    if severity_counts["HIGH"] > 0:
        highest_severity = "HIGH"
    elif severity_counts["MEDIUM"] > 0:
        highest_severity = "MEDIUM"

    # Create JSON structure
    report_json = {
        "report_metadata": {
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "analysis_period": time_range,
            "device": device_name,
            "total_events_analyzed": sum(
                len(v) if isinstance(v, list) else 0 for v in json_data.values()
            ),
            "alerts_generated": len(all_alerts_json),
            "highest_severity": highest_severity,
            "severity_distribution": severity_counts,
        },
        "executive_summary": exec_summary,
        "security_alerts": all_alerts_json,
        "raw_metadata": metadata,
    }

    # Assemble final markdown report
    report_md = f"""# Security Analysis Report
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

**Report End**

*This analysis was generated by AI-powered security log analyzer. Always validate findings with manual investigation and consult with security team for critical decisions.*
"""

    return report_md, report_json


# Usage example
if __name__ == "__main__":
    print("🚀 Starting Security Analysis Report Generation")
    print("=" * 60)

    # Load your JSON data
    json_file_path = "sentinel_logs1/sentinel_logs_2025-11-07 06-00-07-00/cleaned_sentinel_endpoint_security_20251107_0600_0700.json"

    print(f"📁 Loading data from: {json_file_path}")
    with open(json_file_path, "r", encoding="utf-8") as f:
        security_data = json.load(f)

    total_events = sum(len(v) if isinstance(v, list) else 0 for v in security_data.values())
    print(f"✓ Loaded {total_events} total events")
    print()

    # Generate complete report
    report_md, report_json = generate_complete_report(security_data)

    # Save markdown report
    output_file_md = "endpoint_analysis_report.md"
    with open(output_file_md, "w", encoding="utf-8") as f:
        f.write(report_md)

    # Save JSON report
    output_file_json = "endpoint_analysis_report.json"
    with open(output_file_json, "w", encoding="utf-8") as f:
        json.dump(report_json, f, indent=2, ensure_ascii=False)

    print()
    print("=" * 60)
    print(f"✅ Markdown report generated: {output_file_md}")
    print(f"✅ JSON report generated: {output_file_json}")
    print()
    print("Markdown Preview:")
    print("-" * 60)
    print(report_md[:500] + "...")
    print()
    print("JSON Structure:")
    print("-" * 60)
    print(f"Total Alerts: {len(report_json['security_alerts'])}")
    print(f"Highest Severity: {report_json['report_metadata']['highest_severity']}")
