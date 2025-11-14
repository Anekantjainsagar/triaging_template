# components/ip_analysis.py
import streamlit as st
import concurrent.futures
import hashlib
import json
from datetime import datetime

# Replace the analyze_ip_entities_parallel function in main.py with this fixed version


def analyze_ip_entities_parallel(ip_entities: list, client):
    """Analyze multiple IP entities in parallel for True/False Positive classification"""
    import concurrent.futures
    import hashlib

    # Build IP list
    ips = []
    for entity in ip_entities:
        props = entity.get("properties", {})
        ip_address = props.get("address", "Unknown")
        ips.append(ip_address)

    if not ips:
        st.warning("⚠️ No IP addresses to analyze")
        return

    # Progress tracking
    progress_bar = st.progress(0)
    status_text = st.empty()

    # Results container
    results = {}

    def analyze_single_ip(ip_address: str):
        """Analyze single IP entity"""
        cache_key = (
            f"ip_prediction_{ip_address}_{hashlib.md5(ip_address.encode()).hexdigest()}"
        )

        # Check cache first
        if cache_key in st.session_state:
            return ip_address, st.session_state[cache_key]

        try:
            # ✅ FIXED: Call IP analysis endpoint
            ip_analysis = client.analyze_ip_reputation(ip_address)

            if ip_analysis.get("success"):
                # ✅ FIXED: Handle nested response format
                result = {
                    "success": True,
                    "initial_analysis": ip_analysis.get("analysis", {}).get(
                        "initial_analysis", {}
                    ),
                    "executive_summary": ip_analysis.get("analysis", {}).get(
                        "executive_summary", {}
                    ),
                    "threat_intelligence": ip_analysis.get("analysis", {}).get(
                        "threat_intelligence", {}
                    ),
                }
                st.session_state[cache_key] = result
                return ip_address, result
            else:
                error_msg = ip_analysis.get("error", "Unknown error")
                if "No data" in error_msg or "404" in str(error_msg):
                    return ip_address, {"error": "no_data", "ip": ip_address}
                else:
                    return ip_address, {"error": error_msg, "ip": ip_address}
        except Exception as e:
            error_str = str(e)
            if "404" in error_str or "No data" in error_str:
                return ip_address, {"error": "no_data", "ip": ip_address}
            else:
                return ip_address, {"error": str(e), "ip": ip_address}

    # Execute parallel analysis
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(analyze_single_ip, ip): ip for ip in ips}

        completed = 0
        total = len(futures)

        for future in concurrent.futures.as_completed(futures):
            ip_address = futures[future]
            try:
                ip_address, result = future.result()
                results[ip_address] = result
                completed += 1

                progress_bar.progress(completed / total)
                status_text.text(f"Analyzed {completed}/{total} IP addresses...")

            except Exception as e:
                results[ip_address] = {"error": str(e), "ip": ip_address}
                completed += 1
                progress_bar.progress(completed / total)

    progress_bar.empty()
    status_text.empty()

    st.success("✅ IP parallel analysis complete!")
    st.markdown("---")

    # Display results for each IP
    for ip_address in ips:
        result = results.get(ip_address, {})

        if "error" in result:
            if result["error"] == "no_data":
                with st.expander(f"🌐 {ip_address} - ℹ️ No Data", expanded=False):
                    st.info(
                        f"No specific threat intelligence found for {ip_address}. "
                        "This could indicate a legitimate or lesser-known IP address."
                    )
            else:
                with st.expander(f"🌐 {ip_address} - ❌ Error", expanded=False):
                    st.error(f"Analysis failed: {result['error']}")
        else:
            display_ip_analysis_full(ip_address, result)


def display_ip_analysis_full(ip_address: str, ip_analysis: dict):
    """Display complete IP analysis with classification and risk assessment"""

    initial = ip_analysis.get("initial_analysis", {})
    classification = initial.get("classification", "UNKNOWN")

    # IP reputation blocks should be closed by default
    is_expanded = False

    # Accordion header
    if "TRUE POSITIVE" in classification or "MALICIOUS" in classification.upper():
        header = f"🌐 {ip_address} - 🚨 MALICIOUS/TRUE POSITIVE"
    elif "FALSE POSITIVE" in classification or "CLEAN" in classification.upper():
        header = f"🌐 {ip_address} - ✅ BENIGN/FALSE POSITIVE"
    else:
        header = f"🌐 {ip_address} - ℹ️ {classification}"

    with st.expander(header, expanded=is_expanded):
        # Display IP classification results
        display_ip_analysis_results(ip_analysis, ip_address)

        # Download section
        st.markdown("---")
        st.markdown("### 📥 Download Options")

        col1, col2, col3 = st.columns(3)

        with col1:
            # Full JSON report
            import json
            from datetime import datetime

            report_json = json.dumps(ip_analysis, indent=2)
            st.download_button(
                label="📄 Full Analysis (JSON)",
                data=report_json,
                file_name=f"ip_analysis_{ip_address.replace('.', '_').replace(':', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                key=f"download_ip_full_{ip_address}",
                width="stretch",
            )

        with col2:
            exec_summary = ip_analysis.get("executive_summary", {})

            summary_text = f"""IP REPUTATION REPORT

IP Address: {ip_address}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

CLASSIFICATION: {initial.get('classification', 'N/A')}
RISK LEVEL: {initial.get('risk_level', 'N/A')}
THREAT SCORE: {initial.get('threat_score', 'N/A')}/100

EXECUTIVE SUMMARY:
{exec_summary.get('one_line_summary', 'N/A')}

THREAT DETAILS:
{exec_summary.get('threat_details', 'N/A')}

IMMEDIATE ACTIONS:
{chr(10).join([f"- {action}" for action in exec_summary.get('immediate_actions', [])])}

PRIORITY: {exec_summary.get('investigation_priority', 'N/A')}
"""

            st.download_button(
                label="📋 Summary Report (TXT)",
                data=summary_text,
                file_name=f"ip_summary_{ip_address.replace('.', '_').replace(':', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain",
                key=f"download_ip_summary_{ip_address}",
                width="stretch",
            )

        with col3:
            threat_intel = ip_analysis.get("threat_intelligence", {})
            if threat_intel:
                intel_json = json.dumps(threat_intel, indent=2)
                st.download_button(
                    label="🔍 Threat Intel (JSON)",
                    data=intel_json,
                    file_name=f"ip_threat_intel_{ip_address.replace('.', '_').replace(':', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json",
                    key=f"download_ip_intel_{ip_address}",
                    width="stretch",
                )


def display_ip_analysis_results(ip_analysis: dict, ip_address: str):
    """Display IP analysis results with classification, risk metrics, and threat indicators"""

    initial = ip_analysis.get("initial_analysis", {})
    classification = initial.get("classification", "UNKNOWN")

    # Classification badge
    if "MALICIOUS" in classification.upper() or "TRUE POSITIVE" in classification:
        st.error(f"🚨 **Classification:** {classification}")
    elif "CLEAN" in classification.upper() or "FALSE POSITIVE" in classification:
        st.success(f"✅ **Classification:** {classification}")
    else:
        st.info(f"ℹ️ **Classification:** {classification}")

    st.markdown("---")

    # Key metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Risk Level", initial.get("risk_level", "UNKNOWN"))
    with col2:
        st.metric("Threat Score", f"{initial.get('threat_score', 0)}/100")
    with col3:
        st.metric("Confidence", f"{initial.get('confidence_score', 0)}%")

    st.markdown("---")

    # Geolocation information
    geo_info = initial.get("geolocation", {})
    if geo_info and any(geo_info.values()):
        st.markdown("### 📍 Geolocation Information")
        col1, col2, col3 = st.columns(3)

        with col1:
            st.write(f"**Country:** {geo_info.get('country', 'Unknown')}")
        with col2:
            st.write(f"**City:** {geo_info.get('city', 'Unknown')}")
        with col3:
            st.write(f"**ISP:** {geo_info.get('isp', 'Unknown')}")

        if geo_info.get("is_high_risk_country"):
            st.warning("⚠️ **High-risk country detected** - Increases threat assessment")

        st.markdown("---")

    # Threat indicators
    threat_indicators = initial.get("threat_indicators", [])
    if threat_indicators:
        st.markdown("### 🎯 Threat Indicators")
        for indicator in threat_indicators:
            severity = indicator.get("severity", "Medium")
            severity_color = {
                "Critical": "🔴",
                "High": "🟠",
                "Medium": "🟡",
                "Low": "🟢",
            }.get(severity, "⚪")

            st.markdown(
                f"""
**{severity_color} {indicator.get('name', 'Indicator')}** ({severity})
- **Type:** {indicator.get('type', 'N/A')}
- **Details:** {indicator.get('details', 'N/A')}
- **Evidence:** {indicator.get('evidence', 'N/A')}
            """
            )

        st.markdown("---")

    # Reputation services summary
    reputation_sources = initial.get("reputation_sources", {})
    if reputation_sources:
        st.markdown("### 🛡️ Reputation Services")

        col1, col2, col3 = st.columns(3)

        with col1:
            virustotal = reputation_sources.get("virustotal", {})
            if virustotal:
                detections = virustotal.get("detections", 0)
                total = virustotal.get("total_vendors", 95)
                st.metric(
                    "VirusTotal Detections",
                    f"{detections}/{total}",
                )

        with col2:
            if virustotal:
                st.write(
                    f"**Detection Rate:** {virustotal.get('detection_rate', 'N/A')}"
                )

        with col3:
            if virustotal:
                st.write(f"**Country:** {virustotal.get('country', 'Unknown')}")

        st.markdown("---")

    # Key findings
    key_findings = initial.get("key_findings", [])
    if key_findings:
        st.markdown("### 📋 Key Findings")
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
            """
            )

        st.markdown("---")

    # Executive summary
    exec_summary = ip_analysis.get("executive_summary", {})
    if exec_summary:
        st.markdown("### 📝 Executive Summary")
        st.write(exec_summary.get("one_line_summary", "No summary available"))

        actions = exec_summary.get("immediate_actions", [])
        if actions:
            st.markdown("**Immediate Actions:**")
            for action in actions:
                st.markdown(f"- {action}")
