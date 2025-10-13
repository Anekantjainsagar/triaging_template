import os
import json
import streamlit as st
from datetime import datetime
from dotenv import load_dotenv

# Import backend
from backend.predictions_backend import InvestigationAnalyzer, parse_excel_data

load_dotenv()

# Page configuration
st.set_page_config(
    page_title="True/False Positive Analyzer with MITRE ATT&CK",
    page_icon="🔒",
    layout="wide",
)

# Custom CSS
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
    .mitre-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
    .attack-chain-box {
        background-color: #1f2937;
        color: white;
        padding: 1.5rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
    .sub-technique-badge {
        background-color: #3b82f6;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 0.25rem;
        font-size: 0.875rem;
        display: inline-block;
        margin: 0.25rem;
    }
    .technique-hierarchy {
        padding-left: 1.5rem;
        border-left: 3px solid #3b82f6;
        margin: 0.5rem 0;
    }
    
    /* MITRE Matrix Styles */
    .mitre-matrix-container {
        overflow-x: auto;
        margin: 2rem 0;
    }
    .mitre-matrix {
        border-collapse: collapse;
        width: 100%;
        min-width: 1200px;
        font-size: 0.75rem;
    }
    .mitre-matrix th {
        background-color: #1e3a8a;
        color: white;
        padding: 0.5rem;
        text-align: center;
        font-weight: bold;
        border: 1px solid #1e40af;
        position: sticky;
        top: 0;
        z-index: 10;
    }
    .mitre-matrix td {
        padding: 0.25rem 0.5rem;
        border: 1px solid #e5e7eb;
        vertical-align: top;
        background-color: #f9fafb;
        min-height: 80px;
        font-size: 0.7rem;
    }
    .technique-cell {
        cursor: pointer;
        transition: all 0.2s;
        margin: 2px 0;
        padding: 4px 6px;
        border-radius: 3px;
        font-size: 0.7rem;
        line-height: 1.2;
    }
    .technique-cell:hover {
        transform: scale(1.02);
        box-shadow: 0 2px 4px rgba(0,0,0,0.2);
    }
    .severity-red {
        background-color: #dc2626;
        color: white;
        font-weight: bold;
    }
    .severity-amber {
        background-color: #f59e0b;
        color: white;
        font-weight: bold;
    }
    .severity-green {
        background-color: #10b981;
        color: white;
        font-weight: bold;
    }
    .severity-blue {
        background-color: #3b82f6;
        color: white;
        font-weight: bold;
    }
    .severity-grey {
        background-color: #9ca3af;
        color: white;
    }
    .technique-id {
        font-size: 0.65rem;
        opacity: 0.8;
    }
    .info-tooltip {
        background-color: #eff6ff;
        border-left: 4px solid #3b82f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
        font-size: 0.9rem;
    }
    .timeline-item {
        background-color: #f8fafc;
        border-left: 3px solid #3b82f6;
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 0 0.5rem 0.5rem 0;
    }
    .procedure-box {
        background-color: #fef3c7;
        border: 1px solid #fbbf24;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def get_mitre_technique_ids():
    """
    Returns a mapping of technique names to their actual MITRE ATT&CK IDs.
    This should ideally be loaded from the official MITRE ATT&CK JSON/STIX data.
    """
    return {
        # Initial Access
        "Valid Accounts": "T1078",
        "Phishing": "T1566",
        "External Remote Services": "T1133",
        "Exploit Public-Facing Application": "T1190",
        # Persistence
        "Account Manipulation": "T1098",
        "Create Account": "T1136",
        "Valid Accounts": "T1078",
        # Privilege Escalation
        "Account Manipulation": "T1098",
        "Valid Accounts": "T1078",
        "Abuse Elevation Control Mechanism": "T1548",
        # Defense Evasion
        "Impair Defenses": "T1562",
        "Valid Accounts": "T1078",
        "Modify Authentication Process": "T1556",
        # Credential Access
        "Brute Force": "T1110",
        "Multi-Factor Authentication Interception": "T1111",
        "OS Credential Dumping": "T1003",
        "Steal Application Access Token": "T1528",
        # Discovery
        "Account Discovery": "T1087",
        "Cloud Infrastructure Discovery": "T1580",
        "Cloud Service Discovery": "T1526",
        "Cloud Storage Object Discovery": "T1530",
        # Lateral Movement
        "Remote Services": "T1021",
        "Use Alternate Authentication Material": "T1550",
        # Collection
        "Data from Cloud Storage": "T1530",
        "Email Collection": "T1114",
        # Exfiltration
        "Exfiltration Over Web Service": "T1567",
        "Transfer Data to Cloud Account": "T1537",
        # Impact
        "Data Encrypted for Impact": "T1486",
        "Account Access Removal": "T1531",
    }


def get_mitre_subtechnique_ids():
    """
    Returns a mapping of sub-technique names to their IDs.
    Format: "Parent Technique > Sub-technique": "T####.###"
    """
    return {
        # Valid Accounts sub-techniques
        "Valid Accounts > Default Accounts": "T1078.001",
        "Valid Accounts > Domain Accounts": "T1078.002",
        "Valid Accounts > Local Accounts": "T1078.003",
        "Valid Accounts > Cloud Accounts": "T1078.004",
        # Account Manipulation sub-techniques
        "Account Manipulation > Additional Cloud Credentials": "T1098.001",
        "Account Manipulation > Additional Email Delegate Permissions": "T1098.002",
        "Account Manipulation > Additional Cloud Roles": "T1098.003",
        "Account Manipulation > SSH Authorized Keys": "T1098.004",
        "Account Manipulation > Device Registration": "T1098.005",
        # Exfiltration Over Web Service
        "Exfiltration Over Web Service > Exfiltration to Code Repository": "T1567.001",
        "Exfiltration Over Web Service > Exfiltration to Cloud Storage": "T1567.002",
        "Exfiltration Over Web Service > Exfiltration to Text Storage Sites": "T1567.003",
        # Add more as needed...
    }


def create_complete_mitre_matrix(
    techniques_data: list, predicted_steps: list = None
) -> str:
    """
    Create complete MITRE ATT&CK matrix with ALL techniques shown in grey,
    then highlight observed (RED/AMBER/GREEN) and predicted (BLUE) techniques.
    """
    from backend.predictions_backend import MITREAttackAnalyzer

    # Get the complete MITRE data structure
    temp_analyzer = MITREAttackAnalyzer(api_key="dummy")
    mitre_full_data = temp_analyzer.mitre_data

    # Get technique ID mappings
    technique_ids = get_mitre_technique_ids()
    subtechnique_ids = get_mitre_subtechnique_ids()

    # Define all 14 MITRE ATT&CK tactics
    tactics = [
        "Reconnaissance",
        "Resource Development",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command and Control",
        "Exfiltration",
        "Impact",
    ]

    # Create lookup for observed/predicted techniques by name
    observed_map = {}
    for tech in techniques_data:
        key = f"{tech.get('tactic')}||{tech.get('technique')}"
        observed_map[key] = {
            "severity": tech.get("severity", "GREY"),
            "confidence": tech.get("confidence", 0),
            "type": "observed",
            "sub_technique": tech.get("sub_technique", ""),
            "sub_technique_id": tech.get("sub_technique_id", ""),
        }

    predicted_map = {}
    if predicted_steps:
        for pred in predicted_steps:
            key = f"{pred.get('tactic')}||{pred.get('technique')}"
            predicted_map[key] = {
                "severity": "BLUE",
                "confidence": 0,
                "type": "predicted",
                "sub_technique": pred.get("sub_technique", ""),
                "sub_technique_id": pred.get("sub_technique_id", ""),
            }

    # Build complete technique list with ALL MITRE techniques
    tactic_techniques = {tactic: [] for tactic in tactics}

    for tactic in tactics:
        if tactic not in mitre_full_data:
            continue

        for technique_name, sub_techniques_list in mitre_full_data[tactic].items():
            lookup_key = f"{tactic}||{technique_name}"

            # Check if observed or predicted
            if lookup_key in observed_map:
                status = observed_map[lookup_key]
            elif lookup_key in predicted_map:
                status = predicted_map[lookup_key]
            else:
                status = {"severity": "GREY", "confidence": 0, "type": "default"}

            # Get technique ID
            tech_id = technique_ids.get(technique_name, "T????")

            tech_data = {
                "technique": technique_name,
                "technique_id": tech_id,
                "sub_technique": status.get("sub_technique", ""),
                "sub_technique_id": status.get("sub_technique_id", ""),
                "severity": status.get("severity", "GREY"),
                "confidence": status.get("confidence", 0),
                "type": status.get("type", "default"),
                "has_subtechniques": len(sub_techniques_list) > 0,
                "subtechniques_list": sub_techniques_list,
            }

            tactic_techniques[tactic].append(tech_data)

    # Build HTML
    html = '<div class="mitre-matrix-container">'
    html += '<table class="mitre-matrix">'

    # Header
    html += "<tr>"
    for tactic in tactics:
        html += f"<th>{tactic}<br/><span style='font-size:0.8em;'>({len(tactic_techniques[tactic])} techniques)</span></th>"
    html += "</tr>"

    # Find max techniques
    max_techniques = max([len(techs) for techs in tactic_techniques.values()] or [1])

    # Build rows
    for row_idx in range(max_techniques):
        html += "<tr>"
        for tactic in tactics:
            techniques = tactic_techniques[tactic]

            if row_idx < len(techniques):
                tech = techniques[row_idx]

                # Determine color
                severity = tech["severity"].upper()
                tech_type = tech["type"]

                if tech_type == "predicted":
                    color_class = "severity-blue"
                elif severity == "RED":
                    color_class = "severity-red"
                elif severity == "AMBER":
                    color_class = "severity-amber"
                elif severity == "GREEN":
                    color_class = "severity-green"
                else:
                    color_class = "severity-grey"

                # Build cell
                cell = f'<div class="technique-cell {color_class}">'
                cell += f'<strong>{tech["technique"]}</strong><br/>'
                cell += f'<span class="technique-id">{tech["technique_id"]}</span>'

                # Show sub-technique if highlighted
                if tech["sub_technique"] and tech["type"] in ["observed", "predicted"]:
                    cell += f'<br/><span style="font-size:0.65rem;">↳ {tech["sub_technique"]}</span>'
                    if tech["sub_technique_id"]:
                        cell += f'<br/><span class="technique-id">{tech["sub_technique_id"]}</span>'

                # Show count of sub-techniques for grey techniques
                if tech["has_subtechniques"] and tech["type"] == "default":
                    count = len(tech["subtechniques_list"])
                    cell += f'<br/><span style="font-size:0.6rem;opacity:0.6;">({count} sub-techs)</span>'

                if tech["confidence"] > 0:
                    cell += f'<br/><span style="font-size:0.6rem;">Conf: {tech["confidence"]}%</span>'
                elif tech_type == "predicted":
                    cell += '<br/><span style="font-size:0.6rem;">Predicted</span>'

                cell += "</div>"
                html += f"<td>{cell}</td>"
            else:
                html += "<td></td>"

        html += "</tr>"

    html += "</table></div>"

    # Legend
    html += """
    <div style="margin-top: 1rem; padding: 1rem; background-color: #f3f4f6; border-radius: 0.5rem;">
        <strong>Complete MITRE ATT&CK Matrix - Legend:</strong>
        <span style="display: inline-block; margin-left: 1rem;">
            <span style="background-color: #dc2626; color: white; padding: 2px 8px; border-radius: 3px; margin: 0 5px;">RED</span> Confirmed Observed
        </span>
        <span style="display: inline-block; margin-left: 1rem;">
            <span style="background-color: #f59e0b; color: white; padding: 2px 8px; border-radius: 3px; margin: 0 5px;">AMBER</span> Likely Observed
        </span>
        <span style="display: inline-block; margin-left: 1rem;">
            <span style="background-color: #10b981; color: white; padding: 2px 8px; border-radius: 3px; margin: 0 5px;">GREEN</span> Possible Observed
        </span>
        <span style="display: inline-block; margin-left: 1rem;">
            <span style="background-color: #3b82f6; color: white; padding: 2px 8px; border-radius: 3px; margin: 0 5px;">BLUE</span> Predicted Next Step
        </span>
        <span style="display: inline-block; margin-left: 1rem;">
            <span style="background-color: #9ca3af; color: white; padding: 2px 8px; border-radius: 3px; margin: 0 5px;">GREY</span> All Other MITRE Techniques (Not Observed)
        </span>
    </div>
    """

    return html


def display_metric_with_info(label: str, value: str, info_text: str, col):
    """Display metric with info tooltip"""
    with col:
        st.metric(label, value)
        with st.expander(f"ℹ️ About {label}"):
            st.markdown(info_text)


def display_mitre_analysis(mitre_data: dict, username: str):
    """Display comprehensive MITRE ATT&CK analysis with enhanced features"""

    st.markdown("---")
    st.markdown(
        "<h1 style='text-align: center; color: #667eea;'>🎯 MITRE ATT&CK Framework Analysis</h1>",
        unsafe_allow_html=True,
    )
    st.markdown("---")

    if not mitre_data or not isinstance(mitre_data, dict):
        st.error("❌ MITRE analysis data not available or invalid format")
        st.info(
            "💡 The initial analysis was successful, but MITRE mapping encountered an issue. Please review the initial assessment above."
        )
        return

    # Overall Assessment with Info Tooltips
    overall = mitre_data.get("overall_assessment", {})

    if not overall or not isinstance(overall, dict):
        st.warning("⚠️ Overall assessment data is incomplete")
        overall = {}

    col1, col2, col3, col4 = st.columns(4)

    display_metric_with_info(
        "Attack Stage",
        overall.get("attack_stage", "Unknown"),
        """
        **Attack Stage** represents where the attacker currently is in their attack lifecycle:
        
        - **Initial Access**: Attacker has just gained entry to the system
        - **Persistence Established**: Attacker has set up mechanisms to maintain access
        - **Privilege Escalation**: Attacker is gaining higher-level permissions
        - **Lateral Movement**: Attacker is moving across the network
        - **Exfiltration**: Attacker is stealing data
        - **Impact**: Attacker is causing damage or disruption
        
        Understanding the current stage helps prioritize response actions.
        """,
        col1,
    )

    display_metric_with_info(
        "Sophistication",
        overall.get("threat_sophistication", "Unknown"),
        """
        **Threat Sophistication** indicates the attacker's skill level and resources:
        
        - **Low**: Script kiddies using publicly available tools
        - **Medium**: Skilled attackers with custom tools and moderate resources
        - **High**: Professional cybercriminals with advanced capabilities
        - **APT** (Advanced Persistent Threat): Nation-state or highly organized groups with extensive resources
        
        Higher sophistication requires more advanced defensive measures.
        """,
        col2,
    )

    display_metric_with_info(
        "Confidence",
        f"{overall.get('attack_confidence', 0)}%",
        """
        **Confidence Score** reflects how certain we are about the analysis:
        
        - **90-100%**: Very high confidence - strong evidence supports conclusions
        - **70-89%**: High confidence - solid evidence with minor gaps
        - **50-69%**: Medium confidence - some evidence but requires validation
        - **Below 50%**: Low confidence - limited evidence, needs investigation
        
        Higher confidence allows for more decisive response actions.
        """,
        col3,
    )

    display_metric_with_info(
        "Dwell Time",
        overall.get("estimated_dwell_time", "Unknown"),
        """
        **Dwell Time** is how long the attacker has been in your environment:
        
        - **< 1 hour**: Very recent breach, quick response possible
        - **1-24 hours**: Recent breach, immediate action required
        - **1-7 days**: Established presence, thorough investigation needed
        - **> 7 days**: Long-term compromise, assume extensive access
        
        Longer dwell time often means more damage and harder remediation.
        """,
        col4,
    )

    st.markdown("---")

    # MITRE ATT&CK Matrix Visualization with Predicted Steps
    techniques_data = mitre_data.get("mitre_techniques_observed", [])
    predicted_steps = mitre_data.get("predicted_next_steps", [])

    if techniques_data or predicted_steps:
        st.markdown("### 🗺️ MITRE ATT&CK Matrix Visualization")
        st.info(
            "💡 This matrix shows the complete attack chain: **RED/AMBER/GREEN** for observed techniques, "
            "**BLUE** for predicted next steps, and **GREY** for other available techniques in the framework"
        )

        matrix_html = create_complete_mitre_matrix(techniques_data, predicted_steps)
        st.markdown(matrix_html, unsafe_allow_html=True)

        st.markdown("---")

    # Geographic Risk Alert
    if "High-risk country" in overall.get("geographic_threat_indicator", ""):
        st.error(
            f"⚠️ **HIGH-RISK GEOGRAPHIC INDICATOR:** {overall.get('geographic_threat_indicator')}"
        )
        st.markdown("---")

    # Enhanced Attack Chain Narrative
    st.markdown("### 📖 Attack Chain Narrative")
    narrative_text = mitre_data.get("attack_chain_narrative", "No narrative available")

    # Create timeline-based narrative
    attack_timeline = mitre_data.get("attack_timeline", [])

    if attack_timeline:
        st.markdown("#### Timeline of Events")
        for event in attack_timeline:
            stage_num = event.get("stage", 0)
            timestamp = event.get("timestamp", "Unknown")
            tactic = event.get("tactic", "Unknown")
            technique = event.get("technique", "Unknown")
            description = event.get("description", "")
            severity = event.get("severity", "AMBER")

            # Color based on severity
            if severity == "RED":
                icon = "🔴"
                color = "#fee2e2"
            elif severity == "AMBER":
                icon = "🟠"
                color = "#fed7aa"
            else:
                icon = "🟢"
                color = "#d1fae5"

            timeline_html = f"""
            <div class="timeline-item" style="background-color: {color};">
                <strong>{icon} Stage {stage_num}: {tactic}</strong><br/>
                <small><strong>⏰ {timestamp}</strong></small><br/>
                <strong>Technique:</strong> {technique}<br/>
                <strong>Description:</strong> {description}
            </div>
            """
            st.markdown(timeline_html, unsafe_allow_html=True)

        st.markdown("---")
        st.markdown("#### Detailed Narrative")

    st.info(narrative_text)

    st.markdown("---")

    # Enhanced Observed MITRE Techniques with Procedures
    if techniques_data:
        st.markdown("### 🎯 Detailed Technique Analysis")

        for idx, technique in enumerate(techniques_data, 1):
            severity = technique.get("severity", "GREEN").upper()

            if severity == "RED":
                st.error(f"**🔴 Confirmed Technique #{idx}**")
            elif severity == "AMBER":
                st.warning(f"**🟠 Likely Technique #{idx}**")
            else:
                st.success(f"**🟢 Predicted Technique #{idx}**")

            col1, col2 = st.columns([2, 1])

            with col1:
                st.write(
                    f"**Technique:** {technique.get('technique', 'Unknown')} ({technique.get('technique_id', 'N/A')})"
                )
                st.write(
                    f"**Tactic:** {technique.get('tactic', 'N/A')} ({technique.get('tactic_id', 'N/A')})"
                )

                # Show sub-technique
                if (
                    technique.get("sub_technique")
                    and technique.get("sub_technique") != "N/A"
                ):
                    st.info(
                        f"**Sub-Technique:** {technique.get('sub_technique', 'N/A')} ({technique.get('sub_technique_id', 'N/A')})"
                    )
                    st.caption(
                        f"_{technique.get('sub_technique_justification', 'No justification provided')}_"
                    )

            with col2:
                st.metric("Confidence", f"{technique.get('confidence', 0)}%")
                st.write(f"**Timestamp:** {technique.get('timestamp', 'N/A')}")

            st.write(f"**Evidence:** {technique.get('evidence', 'No evidence')}")
            st.write(f"**Indicators:** {', '.join(technique.get('indicators', []))}")

            # Add Procedure section
            procedure = technique.get("procedure", "")
            if procedure:
                st.markdown(
                    f"""
                <div class="procedure-box">
                    <strong>🔧 Procedure (TTP Details):</strong><br/>
                    {procedure}
                </div>
                """,
                    unsafe_allow_html=True,
                )

            st.markdown("---")

    # Predicted Next Steps
    predicted_steps = mitre_data.get("predicted_next_steps", [])
    if predicted_steps:
        st.markdown("### 🔮 Predicted Next Attacker Moves")
        st.info(
            "💡 These techniques have been added to the matrix visualization above in **BLUE** color"
        )

        for idx, step in enumerate(predicted_steps, 1):
            likelihood = step.get("likelihood", "Unknown")

            if likelihood == "High":
                st.error(f"**🚨 High Likelihood - Sequence {idx}**")
            elif likelihood == "Medium":
                st.warning(f"**⚠️ Medium Likelihood - Sequence {idx}**")
            else:
                st.info(f"**ℹ️ Low Likelihood - Sequence {idx}**")

            col1, col2 = st.columns(2)

            with col1:
                st.write(f"**Tactic:** {step.get('tactic', 'N/A')}")
                st.write(
                    f"**Technique:** {step.get('technique', 'N/A')} ({step.get('technique_id', 'N/A')})"
                )

                # Show sub-technique
                if step.get("sub_technique"):
                    st.info(
                        f"**Sub-Technique:** {step.get('sub_technique', 'N/A')} ({step.get('sub_technique_id', 'N/A')})"
                    )

                st.write(f"**Description:** {step.get('description', 'N/A')}")

            with col2:
                st.write(f"**Rationale:** {step.get('rationale', 'N/A')}")
                st.write(
                    f"**Indicators to Watch:** {', '.join(step.get('indicators_to_watch', []))}"
                )
                st.write(
                    f"**Preventive Action:** {step.get('recommended_preventive_action', 'N/A')}"
                )

            st.markdown("---")

    # Threat Actor Profile
    threat_profile = mitre_data.get("threat_actor_profile", {})
    if threat_profile:
        st.markdown("### 👤 Threat Actor Profile")

        col1, col2 = st.columns(2)

        with col1:
            st.write(
                f"**Sophistication Level:** {threat_profile.get('sophistication_level', 'Unknown')}"
            )
            st.write(
                f"**Likely Motivation:** {threat_profile.get('likely_motivation', 'Unknown')}"
            )
            st.write(
                f"**Probable Attribution:** {threat_profile.get('probable_attribution', 'Unknown')}"
            )

        with col2:
            st.write(
                f"**Geographic Indicators:** {', '.join(threat_profile.get('geographic_indicators', []))}"
            )
            st.write(
                f"**Tactics Signature:** {threat_profile.get('tactics_signature', 'Unknown')}"
            )

        if threat_profile.get("similar_campaigns"):
            st.write(
                f"**Similar Campaigns:** {', '.join(threat_profile.get('similar_campaigns', []))}"
            )

        if threat_profile.get("preferred_sub_techniques"):
            st.info(
                f"**Preferred Sub-Techniques:** {', '.join(threat_profile.get('preferred_sub_techniques', []))}"
            )

    st.markdown("---")

    # Defensive Recommendations
    recommendations = mitre_data.get("defensive_recommendations", [])
    if recommendations:
        st.markdown("### 🛡️ Defensive Recommendations")

        for idx, rec in enumerate(recommendations, 1):
            priority = rec.get("priority", "MEDIUM").upper()

            if priority == "CRITICAL":
                st.error(f"**🚨 CRITICAL #{idx}:** {rec.get('recommendation', 'N/A')}")
            elif priority == "HIGH":
                st.warning(f"**⚠️ HIGH #{idx}:** {rec.get('recommendation', 'N/A')}")
            else:
                st.info(f"**📋 {priority} #{idx}:** {rec.get('recommendation', 'N/A')}")

            with st.expander("View Details"):
                st.write(f"**MITRE Mitigation:** {rec.get('mitre_mitigation', 'N/A')}")
                st.write(
                    f"**Mapped Techniques:** {', '.join(rec.get('mapped_techniques', []))}"
                )

                if rec.get("mapped_sub_techniques"):
                    st.info(
                        f"**Mapped Sub-Techniques:** {', '.join(rec.get('mapped_sub_techniques', []))}"
                    )

                st.write(
                    f"**Implementation Complexity:** {rec.get('implementation_complexity', 'N/A')}"
                )
                st.write(
                    f"**Estimated Effectiveness:** {rec.get('estimated_effectiveness', 'N/A')}"
                )

    st.markdown("---")

    # Detection Gaps
    detection_gaps = mitre_data.get("detection_gaps", [])
    if detection_gaps:
        st.markdown("### 🔍 Detection Gaps")

        for idx, gap in enumerate(detection_gaps, 1):
            risk_level = gap.get("risk_level", "MEDIUM").upper()

            if risk_level in ["HIGH", "CRITICAL"]:
                st.error(f"**Gap #{idx}: {gap.get('gap_description', 'Unknown')}**")
            elif risk_level == "MEDIUM":
                st.warning(f"**Gap #{idx}: {gap.get('gap_description', 'Unknown')}**")
            else:
                st.info(f"**Gap #{idx}: {gap.get('gap_description', 'Unknown')}**")

            st.write(
                f"**Affected Techniques:** {', '.join(gap.get('affected_techniques', []))}"
            )

            if gap.get("affected_sub_techniques"):
                st.info(
                    f"**Affected Sub-Techniques:** {', '.join(gap.get('affected_sub_techniques', []))}"
                )

            st.write(f"**Risk Level:** {risk_level}")
            st.write(
                f"**Recommended Detection:** {gap.get('recommended_detection', 'N/A')}"
            )
            st.write(f"**MITRE Data Source:** {gap.get('mitre_data_source', 'N/A')}")

            st.markdown("---")

    # MITRE Navigator Export
    navigator_layer = mitre_data.get("mitre_navigator_layer", {})
    if navigator_layer:
        st.markdown("### 📊 MITRE ATT&CK Navigator Layer")
        st.info(
            "💡 Download this layer to import into MITRE ATT&CK Navigator for interactive visualization"
        )

        navigator_json = json.dumps(navigator_layer, indent=2)
        st.download_button(
            label="📥 Download MITRE Navigator Layer (JSON)",
            data=navigator_json,
            file_name=f"mitre_navigator_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            width="stretch",
        )

        with st.expander("Preview Navigator Layer"):
            st.json(navigator_layer)


def display_analysis_results(analysis: dict, username: str):
    """Display initial analysis results"""

    initial = analysis.get("initial_analysis", {})

    if not initial:
        st.error("❌ Analysis data not available")
        return

    # Header
    st.markdown(
        f"<h2>🔍 Investigation Assessment for: <code>{username}</code></h2>",
        unsafe_allow_html=True,
    )
    st.markdown("---")

    # Classification and Risk Level
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
        risk_level = initial.get("risk_level", "UNKNOWN")
        risk_colors = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        icon = risk_colors.get(risk_level, "⚪")
        st.metric("Risk Level", f"{icon} {risk_level}")

    with col3:
        confidence = initial.get("confidence_score", 0)
        st.metric("Confidence Score", f"{confidence}%")

    st.markdown("---")

    # Geographic Risk Alert
    geo_risk = analysis.get("geographic_risk", {})
    if geo_risk and geo_risk.get("has_high_risk_country"):
        st.error(
            f"""
        **🌍 HIGH-RISK GEOGRAPHIC LOCATION DETECTED!**
        
        **Countries:** {', '.join([loc['country'] for loc in geo_risk.get('high_risk_locations', [])])}
        
        **Suspicious IPs:** {', '.join(geo_risk.get('suspicious_ips', []))}
        
        ⚠️ Access from high-risk countries (Russia, China, North Korea, Iran, etc.) automatically elevates this to a TRUE POSITIVE with CRITICAL risk level.
        """
        )
        st.markdown("---")

    # Executive Summary
    if "summary" in initial:
        st.subheader("📋 Executive Summary")
        st.write(initial["summary"])
        st.markdown("---")

    # Pattern Analysis
    if "pattern_analysis" in initial:
        st.subheader("🔬 Pattern Analysis")
        pattern = initial["pattern_analysis"]

        col1, col2 = st.columns(2)

        with col1:
            for key in [
                "privilege_escalation_risk",
                "temporal_anomalies",
                "geographic_anomalies",
            ]:
                if pattern.get(key):
                    st.markdown(f"**{key.replace('_', ' ').title()}:**")
                    st.write(pattern[key])

        with col2:
            for key in [
                "authentication_concerns",
                "device_trust_issues",
                "behavioral_deviations",
            ]:
                if pattern.get(key):
                    st.markdown(f"**{key.replace('_', ' ').title()}:**")
                    st.write(pattern[key])

        st.markdown("---")

    # Key Findings
    if "key_findings" in initial and initial["key_findings"]:
        st.subheader("🔎 Key Findings by Investigation Step")
        for idx, finding in enumerate(initial["key_findings"], 1):
            severity = finding.get("severity", "Unknown").upper()

            if severity == "CRITICAL":
                st.error(
                    f"**🔴 Finding #{idx}: {finding.get('category', 'Unknown Category')} (CRITICAL)**"
                )
            elif severity == "HIGH":
                st.warning(
                    f"**🟠 Finding #{idx}: {finding.get('category', 'Unknown Category')} (HIGH)**"
                )
            elif severity == "MEDIUM":
                st.info(
                    f"**🟡 Finding #{idx}: {finding.get('category', 'Unknown Category')} (MEDIUM)**"
                )
            else:
                st.success(
                    f"**🟢 Finding #{idx}: {finding.get('category', 'Unknown Category')} (LOW)**"
                )

            st.write(f"**🔍 Step Reference:** {finding.get('step_reference', 'N/A')}")
            st.write(f"**📝 Details:** {finding.get('details', 'No details provided')}")
            st.write(
                f"**🔬 Evidence:** {finding.get('evidence', 'No evidence provided')}"
            )
            st.write(f"**⚠️ Impact:** {finding.get('impact', 'No impact assessment')}")
            st.markdown("---")

    # Recommendations
    if "recommendations" in initial and initial["recommendations"]:
        st.subheader("✅ Recommended Actions")
        for idx, rec in enumerate(initial["recommendations"], 1):
            if idx == 1 and "TRUE POSITIVE" in initial.get("classification", ""):
                st.error(f"**🚨 URGENT #{idx}:** {rec}")
            elif idx <= 3:
                st.warning(f"**⚠️ High Priority #{idx}:** {rec}")
            else:
                st.info(f"**📋 #{idx}:** {rec}")


def main():
    """Main application"""

    final_api_key = os.getenv("GOOGLE_API_KEY")

    st.markdown(
        "<h1 class='main-header'>🔒 True/False Positive Analyzer with MITRE ATT&CK</h1>",
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


if __name__ == "__main__":
    main()
