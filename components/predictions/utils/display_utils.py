import json
import os
import streamlit as st
from datetime import datetime
from components.predictions.utils.mitre_utils import create_complete_mitre_matrix
from utils.html_utils import decode_html_entities, clean_display_text


def display_metric_with_info(label: str, value: str, info_text: str, col):
    """Display metric with info tooltip"""
    with col:
        st.metric(label, value)
        with st.expander(f"ℹ️ About {label}"):
            st.markdown(info_text)


def display_mitre_analysis(mitre_data: dict, username: str):
    """Display comprehensive MITRE ATT&CK analysis with enhanced features"""
    
    # Check if TESTING is enabled
    is_testing = os.getenv("TESTING", "false").lower() == "true"
    
    if not is_testing:
        # In production, skip MITRE analysis display
        return

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
    narrative_text = decode_html_entities(mitre_data.get("attack_chain_narrative", "No narrative available"))

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

            st.write(f"**Evidence:** {clean_display_text(technique.get('evidence', 'No evidence'))}")
            st.write(f"**Indicators:** {', '.join([clean_display_text(str(ind)) for ind in technique.get('indicators', [])])}")

            # Add Procedure section
            procedure = clean_display_text(technique.get("procedure", ""))
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

                st.write(f"**Description:** {clean_display_text(step.get('description', 'N/A'))}")

            with col2:
                st.write(f"**Rationale:** {clean_display_text(step.get('rationale', 'N/A'))}")
                st.write(
                    f"**Indicators to Watch:** {', '.join([clean_display_text(str(ind)) for ind in step.get('indicators_to_watch', [])])}"
                )
                st.write(
                    f"**Preventive Action:** {clean_display_text(step.get('recommended_preventive_action', 'N/A'))}"
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
                st.error(f"**🚨 CRITICAL #{idx}:** {clean_display_text(rec.get('recommendation', 'N/A'))}")
            elif priority == "HIGH":
                st.warning(f"**⚠️ HIGH #{idx}:** {clean_display_text(rec.get('recommendation', 'N/A'))}")
            else:
                st.info(f"**📋 {priority} #{idx}:** {clean_display_text(rec.get('recommendation', 'N/A'))}")

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
    # Pattern Analysis with Icons
    if "pattern_analysis" in initial:
        st.subheader("🔬 Pattern Analysis")
        pattern = initial["pattern_analysis"]

        # Icon mapping for each pattern type
        pattern_icons = {
            "privilege_escalation_risk": "🔐",
            "temporal_anomalies": "⏰",
            "geographic_anomalies": "🌍",
            "authentication_concerns": "🔑",
            "device_trust_issues": "💻",
            "behavioral_deviations": "👤",
        }

        col1, col2 = st.columns(2)

        with col1:
            for key in [
                "privilege_escalation_risk",
                "temporal_anomalies",
                "geographic_anomalies",
            ]:
                if pattern.get(key):
                    icon = pattern_icons.get(key, "📌")
                    st.markdown(f"**{icon} {key.replace('_', ' ').title()}:**")
                    st.write(pattern[key])
                    st.markdown("")

        with col2:
            for key in [
                "authentication_concerns",
                "device_trust_issues",
                "behavioral_deviations",
            ]:
                if pattern.get(key):
                    icon = pattern_icons.get(key, "📌")
                    st.markdown(f"**{icon} {key.replace('_', ' ').title()}:**")
                    st.write(pattern[key])
                    st.markdown("")

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

            st.write(f"**🔍 Step Reference:** {clean_display_text(finding.get('step_reference', 'N/A'))}")
            st.write(f"**📝 Details:** {clean_display_text(finding.get('details', 'No details provided'))}")
            st.write(
                f"**🔬 Evidence:** {clean_display_text(finding.get('evidence', 'No evidence provided'))}"
            )
            st.write(f"**⚠️ Impact:** {clean_display_text(finding.get('impact', 'No impact assessment'))}")
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
