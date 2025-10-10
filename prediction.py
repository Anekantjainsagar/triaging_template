import os
import json
import pandas as pd
import streamlit as st
import plotly.express as px
from datetime import datetime
from dotenv import load_dotenv
import plotly.graph_objects as go

# Import backend
from predictions_backend import InvestigationAnalyzer, parse_excel_data

load_dotenv()

# Page configuration
st.set_page_config(
    page_title="True/False Positive Analyzer with MITRE ATT&CK",
    page_icon="🔐",
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
    </style>
    """,
    unsafe_allow_html=True,
)


def create_attack_timeline_chart(timeline_data: list) -> go.Figure:
    """Create enhanced interactive attack timeline visualization"""

    if not timeline_data:
        return None

    fig = go.Figure()

    # Color mapping
    color_map = {"RED": "#dc2626", "AMBER": "#f59e0b", "GREEN": "#10b981"}

    # Sort timeline by stage number
    sorted_timeline = sorted(timeline_data, key=lambda x: x.get("stage", 0))

    stages = []
    tactics = []
    techniques = []
    colors = []
    descriptions = []
    timestamps = []
    subtechniques = []

    for event in sorted_timeline:
        stage_num = event.get("stage", 0)
        stages.append(stage_num)
        tactics.append(event.get("tactic", "Unknown"))

        # Extract technique name and sub-technique
        technique_full = event.get("technique", "Unknown")
        technique_parts = technique_full.split(":")
        technique_name = technique_parts[0].strip()
        subtechnique_name = (
            technique_parts[1].strip() if len(technique_parts) > 1 else ""
        )

        techniques.append(technique_name)
        subtechniques.append(subtechnique_name)
        colors.append(color_map.get(event.get("severity", "GREEN"), "#6b7280"))
        descriptions.append(event.get("description", ""))
        timestamps.append(event.get("timestamp", ""))

    # Create the main timeline trace
    fig.add_trace(
        go.Scatter(
            x=stages,
            y=tactics,
            mode="markers+lines+text",
            marker=dict(
                size=25,
                color=colors,
                line=dict(width=3, color="white"),
                symbol="circle",
            ),
            line=dict(width=4, color="#6b7280", dash="dot"),
            text=[f"Stage {s}" for s in stages],
            textposition="top center",
            textfont=dict(size=12, color="white"),
            hovertemplate=(
                "<b>Stage %{x}</b><br>"
                "<b>Tactic:</b> %{y}<br>"
                "<b>Technique:</b> %{customdata[0]}<br>"
                "<b>Sub-Technique:</b> %{customdata[1]}<br>"
                "<b>Time:</b> %{customdata[2]}<br>"
                "<b>Description:</b> %{customdata[3]}"
                "<extra></extra>"
            ),
            customdata=list(zip(techniques, subtechniques, timestamps, descriptions)),
            name="Attack Progression",
        )
    )

    # Add technique labels below
    fig.add_trace(
        go.Scatter(
            x=stages,
            y=[0] * len(stages),  # Place at bottom
            mode="text",
            text=techniques,
            textposition="bottom center",
            textfont=dict(size=10, color="#9ca3af"),
            showlegend=False,
            hoverinfo="skip",
        )
    )

    fig.update_layout(
        title={
            "text": "⏱️ Attack Timeline & Progression",
            "font": {"size": 22, "color": "white"},
        },
        xaxis={
            "title": "Attack Sequence",
            "showgrid": True,
            "gridcolor": "#374151",
            "dtick": 1,
        },
        yaxis={
            "title": "MITRE ATT&CK Tactic",
            "showgrid": True,
            "gridcolor": "#374151",
        },
        height=550,
        template="plotly_dark",
        showlegend=True,
        hovermode="closest",
        plot_bgcolor="#1f2937",
        paper_bgcolor="#111827",
    )

    return fig


def create_mitre_heatmap(techniques_data: list) -> go.Figure:
    """Create enhanced MITRE ATT&CK heatmap visualization with sub-techniques"""

    if not techniques_data:
        return None

    # MITRE ATT&CK Tactics in order
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

    # Create matrix with sub-technique tracking
    tactic_data = {
        tactic: {
            "RED": 0,
            "AMBER": 0,
            "GREEN": 0,
            "SUBTECHNIQUES": 0,
            "TOTAL": 0,
            "COVERAGE": 0,
        }
        for tactic in tactics
    }

    # Count techniques and sub-techniques per tactic
    for technique in techniques_data:
        tactic = technique.get("tactic", "")
        severity = technique.get("severity", "GREEN")
        has_subtechnique = bool(
            technique.get("sub_technique")
            and technique.get("sub_technique") != "N/A"
            and technique.get("sub_technique").strip()
        )

        if tactic in tactic_data:
            tactic_data[tactic][severity] += 1
            tactic_data[tactic]["TOTAL"] += 1
            if has_subtechnique:
                tactic_data[tactic]["SUBTECHNIQUES"] += 1

    # Calculate coverage percentage for each tactic
    for tactic in tactics:
        total = tactic_data[tactic]["TOTAL"]
        if total > 0:
            tactic_data[tactic]["COVERAGE"] = (
                tactic_data[tactic]["SUBTECHNIQUES"] / total
            ) * 100

    # Prepare data for stacked bar chart
    red_counts = [tactic_data[t]["RED"] for t in tactics]
    amber_counts = [tactic_data[t]["AMBER"] for t in tactics]
    green_counts = [tactic_data[t]["GREEN"] for t in tactics]
    coverage_pct = [tactic_data[t]["COVERAGE"] for t in tactics]

    # Create figure with secondary y-axis
    fig = go.Figure()

    # Add stacked bars for techniques
    fig.add_trace(
        go.Bar(
            name="Confirmed (RED)",
            x=tactics,
            y=red_counts,
            marker_color="#dc2626",
            hovertemplate="<b>%{x}</b><br>Confirmed: %{y}<extra></extra>",
        )
    )

    fig.add_trace(
        go.Bar(
            name="Likely (AMBER)",
            x=tactics,
            y=amber_counts,
            marker_color="#f59e0b",
            hovertemplate="<b>%{x}</b><br>Likely: %{y}<extra></extra>",
        )
    )

    fig.add_trace(
        go.Bar(
            name="Predicted (GREEN)",
            x=tactics,
            y=green_counts,
            marker_color="#10b981",
            hovertemplate="<b>%{x}</b><br>Predicted: %{y}<extra></extra>",
        )
    )

    # Add line for sub-technique coverage
    fig.add_trace(
        go.Scatter(
            name="Sub-Technique Coverage %",
            x=tactics,
            y=coverage_pct,
            yaxis="y2",
            mode="lines+markers",
            line=dict(color="#3b82f6", width=3),
            marker=dict(size=10, color="#3b82f6", line=dict(width=2, color="white")),
            hovertemplate="<b>%{x}</b><br>Coverage: %{y:.1f}%<extra></extra>",
        )
    )

    fig.update_layout(
        title={
            "text": "MITRE ATT&CK Coverage Map with Sub-Technique Analysis",
            "font": {"size": 20},
        },
        xaxis={"title": "MITRE ATT&CK Tactics", "tickangle": -45},
        yaxis={"title": "Number of Techniques", "side": "left"},
        yaxis2={
            "title": "Sub-Technique Coverage (%)",
            "overlaying": "y",
            "side": "right",
            "range": [0, 100],
        },
        barmode="stack",
        height=600,
        template="plotly_dark",
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        hovermode="x unified",
    )

    return fig


def create_subtechnique_coverage_chart(coverage_data: dict) -> go.Figure:
    """Create pie chart showing sub-technique coverage"""

    if not coverage_data:
        return None

    total = coverage_data.get("total_techniques_mapped", 0)
    with_sub = coverage_data.get("techniques_with_sub_techniques", 0)
    without_sub = total - with_sub

    if total == 0:
        return None

    fig = go.Figure(
        data=[
            go.Pie(
                labels=["With Sub-Techniques", "Without Sub-Techniques"],
                values=[with_sub, without_sub],
                marker=dict(colors=["#10b981", "#6b7280"]),
                hole=0.4,
            )
        ]
    )

    fig.update_layout(
        title=f"Sub-Technique Coverage: {coverage_data.get('sub_technique_percentage', '0%')}",
        height=400,
        template="plotly_dark",
    )

    return fig


def create_attack_path_sankey(attack_paths: list) -> go.Figure:
    """Create enhanced Sankey diagram for attack path visualization"""

    if not attack_paths:
        return None

    # Collect all stages and create links
    all_nodes = []
    links = []
    node_colors = []

    for path in attack_paths:
        stages = path.get("stages", [])
        for i, stage in enumerate(stages):
            stage_name = stage.get("stage", "Unknown")
            techniques = stage.get("techniques", [])

            # Create node label with techniques
            node_label = f"{stage_name}\n{'• ' + techniques[0] if techniques else ''}"

            if node_label not in all_nodes:
                all_nodes.append(node_label)
                # Color based on status
                status_color = {
                    "CONFIRMED": "#dc2626",
                    "LIKELY": "#f59e0b",
                    "PREDICTED": "#10b981",
                }
                node_colors.append(
                    status_color.get(stage.get("status", "PREDICTED"), "#6b7280")
                )

            if i < len(stages) - 1:
                next_stage = stages[i + 1]
                next_label = f"{next_stage.get('stage', 'Unknown')}\n{'• ' + next_stage.get('techniques', [''])[0] if next_stage.get('techniques') else ''}"

                if next_label not in all_nodes:
                    all_nodes.append(next_label)
                    status_color = {
                        "CONFIRMED": "#dc2626",
                        "LIKELY": "#f59e0b",
                        "PREDICTED": "#10b981",
                    }
                    node_colors.append(
                        status_color.get(
                            next_stage.get("status", "PREDICTED"), "#6b7280"
                        )
                    )

                links.append(
                    {
                        "source": all_nodes.index(node_label),
                        "target": all_nodes.index(next_label),
                        "value": 10,
                        "color": stage.get("color", "green"),
                    }
                )

    # Prepare link data
    source_indices = [link["source"] for link in links]
    target_indices = [link["target"] for link in links]
    values = [link["value"] for link in links]

    color_map = {
        "RED": "rgba(220, 38, 38, 0.5)",
        "AMBER": "rgba(245, 158, 11, 0.5)",
        "GREEN": "rgba(16, 185, 129, 0.5)",
        "green": "rgba(16, 185, 129, 0.5)",
        "amber": "rgba(245, 158, 11, 0.5)",
        "red": "rgba(220, 38, 38, 0.5)",
    }
    link_colors = [
        color_map.get(link["color"].upper(), "rgba(107, 114, 128, 0.5)")
        for link in links
    ]

    fig = go.Figure(
        data=[
            go.Sankey(
                node=dict(
                    pad=20,
                    thickness=30,
                    line=dict(color="white", width=2),
                    label=all_nodes,
                    color=node_colors,
                    customdata=all_nodes,
                    hovertemplate="<b>%{label}</b><br>Stage in attack chain<extra></extra>",
                ),
                link=dict(
                    source=source_indices,
                    target=target_indices,
                    value=values,
                    color=link_colors,
                    hovertemplate="<b>%{source.label}</b> → <b>%{target.label}</b><extra></extra>",
                ),
            )
        ]
    )

    fig.update_layout(
        title={
            "text": "🔄 Attack Path Flow Diagram",
            "font": {"size": 22, "color": "white"},
        },
        height=650,
        template="plotly_dark",
        font=dict(size=12, color="white"),
        plot_bgcolor="#1f2937",
        paper_bgcolor="#111827",
    )

    return fig


def display_mitre_analysis(mitre_data: dict, username: str):
    """Display comprehensive MITRE ATT&CK analysis with sub-techniques"""

    st.markdown("---")
    st.markdown(
        "<h1 style='text-align: center; color: #667eea;'>🎯 MITRE ATT&CK Framework Analysis</h1>",
        unsafe_allow_html=True,
    )
    st.markdown("---")

    if not mitre_data:
        st.error("❌ MITRE analysis data not available")
        return

    # Overall Assessment
    overall = mitre_data.get("overall_assessment", {})

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Attack Stage", overall.get("attack_stage", "Unknown"))

    with col2:
        st.metric("Sophistication", overall.get("threat_sophistication", "Unknown"))

    with col3:
        st.metric("Confidence", f"{overall.get('attack_confidence', 0)}%")

    with col4:
        st.metric("Dwell Time", overall.get("estimated_dwell_time", "Unknown"))

    st.markdown("---")

    # Geographic Risk Alert
    if "High-risk country" in overall.get("geographic_threat_indicator", ""):
        st.error(
            f"⚠️ **HIGH-RISK GEOGRAPHIC INDICATOR:** {overall.get('geographic_threat_indicator')}"
        )
        st.markdown("---")

    # Attack Chain Narrative (MOVED TO TOP)
    st.markdown("### 📖 Attack Chain Narrative")
    st.markdown(
        f"""
    <div class="attack-chain-box">
    {mitre_data.get("attack_chain_narrative", "No narrative available")}
    </div>
    """,
        unsafe_allow_html=True,
    )

    st.markdown("---")

    # Sub-Technique Coverage Metrics (NOW AFTER NARRATIVE)
    coverage_data = mitre_data.get("sub_technique_coverage", {})
    if coverage_data:
        st.markdown("### 📊 Sub-Technique Coverage Metrics")

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric(
                "Total Techniques", coverage_data.get("total_techniques_mapped", 0)
            )

        with col2:
            st.metric(
                "With Sub-Techniques",
                coverage_data.get("techniques_with_sub_techniques", 0),
            )

        with col3:
            st.metric("Coverage", coverage_data.get("sub_technique_percentage", "0%"))

        with col4:
            quality = coverage_data.get("quality_score", "N/A")
            quality_color = (
                "🟢" if quality == "Excellent" else "🟡" if quality == "Good" else "🔴"
            )
            st.metric("Quality", f"{quality_color} {quality}")

        # Coverage pie chart
        coverage_chart = create_subtechnique_coverage_chart(coverage_data)
        if coverage_chart:
            st.plotly_chart(coverage_chart, use_container_width=True)

        # Show techniques requiring sub-techniques
        if coverage_data.get("techniques_requiring_sub_techniques"):
            with st.expander("⚠️ Techniques That Could Have Sub-Techniques"):
                for tech in coverage_data["techniques_requiring_sub_techniques"]:
                    st.warning(
                        f"**{tech['technique']}** ({tech['technique_id']}) - Tactic: {tech.get('tactic', 'N/A')}"
                    )
                    st.write(
                        f"Available sub-techniques: {', '.join(tech['available_sub_techniques'])}"
                    )

        st.markdown("---")

    # Attack Timeline Visualization
    timeline_data = mitre_data.get("attack_timeline", [])
    if timeline_data:
        st.markdown("### ⏱️ Attack Timeline Visualization")
        timeline_fig = create_attack_timeline_chart(timeline_data)
        if timeline_fig:
            st.plotly_chart(timeline_fig, use_container_width=True)

    st.markdown("---")

    # MITRE Techniques Coverage
    techniques_data = mitre_data.get("mitre_techniques_observed", [])
    if techniques_data:
        st.markdown("### 🗺️ MITRE ATT&CK Coverage Map")
        heatmap_fig = create_mitre_heatmap(techniques_data)
        if heatmap_fig:
            st.plotly_chart(heatmap_fig, use_container_width=True)

    st.markdown("---")

    # Attack Path Flow
    attack_paths = mitre_data.get("attack_path_visualization", {}).get("paths", [])
    if attack_paths:
        st.markdown("### 🔄 Attack Path Flow Diagram")
        sankey_fig = create_attack_path_sankey(attack_paths)
        if sankey_fig:
            st.plotly_chart(sankey_fig, use_container_width=True)

    st.markdown("---")

    # Observed MITRE Techniques with Sub-Techniques (FIXED - NO HTML)
    if techniques_data:
        st.markdown("### 🎯 Observed MITRE ATT&CK Techniques & Sub-Techniques")

        for idx, technique in enumerate(techniques_data, 1):
            severity = technique.get("severity", "GREEN").upper()

            if severity == "RED":
                emoji = "🔴"
                severity_label = "CRITICAL"
            elif severity == "AMBER":
                emoji = "🟠"
                severity_label = "HIGH"
            else:
                emoji = "🟢"
                severity_label = "MEDIUM"

            # Check if sub-technique exists
            has_subtechnique = bool(
                technique.get("sub_technique")
                and technique.get("sub_technique") != "N/A"
                and technique.get("sub_technique").strip()
            )

            # Build technique display
            technique_display = f"{technique.get('technique', 'Unknown')} ({technique.get('technique_id', 'N/A')})"

            # Create container for each technique
            with st.container():
                # Header row with technique name and severity
                col1, col2 = st.columns([4, 1])

                with col1:
                    st.markdown(f"#### {emoji} Technique #{idx}: {technique_display}")

                with col2:
                    st.markdown(f"**{emoji} {severity_label}**")

                # Tactic information
                st.markdown(
                    f"**🎯 Tactic:** {technique.get('tactic', 'N/A')} ({technique.get('tactic_id', 'N/A')})"
                )

                # Display sub-technique if available
                if has_subtechnique:
                    st.info(
                        f"""
**Sub-Technique:** {technique.get('sub_technique', 'N/A')} ({technique.get('sub_technique_id', 'N/A')})

*{technique.get('sub_technique_justification', 'No justification provided')}*
                    """
                    )

                # Two column layout for details
                col1, col2 = st.columns(2)

                with col1:
                    st.markdown(f"**📊 Confidence:** {technique.get('confidence', 0)}%")
                    st.markdown(
                        f"**⏰ Timestamp:** {technique.get('timestamp', 'N/A')}"
                    )

                with col2:
                    indicators = technique.get("indicators", [])
                    if indicators:
                        st.markdown(f"**🚨 Indicators:**")
                        for indicator in indicators:
                            st.markdown(f"  • {indicator}")

                # Evidence section (full width)
                st.markdown(
                    f"**🔬 Evidence:** {technique.get('evidence', 'No evidence')}"
                )

                st.markdown("---")

    # Predicted Next Steps with Sub-Techniques
    predicted_steps = mitre_data.get("predicted_next_steps", [])
    if predicted_steps:
        st.markdown("### 🔮 Predicted Next Attacker Moves (with Sub-Techniques)")

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
                st.markdown(f"**Tactic:** {step.get('tactic', 'N/A')}")
                st.markdown(
                    f"**Technique:** {step.get('technique', 'N/A')} ({step.get('technique_id', 'N/A')})"
                )

                # Show sub-technique if available
                if step.get("sub_technique"):
                    st.markdown(
                        f"**Sub-Technique:** :blue[{step.get('sub_technique', 'N/A')} ({step.get('sub_technique_id', 'N/A')})]"
                    )

                st.markdown(f"**Description:** {step.get('description', 'N/A')}")

            with col2:
                st.markdown(f"**Rationale:** {step.get('rationale', 'N/A')}")
                st.markdown(
                    f"**Indicators to Watch:** {', '.join(step.get('indicators_to_watch', []))}"
                )
                st.markdown(
                    f"**Preventive Action:** {step.get('recommended_preventive_action', 'N/A')}"
                )

    st.markdown("---")

    # Threat Actor Profile
    threat_profile = mitre_data.get("threat_actor_profile", {})
    if threat_profile:
        st.markdown("### 👤 Threat Actor Profile")

        preferred_subtechniques = threat_profile.get("preferred_sub_techniques", [])
        subtechniques_html = ""
        if preferred_subtechniques:
            subtechniques_html = f"<p><strong>Preferred Sub-Techniques:</strong> {', '.join(preferred_subtechniques)}</p>"

        st.markdown(
            f"""
        <div class="mitre-card">
            <h3>Threat Intelligence Assessment</h3>
            <p><strong>Sophistication Level:</strong> {threat_profile.get('sophistication_level', 'Unknown')}</p>
            <p><strong>Likely Motivation:</strong> {threat_profile.get('likely_motivation', 'Unknown')}</p>
            <p><strong>Probable Attribution:</strong> {threat_profile.get('probable_attribution', 'Unknown')}</p>
            <p><strong>Geographic Indicators:</strong> {', '.join(threat_profile.get('geographic_indicators', []))}</p>
            <p><strong>Tactics Signature:</strong> {threat_profile.get('tactics_signature', 'Unknown')}</p>
            <p><strong>Similar Campaigns:</strong> {', '.join(threat_profile.get('similar_campaigns', []))}</p>
            {subtechniques_html}
        </div>
        """,
            unsafe_allow_html=True,
        )

    st.markdown("---")

    # Defensive Recommendations with Sub-Techniques
    recommendations = mitre_data.get("defensive_recommendations", [])
    if recommendations:
        st.markdown("### 🛡️ Defensive Recommendations (MITRE Mitigations)")

        for idx, rec in enumerate(recommendations, 1):
            priority = rec.get("priority", "MEDIUM").upper()

            if priority == "CRITICAL":
                st.error(f"**🚨 CRITICAL #{idx}:** {rec.get('recommendation', 'N/A')}")
            elif priority == "HIGH":
                st.warning(f"**⚠️ HIGH #{idx}:** {rec.get('recommendation', 'N/A')}")
            else:
                st.info(f"**📋 {priority} #{idx}:** {rec.get('recommendation', 'N/A')}")

            with st.expander("View Details"):
                st.markdown(
                    f"**MITRE Mitigation:** {rec.get('mitre_mitigation', 'N/A')}"
                )
                st.markdown(
                    f"**Mapped Techniques:** {', '.join(rec.get('mapped_techniques', []))}"
                )

                # Show sub-techniques if available
                if rec.get("mapped_sub_techniques"):
                    st.markdown(
                        f"**Mapped Sub-Techniques:** :blue[{', '.join(rec.get('mapped_sub_techniques', []))}]"
                    )

                st.markdown(
                    f"**Implementation Complexity:** {rec.get('implementation_complexity', 'N/A')}"
                )
                st.markdown(
                    f"**Estimated Effectiveness:** {rec.get('estimated_effectiveness', 'N/A')}"
                )

    st.markdown("---")

    # Final Summary Section (Optional - you can keep or remove)
    st.markdown("### 📊 Analysis Complete")
    st.success(
        f"""
✅ **Analysis completed for user:** {username}

**Summary:**
- Total Techniques Mapped: {coverage_data.get('total_techniques_mapped', 0)}
- Sub-Techniques Identified: {coverage_data.get('techniques_with_sub_techniques', 0)}
- Coverage Quality: {coverage_data.get('quality_score', 'N/A')}
- Attack Sophistication: {overall.get('threat_sophistication', 'Unknown')}
- Confidence Level: {overall.get('attack_confidence', 0)}%
    """
    )


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
                                    # Executive summary
                                    exec_summary = complete_analysis.get(
                                        "executive_summary", {}
                                    )

                                    # Include sub-techniques in summary
                                    subtechniques_text = ""
                                    if exec_summary.get("key_sub_techniques_observed"):
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
                                    ].get("sub_technique_coverage", {})
                                    if coverage:
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

                                        if (
                                            coverage.get("sub_technique_percentage")
                                            and float(
                                                coverage.get(
                                                    "sub_technique_percentage", "0%"
                                                ).rstrip("%")
                                            )
                                            < 50
                                        ):
                                            st.warning(
                                                "⚠️ Low sub-technique coverage detected. Consider reviewing the analysis for more specific sub-technique identification."
                                            )
                            else:
                                st.error(
                                    "❌ Analysis failed. Please check the logs and try again."
                                )
                else:
                    st.warning("⚠️ Please enter a username to analyze")
    else:
        st.info("👆 Please upload an Excel file to begin analysis")

        # Information section
        st.markdown("---")
        st.markdown("### 📖 About This Tool")
        st.markdown(
            """
        This advanced security investigation tool provides:
        
        - **Automated Classification**: AI-powered TRUE/FALSE POSITIVE detection
        - **MITRE ATT&CK Mapping**: Complete attack chain reconstruction using MITRE framework
        - **Sub-Technique Analysis**: Detailed sub-technique identification for precise threat mapping
        - **Geographic Risk Analysis**: Automatic detection of high-risk countries (Russia, China, etc.)
        - **Attack Prediction**: AI-powered prediction of attacker's next moves with specific sub-techniques
        - **Interactive Visualizations**: Timeline, heatmaps, and flow diagrams
        - **Threat Intelligence**: Actor profiling and attribution analysis
        - **Actionable Recommendations**: Prioritized defensive measures with MITRE mitigations
        - **Sub-Technique Coverage Tracking**: Metrics showing the depth of analysis
        
        **Key Features**:
        - ✅ **Sub-Technique Mapping**: Every technique is mapped to specific sub-techniques based on evidence
        - ✅ **Coverage Metrics**: Track how many techniques have detailed sub-technique analysis
        - ✅ **Navigator Export**: MITRE ATT&CK Navigator layers include both parent and sub-techniques
        - ✅ **Evidence-Based**: All sub-techniques are justified with specific evidence from investigation
        
        **High-Risk Country Detection**: Access from Russia, China, North Korea, Iran, Syria, Belarus, Venezuela, Cuba, or Afghanistan automatically triggers TRUE POSITIVE classification.
        
        **Sub-Technique Examples**:
        - Valid Accounts → Cloud Accounts (T1078.004)
        - Account Manipulation → Additional Cloud Roles (T1098.003)
        - Exfiltration Over Web Service → Exfiltration to Cloud Storage (T1567.002)
        """
        )

        st.markdown("---")
        st.markdown("### 🎯 Why Sub-Techniques Matter")
        st.info(
            """
            Sub-techniques provide **granular detail** about attacker behavior:
            
            - **More Precise Threat Detection**: Identify exactly HOW an attack was executed
            - **Better Defense Planning**: Target specific attack methods with appropriate controls
            - **Improved Incident Response**: Understand the exact TTPs used by attackers
            - **Threat Intelligence**: Match attacks to known threat actor behaviors
            - **Compliance & Reporting**: Provide detailed evidence for security audits
            """
        )


if __name__ == "__main__":
    main()
