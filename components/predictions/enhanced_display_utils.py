import json
import streamlit as st
from datetime import datetime
from components.predictions.utils.mitre_utils import create_complete_mitre_matrix
from utils.html_utils import clean_html_content, clean_dict_html_content, decode_html_entities, clean_display_text


def display_enhanced_analysis_results(analysis: dict, username: str):
    """Enhanced display with better structure and specific investigation details"""
    
    # Clean HTML entities from analysis data
    analysis = clean_dict_html_content(analysis)
    
    initial = analysis.get("initial_analysis", {})
    
    if not initial:
        st.error("❌ Analysis data not available")
        return

    # Enhanced Header with better styling
    st.markdown(
        f"""
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                    padding: 1.5rem; border-radius: 10px; margin-bottom: 1rem;">
            <h2 style="color: white; margin: 0; text-align: center;">
                🔍 Investigation Assessment for: <code style="background: rgba(255,255,255,0.2); 
                padding: 0.3rem 0.6rem; border-radius: 5px;">{username}</code>
            </h2>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Classification with enhanced styling
    classification = initial.get("classification", "UNKNOWN")
    risk_level = initial.get("risk_level", "UNKNOWN")
    confidence = initial.get("confidence_score", 0)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if "TRUE POSITIVE" in classification:
            st.markdown(
                f"""
                <div style="background: #fee2e2; border: 2px solid #dc2626; border-radius: 8px; 
                           padding: 1rem; text-align: center;">
                    <h3 style="color: #dc2626; margin: 0;">🚨 Classification</h3>
                    <p style="color: #991b1b; font-weight: bold; margin: 0.5rem 0 0 0;">{classification}</p>
                </div>
                """,
                unsafe_allow_html=True
            )
        elif "FALSE POSITIVE" in classification:
            st.markdown(
                f"""
                <div style="background: #d1fae5; border: 2px solid #10b981; border-radius: 8px; 
                           padding: 1rem; text-align: center;">
                    <h3 style="color: #10b981; margin: 0;">✅ Classification</h3>
                    <p style="color: #065f46; font-weight: bold; margin: 0.5rem 0 0 0;">{classification}</p>
                </div>
                """,
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                f"""
                <div style="background: #e0e7ff; border: 2px solid #6366f1; border-radius: 8px; 
                           padding: 1rem; text-align: center;">
                    <h3 style="color: #6366f1; margin: 0;">ℹ️ Classification</h3>
                    <p style="color: #4338ca; font-weight: bold; margin: 0.5rem 0 0 0;">{classification}</p>
                </div>
                """,
                unsafe_allow_html=True
            )

    with col2:
        risk_colors = {
            "CRITICAL": {"bg": "#fee2e2", "border": "#dc2626", "text": "#991b1b", "icon": "🔴"},
            "HIGH": {"bg": "#fed7aa", "border": "#f59e0b", "text": "#92400e", "icon": "🟠"},
            "MEDIUM": {"bg": "#fef3c7", "border": "#f59e0b", "text": "#92400e", "icon": "🟡"},
            "LOW": {"bg": "#d1fae5", "border": "#10b981", "text": "#065f46", "icon": "🟢"}
        }
        
        risk_style = risk_colors.get(risk_level, {"bg": "#f3f4f6", "border": "#9ca3af", "text": "#374151", "icon": "⚪"})
        
        st.markdown(
            f"""
            <div style="background: {risk_style['bg']}; border: 2px solid {risk_style['border']}; 
                       border-radius: 8px; padding: 1rem; text-align: center;">
                <h3 style="color: {risk_style['border']}; margin: 0;">Risk Level</h3>
                <p style="color: {risk_style['text']}; font-weight: bold; margin: 0.5rem 0 0 0;">
                    {risk_style['icon']} {risk_level}
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col3:
        confidence_color = "#10b981" if confidence >= 80 else "#f59e0b" if confidence >= 60 else "#dc2626"
        confidence_bg = "#d1fae5" if confidence >= 80 else "#fed7aa" if confidence >= 60 else "#fee2e2"
        
        st.markdown(
            f"""
            <div style="background: {confidence_bg}; border: 2px solid {confidence_color}; 
                       border-radius: 8px; padding: 1rem; text-align: center;">
                <h3 style="color: {confidence_color}; margin: 0;">Confidence Score</h3>
                <p style="color: {confidence_color}; font-weight: bold; margin: 0.5rem 0 0 0; font-size: 1.5rem;">
                    {confidence}%
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("---")

    # Enhanced Key Findings with better structure
    if "key_findings" in initial and initial["key_findings"]:
        st.markdown("### 🔎 Key Findings by Investigation Step")
        
        for idx, finding in enumerate(initial["key_findings"], 1):
            severity = finding.get("severity", "Unknown").upper()
            category = finding.get("category", "Unknown Category")
            step_ref = finding.get("step_reference", "N/A")
            details = clean_display_text(finding.get("details", "No details provided"))
            evidence = clean_display_text(finding.get("evidence", "No evidence provided"))
            impact = clean_display_text(finding.get("impact", "No impact assessment"))
            
            # Enhanced finding display with better structure
            if severity == "CRITICAL":
                st.markdown(
                    f"""
                    <div style="background: #fee2e2; border-left: 5px solid #dc2626; 
                               padding: 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                        <h4 style="color: #dc2626; margin: 0 0 0.5rem 0;">
                            🔴 Finding #{idx}: {category} (CRITICAL)
                        </h4>
                        <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                            <strong style="color: #374151;">🔍 Step Reference:</strong> 
                            <span style="color: #6b7280;">{step_ref}</span>
                        </div>
                        <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                            <strong style="color: #374151;">📝 Details:</strong> 
                            <span style="color: #6b7280;">{details}</span>
                        </div>
                        <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                            <strong style="color: #374151;">🔬 Evidence:</strong> 
                            <span style="color: #6b7280;">{evidence}</span>
                        </div>
                        <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                            <strong style="color: #374151;">⚠️ Impact:</strong> 
                            <span style="color: #6b7280;">{impact}</span>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            elif severity == "HIGH":
                st.markdown(
                    f"""
                    <div style="background: #fed7aa; border-left: 5px solid #f59e0b; 
                               padding: 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                        <h4 style="color: #f59e0b; margin: 0 0 0.5rem 0;">
                            🟠 Finding #{idx}: {category} (HIGH)
                        </h4>
                        <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                            <strong style="color: #374151;">🔍 Step Reference:</strong> 
                            <span style="color: #6b7280;">{step_ref}</span>
                        </div>
                        <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                            <strong style="color: #374151;">📝 Details:</strong> 
                            <span style="color: #6b7280;">{details}</span>
                        </div>
                        <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                            <strong style="color: #374151;">🔬 Evidence:</strong> 
                            <span style="color: #6b7280;">{evidence}</span>
                        </div>
                        <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                            <strong style="color: #374151;">⚠️ Impact:</strong> 
                            <span style="color: #6b7280;">{impact}</span>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            elif severity == "MEDIUM":
                st.markdown(
                    f"""
                    <div style="background: #fef3c7; border-left: 5px solid #f59e0b; 
                               padding: 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                        <h4 style="color: #d97706; margin: 0 0 0.5rem 0;">
                            🟡 Finding #{idx}: {category} (MEDIUM)
                        </h4>
                        <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                            <strong style="color: #374151;">🔍 Step Reference:</strong> 
                            <span style="color: #6b7280;">{step_ref}</span>
                        </div>
                        <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                            <strong style="color: #374151;">📝 Details:</strong> 
                            <span style="color: #6b7280;">{details}</span>
                        </div>
                        <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                            <strong style="color: #374151;">🔬 Evidence:</strong> 
                            <span style="color: #6b7280;">{evidence}</span>
                        </div>
                        <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                            <strong style="color: #374151;">⚠️ Impact:</strong> 
                            <span style="color: #6b7280;">{impact}</span>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    f"""
                    <div style="background: #d1fae5; border-left: 5px solid #10b981; 
                               padding: 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                        <h4 style="color: #10b981; margin: 0 0 0.5rem 0;">
                            🟢 Finding #{idx}: {category} (LOW)
                        </h4>
                        <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                            <strong style="color: #374151;">🔍 Step Reference:</strong> 
                            <span style="color: #6b7280;">{step_ref}</span>
                        </div>
                        <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                            <strong style="color: #374151;">📝 Details:</strong> 
                            <span style="color: #6b7280;">{details}</span>
                        </div>
                        <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                            <strong style="color: #374151;">🔬 Evidence:</strong> 
                            <span style="color: #6b7280;">{evidence}</span>
                        </div>
                        <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                            <strong style="color: #374151;">⚠️ Impact:</strong> 
                            <span style="color: #6b7280;">{impact}</span>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

        st.markdown("---")

    # Enhanced Pattern Analysis
    if "pattern_analysis" in initial:
        st.markdown("### 🔬 Pattern Analysis")
        pattern = initial["pattern_analysis"]
        
        pattern_data = [
            ("privilege_escalation_risk", "🔐 Privilege Escalation Risk", "#dc2626"),
            ("temporal_anomalies", "⏰ Temporal Anomalies", "#f59e0b"),
            ("geographic_anomalies", "🌍 Geographic Anomalies", "#8b5cf6"),
            ("authentication_concerns", "🔑 Authentication Concerns", "#ef4444"),
            ("device_trust_issues", "💻 Device Trust Issues", "#06b6d4"),
            ("behavioral_deviations", "👤 Behavioral Deviations", "#10b981"),
        ]
        
        col1, col2 = st.columns(2)
        
        for idx, (key, title, color) in enumerate(pattern_data):
            if pattern.get(key):
                target_col = col1 if idx % 2 == 0 else col2
                with target_col:
                    clean_pattern_text = clean_display_text(pattern[key])
                    st.markdown(
                        f"""
                        <div style="background: white; border: 2px solid {color}; 
                                   border-radius: 8px; padding: 1rem; margin: 0.5rem 0;">
                            <h4 style="color: {color}; margin: 0 0 0.5rem 0;">{title}</h4>
                            <p style="color: #374151; margin: 0; line-height: 1.5;">{clean_pattern_text}</p>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

        st.markdown("---")

    # Enhanced Executive Summary
    if "summary" in initial:
        st.markdown("### 📋 Executive Summary")
        clean_summary = clean_display_text(initial["summary"])
        st.markdown(
            f"""
            <div style="background: #f8fafc; border: 2px solid #e2e8f0; 
                       border-radius: 8px; padding: 1.5rem; margin: 1rem 0;">
                <p style="color: #374151; line-height: 1.6; margin: 0; font-size: 1.1rem;">
                    {clean_summary}
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.markdown("---")

    # Enhanced Recommendations
    if "recommendations" in initial and initial["recommendations"]:
        st.markdown("### ✅ Recommended Actions")
        
        for idx, rec in enumerate(initial["recommendations"], 1):
            clean_rec = clean_display_text(rec)
            if idx == 1 and "TRUE POSITIVE" in initial.get("classification", ""):
                st.markdown(
                    f"""
                    <div style="background: #fee2e2; border: 2px solid #dc2626; 
                               border-radius: 8px; padding: 1rem; margin: 0.5rem 0;">
                        <h4 style="color: #dc2626; margin: 0 0 0.5rem 0;">🚨 URGENT #{idx}</h4>
                        <p style="color: #991b1b; margin: 0; font-weight: 500;">{clean_rec}</p>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            elif idx <= 3:
                st.markdown(
                    f"""
                    <div style="background: #fed7aa; border: 2px solid #f59e0b; 
                               border-radius: 8px; padding: 1rem; margin: 0.5rem 0;">
                        <h4 style="color: #f59e0b; margin: 0 0 0.5rem 0;">⚠️ High Priority #{idx}</h4>
                        <p style="color: #92400e; margin: 0; font-weight: 500;">{clean_rec}</p>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    f"""
                    <div style="background: #e0e7ff; border: 2px solid #6366f1; 
                               border-radius: 8px; padding: 1rem; margin: 0.5rem 0;">
                        <h4 style="color: #6366f1; margin: 0 0 0.5rem 0;">📋 #{idx}</h4>
                        <p style="color: #4338ca; margin: 0; font-weight: 500;">{clean_rec}</p>
                    </div>
                    """,
                    unsafe_allow_html=True
                )


def display_enhanced_mitre_analysis(mitre_data: dict, username: str):
    """Enhanced MITRE analysis with better structure and always visible matrix"""
    
    # Clean HTML entities from MITRE data
    mitre_data = clean_dict_html_content(mitre_data)
    
    st.markdown("---")
    st.markdown(
        """
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                    padding: 1.5rem; border-radius: 10px; margin: 1rem 0;">
            <h1 style="color: white; text-align: center; margin: 0;">
                🎯 MITRE ATT&CK Framework Analysis
            </h1>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not mitre_data or not isinstance(mitre_data, dict):
        st.error("❌ MITRE analysis data not available or invalid format")
        st.info(
            "💡 The initial analysis was successful, but MITRE mapping encountered an issue. Please review the initial assessment above."
        )
        return

    # Always show MITRE Matrix first (even if empty)
    st.markdown("### 🗺️ MITRE ATT&CK Matrix Visualization")
    
    techniques_data = mitre_data.get("mitre_techniques_observed", [])
    predicted_steps = mitre_data.get("predicted_next_steps", [])
    
    if techniques_data or predicted_steps:
        st.info(
            "💡 This matrix shows the complete attack chain: **RED/AMBER/GREEN** for observed techniques, "
            "**BLUE** for predicted next steps, and **GREY** for other available techniques in the framework"
        )
        matrix_html = create_complete_mitre_matrix(techniques_data, predicted_steps)
        st.markdown(matrix_html, unsafe_allow_html=True)
    else:
        st.warning("⚠️ No MITRE techniques mapped yet. Matrix will populate as analysis progresses.")
        # Show empty matrix
        matrix_html = create_complete_mitre_matrix([], [])
        st.markdown(matrix_html, unsafe_allow_html=True)

    st.markdown("---")

    # Overall Assessment with enhanced metrics
    overall = mitre_data.get("overall_assessment", {})
    
    if overall and isinstance(overall, dict):
        st.markdown("### 📊 Overall Assessment")
        
        col1, col2, col3, col4 = st.columns(4)
        
        metrics_data = [
            ("Attack Stage", overall.get("attack_stage", "Unknown"), "🎯"),
            ("Sophistication", overall.get("threat_sophistication", "Unknown"), "🧠"),
            ("Confidence", f"{overall.get('attack_confidence', 0)}%", "📈"),
            ("Dwell Time", overall.get("estimated_dwell_time", "Unknown"), "⏱️")
        ]
        
        for idx, (label, value, icon) in enumerate(metrics_data):
            target_col = [col1, col2, col3, col4][idx]
            with target_col:
                st.markdown(
                    f"""
                    <div style="background: white; border: 2px solid #667eea; 
                               border-radius: 8px; padding: 1rem; text-align: center;">
                        <h4 style="color: #667eea; margin: 0 0 0.5rem 0;">{icon} {label}</h4>
                        <p style="color: #374151; margin: 0; font-weight: bold; font-size: 1.1rem;">{value}</p>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

        st.markdown("---")

    # Enhanced Attack Chain Narrative
    if mitre_data.get("attack_chain_narrative"):
        st.markdown("### 📖 Attack Chain Narrative")
        
        narrative_text = clean_display_text(mitre_data.get("attack_chain_narrative", "No narrative available"))
        
        st.markdown(
            f"""
            <div style="background: #f8fafc; border-left: 5px solid #667eea; 
                       padding: 1.5rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                <p style="color: #374151; line-height: 1.6; margin: 0; font-size: 1.1rem;">
                    {narrative_text}
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )
        
        st.markdown("---")

    # Enhanced Technique Details
    if techniques_data:
        st.markdown("### 🎯 Detailed Technique Analysis")
        
        for idx, technique in enumerate(techniques_data, 1):
            severity = technique.get("severity", "GREEN").upper()
            
            # Color scheme based on severity
            if severity == "RED":
                bg_color = "#fee2e2"
                border_color = "#dc2626"
                text_color = "#991b1b"
                icon = "🔴"
                title = "Confirmed Technique"
            elif severity == "AMBER":
                bg_color = "#fed7aa"
                border_color = "#f59e0b"
                text_color = "#92400e"
                icon = "🟠"
                title = "Likely Technique"
            else:
                bg_color = "#d1fae5"
                border_color = "#10b981"
                text_color = "#065f46"
                icon = "🟢"
                title = "Predicted Technique"
            
            st.markdown(
                f"""
                <div style="background: {bg_color}; border: 2px solid {border_color}; 
                           border-radius: 8px; padding: 1.5rem; margin: 1rem 0;">
                    <h4 style="color: {border_color}; margin: 0 0 1rem 0;">
                        {icon} {title} #{idx}
                    </h4>
                    
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                        <div>
                            <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                                <strong style="color: #374151;">🎯 Technique:</strong><br>
                                <span style="color: #6b7280;">{technique.get('technique', 'Unknown')} ({technique.get('technique_id', 'N/A')})</span>
                            </div>
                            <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                                <strong style="color: #374151;">📋 Tactic:</strong><br>
                                <span style="color: #6b7280;">{technique.get('tactic', 'N/A')} ({technique.get('tactic_id', 'N/A')})</span>
                            </div>
                        </div>
                        <div>
                            <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                                <strong style="color: #374151;">📈 Confidence:</strong><br>
                                <span style="color: #6b7280; font-weight: bold;">{technique.get('confidence', 0)}%</span>
                            </div>
                            <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                                <strong style="color: #374151;">⏰ Timestamp:</strong><br>
                                <span style="color: #6b7280;">{technique.get('timestamp', 'N/A')}</span>
                            </div>
                        </div>
                    </div>
                    
                    <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                        <strong style="color: #374151;">🔍 Evidence:</strong><br>
                        <span style="color: #6b7280;">{clean_display_text(technique.get('evidence', 'No evidence'))}</span>
                    </div>
                    
                    <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                        <strong style="color: #374151;">🏷️ Indicators:</strong><br>
                        <span style="color: #6b7280;">{', '.join([clean_display_text(str(ind)) for ind in technique.get('indicators', [])])}</span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
            
            # Sub-technique details
            if technique.get("sub_technique") and technique.get("sub_technique") != "N/A":
                st.markdown(
                    f"""
                    <div style="background: #e0e7ff; border: 2px solid #6366f1; 
                               border-radius: 8px; padding: 1rem; margin: 0.5rem 0 1rem 2rem;">
                        <h5 style="color: #6366f1; margin: 0 0 0.5rem 0;">🎯 Sub-Technique Details</h5>
                        <p style="color: #4338ca; margin: 0;">
                            <strong>{technique.get('sub_technique', 'N/A')} ({technique.get('sub_technique_id', 'N/A')})</strong>
                        </p>
                        <p style="color: #6b7280; margin: 0.5rem 0 0 0; font-style: italic;">
                            {technique.get('sub_technique_justification', 'No justification provided')}
                        </p>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

        st.markdown("---")

    # Enhanced Predicted Next Steps
    if predicted_steps:
        st.markdown("### 🔮 Predicted Next Attacker Moves")
        st.info(
            "💡 These techniques have been added to the matrix visualization above in **BLUE** color"
        )
        
        for idx, step in enumerate(predicted_steps, 1):
            likelihood = step.get("likelihood", "Unknown")
            
            if likelihood == "High":
                bg_color = "#fee2e2"
                border_color = "#dc2626"
                icon = "🚨"
                title = "High Likelihood"
            elif likelihood == "Medium":
                bg_color = "#fed7aa"
                border_color = "#f59e0b"
                icon = "⚠️"
                title = "Medium Likelihood"
            else:
                bg_color = "#e0e7ff"
                border_color = "#6366f1"
                icon = "ℹ️"
                title = "Low Likelihood"
            
            st.markdown(
                f"""
                <div style="background: {bg_color}; border: 2px solid {border_color}; 
                           border-radius: 8px; padding: 1.5rem; margin: 1rem 0;">
                    <h4 style="color: {border_color}; margin: 0 0 1rem 0;">
                        {icon} {title} - Sequence #{idx}
                    </h4>
                    
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                        <div>
                            <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                                <strong style="color: #374151;">📋 Tactic:</strong><br>
                                <span style="color: #6b7280;">{step.get('tactic', 'N/A')}</span>
                            </div>
                            <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                                <strong style="color: #374151;">🎯 Technique:</strong><br>
                                <span style="color: #6b7280;">{step.get('technique', 'N/A')} ({step.get('technique_id', 'N/A')})</span>
                            </div>
                            <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                                <strong style="color: #374151;">📝 Description:</strong><br>
                                <span style="color: #6b7280;">{clean_display_text(step.get('description', 'N/A'))}</span>
                            </div>
                        </div>
                        <div>
                            <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                                <strong style="color: #374151;">🧠 Rationale:</strong><br>
                                <span style="color: #6b7280;">{clean_display_text(step.get('rationale', 'N/A'))}</span>
                            </div>
                            <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                                <strong style="color: #374151;">👀 Indicators to Watch:</strong><br>
                                <span style="color: #6b7280;">{', '.join([clean_display_text(str(ind)) for ind in step.get('indicators_to_watch', [])])}</span>
                            </div>
                            <div style="background: white; padding: 0.8rem; border-radius: 5px; margin: 0.5rem 0;">
                                <strong style="color: #374151;">🛡️ Preventive Action:</strong><br>
                                <span style="color: #6b7280;">{clean_display_text(step.get('recommended_preventive_action', 'N/A'))}</span>
                            </div>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        st.markdown("---")

    # Enhanced Defensive Recommendations
    recommendations = mitre_data.get("defensive_recommendations", [])
    if recommendations:
        st.markdown("### 🛡️ Defensive Recommendations")
        
        for idx, rec in enumerate(recommendations, 1):
            priority = rec.get("priority", "MEDIUM").upper()
            
            if priority == "CRITICAL":
                bg_color = "#fee2e2"
                border_color = "#dc2626"
                icon = "🚨"
            elif priority == "HIGH":
                bg_color = "#fed7aa"
                border_color = "#f59e0b"
                icon = "⚠️"
            else:
                bg_color = "#e0e7ff"
                border_color = "#6366f1"
                icon = "📋"
            
            st.markdown(
                f"""
                <div style="background: {bg_color}; border: 2px solid {border_color}; 
                           border-radius: 8px; padding: 1rem; margin: 0.5rem 0;">
                    <h4 style="color: {border_color}; margin: 0 0 0.5rem 0;">
                        {icon} {priority} #{idx}
                    </h4>
                    <p style="color: #374151; margin: 0; font-weight: 500;">
                        {clean_display_text(rec.get('recommendation', 'N/A'))}
                    </p>
                </div>
                """,
                unsafe_allow_html=True
            )

        st.markdown("---")


def display_enhanced_entity_analysis(username: str, complete_analysis: dict):
    """Enhanced entity analysis with closed accordion by default and better structure"""
    
    # Clean all HTML entities from the complete analysis data
    complete_analysis = clean_dict_html_content(complete_analysis)
    
    initial = complete_analysis.get("initial_analysis", {})
    classification = initial.get("classification", "UNKNOWN")
    
    # Determine accordion header and default state (closed by default)
    if "TRUE POSITIVE" in classification:
        header = f"👤 {username} - 🚨 TRUE POSITIVE"
    elif "FALSE POSITIVE" in classification:
        header = f"👤 {username} - ✅ FALSE POSITIVE"
    else:
        header = f"👤 {username} - ℹ️ {classification}"

    # Always closed by default as requested
    with st.expander(header, expanded=False):
        # Display enhanced analysis results
        display_enhanced_analysis_results(complete_analysis, username)

        # Display enhanced MITRE analysis
        if complete_analysis.get("mitre_attack_analysis"):
            display_enhanced_mitre_analysis(
                complete_analysis["mitre_attack_analysis"],
                username,
            )

        # Enhanced Download section
        st.markdown("---")
        st.markdown(
            """
            <div style="background: #f8fafc; border: 2px solid #e2e8f0; 
                       border-radius: 8px; padding: 1rem; margin: 1rem 0;">
                <h3 style="color: #374151; margin: 0 0 1rem 0;">📥 Download Options</h3>
            </div>
            """,
            unsafe_allow_html=True
        )

        col1, col2, col3 = st.columns(3)

        with col1:
            report_json = json.dumps(complete_analysis, indent=2)
            st.download_button(
                label="📄 Full Analysis (JSON)",
                data=report_json,
                file_name=f"complete_analysis_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                key=f"download_full_{username}",
                use_container_width=True,
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
                key=f"download_summary_{username}",
                use_container_width=True,
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
                        key=f"download_mitre_{username}",
                        use_container_width=True,
                    )

        # Enhanced Analysis Coverage
        if complete_analysis.get("mitre_attack_analysis"):
            coverage = complete_analysis["mitre_attack_analysis"].get(
                "sub_technique_coverage"
            )

            if coverage and isinstance(coverage, dict):
                st.markdown("---")
                st.markdown(
                    """
                    <div style="background: #f8fafc; border: 2px solid #e2e8f0; 
                               border-radius: 8px; padding: 1rem; margin: 1rem 0;">
                        <h3 style="color: #374151; margin: 0 0 1rem 0;">📊 Analysis Coverage</h3>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

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