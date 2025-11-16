import time
import streamlit as st
from datetime import datetime


def display_ai_threat_analysis_tab(alert_name, api_client, analysis_key, alert_data):
    """Display AI threat analysis for an alert"""

    if analysis_key in st.session_state and st.session_state[analysis_key]:
        result = st.session_state[analysis_key]
        if result.get("success"):
            analysis = result.get("analysis", "")

            st.markdown('<div class="threat-intel-box">', unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

            # Display sections...
            sections = analysis.split("## ")
            for section in sections:
                if not section.strip():
                    continue
                st.markdown(f"## {section}")

            # Download button
            st.markdown("---")
            col1, col2, col3 = st.columns([1, 1, 1])
            with col2:
                st.download_button(
                    label="📥 Download Analysis Report",
                    data=analysis,
                    file_name=f"threat_analysis_{alert_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                    mime="text/markdown",
                    width="stretch",
                    type="primary",
                )
    else:
        # Run analysis
        progress_placeholder = st.empty()

        with progress_placeholder.container():
            progress_bar = st.progress(0)
            status_text = st.empty()

            status_text.text("🚀 Initializing AI analysis engine...")
            progress_bar.progress(20)
            time.sleep(0.3)

            status_text.text("🔍 Analyzing threat patterns...")
            progress_bar.progress(50)
            time.sleep(0.3)

            status_text.text("🌐 Researching threat intelligence...")
            progress_bar.progress(75)

            # Extract description from alert data
            alert_description = alert_data.get("description") or alert_data.get("alert_description") or alert_data.get("alert_summary")
            
            # Call API with both title and description
            result = api_client.analyze_alert(alert_name, alert_description)

            progress_bar.progress(95)
            status_text.text("📊 Finalizing analysis...")
            time.sleep(0.2)
            progress_bar.progress(100)

            time.sleep(0.5)
            progress_placeholder.empty()

        # Cache and display
        st.session_state[analysis_key] = result

        if result.get("success"):
            st.rerun()
        else:
            st.error(f"❌ Analysis failed: {result.get('error')}")
