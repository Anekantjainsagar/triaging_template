import streamlit as st
from datetime import datetime


def display_alert_analysis_tab(rule_name: str, alert_analyzer):
    """Display AI-powered alert analysis tab"""

    st.markdown(
        """
        ### 🎯 Comprehensive Threat Intelligence
        
        This AI-powered analysis provides:
        - **Technical threat breakdown** with detailed attack vectors
        - **MITRE ATT&CK technique mapping** for framework alignment
        - **Real threat actor intelligence** from global threat databases
        - **Business impact assessment** and compliance implications
        """
    )

    st.markdown("---")

    progress_bar = st.progress(0)
    status_text = st.empty()

    try:
        status_text.text("🚀 Initializing AI analysis engine...")
        progress_bar.progress(20)

        status_text.text("🔍 Analyzing alert patterns and mapping to MITRE ATT&CK...")
        progress_bar.progress(40)

        status_text.text("🌐 Researching threat intelligence and actor TTPs...")
        progress_bar.progress(60)

        status_text.text("📊 Assessing business impact and compliance implications...")
        progress_bar.progress(80)

        # Generate analysis
        analysis = alert_analyzer.analyze_alert(rule_name)

        progress_bar.progress(100)
        status_text.text("✅ Analysis complete!")

        # Clear progress indicators
        progress_bar.empty()
        status_text.empty()

        # Display analysis in styled container
        st.markdown('<div class="threat-intel-box">', unsafe_allow_html=True)
        st.markdown(analysis)
        st.markdown("</div>", unsafe_allow_html=True)

        # Download option
        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            st.download_button(
                label="📄 Download Analysis Report",
                data=analysis,
                file_name=f"threat_analysis_{rule_name[:30]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown",
                width="stretch",
            )

    except Exception as e:
        st.error(f"❌ Analysis Error: {str(e)}")
        with st.expander("🔍 View Error Details"):
            st.code(str(e))
            st.markdown(
                """
            **Common Solutions:**
            1. Ensure Ollama is running: `ollama serve`
            2. Verify model is installed: `ollama pull qwen2.5:1.5b`
            3. Check Ollama status at: http://localhost:11434
            """
            )
