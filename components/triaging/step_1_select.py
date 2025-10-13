import streamlit as st
from utils.file_handlers import export_rule_incidents


def render_step_1():
    st.markdown(
        '<div class="step-header"><h2>Step 2: Select an Alert & Export Historical Data</h2></div>',
        unsafe_allow_html=True,
    )

    st.markdown(f"**Search Query:** `{st.session_state.get('search_input', 'N/A')}`")
    st.markdown(f"Found **{len(st.session_state.alerts)}** relevant alerts:")
    st.markdown("---")

    # Render each alert
    for idx, alert_title in enumerate(st.session_state.alerts):
        _render_alert_card(idx, alert_title)

    # Navigation
    if st.button("← Back to Search"):
        st.session_state.step = 0
        st.session_state.alerts = []
        st.rerun()


def _render_alert_card(idx, alert_title):
    with st.container():
        col1, col2, col3 = st.columns([4, 1, 1])

        with col1:
            st.markdown(f"### {idx + 1}. {alert_title}")
            _render_alert_metrics(alert_title)

        with col2:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("📁 Export", key=f"export_{idx}"):
                excel_data = export_rule_incidents(
                    st.session_state.all_data, alert_title
                )
                if excel_data:
                    _render_download_button(idx, alert_title, excel_data)

        with col3:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("Select →", key=f"select_{idx}", type="primary"):
                _select_alert(alert_title)

        st.markdown("---")


def _render_alert_metrics(alert_title):
    try:
        parts = alert_title.split(" - ")
        if len(parts) >= 2:
            rule = parts[0].strip()
            incident = parts[1].replace("Incident ", "").strip()

            incident_row = st.session_state.all_data[
                st.session_state.all_data["incident_no"].astype(str).str.strip()
                == incident
            ]

            if not incident_row.empty:
                info = incident_row.iloc[0]
                col_a, col_b, col_c = st.columns(3)
                with col_a:
                    st.metric("Priority", info.get("priority", "N/A"))
                with col_b:
                    st.metric("Type", info.get("alert_incident", "N/A"))
                with col_c:
                    st.metric("Connector", info.get("data_connector", "N/A"))
    except Exception:
        pass


def _render_download_button(idx, alert_title, excel_data):
    rule_name = alert_title.split(" - ")[0].strip().replace("#", "_")
    st.download_button(
        label="📥 Download Excel",
        data=excel_data,
        file_name=f"{rule_name}_historical_incidents.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        key=f"download_{idx}",
    )


def _select_alert(alert_title):
    parts = alert_title.split(" - ")
    rule = parts[0].strip() if parts else "Unknown"
    incident = (
        parts[1].replace("Incident ", "").strip() if len(parts) > 1 else "Unknown"
    )

    st.session_state.selected_alert = {
        "incident": incident,
        "rule": rule,
        "description": alert_title,
    }
    st.session_state.step = 2
    st.rerun()
