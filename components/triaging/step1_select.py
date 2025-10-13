# step1_select.py

import streamlit as st

def show_page(session_state, export_rule_incidents_to_excel):
    st.markdown(
        '<div class="step-header"><h2>Step 2: Select an Alert & Export Historical Data</h2></div>',
        unsafe_allow_html=True,
    )

    st.markdown(f"**Search Query:** `{session_state.get('search_input', 'N/A')}`")
    st.markdown(f"Found **{len(session_state.alerts)}** relevant alerts:")

    st.markdown("---")

    for idx, alert_title in enumerate(session_state.alerts):
        with st.container():
            col1, col2, col3 = st.columns([4, 1, 1])

            with col1:
                st.markdown(f"### {idx + 1}. {alert_title}")

                try:
                    parts = alert_title.split(" - ")
                    if len(parts) >= 2:
                        rule = parts[0].strip()
                        incident = parts[1].replace("Incident ", "").strip()

                        incident_row = session_state.all_data[
                            session_state.all_data["incident_no"]
                            .astype(str)
                            .str.strip()
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
                                st.metric(
                                    "Connector", info.get("data_connector", "N/A")
                                )
                except:
                    pass

            with col2:
                st.markdown("<br>", unsafe_allow_html=True)
                if st.button(
                    "💾 Export",
                    key=f"export_{idx}",
                    help="Download all incidents for this rule",
                ):
                    try:
                        parts = alert_title.split(" - ")
                        rule = parts[0].strip() if parts else "Unknown"

                        # Generate Excel file
                        excel_data = export_rule_incidents_to_excel(
                            session_state.all_data, rule
                        )

                        st.download_button(
                            label="💾 Download Excel",
                            data=excel_data,
                            file_name=f"{rule.replace('#', '_')}_historical_incidents.xlsx",
                            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            key=f"download_{idx}",
                        )
                    except Exception as e:
                        st.error(f"Export error: {str(e)}")

            with col3:
                st.markdown("<br>", unsafe_allow_html=True)
                if st.button("Select →", key=f"select_{idx}", type="primary"):
                    parts = alert_title.split(" - ")
                    rule = parts[0].strip() if parts else "Unknown"
                    incident = (
                        parts[1].replace("Incident ", "").strip()
                        if len(parts) > 1
                        else "Unknown"
                    )

                    session_state.selected_alert = {
                        "incident": incident,
                        "rule": rule,
                        "description": alert_title,
                    }
                    session_state.step = 2
                    st.rerun()

            st.markdown("---")

    if st.button("← Back to Search"):
        session_state.step = 0
        session_state.alerts = []
        st.rerun()