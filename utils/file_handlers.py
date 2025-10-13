import streamlit as st
from src.utils import export_rule_incidents_to_excel, generate_completed_template


def export_rule_incidents(data, alert_title):
    """Export rule incidents to Excel."""
    try:
        rule = (
            alert_title.split(" - ")[0].strip() if " - " in alert_title else "Unknown"
        )
        return export_rule_incidents_to_excel(data, rule)
    except Exception as e:
        st.error(f"Export error: {str(e)}")
        return None


def generate_final_report(consolidated_data, triaging_output, predictions):
    """Generate the final triaging report."""
    return generate_completed_template(
        consolidated_data, triaging_output, predictions[0] if predictions else {}
    )
