import streamlit as st
from datetime import datetime
from typing import Dict, List, Any


def extract_entities_from_alert(alert_data: dict) -> List[Dict[str, Any]]:
    """
    Extract all entities from alert data with their IDs and types

    Args:
        alert_data: Full alert data including entities

    Returns:
        List of entity dictionaries with id, type, and display info
    """
    entities_list = []

    if not alert_data:
        return entities_list

    # Get entities from alert data
    entities = alert_data.get("entities", {})

    if isinstance(entities, dict):
        raw_entities = entities.get("entities", [])
    else:
        raw_entities = entities if isinstance(entities, list) else []

    for entity in raw_entities:
        kind = entity.get("kind", "Unknown")
        props = entity.get("properties", {})

        # Generate entity ID based on type
        entity_id = None
        display_name = None

        if kind == "Account":
            account_name = props.get("accountName", "")
            upn_suffix = props.get("upnSuffix", "")
            friendly_name = props.get("friendlyName", "")

            if account_name and upn_suffix:
                entity_id = f"{account_name}@{upn_suffix}"
                display_name = entity_id
            elif account_name:
                entity_id = account_name
                display_name = account_name
            else:
                entity_id = friendly_name or f"unknown_account_{id(entity)}"
                display_name = friendly_name or "Unknown Account"

        # elif kind == "Ip":
        #     entity_id = props.get("address", "")
        #     display_name = entity_id

        # elif kind == "Host":
        #     entity_id = props.get("hostName") or props.get("netBiosName", "")
        #     display_name = entity_id

        # elif kind == "File":
        #     entity_id = props.get("name") or props.get("fileName", "")
        #     display_name = entity_id

        # elif kind == "Process":
        #     entity_id = props.get("processName", "")
        #     display_name = entity_id

        # elif kind == "MailMessage":
        #     entity_id = props.get("sender", "")
        #     display_name = f"{entity_id} → {props.get('recipient', '')}"

        # elif kind == "Url":
        #     entity_id = props.get("url", "")
        #     display_name = entity_id

        # elif kind == "CloudApplication":
        #     entity_id = props.get("name") or props.get("displayName", "")
        #     display_name = entity_id

        # else:
        #     entity_id = props.get("name") or f"unknown_{kind}_{id(entity)}"
        #     display_name = entity_id

        if entity_id:
            entities_list.append(
                {
                    "id": entity_id,
                    "type": kind,
                    "display_name": display_name,
                    "properties": props,
                    "raw_entity": entity,
                }
            )

    return entities_list


def predict_entity_classification(
    entity: Dict[str, Any], alert_context: dict, api_client
) -> Dict[str, Any]:
    """
    Predict if an entity's involvement is True Positive or False Positive

    Args:
        entity: Entity dictionary with id, type, and properties
        alert_context: Full alert context for analysis
        api_client: API client for predictions

    Returns:
        Prediction result dictionary
    """
    try:
        # Prepare entity-specific analysis context
        entity_analysis_text = f"""
Entity Analysis Request:
- Entity ID: {entity['id']}
- Entity Type: {entity['type']}
- Alert Name: {alert_context.get('title', 'Unknown')}
- Alert Severity: {alert_context.get('severity', 'Unknown')}
- Alert Description: {alert_context.get('description', '')}

Entity Properties:
{_format_entity_properties(entity['properties'])}

Analyze if this entity's involvement in the alert is a True Positive or False Positive.
"""

        # Call prediction API with entity-specific context
        result = api_client.predict_entity_classification(
            entity_id=entity["id"],
            entity_type=entity["type"],
            analysis_context=entity_analysis_text,
            alert_data=alert_context,
        )

        return result

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "entity_id": entity["id"],
            "classification": "UNKNOWN",
            "confidence": 0,
        }


def _format_entity_properties(properties: dict) -> str:
    """Format entity properties for analysis"""
    formatted = []
    for key, value in properties.items():
        if value and str(value).strip():
            formatted.append(f"  - {key}: {value}")
    return "\n".join(formatted) if formatted else "  No additional properties"


def display_entity_predictions_panel(alert_data: dict):
    """
    Display automated predictions for Account entities only - auto-analyzes without button clicks

    Args:
        alert_data: Full alert data including entities
    """

    st.markdown("---")
    st.markdown("### 🎯 Entity-Level Predictions (Account Entities Only)")
    st.info("🤖 Automatically analyzing Account entities involved in this alert...")

    # Extract entities
    entities = extract_entities_from_alert(alert_data)

    if not entities:
        st.warning("⚠️ No entities found in this alert")
        return

    # ✅ FILTER: Only process Account entities
    account_entities = [e for e in entities if e["type"] == "Account"]

    if not account_entities:
        st.warning("⚠️ No Account entities found in this alert")
        return

    st.success(f"✅ Found {len(account_entities)} Account entities to analyze")

    # Initialize API client
    import os
    from api_client.predictions_api_client import get_predictions_client

    final_api_key = os.getenv("GOOGLE_API_KEY")
    predictions_api_url = os.getenv("PREDICTIONS_API_URL", "http://localhost:8000")

    try:
        client = get_predictions_client(predictions_api_url, final_api_key)
    except Exception as e:
        st.error(f"❌ Failed to initialize predictions API: {str(e)}")
        return

    # Initialize session state for entity predictions
    if "entity_predictions" not in st.session_state:
        st.session_state.entity_predictions = {}

    # ✅ AUTO-ANALYZE: Process each Account entity automatically
    st.markdown("#### 👤 Account Entities Analysis")

    for entity in account_entities:
        entity_id = entity["id"]
        entity_key = f"Account_{entity_id}"

        # Check if prediction already exists
        if entity_key in st.session_state.entity_predictions:
            prediction = st.session_state.entity_predictions[entity_key]
            _display_entity_prediction(entity, prediction)
        else:
            # ✅ AUTO-PREDICT: Automatically analyze without button click
            with st.spinner(f"🔍 Analyzing {entity['display_name']}..."):
                prediction = predict_entity_classification(entity, alert_data, client)
                st.session_state.entity_predictions[entity_key] = prediction

            # Display immediately after prediction
            _display_entity_prediction(entity, prediction)

    st.markdown("---")

    # Display summary if predictions exist
    if st.session_state.entity_predictions:
        _display_predictions_summary(st.session_state.entity_predictions)


def _display_entity_prediction(entity: Dict[str, Any], prediction: Dict[str, Any]):
    """Display prediction results for a single entity"""

    classification = prediction.get("classification", "UNKNOWN")
    confidence = prediction.get("confidence", 0)

    # Determine color based on classification
    if "TRUE POSITIVE" in classification:
        bg_color = "#ffebee"
        border_color = "#d32f2f"
        icon = "🚨"
    elif "FALSE POSITIVE" in classification:
        bg_color = "#e8f5e9"
        border_color = "#388e3c"
        icon = "✅"
    else:
        bg_color = "#fff3e0"
        border_color = "#f57c00"
        icon = "⚠️"

    with st.expander(
        f"{icon} {entity['display_name']} - {classification}", expanded=True
    ):
        col1, col2 = st.columns([2, 1])

        with col1:
            st.markdown(f"**Entity ID:** `{entity['id']}`")
            st.markdown(f"**Entity Type:** {entity['type']}")

        with col2:
            st.markdown(
                f"""
                <div style="
                    background-color: {bg_color};
                    border-left: 4px solid {border_color};
                    padding: 15px;
                    border-radius: 8px;
                    text-align: center;
                ">
                    <h3 style="margin: 0; color: {border_color};">{classification}</h3>
                    <p style="margin: 5px 0 0 0; font-size: 14px;">Confidence: {confidence}%</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # Display reasoning if available
        reasoning = prediction.get("reasoning", "")
        if reasoning:
            st.markdown("**Analysis Reasoning:**")
            st.write(reasoning)

        # Risk indicators
        risk_level = prediction.get("risk_level", "UNKNOWN")
        if risk_level:
            st.markdown(f"**Risk Level:** `{risk_level}`")


def _display_predictions_summary(predictions: Dict[str, Dict[str, Any]]):
    """Display summary statistics of all predictions"""

    st.markdown("---")
    st.markdown("### 📊 Predictions Summary")

    total = len(predictions)
    true_positives = sum(
        1
        for p in predictions.values()
        if "TRUE POSITIVE" in p.get("classification", "")
    )
    false_positives = sum(
        1
        for p in predictions.values()
        if "FALSE POSITIVE" in p.get("classification", "")
    )
    unknown = sum(
        1 for p in predictions.values() if "UNKNOWN" in p.get("classification", "")
    )

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Entities", total)

    with col2:
        st.metric("🚨 True Positives", true_positives)

    with col3:
        st.metric("✅ False Positives", false_positives)

    with col4:
        st.metric("⚠️ Unknown", unknown)

    # Overall assessment
    if true_positives > 0:
        st.error(
            f"⚠️ **ALERT**: {true_positives} entity/entities confirmed as True Positive. Immediate investigation required!"
        )
    elif false_positives == total:
        st.success(
            "✅ All entities appear to be False Positives. Consider tuning the alert rule."
        )
    else:
        st.info(
            "ℹ️ Mixed results detected. Review individual entity predictions for details."
        )

    # Export option
    if st.button("📥 Export Entity Predictions", use_container_width=True):
        import json

        export_data = {
            "timestamp": datetime.now().isoformat(),
            "total_entities": total,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "unknown": unknown,
            "predictions": predictions,
        }

        st.download_button(
            label="💾 Download JSON Report",
            data=json.dumps(export_data, indent=2),
            file_name=f"entity_predictions_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
        )


def _get_entity_icon(entity_type: str) -> str:
    """Get emoji icon for entity type"""
    icons = {
        "Account": "👤",
        "Ip": "🌐",
        "Host": "💻",
        "File": "📄",
        "Process": "⚙️",
        "MailMessage": "📧",
        "Url": "🔗",
        "CloudApplication": "☁️",
    }
    return icons.get(entity_type, "📋")
