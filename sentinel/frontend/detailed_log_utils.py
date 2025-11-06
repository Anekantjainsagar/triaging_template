import streamlit as st


def format_as_bullets(text: str) -> str:
    """
    Ensure the response is formatted as clean, spaced bullet points.
    """
    lines = text.strip().split("\n")
    bullets = []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Skip lines that are just "Here are the three bullet points..." or similar
        if line.lower().startswith("here are") or line.lower().startswith("based on"):
            continue

        # Remove existing bullet symbols and clean up
        if line.startswith("•") or line.startswith("-") or line.startswith("*"):
            line = line.lstrip("•-*").strip()

        # Remove markdown bold markers (**text**)
        line = line.replace("**", "").strip()

        # Only add non-empty lines
        if line:
            bullets.append(f"• {line}")

    # Join with double newlines for better spacing
    return "\n".join(bullets)


def render_field(label: str, value: str, key: str = None):
    """Render a field with grey label and black value"""
    st.markdown(
        f"""
        <div class="field-container">
            <div class="field-label">{label}</div>
            <div class="field-value">{value}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_textarea_field(label: str, value: str, key: str = None):
    """Render a textarea field with grey label and black value"""
    st.markdown(
        f"""
        <div class="field-container">
            <div class="field-label">{label}</div>
            <div class="field-value-textarea">{value}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def get_unique_sources(logs):
    """Extract unique source systems and app display names from logs"""
    sources = set()
    for log in logs:
        source = log.get("SourceSystem", "Unknown")
        app_name = log.get("AppDisplayName", "")

        if source:
            sources.add(source)
        if app_name:
            sources.add(app_name)
    return sorted(list(sources))


def prepare_log_for_soc_analysis(log_data, error_info):
    """
    Convert SigninLogs data to SOC Hub alert format
    """
    # Extract title
    title = log_data.get("Status", {}).get("failureReason", "Sign-in Failure")

    # Extract description from error_info (if available in session state)
    # Or construct from available data
    error_code = log_data.get("Status", {}).get("errorCode", "N/A")
    result_type = log_data.get("ResultType", "N/A")
    description = error_info

    # Compile location information
    location_details = log_data.get("LocationDetails", {})
    ip_address = log_data.get("IPAddress", "N/A")

    location_parts = []
    if isinstance(location_details, dict):
        city = location_details.get("city", "")
        state = location_details.get("state", "")
        country = location_details.get("countryOrRegion", "")

        if city:
            location_parts.append(city)
        if state:
            location_parts.append(state)
        if country:
            location_parts.append(country)

    location = (
        ", ".join(location_parts) if location_parts else log_data.get("Location", "N/A")
    )

    # Create entities structure
    entities = {"entities": []}

    # Add Account entity
    user_principal = log_data.get("UserPrincipalName", "")
    if user_principal:
        entities["entities"].append(
            {
                "kind": "Account",
                "properties": {
                    "accountName": (
                        user_principal.split("@")[0]
                        if "@" in user_principal
                        else user_principal
                    ),
                    "upnSuffix": (
                        user_principal.split("@")[1] if "@" in user_principal else ""
                    ),
                    "userPrincipalName": user_principal,
                    "friendlyName": log_data.get("UserDisplayName", ""),
                },
            }
        )

    # Add IP entity
    if ip_address and ip_address != "N/A":
        entities["entities"].append(
            {
                "kind": "Ip",
                "properties": {
                    "address": ip_address,
                    "location": {
                        "city": (
                            location_details.get("city", "")
                            if isinstance(location_details, dict)
                            else ""
                        ),
                        "state": (
                            location_details.get("state", "")
                            if isinstance(location_details, dict)
                            else ""
                        ),
                        "countryName": (
                            location_details.get("countryOrRegion", "")
                            if isinstance(location_details, dict)
                            else ""
                        ),
                    },
                },
            }
        )

    # Add CloudApplication entity
    app_name = log_data.get("AppDisplayName", "")
    if app_name:
        entities["entities"].append(
            {
                "kind": "CloudApplication",
                "properties": {"name": app_name, "displayName": app_name},
            }
        )

    # Construct alert data structure
    alert_data = {
        "title": title,
        "description": description,
        "severity": "Medium",  # Default severity for sign-in logs
        "status": "Active",  # Default status
        "full_alert": {
            "properties": {
                "timeGenerated": log_data.get("TimeGenerated", ""),
                "alertDisplayName": title,
                "description": description,
            }
        },
        "entities": entities,
        "source": "signin_logs",
        "additional_context": {
            "user_principal": user_principal,
            "ip_address": ip_address,
            "location": location,
            "error_code": error_code,
            "result_type": result_type,
            "app_display_name": app_name,
            "device_info": log_data.get("DeviceDetail", {}),
            "raw_log": log_data,
        },
    }

    return alert_data
