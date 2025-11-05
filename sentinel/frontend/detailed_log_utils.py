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
