import os
import streamlit as st
from typing import Optional
from datetime import datetime
from sentinel.backend import *
import google.generativeai as genai
from crewai_tools import SerperDevTool

# Configure these with your API keys
SERPER_API_KEY = os.getenv("SERPER_API_KEY")
GEMINI_API_KEY = os.getenv("GOOGLE_API_KEY")

genai.configure(api_key=GEMINI_API_KEY)
serper_tool = SerperDevTool()

# Page configuration
st.set_page_config(page_title="Sentinel Logs Dashboard", page_icon="🔒", layout="wide")

# Initialize session state for details view
if "show_details" not in st.session_state:
    st.session_state.show_details = False
if "selected_log" not in st.session_state:
    st.session_state.selected_log = None
if "selected_log_index" not in st.session_state:
    st.session_state.selected_log_index = None

# Custom CSS
st.markdown(
    """
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: bold;
        color: #1f77b4;
        margin-bottom: 1rem;
    }
    .card {
        background-color: #f8f9fa;
        border-radius: 10px;
        padding: 20px;
        margin: 10px 0;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border-radius: 10px;
        padding: 20px;
        text-align: center;
    }
    .alert-card {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        color: white;
        border-radius: 10px;
        padding: 20px;
        text-align: center;
    }
    .success-card {
        background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        color: white;
        border-radius: 10px;
        padding: 20px;
        text-align: center;
    }
    .source-badge {
        display: inline-block;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 8px 15px;
        margin: 5px;
        border-radius: 20px;
        font-size: 0.9rem;
        font-weight: 500;
    }
    .record-card {
        background-color: white;
        border-left: 4px solid #1f77b4;
        padding: 12px;
        margin: 8px 0;
        border-radius: 4px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }
    .record-card:hover {
        box-shadow: 0 2px 6px rgba(0,0,0,0.15);
    }
    .detail-section {
        background-color: #f8f9fa;
        border-radius: 10px;
        padding: 20px;
        margin: 15px 0;
    }
    .detail-section h4 {
        color: #1f77b4;
        margin-bottom: 15px;
        font-size: 1.2rem;
    }
    .info-box {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 15px;
        border-radius: 8px;
        margin: 10px 0;
    }
</style>
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


def fetch_error_code_info(
    error_code: str, error_name: str = "", source: str = ""
) -> Optional[str]:
    try:
        # Step 1: Search for error code information using Serper (via crewai)
        search_query = f"Sentinel error code {error_code} {error_name} Azure AD sign-in"

        search_results = serper_tool.run(query=search_query)

        if not search_results:
            return None

        # Step 2: Use Gemini to summarize as bullet points
        source_context = f" from {source}" if source else ""
        prompt = f"""Based on the following search results about Azure AD/Sentinel error code {error_code}{source_context}, 
provide ONLY 3 bullet points:
• What this error means
• Common cause why it came
• What can be the affect

Keep each point to 1 sentence max.

Search Results:
{search_results}"""

        model = genai.GenerativeModel("gemini-2.5-flash")
        response = model.generate_content(prompt)

        if response and response.text:
            # Format response as markdown bullet points
            formatted_response = format_as_bullets(response.text)
            return formatted_response
        return None

    except Exception as e:
        print(f"Error fetching error code info: {e}")
        return None


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


# Replace the entire detail view section (after "if st.session_state.show_details...") with this:
if st.session_state.show_details and st.session_state.selected_log:
    # DETAILS VIEW - Full Page
    log_data = st.session_state.selected_log

    # Header with back button
    col1, col2 = st.columns([6, 1])
    # st.write(log_data)
    with col1:
        heading = log_data.get("Status", {}).get("failureReason", "N/A")
        st.markdown(
            f'<div class="main-header">🔍{heading if len(heading) <= 100 else (heading[:100]+"...")}</div>',
            unsafe_allow_html=True,
        )
    with col2:
        if st.button(
            "⬅️ Back to List", key="back_top", type="primary", use_container_width=True
        ):
            st.session_state.show_details = False
            st.rerun()

    st.markdown("---")

    # Display key information in cards
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(
            f"""
            <div class="card">
                <h4>⏰ Timestamp</h4>
                <p>{datetime.fromisoformat(log_data.get('TimeGenerated', '').replace('Z', '+00:00')).strftime('%b %d, %Y %I:%M:%S %p') if log_data.get('TimeGenerated') else 'N/A'}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        result_type = log_data.get("ResultType", "N/A")
        st.markdown(
            f"""
            <div class="card">
                <h4>🔢 Result Type</h4>
                <p style="color: #dc3545; font-weight: bold;">{result_type}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col3:
        source = log_data.get("AppDisplayName") or log_data.get("SourceSystem", "N/A")
        st.markdown(
            f"""
            <div class="card">
                <h4>🌐 Source</h4>
                <p>{source}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col4:
        result_sig = log_data.get("ResultSignature", "N/A")
        st.markdown(
            f"""
            <div class="card">
                <h4>✅ Result</h4>
                <p style="color: #dc3545; font-weight: bold;">{result_sig}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    error_code = log_data.get("Status", {}).get("errorCode", "N/A")
    if isinstance(log_data.get("Status"), dict) and error_code != "N/A":
        st.markdown('<div class="detail-section">', unsafe_allow_html=True)
        st.markdown("#### 🔍 Error Code Analysis")

        with st.spinner("Fetching error code information..."):
            error_info = fetch_error_code_info(
                str(error_code),
                log_data.get("ResultDescription", ""),
                log_data.get("AppDisplayName") or log_data.get("SourceSystem", "N/A"),
            )

        if error_info:
            st.markdown(
                f"""
            <div class="info-box">
                <div style="color: white; font-family: monospace; white-space: pre-wrap; word-wrap: break-word; line-height: 1.8;">{error_info}</div>
            </div>
            """,
                unsafe_allow_html=True,
            )
        else:
            st.info("Unable to fetch error code information at this time.")

        st.markdown("</div>", unsafe_allow_html=True)

    # User Information
    st.markdown('<div class="detail-section">', unsafe_allow_html=True)
    st.markdown("#### 👤 User Information")
    user_col1, user_col2, user_col3 = st.columns(3)

    with user_col1:
        st.text_input(
            "User Principal Name",
            value=log_data.get("UserPrincipalName", "N/A"),
            disabled=True,
        )
        st.text_input(
            "User Display Name",
            value=log_data.get("UserDisplayName", "N/A"),
            disabled=True,
        )
        st.text_input("Identity", value=log_data.get("Identity", "N/A"), disabled=True)

    with user_col2:
        st.text_input("User ID", value=log_data.get("UserId", "N/A"), disabled=True)
        st.text_input("User Type", value=log_data.get("UserType", "N/A"), disabled=True)
        st.text_input(
            "Sign-in Identifier",
            value=log_data.get("SignInIdentifier", "N/A"),
            disabled=True,
        )

    with user_col3:
        st.text_input(
            "Alternate Sign-in Name",
            value=log_data.get("AlternateSignInName", "N/A"),
            disabled=True,
        )
        st.text_input(
            "Sign-in Identifier Type",
            value=log_data.get("SignInIdentifierType", "N/A"),
            disabled=True,
        )
        st.text_input(
            "Home Tenant Name",
            value=log_data.get("HomeTenantName", "N/A"),
            disabled=True,
        )
    st.markdown("</div>", unsafe_allow_html=True)

    # Location & Network Information
    st.markdown('<div class="detail-section">', unsafe_allow_html=True)
    st.markdown("#### 🌍 Location & Network Information")
    loc_col1, loc_col2, loc_col3 = st.columns(3)

    with loc_col1:
        st.text_input(
            "IP Address", value=log_data.get("IPAddress", "N/A"), disabled=True
        )
        st.text_input("Location", value=log_data.get("Location", "N/A"), disabled=True)
        location_details = log_data.get("LocationDetails", {})
        if isinstance(location_details, dict):
            st.text_input(
                "City", value=location_details.get("city", "N/A"), disabled=True
            )

    with loc_col2:
        if isinstance(location_details, dict):
            st.text_input(
                "State", value=location_details.get("state", "N/A"), disabled=True
            )
            st.text_input(
                "Country",
                value=location_details.get("countryOrRegion", "N/A"),
                disabled=True,
            )
            geo = location_details.get("geoCoordinates", {})
            if isinstance(geo, dict):
                st.text_input(
                    "Latitude", value=str(geo.get("latitude", "N/A")), disabled=True
                )
        else:
            st.text_input("State", value="N/A", disabled=True)
            st.text_input("Country", value="N/A", disabled=True)
            st.text_input("Latitude", value="N/A", disabled=True)

    with loc_col3:
        if isinstance(location_details, dict) and isinstance(geo, dict):
            st.text_input(
                "Longitude", value=str(geo.get("longitude", "N/A")), disabled=True
            )
        else:
            st.text_input("Longitude", value="N/A", disabled=True)
        st.text_input(
            "Autonomous System Number",
            value=log_data.get("AutonomousSystemNumber", "N/A"),
            disabled=True,
        )
        st.text_input(
            "Global Secure Access IP",
            value=log_data.get("GlobalSecureAccessIpAddress", "N/A"),
            disabled=True,
        )
    st.markdown("</div>", unsafe_allow_html=True)

    # Authentication Details
    st.markdown('<div class="detail-section">', unsafe_allow_html=True)
    st.markdown("#### 🔐 Authentication Details")
    auth_col1, auth_col2 = st.columns(2)

    with auth_col1:
        status = log_data.get("Status", {})
        if isinstance(status, dict):
            st.text_input(
                "Error Code", value=str(status.get("errorCode", "N/A")), disabled=True
            )
            st.text_area(
                "Failure Reason",
                value=status.get("failureReason", "N/A"),
                height=80,
                disabled=True,
            )
        else:
            st.text_input("Error Code", value="N/A", disabled=True)
            st.text_area("Failure Reason", value="N/A", height=80, disabled=True)
        st.text_area(
            "Result Description",
            value=log_data.get("ResultDescription", "N/A"),
            height=80,
            disabled=True,
        )
        st.text_input(
            "Authentication Requirement",
            value=log_data.get("AuthenticationRequirement", "N/A"),
            disabled=True,
        )
        st.text_input(
            "Authentication Protocol",
            value=log_data.get("AuthenticationProtocol", "N/A"),
            disabled=True,
        )

    with auth_col2:
        st.text_input(
            "Authentication Methods Used",
            value=log_data.get("AuthenticationMethodsUsed", "N/A"),
            disabled=True,
        )
        st.text_input(
            "Conditional Access Status",
            value=log_data.get("ConditionalAccessStatus", "N/A"),
            disabled=True,
        )
        st.text_input(
            "Client Credential Type",
            value=log_data.get("ClientCredentialType", "N/A"),
            disabled=True,
        )
        st.text_input(
            "Incoming Token Type",
            value=log_data.get("IncomingTokenType", "N/A"),
            disabled=True,
        )
        st.text_input(
            "Original Transfer Method",
            value=log_data.get("OriginalTransferMethod", "N/A"),
            disabled=True,
        )
    st.markdown("</div>", unsafe_allow_html=True)

    # Authentication Processing Details
    st.markdown('<div class="detail-section">', unsafe_allow_html=True)
    st.markdown("#### 🔍 Authentication Processing Details")
    auth_details = log_data.get("AuthenticationDetails", [])
    if auth_details and isinstance(auth_details, list):
        for i, detail in enumerate(auth_details):
            with st.expander(f"Authentication Step {i+1}", expanded=(i == 0)):
                det_col1, det_col2 = st.columns(2)
                with det_col1:
                    st.text_input(
                        "Method",
                        value=detail.get("authenticationMethod", "N/A"),
                        disabled=True,
                        key=f"Method_{i}",
                    )
                    st.text_input(
                        "Method Detail",
                        value=detail.get("authenticationMethodDetail", "N/A"),
                        disabled=True,
                        key=f"Detail_{i}",
                    )
                    st.text_input(
                        "Succeeded",
                        value=str(detail.get("succeeded", "N/A")),
                        disabled=True,
                        key=f"Succeeded_{i}",
                    )
                with det_col2:
                    st.text_input(
                        "DateTime",
                        value=detail.get("authenticationStepDateTime", "N/A"),
                        disabled=True,
                        key=f"DateTime_{i}",
                    )
                    st.text_input(
                        "Result Detail",
                        value=detail.get("authenticationStepResultDetail", "N/A"),
                        disabled=True,
                        key=f"Result_{i}",
                    )
                    st.text_input(
                        "Requirement",
                        value=detail.get("authenticationStepRequirement", "N/A"),
                        disabled=True,
                        key=f"Req_{i}",
                    )
    else:
        st.info("No authentication details available")

    auth_processing = log_data.get("AuthenticationProcessingDetails", [])
    if auth_processing and isinstance(auth_processing, list):
        st.markdown("**Processing Details:**")
        for detail in auth_processing:
            if isinstance(detail, dict):
                st.text(f"• {detail.get('key', 'N/A')}: {detail.get('value', 'N/A')}")
    st.markdown("</div>", unsafe_allow_html=True)

    # Device Information
    st.markdown('<div class="detail-section">', unsafe_allow_html=True)
    st.markdown("#### 📱 Device Information")
    device_col1, device_col2, device_col3 = st.columns(3)

    device_detail = log_data.get("DeviceDetail", {})
    with device_col1:
        if isinstance(device_detail, dict):
            st.text_input(
                "Device ID",
                value=device_detail.get("deviceId", "N/A") or "N/A",
                disabled=True,
            )
            st.text_input(
                "Operating System",
                value=device_detail.get("operatingSystem", "N/A"),
                disabled=True,
            )
            st.text_input(
                "Browser", value=device_detail.get("browser", "N/A"), disabled=True
            )
        else:
            st.text_input("Device ID", value="N/A", disabled=True)
            st.text_input("Operating System", value="N/A", disabled=True)
            st.text_input("Browser", value="N/A", disabled=True)

    with device_col2:
        if isinstance(device_detail, dict):
            st.text_input(
                "Display Name",
                value=device_detail.get("displayName", "N/A") or "N/A",
                disabled=True,
            )
            st.text_input(
                "Is Compliant",
                value=str(device_detail.get("isCompliant", "N/A")),
                disabled=True,
            )
            st.text_input(
                "Is Managed",
                value=str(device_detail.get("isManaged", "N/A")),
                disabled=True,
            )
        else:
            st.text_input("Display Name", value="N/A", disabled=True)
            st.text_input("Is Compliant", value="N/A", disabled=True)
            st.text_input("Is Managed", value="N/A", disabled=True)

    with device_col3:
        if isinstance(device_detail, dict):
            st.text_input(
                "Trust Type",
                value=device_detail.get("trustType", "N/A") or "N/A",
                disabled=True,
            )
            st.text_input(
                "Management Type",
                value=device_detail.get("managementType", "N/A") or "N/A",
                disabled=True,
            )
        else:
            st.text_input("Trust Type", value="N/A", disabled=True)
            st.text_input("Management Type", value="N/A", disabled=True)
        st.text_input(
            "Client App Used", value=log_data.get("ClientAppUsed", "N/A"), disabled=True
        )

    st.text_area(
        "User Agent", value=log_data.get("UserAgent", "N/A"), height=80, disabled=True
    )
    st.markdown("</div>", unsafe_allow_html=True)

    # Application Information
    st.markdown('<div class="detail-section">', unsafe_allow_html=True)
    st.markdown("#### 📦 Application Information")
    app_col1, app_col2 = st.columns(2)

    with app_col1:
        st.text_input(
            "Application Name",
            value=log_data.get("AppDisplayName", "N/A"),
            disabled=True,
        )
        st.text_input(
            "Application ID", value=log_data.get("AppId", "N/A"), disabled=True
        )
        st.text_input(
            "Service Principal ID",
            value=log_data.get("ServicePrincipalId", "N/A") or "N/A",
            disabled=True,
        )
        st.text_input(
            "Service Principal Name",
            value=log_data.get("ServicePrincipalName", "N/A") or "N/A",
            disabled=True,
        )
        st.text_input(
            "App Owner Tenant ID",
            value=log_data.get("AppOwnerTenantId", "N/A"),
            disabled=True,
        )

    with app_col2:
        st.text_input(
            "Resource Display Name",
            value=log_data.get("ResourceDisplayName", "N/A"),
            disabled=True,
        )
        st.text_input("Resource", value=log_data.get("Resource", "N/A"), disabled=True)
        st.text_input(
            "Resource Identity",
            value=log_data.get("ResourceIdentity", "N/A"),
            disabled=True,
        )
        st.text_input(
            "Resource Service Principal ID",
            value=log_data.get("ResourceServicePrincipalId", "N/A"),
            disabled=True,
        )
        st.text_input(
            "Resource Owner Tenant ID",
            value=log_data.get("ResourceOwnerTenantId", "N/A"),
            disabled=True,
        )

    st.text_input("Resource ID", value=log_data.get("ResourceId", "N/A"), disabled=True)
    st.text_input(
        "Resource Group", value=log_data.get("ResourceGroup", "N/A"), disabled=True
    )
    st.text_input(
        "Source App Client ID",
        value=log_data.get("SourceAppClientId", "N/A") or "N/A",
        disabled=True,
    )
    st.markdown("</div>", unsafe_allow_html=True)

    # Risk & Security Information
    st.markdown('<div class="detail-section">', unsafe_allow_html=True)
    st.markdown("#### ⚠️ Risk & Security Information")
    risk_col1, risk_col2, risk_col3 = st.columns(3)

    with risk_col1:
        st.text_input(
            "Risk State", value=log_data.get("RiskState", "N/A"), disabled=True
        )
        st.text_input(
            "Risk Level Aggregated",
            value=log_data.get("RiskLevelAggregated", "N/A"),
            disabled=True,
        )
        st.text_input(
            "Risk Level During Sign-in",
            value=log_data.get("RiskLevelDuringSignIn", "N/A"),
            disabled=True,
        )
        st.text_input(
            "Risk Detail", value=log_data.get("RiskDetail", "N/A"), disabled=True
        )

    with risk_col2:
        st.text_input(
            "Is Risky", value=str(log_data.get("IsRisky", "N/A")), disabled=True
        )
        st.text_input(
            "Flagged For Review",
            value=str(log_data.get("FlaggedForReview", "N/A")),
            disabled=True,
        )
        st.text_input(
            "Is Interactive",
            value=str(log_data.get("IsInteractive", "N/A")),
            disabled=True,
        )
        st.text_input(
            "Is Tenant Restricted",
            value=str(log_data.get("IsTenantRestricted", "N/A")),
            disabled=True,
        )

    with risk_col3:
        st.text_input(
            "Cross Tenant Access Type",
            value=log_data.get("CrossTenantAccessType", "N/A"),
            disabled=True,
        )
        st.text_input(
            "Is Through Global Secure Access",
            value=str(log_data.get("IsThroughGlobalSecureAccess", "N/A")),
            disabled=True,
        )
        token_protection = log_data.get("TokenProtectionStatusDetails", {})
        if isinstance(token_protection, dict):
            st.text_input(
                "Token Session Status",
                value=token_protection.get("signInSessionStatus", "N/A"),
                disabled=True,
            )
            st.text_input(
                "Token Session Status Code",
                value=str(token_protection.get("signInSessionStatusCode", "N/A")),
                disabled=True,
            )

    risk_events = log_data.get("RiskEventTypes_V2", [])
    if risk_events and isinstance(risk_events, list) and len(risk_events) > 0:
        st.text_area(
            "Risk Event Types", value=", ".join(risk_events), height=60, disabled=True
        )
    else:
        st.text_input("Risk Event Types", value="None", disabled=True)
    st.markdown("</div>", unsafe_allow_html=True)

    # Session & Token Information
    st.markdown('<div class="detail-section">', unsafe_allow_html=True)
    st.markdown("#### 🎫 Session & Token Information")
    session_col1, session_col2, session_col3 = st.columns(3)

    with session_col1:
        st.text_input(
            "Session ID", value=log_data.get("SessionId", "N/A") or "N/A", disabled=True
        )
        st.text_input(
            "Unique Token Identifier",
            value=log_data.get("UniqueTokenIdentifier", "N/A"),
            disabled=True,
        )
        st.text_input(
            "Token Issuer Name",
            value=log_data.get("TokenIssuerName", "N/A") or "N/A",
            disabled=True,
        )

    with session_col2:
        st.text_input(
            "Token Issuer Type",
            value=log_data.get("TokenIssuerType", "N/A"),
            disabled=True,
        )
        st.text_input(
            "Federated Credential ID",
            value=log_data.get("FederatedCredentialId", "N/A") or "N/A",
            disabled=True,
        )

    with session_col3:
        session_policies = log_data.get("SessionLifetimePolicies", [])
        if (
            session_policies
            and isinstance(session_policies, list)
            and len(session_policies) > 0
        ):
            st.text_area(
                "Session Lifetime Policies",
                value=str(session_policies),
                height=80,
                disabled=True,
            )
        else:
            st.text_input("Session Lifetime Policies", value="None", disabled=True)
    st.markdown("</div>", unsafe_allow_html=True)

    # Tenant & System Information
    st.markdown('<div class="detail-section">', unsafe_allow_html=True)
    st.markdown("#### 🏢 Tenant & System Information")
    tenant_col1, tenant_col2, tenant_col3 = st.columns(3)

    with tenant_col1:
        st.text_input("Tenant ID", value=log_data.get("TenantId", "N/A"), disabled=True)
        st.text_input(
            "AAD Tenant ID", value=log_data.get("AADTenantId", "N/A"), disabled=True
        )
        st.text_input(
            "Home Tenant ID", value=log_data.get("HomeTenantId", "N/A"), disabled=True
        )

    with tenant_col2:
        st.text_input(
            "Resource Tenant ID",
            value=log_data.get("ResourceTenantId", "N/A"),
            disabled=True,
        )
        st.text_input(
            "Source System", value=log_data.get("SourceSystem", "N/A"), disabled=True
        )
        st.text_input(
            "Resource Provider",
            value=log_data.get("ResourceProvider", "N/A") or "N/A",
            disabled=True,
        )

    with tenant_col3:
        st.text_input("Category", value=log_data.get("Category", "N/A"), disabled=True)
        st.text_input(
            "Operation Name", value=log_data.get("OperationName", "N/A"), disabled=True
        )
        st.text_input(
            "Operation Version",
            value=log_data.get("OperationVersion", "N/A"),
            disabled=True,
        )
    st.markdown("</div>", unsafe_allow_html=True)

    # Additional Technical Details
    st.markdown('<div class="detail-section">', unsafe_allow_html=True)
    st.markdown("#### 🔧 Technical Details")
    tech_col1, tech_col2, tech_col3 = st.columns(3)

    with tech_col1:
        st.text_input(
            "Correlation ID", value=log_data.get("CorrelationId", "N/A"), disabled=True
        )
        st.text_input(
            "Original Request ID",
            value=log_data.get("OriginalRequestId", "N/A"),
            disabled=True,
        )
        st.text_input("Record ID", value=log_data.get("Id", "N/A"), disabled=True)

    with tech_col2:
        st.text_input(
            "Processing Time (ms)",
            value=log_data.get("ProcessingTimeInMilliseconds", "N/A"),
            disabled=True,
        )
        st.text_input(
            "Duration (ms)", value=str(log_data.get("DurationMs", "N/A")), disabled=True
        )
        st.text_input("Level", value=log_data.get("Level", "N/A"), disabled=True)

    with tech_col3:
        st.text_input(
            "Created DateTime",
            value=log_data.get("CreatedDateTime", "N/A"),
            disabled=True,
        )
        st.text_input("Type", value=log_data.get("Type", "N/A"), disabled=True)
        st.text_input(
            "xy_CF", value=log_data.get("xy_CF", "N/A") or "N/A", disabled=True
        )
    st.markdown("</div>", unsafe_allow_html=True)

    # Conditional Access & Policies
    ca_policies = log_data.get("ConditionalAccessPolicies", [])
    if ca_policies and isinstance(ca_policies, list) and len(ca_policies) > 0:
        st.markdown('<div class="detail-section">', unsafe_allow_html=True)
        st.markdown("#### 🛡️ Conditional Access Policies")
        for i, policy in enumerate(ca_policies):
            with st.expander(
                f"Policy {i+1}: {policy.get('displayName', 'N/A')}", expanded=False
            ):
                pol_col1, pol_col2 = st.columns(2)
                with pol_col1:
                    st.text_input(
                        "Policy ID",
                        value=policy.get("id", "N/A"),
                        disabled=True,
                        key=f"pol_id_{i}",
                    )
                    st.text_input(
                        "Result",
                        value=policy.get("result", "N/A"),
                        disabled=True,
                        key=f"pol_result_{i}",
                    )
                with pol_col2:
                    st.text_input(
                        "Enforced Controls",
                        value=str(policy.get("enforcedGrantControls", [])),
                        disabled=True,
                        key=f"pol_enforced_{i}",
                    )
                    st.text_input(
                        "Session Controls",
                        value=str(policy.get("enforcedSessionControls", [])),
                        disabled=True,
                        key=f"pol_session_{i}",
                    )
        st.markdown("</div>", unsafe_allow_html=True)

    # Applied Event Listeners
    applied_listeners = log_data.get("AppliedEventListeners", [])
    if (
        applied_listeners
        and isinstance(applied_listeners, list)
        and len(applied_listeners) > 0
    ):
        st.markdown('<div class="detail-section">', unsafe_allow_html=True)
        st.markdown("#### 📡 Applied Event Listeners")
        st.json(applied_listeners)
        st.markdown("</div>", unsafe_allow_html=True)

    # Agent Information
    agent_info = log_data.get("Agent", {})
    if agent_info and isinstance(agent_info, dict):
        st.markdown('<div class="detail-section">', unsafe_allow_html=True)
        st.markdown("#### 🤖 Agent Information")
        st.text_input(
            "Agent Type", value=agent_info.get("agentType", "N/A"), disabled=True
        )
        st.markdown("</div>", unsafe_allow_html=True)

    # Network Location Details
    network_details = log_data.get("NetworkLocationDetails", [])
    if (
        network_details
        and isinstance(network_details, list)
        and len(network_details) > 0
    ):
        st.markdown('<div class="detail-section">', unsafe_allow_html=True)
        st.markdown("#### 🌐 Network Location Details")
        st.json(network_details)
        st.markdown("</div>", unsafe_allow_html=True)

    # Authentication Context & Requirement Policies
    auth_context = log_data.get("AuthenticationContextClassReferences", [])
    auth_req_policies = log_data.get("AuthenticationRequirementPolicies", [])

    if (auth_context and len(auth_context) > 0) or (
        auth_req_policies and len(auth_req_policies) > 0
    ):
        st.markdown('<div class="detail-section">', unsafe_allow_html=True)
        st.markdown("#### 📋 Authentication Context & Policies")
        if auth_context and len(auth_context) > 0:
            st.text_area(
                "Authentication Context Class References",
                value=str(auth_context),
                height=80,
                disabled=True,
            )
        if auth_req_policies and len(auth_req_policies) > 0:
            st.text_area(
                "Authentication Requirement Policies",
                value=str(auth_req_policies),
                height=80,
                disabled=True,
            )
        st.markdown("</div>", unsafe_allow_html=True)

    # MFA Details
    mfa_detail = log_data.get("MfaDetail")
    if mfa_detail:
        st.markdown('<div class="detail-section">', unsafe_allow_html=True)
        st.markdown("#### 🔐 MFA Details")
        st.json(mfa_detail)
        st.markdown("</div>", unsafe_allow_html=True)

    # Full JSON Data
    st.markdown('<div class="detail-section">', unsafe_allow_html=True)
    st.markdown("#### 📄 Complete JSON Data")
    with st.expander("View Raw JSON", expanded=False):
        st.json(log_data)
    st.markdown("</div>", unsafe_allow_html=True)

    # Bottom buttons
    st.markdown("---")
    col1, col2, col3 = st.columns([1, 1, 4])
    with col1:
        if st.button(
            "⬅️ Back to List",
            key="back_bottom",
            type="primary",
            use_container_width=True,
        ):
            st.session_state.show_details = False
            st.rerun()
    with col2:
        if st.button("📋 Copy JSON", key="copy_json", use_container_width=True):
            st.code(json.dumps(log_data, indent=2), language="json")

    st.stop()
    
# MAIN LIST VIEW
else:
    st.markdown(
        '<div class="main-header">🔒 Sentinel Logs Dashboard - SigninLogs</div>',
        unsafe_allow_html=True,
    )

    # Sidebar filters
    st.sidebar.header("⚙️ Filters")

    # Check if sentinel_logs folder exists
    if not os.path.exists("sentinel_logs"):
        st.error(
            "❌ sentinel_logs folder not found. Please run the data collection script first."
        )
        st.stop()

    # Fixed table selection
    selected_table = "SigninLogs"
    st.sidebar.info(f"📊 Currently viewing: **{selected_table}**")
    st.sidebar.caption("(Table selection locked)")

    # Days filter
    days_filter = st.sidebar.slider("📅 Days to Show", 1, 30, 7)

    # Sort options
    sort_by = st.sidebar.selectbox(
        "🔄 Sort By", ["TimeGenerated", "ResultType", "UserPrincipalName"]
    )
    sort_order = st.sidebar.radio("Sort Order", ["Descending", "Ascending"])

    # Auto-refresh for SigninLogs
    st.sidebar.markdown("---")
    st.sidebar.subheader("♻️ Auto-Refresh")

    needs_refresh, status_msg = check_signin_logs_freshness()

    if needs_refresh:
        st.sidebar.warning(f"⚠️ {status_msg}")
        if st.sidebar.button("🔄 Refresh SigninLogs Now"):
            with st.spinner("Refreshing SigninLogs..."):
                success, message = refresh_signin_logs()
                if success:
                    st.sidebar.success("✅ Refresh completed!")
                    st.rerun()
                else:
                    st.sidebar.error(f"❌ Refresh failed: {message}")
    else:
        st.sidebar.success(f"✅ {status_msg}")

    # Load logs
    logs, error = load_logs(selected_table, days_filter)

    if error:
        st.error(f"❌ Error loading logs: {error}")
        st.stop()

    if not logs:
        st.warning(f"⚠️ No logs found for {selected_table} in the last {days_filter} days.")
        st.stop()

    # Dashboard metrics
    col2, col3 = st.columns(2)

    with col2:
        failed_logins = len([l for l in logs if l.get("ResultType") != "0"])
        st.markdown(
            f"""
        <div class="alert-card">
            <h3>🚨 Failed Sign-ins</h3>
            <h1>{failed_logins:,}</h1>
        </div>
        """,
            unsafe_allow_html=True,
        )

    with col3:
        unique_users = len(set([l.get("UserPrincipalName", "Unknown") for l in logs]))
        st.markdown(
            f"""
        <div class="success-card">
            <h3>👥 Unique Users</h3>
            <h1>{unique_users:,}</h1>
        </div>
        """,
            unsafe_allow_html=True,
        )

    st.markdown("---")

    # Display unique sources
    unique_sources = get_unique_sources(logs)

    # Initialize session state for sources visibility
    if "show_sources" not in st.session_state:
        st.session_state.show_sources = False

    col1, col2 = st.columns([6, 1])
    with col1:
        st.subheader(f"🌐 Unique Sources ({len(unique_sources)})")
    with col2:
        if st.button(
            "▼ Show" if not st.session_state.show_sources else "▲ Hide",
            key="toggle_sources",
        ):
            st.session_state.show_sources = not st.session_state.show_sources

    if st.session_state.show_sources:
        sources_html = "".join(
            [f'<span class="source-badge">{source}</span>' for source in unique_sources]
        )
        st.markdown(sources_html, unsafe_allow_html=True)

    st.markdown("---")

    # Search functionality
    search_query = st.text_input("🔍 Search logs", placeholder="Search by any field...")

    # Filter logs by search query
    if search_query:
        filtered_logs = [
            log
            for log in logs
            if any(search_query.lower() in str(v).lower() for v in log.values())
        ]
    else:
        filtered_logs = logs

    # Pagination
    records_per_page = 50
    total_records = len(filtered_logs)
    total_pages = (total_records + records_per_page - 1) // records_per_page

    if total_pages > 0:
        # Initialize session state for page
        if "current_page" not in st.session_state:
            st.session_state.current_page = 1

        # Pagination buttons
        col1, col2, col3, col4, col5 = st.columns([1, 1, 2, 1, 1])

        with col1:
            if st.button("⏮️ First", disabled=(st.session_state.current_page == 1)):
                st.session_state.current_page = 1
                st.rerun()

        with col2:
            if st.button("⬅️ Prev", disabled=(st.session_state.current_page == 1)):
                st.session_state.current_page -= 1
                st.rerun()

        with col3:
            st.markdown(
                f"<div style='text-align: center; padding: 8px; font-weight: bold;'>Page {st.session_state.current_page} of {total_pages}</div>",
                unsafe_allow_html=True,
            )

        with col4:
            if st.button("Next ➡️", disabled=(st.session_state.current_page == total_pages)):
                st.session_state.current_page += 1
                st.rerun()

        with col5:
            if st.button("Last ⏭️", disabled=(st.session_state.current_page == total_pages)):
                st.session_state.current_page = total_pages
                st.rerun()

        page = st.session_state.current_page
    else:
        page = 1

    start_idx = (page - 1) * records_per_page
    end_idx = min(start_idx + records_per_page, total_records)

    st.subheader(
        f"📋 {selected_table} - Page {page} of {total_pages} ({total_records} total records)"
    )

    # Display logs for current page with compact design
    for idx in range(start_idx, end_idx):
        log = filtered_logs[idx]

        # Extract the three fields
        failure_reason = (
            log.get("Status", {}).get("failureReason", "N/A")
            if isinstance(log.get("Status"), dict)
            else "N/A"
        )
        result_type = log.get("ResultType", "N/A")
        source = log.get("AppDisplayName") or log.get("SourceSystem", "N/A")
        timestamp = log.get("TimeGenerated", "No timestamp")

        # Create columns for card and button
        col_card, col_btn = st.columns([9, 1])

        with col_card:
            # Compact card display
            st.markdown(
                f"""
                <div class="record-card">
                    <div style="display: flex; align-items: start; gap: 12px;">
                        <span style="color: #1f77b4; font-weight: bold; font-size: 0.9rem;">{idx + 1}</span>
                        <div style="flex: 1;">
                            <div style="font-size: 0.75rem; color: #666; margin-bottom: 4px;">
                                📅 {datetime.fromisoformat(timestamp.replace('Z', '+00:00')).strftime('%b %d, %Y %I:%M:%S %p') if timestamp != 'No timestamp' else 'No timestamp'}
                            </div>
                            <div style="font-size: 0.9rem; margin-bottom: 2px;">
                                <strong>Failure:</strong> {failure_reason}
                            </div>
                            <div style="font-size: 0.9rem; margin-bottom: 2px;">
                                <strong>Error:</strong> <span style="color: #dc3545;">{result_type}</span>
                            </div>
                            <div style="font-size: 0.9rem;">
                                <strong>Source:</strong> <span style="color: #1f77b4;">{source}</span>
                            </div>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with col_btn:
            # Button to view details
            if st.button("👁️", key=f"view_{idx}", help="View full details"):
                st.session_state.selected_log = log
                st.session_state.selected_log_index = idx + 1
                st.session_state.show_details = True
                st.rerun()

    # Pagination info
    st.caption(f"Showing records {start_idx + 1} to {end_idx} of {total_records}")

# Footer
st.markdown("---")
st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
