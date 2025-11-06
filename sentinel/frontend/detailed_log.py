import os
import json
import streamlit as st
from typing import Optional
from datetime import datetime
from sentinel.backend import *
import google.generativeai as genai
from crewai_tools import SerperDevTool
from sentinel.frontend.detailed_log_utils import *
from components.soc_hub_overlay import display_soc_hub_overlay, prepare_alert_from_log

# Configure these with your API keys
SERPER_API_KEY = os.getenv("SERPER_API_KEY")
GEMINI_API_KEY = os.getenv("GOOGLE_API_KEY")

genai.configure(api_key=GEMINI_API_KEY)
serper_tool = SerperDevTool()


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


def logs_display():
    # DETAILS VIEW - Full Page
    log_data = st.session_state.selected_log

    # Header with back button
    col1, col2 = st.columns([6, 1])
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
        render_field("User Principal Name", log_data.get("UserPrincipalName", "N/A"))
        render_field("User Display Name", log_data.get("UserDisplayName", "N/A"))
        render_field("Identity", log_data.get("Identity", "N/A"))

    with user_col2:
        render_field("User ID", log_data.get("UserId", "N/A"))
        render_field("User Type", log_data.get("UserType", "N/A"))
        render_field("Sign-in Identifier", log_data.get("SignInIdentifier", "N/A"))

    with user_col3:
        render_field(
            "Alternate Sign-in Name", log_data.get("AlternateSignInName", "N/A")
        )
        render_field(
            "Sign-in Identifier Type", log_data.get("SignInIdentifierType", "N/A")
        )
        render_field("Home Tenant Name", log_data.get("HomeTenantName", "N/A"))
    st.markdown("</div>", unsafe_allow_html=True)

    # Location & Network Information
    st.markdown('<div class="detail-section">', unsafe_allow_html=True)
    st.markdown("#### 🌍 Location & Network Information")
    loc_col1, loc_col2, loc_col3 = st.columns(3)

    location_details = log_data.get("LocationDetails", {})
    geo = {}
    if isinstance(location_details, dict):
        geo = location_details.get("geoCoordinates", {})

    with loc_col1:
        render_field("IP Address", log_data.get("IPAddress", "N/A"))
        render_field("Location", log_data.get("Location", "N/A"))
        if isinstance(location_details, dict):
            render_field("City", location_details.get("city", "N/A"))
        else:
            render_field("City", "N/A")

    with loc_col2:
        if isinstance(location_details, dict):
            render_field("State", location_details.get("state", "N/A"))
            render_field("Country", location_details.get("countryOrRegion", "N/A"))
            if isinstance(geo, dict):
                render_field("Latitude", str(geo.get("latitude", "N/A")))
            else:
                render_field("Latitude", "N/A")
        else:
            render_field("State", "N/A")
            render_field("Country", "N/A")
            render_field("Latitude", "N/A")

    with loc_col3:
        if isinstance(location_details, dict) and isinstance(geo, dict):
            render_field("Longitude", str(geo.get("longitude", "N/A")))
        else:
            render_field("Longitude", "N/A")
        render_field(
            "Autonomous System Number",
            str(log_data.get("AutonomousSystemNumber", "N/A")),
        )
        render_field(
            "Global Secure Access IP",
            log_data.get("GlobalSecureAccessIpAddress", "N/A"),
        )
    st.markdown("</div>", unsafe_allow_html=True)

    # Authentication Details
    st.markdown('<div class="detail-section">', unsafe_allow_html=True)
    st.markdown("#### 🔐 Authentication Details")
    auth_col1, auth_col2 = st.columns(2)

    status = log_data.get("Status", {})
    with auth_col1:
        if isinstance(status, dict):
            render_field("Error Code", str(status.get("errorCode", "N/A")))
            render_textarea_field("Failure Reason", status.get("failureReason", "N/A"))
        else:
            render_field("Error Code", "N/A")
            render_textarea_field("Failure Reason", "N/A")
        render_textarea_field(
            "Result Description", log_data.get("ResultDescription", "N/A")
        )
        render_field(
            "Authentication Requirement",
            log_data.get("AuthenticationRequirement", "N/A"),
        )
        render_field(
            "Authentication Protocol", log_data.get("AuthenticationProtocol", "N/A")
        )

    with auth_col2:
        render_field(
            "Authentication Methods Used",
            str(log_data.get("AuthenticationMethodsUsed", "N/A")),
        )
        render_field(
            "Conditional Access Status", log_data.get("ConditionalAccessStatus", "N/A")
        )
        render_field(
            "Client Credential Type", log_data.get("ClientCredentialType", "N/A")
        )
        render_field("Incoming Token Type", log_data.get("IncomingTokenType", "N/A"))
        render_field(
            "Original Transfer Method", log_data.get("OriginalTransferMethod", "N/A")
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
                    render_field("Method", detail.get("authenticationMethod", "N/A"))
                    render_field(
                        "Method Detail", detail.get("authenticationMethodDetail", "N/A")
                    )
                    render_field("Succeeded", str(detail.get("succeeded", "N/A")))
                with det_col2:
                    render_field(
                        "DateTime", detail.get("authenticationStepDateTime", "N/A")
                    )
                    render_field(
                        "Result Detail",
                        detail.get("authenticationStepResultDetail", "N/A"),
                    )
                    render_field(
                        "Requirement",
                        detail.get("authenticationStepRequirement", "N/A"),
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
            render_field("Device ID", device_detail.get("deviceId", "N/A") or "N/A")
            render_field(
                "Operating System", device_detail.get("operatingSystem", "N/A")
            )
            render_field("Browser", device_detail.get("browser", "N/A"))
        else:
            render_field("Device ID", "N/A")
            render_field("Operating System", "N/A")
            render_field("Browser", "N/A")

    with device_col2:
        if isinstance(device_detail, dict):
            render_field(
                "Display Name", device_detail.get("displayName", "N/A") or "N/A"
            )
            render_field("Is Compliant", str(device_detail.get("isCompliant", "N/A")))
            render_field("Is Managed", str(device_detail.get("isManaged", "N/A")))
        else:
            render_field("Display Name", "N/A")
            render_field("Is Compliant", "N/A")
            render_field("Is Managed", "N/A")

    with device_col3:
        if isinstance(device_detail, dict):
            render_field("Trust Type", device_detail.get("trustType", "N/A") or "N/A")
            render_field(
                "Management Type", device_detail.get("managementType", "N/A") or "N/A"
            )
        else:
            render_field("Trust Type", "N/A")
            render_field("Management Type", "N/A")
        render_field("Client App Used", log_data.get("ClientAppUsed", "N/A"))

    render_textarea_field("User Agent", log_data.get("UserAgent", "N/A"))
    st.markdown("</div>", unsafe_allow_html=True)

    # Application Information
    st.markdown('<div class="detail-section">', unsafe_allow_html=True)
    st.markdown("#### 📦 Application Information")
    app_col1, app_col2 = st.columns(2)

    with app_col1:
        render_field("Application Name", log_data.get("AppDisplayName", "N/A"))
        render_field("Application ID", log_data.get("AppId", "N/A"))
        render_field(
            "Service Principal ID", log_data.get("ServicePrincipalId", "N/A") or "N/A"
        )
        render_field(
            "Service Principal Name",
            log_data.get("ServicePrincipalName", "N/A") or "N/A",
        )
        render_field("App Owner Tenant ID", log_data.get("AppOwnerTenantId", "N/A"))

    with app_col2:
        render_field(
            "Resource Display Name", log_data.get("ResourceDisplayName", "N/A")
        )
        render_field("Resource", log_data.get("Resource", "N/A"))
        render_field("Resource Identity", log_data.get("ResourceIdentity", "N/A"))
        render_field(
            "Resource Service Principal ID",
            log_data.get("ResourceServicePrincipalId", "N/A"),
        )
        render_field(
            "Resource Owner Tenant ID", log_data.get("ResourceOwnerTenantId", "N/A")
        )

    render_field("Resource ID", log_data.get("ResourceId", "N/A"))
    render_field("Resource Group", log_data.get("ResourceGroup", "N/A"))
    render_field(
        "Source App Client ID", log_data.get("SourceAppClientId", "N/A") or "N/A"
    )
    st.markdown("</div>", unsafe_allow_html=True)

    # Risk & Security Information
    st.markdown('<div class="detail-section">', unsafe_allow_html=True)
    st.markdown("#### ⚠️ Risk & Security Information")
    risk_col1, risk_col2, risk_col3 = st.columns(3)

    with risk_col1:
        render_field("Risk State", log_data.get("RiskState", "N/A"))
        render_field(
            "Risk Level Aggregated", log_data.get("RiskLevelAggregated", "N/A")
        )
        render_field(
            "Risk Level During Sign-in", log_data.get("RiskLevelDuringSignIn", "N/A")
        )
        render_field("Risk Detail", log_data.get("RiskDetail", "N/A"))

    with risk_col2:
        render_field("Is Risky", str(log_data.get("IsRisky", "N/A")))
        render_field("Flagged For Review", str(log_data.get("FlaggedForReview", "N/A")))
        render_field("Is Interactive", str(log_data.get("IsInteractive", "N/A")))
        render_field(
            "Is Tenant Restricted", str(log_data.get("IsTenantRestricted", "N/A"))
        )

    with risk_col3:
        render_field(
            "Cross Tenant Access Type", log_data.get("CrossTenantAccessType", "N/A")
        )
        render_field(
            "Is Through Global Secure Access",
            str(log_data.get("IsThroughGlobalSecureAccess", "N/A")),
        )
        token_protection = log_data.get("TokenProtectionStatusDetails", {})
        if isinstance(token_protection, dict):
            render_field(
                "Token Session Status",
                token_protection.get("signInSessionStatus", "N/A"),
            )
            render_field(
                "Token Session Status Code",
                str(token_protection.get("signInSessionStatusCode", "N/A")),
            )

    risk_events = log_data.get("RiskEventTypes_V2", [])
    if risk_events and isinstance(risk_events, list) and len(risk_events) > 0:
        render_textarea_field("Risk Event Types", ", ".join(risk_events))
    else:
        render_field("Risk Event Types", "None")
    st.markdown("</div>", unsafe_allow_html=True)

    # Session & Token Information
    st.markdown('<div class="detail-section">', unsafe_allow_html=True)
    st.markdown("#### 🎫 Session & Token Information")
    session_col1, session_col2, session_col3 = st.columns(3)

    with session_col1:
        render_field("Session ID", log_data.get("SessionId", "N/A") or "N/A")
        render_field(
            "Unique Token Identifier", log_data.get("UniqueTokenIdentifier", "N/A")
        )
        render_field(
            "Token Issuer Name", log_data.get("TokenIssuerName", "N/A") or "N/A"
        )

    with session_col2:
        render_field("Token Issuer Type", log_data.get("TokenIssuerType", "N/A"))
        render_field(
            "Federated Credential ID",
            log_data.get("FederatedCredentialId", "N/A") or "N/A",
        )

    with session_col3:
        session_policies = log_data.get("SessionLifetimePolicies", [])
        if (
            session_policies
            and isinstance(session_policies, list)
            and len(session_policies) > 0
        ):
            render_textarea_field("Session Lifetime Policies", str(session_policies))
        else:
            render_field("Session Lifetime Policies", "None")
    st.markdown("</div>", unsafe_allow_html=True)

    # Tenant & System Information
    st.markdown('<div class="detail-section">', unsafe_allow_html=True)
    st.markdown("#### 🏢 Tenant & System Information")
    tenant_col1, tenant_col2, tenant_col3 = st.columns(3)

    with tenant_col1:
        render_field("Tenant ID", log_data.get("TenantId", "N/A"))
        render_field("AAD Tenant ID", log_data.get("AADTenantId", "N/A"))
        render_field("Home Tenant ID", log_data.get("HomeTenantId", "N/A"))

    with tenant_col2:
        render_field("Resource Tenant ID", log_data.get("ResourceTenantId", "N/A"))
        render_field("Source System", log_data.get("SourceSystem", "N/A"))
        render_field(
            "Resource Provider", log_data.get("ResourceProvider", "N/A") or "N/A"
        )

    with tenant_col3:
        render_field("Category", log_data.get("Category", "N/A"))
        render_field("Operation Name", log_data.get("OperationName", "N/A"))
        render_field("Operation Version", log_data.get("OperationVersion", "N/A"))
    st.markdown("</div>", unsafe_allow_html=True)

    # Additional Technical Details
    st.markdown('<div class="detail-section">', unsafe_allow_html=True)
    st.markdown("#### 🔧 Technical Details")
    tech_col1, tech_col2, tech_col3 = st.columns(3)

    with tech_col1:
        render_field("Correlation ID", log_data.get("CorrelationId", "N/A"))
        render_field("Original Request ID", log_data.get("OriginalRequestId", "N/A"))
        render_field("Record ID", log_data.get("Id", "N/A"))

    with tech_col2:
        render_field(
            "Processing Time (ms)",
            str(log_data.get("ProcessingTimeInMilliseconds", "N/A")),
        )
        render_field("Duration (ms)", str(log_data.get("DurationMs", "N/A")))
        render_field("Level", log_data.get("Level", "N/A"))

    with tech_col3:
        render_field("Created DateTime", log_data.get("CreatedDateTime", "N/A"))
        render_field("Type", log_data.get("Type", "N/A"))
        render_field("xy_CF", log_data.get("xy_CF", "N/A") or "N/A")
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
                    render_field("Policy ID", policy.get("id", "N/A"))
                    render_field("Result", policy.get("result", "N/A"))
                with pol_col2:
                    render_field(
                        "Enforced Controls",
                        str(policy.get("enforcedGrantControls", [])),
                    )
                    render_field(
                        "Session Controls",
                        str(policy.get("enforcedSessionControls", [])),
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
        render_field("Agent Type", agent_info.get("agentType", "N/A"))
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
            render_textarea_field(
                "Authentication Context Class References", str(auth_context)
            )
        if auth_req_policies and len(auth_req_policies) > 0:
            render_textarea_field(
                "Authentication Requirement Policies", str(auth_req_policies)
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
    col1, col2 = st.columns([1, 1])

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
        if st.button(
            "🚀 Analyze in SOC Hub",
            key="analyze_soc_hub",
            type="primary",
            use_container_width=True,
        ):
            # Prepare alert data for SOC Hub
            alert_data = prepare_alert_from_log(log_data, error_info)
            st.session_state.soc_alert_data = alert_data
            st.session_state.current_page = "soc_analysis"
            st.session_state.show_soc_hub = True
            st.rerun()

    st.stop()
