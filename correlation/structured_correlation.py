import json
import os
import re
from dotenv import load_dotenv
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field
from crewai import Agent, Task, Crew, Process
from crewai.tools import BaseTool
import google.generativeai as genai
from langchain_google_genai import ChatGoogleGenerativeAI

import time
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)
from litellm.exceptions import RateLimitError


load_dotenv()

# ============================================================================
# STRUCTURED OUTPUT MODELS
# ============================================================================


@retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=4, max=60),
    retry=retry_if_exception_type(RateLimitError),
    before_sleep=lambda retry_state: print(
        f"⏳ Rate limit hit. Retrying in {retry_state.next_action.sleep} seconds..."
    ),
)
def run_crew_with_retry(crew):
    """Run crew with automatic retry on rate limit"""
    return crew.kickoff()


@retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=2, min=8, max=120),
    retry=retry_if_exception_type((RateLimitError, json.JSONDecodeError)),
    before_sleep=lambda retry_state: print(
        f"⏳ Retry attempt {retry_state.attempt_number}. Waiting {retry_state.next_action.sleep}s..."
    ),
)
def generate_with_retry(model, prompt):
    """Enhanced retry with JSON validation and increased token limit"""
    response = model.generate_content(
        prompt,
        generation_config=genai.types.GenerationConfig(
            max_output_tokens=8192,  # Increased from default
            temperature=0.1,
        ),
    )

    # Validate response is complete JSON before returning
    response_text = response.text.strip()

    # Remove markdown code blocks
    if response_text.startswith("```json"):
        response_text = response_text[7:]
    if response_text.startswith("```"):
        response_text = response_text[3:]
    if response_text.endswith("```"):
        response_text = response_text[:-3]

    response_text = response_text.strip()

    # Quick validation - will raise JSONDecodeError if invalid
    try:
        json.loads(response_text)
    except json.JSONDecodeError as e:
        print(f"⚠️ Response is not valid JSON at position {e.pos}: {e.msg}")
        print(f"Response length: {len(response_text)}")
        print(f"Last 200 chars: ...{response_text[-200:]}")
        raise

    return response


class UserDetails(BaseModel):
    """User information from the security event"""

    user_principal_name: str = Field(
        description="The user's UPN or email", default="Unknown"
    )
    user_id: str = Field(description="The unique user ID", default="Unknown")
    user_type: str = Field(description="Member or Guest", default="Unknown")
    user_display_name: Optional[str] = Field(
        default=None, description="User's display name"
    )


class LocationDetails(BaseModel):
    """Geographic and network location information"""

    city: str = Field(description="City of sign-in")
    state: Optional[str] = Field(default=None, description="State/region")
    country: str = Field(description="Country of sign-in")
    ip_address: str = Field(description="IP address used")
    isp: Optional[str] = Field(default=None, description="Internet Service Provider")


class AuthenticationDetails(BaseModel):
    """Authentication method and status"""

    authentication_method: str = Field(description="Method used for authentication")
    authentication_requirement: str = Field(description="MFA or single factor")
    mfa_detail: Optional[str] = Field(default=None, description="MFA method details")
    result_type: str = Field(description="Result code (0=success, other=failure)")
    result_description: str = Field(description="Human-readable result description")


class ApplicationDetails(BaseModel):
    """Application and resource being accessed"""

    app_display_name: str = Field(description="Application name")
    app_id: str = Field(description="Application ID")
    resource_display_name: Optional[str] = Field(
        default=None, description="Resource name"
    )
    resource_id: Optional[str] = Field(default=None, description="Resource ID")


class BehavioralFlags(BaseModel):
    """Behavioral analytics flags"""

    first_time_device: bool = Field(default=False)
    first_time_browser: bool = Field(default=False)
    first_time_app: bool = Field(default=False)
    first_time_resource: bool = Field(default=False)
    first_time_country: bool = Field(default=False)
    first_time_isp: bool = Field(default=False)
    first_time_app_in_tenant: bool = Field(default=False)
    uncommonly_used_browser: bool = Field(default=False)
    uncommonly_used_isp: bool = Field(default=False)
    app_uncommonly_used_among_peers: bool = Field(default=False)
    investigation_priority: Optional[int] = Field(default=None)
    action_type: Optional[str] = Field(default=None)


class CorrelationAnalysis(BaseModel):
    """AI-generated correlation and risk analysis"""

    threat_indicators: List[str] = Field(
        description="List of threat indicators found", max_length=10
    )
    behavioral_patterns: List[str] = Field(
        description="Notable behavioral patterns", max_length=10
    )
    risk_score: int = Field(description="Risk score from 1-10", ge=1, le=10)
    recommended_actions: List[str] = Field(
        description="Recommended actions", max_length=10
    )
    related_events: List[str] = Field(
        default=[], description="Related event IDs or patterns", max_length=10
    )
    attack_vector: Optional[str] = Field(
        default=None, description="Potential attack vector"
    )


class SecurityEvent(BaseModel):
    """Complete security event with correlation"""

    # Metadata
    event_id: str = Field(description="Unique event identifier (CorrelationId)")
    timestamp: str = Field(description="When the event occurred")
    severity: str = Field(description="HIGH, MEDIUM, or LOW")
    title: str = Field(description="Brief title summarizing the event")

    # Core Details
    user: UserDetails
    location: LocationDetails
    authentication: AuthenticationDetails
    application: ApplicationDetails
    behavioral_flags: BehavioralFlags

    # Analysis
    correlation_analysis: CorrelationAnalysis
    raw_event_summary: str = Field(description="Brief summary of raw event")


class SecurityCorrelationReport(BaseModel):
    """Complete correlation report with prioritized events"""

    report_metadata: dict = Field(description="Report generation metadata")
    high_priority_events: List[SecurityEvent] = Field(default=[])
    medium_priority_events: List[SecurityEvent] = Field(default=[])
    low_priority_events: List[SecurityEvent] = Field(default=[])
    summary_statistics: dict = Field(description="Overall statistics")
    executive_summary: str = Field(description="High-level summary for leadership")


# ============================================================================
# TOOLS
# ============================================================================


class LogAnalysisTool(BaseTool):
    name: str = "Log Analysis Tool"
    description: str = "Analyzes security log data and extracts structured information"

    def _run(self, log_data: dict) -> str:
        """Process log data and return formatted string for AI analysis"""
        return json.dumps(log_data, indent=2)


# ============================================================================
# CREWAI AGENTS AND TASKS
# ============================================================================


def create_security_analysts():
    """Create specialized security analyst agents"""
    from crewai import LLM

    # Configure Gemini LLM for all agents
    gemini_llm = LLM(
        model="gemini/gemini-2.5-flash",
        api_key=os.getenv("GOOGLE_API_KEY"),
        temperature=0.1,
        max_retries=5,
        timeout=300,
    )

    # Behavioral Analysis Agent
    behavioral_analyst = Agent(
        role="Behavioral Security Analyst",
        goal="Identify anomalous user behavior patterns and first-time activities",
        backstory="""You are an expert in behavioral analytics and user activity patterns.
        You excel at spotting unusual combinations of first-time activities that may indicate
        compromised accounts or insider threats. You understand the context of user behavior
        and can distinguish between legitimate new activities and suspicious patterns.""",
        verbose=False,
        allow_delegation=False,
        llm=gemini_llm,
    )

    # Authentication Security Agent
    auth_analyst = Agent(
        role="Authentication Security Specialist",
        goal="Analyze authentication events, MFA failures, and access patterns",
        backstory="""You are a specialist in authentication security and identity protection.
        You can quickly identify failed authentication attempts, weak authentication methods,
        and patterns that suggest credential compromise or brute force attacks. You understand
        the nuances of MFA, conditional access policies, and authentication flows.""",
        verbose=False,
        allow_delegation=False,
        llm=gemini_llm,
    )

    # Threat Intelligence Agent
    threat_analyst = Agent(
        role="Threat Intelligence Analyst",
        goal="Correlate multiple indicators to identify potential security incidents",
        backstory="""You are a seasoned threat intelligence analyst who connects the dots
        between seemingly unrelated events. You understand attack vectors, threat actor TTPs,
        and can assess risk levels based on multiple indicators. You provide actionable
        recommendations for security teams.""",
        verbose=False,
        allow_delegation=False,
        llm=gemini_llm,
    )

    return behavioral_analyst, auth_analyst, threat_analyst


def create_analysis_tasks(log_data: dict, agents: tuple):
    """Create analysis tasks for the agents"""
    behavioral_analyst, auth_analyst, threat_analyst = agents

    # Task 1: Behavioral Analysis
    behavioral_task = Task(
        description=f"""Analyze the following security log data and identify all behavioral anomalies:
        
        {json.dumps(log_data, indent=2)}
        
        Focus on:
        1. FirstTime activities (device, browser, app, resource, country, ISP)
        2. Uncommonly used attributes among peers
        3. Multiple simultaneous first-time behaviors
        4. Investigation priority flags
        
        For each anomalous event, extract:
        - User details (UPN, ID, type)
        - All behavioral flags
        - Timestamp and location
        - Context of the activity
        """,
        agent=behavioral_analyst,
        expected_output="Detailed list of behavioral anomalies with full context",
    )

    # Task 2: Authentication Analysis
    auth_task = Task(
        description=f"""Analyze authentication events from the log data:
        
        {json.dumps(log_data, indent=2)}
        
        Focus on:
        1. Failed authentication attempts (ResultType != 0)
        2. MFA failures or challenges
        3. Authentication method patterns
        4. Session-related errors
        5. Conditional access policy evaluations
        
        For each security-relevant event, extract:
        - Authentication details (method, requirement, result)
        - MFA status and details
        - Result codes and descriptions
        - IP address and application accessed
        """,
        agent=auth_analyst,
        expected_output="Comprehensive authentication security assessment",
    )

    # Task 3: Threat Correlation and Risk Scoring
    correlation_task = Task(
        description=f"""Based on the behavioral and authentication analysis, perform threat correlation:
        
        Original Log Data:
        {json.dumps(log_data, indent=2)}
        
        Your task:
        1. Correlate findings from behavioral and authentication analysis
        2. Identify high-risk events (multiple indicators + failed auth)
        3. Score each event's risk level (1-10)
        4. Determine severity (HIGH/MEDIUM/LOW)
        5. Identify potential attack vectors
        6. Provide specific recommended actions
        
        Prioritize events with:
        - Failed MFA + multiple FirstTime flags = HIGH severity
        - Multiple FirstTime flags + successful auth = MEDIUM severity
        - Single anomaly or routine errors = LOW severity
        
        Create a structured report with all events categorized by severity.
        Keep your output concise and focused on the most critical findings.
        """,
        agent=threat_analyst,
        expected_output="Complete security correlation report with risk scores and recommendations",
        context=[behavioral_task, auth_task],
    )

    return [behavioral_task, auth_task, correlation_task]


# ============================================================================
# MAIN PROCESSING FUNCTIONS
# ============================================================================


def load_json(json_file_path: str) -> Optional[dict]:
    """Load JSON log file"""
    if not os.path.exists(json_file_path):
        print(f"❌ File not found: {json_file_path}")
        return None

    with open(json_file_path, "r") as file:
        content = file.read()
        if not content.strip():
            print(f"❌ File is empty: {json_file_path}")
            return None
        return json.loads(content)


def clean_event(event):
    """Clean a single event to ensure valid types"""
    # Ensure all required nested structures exist
    if "location" not in event:
        event["location"] = {}
    if "authentication" not in event:
        event["authentication"] = {}
    if "user" not in event:
        event["user"] = {}
    if "application" not in event:
        event["application"] = {}
    if "behavioral_flags" not in event:
        event["behavioral_flags"] = {}
    if "correlation_analysis" not in event:
        event["correlation_analysis"] = {}

    # Fix user fields
    user = event.get("user", {})
    if user.get("user_type") is None or user.get("user_type") == "":
        user["user_type"] = "Unknown"
    if user.get("user_principal_name") is None:
        user["user_principal_name"] = "Unknown"
    if user.get("user_id") is None:
        user["user_id"] = "Unknown"

    # Fix location fields
    location = event.get("location", {})
    if location.get("country") is None or location.get("country") == "":
        location["country"] = "Unknown"
    if location.get("city") is None or location.get("city") == "":
        location["city"] = "Unknown"
    if location.get("ip_address") is None:
        location["ip_address"] = "Unknown"

    # Fix authentication fields
    auth = event.get("authentication", {})
    if auth.get("authentication_method") is None:
        auth["authentication_method"] = "Unknown"
    if auth.get("authentication_requirement") is None:
        auth["authentication_requirement"] = "Unknown"
    if isinstance(auth.get("mfa_detail"), dict):
        auth["mfa_detail"] = None
    if auth.get("result_type") is None:
        auth["result_type"] = "Unknown"
    if auth.get("result_description") is None:
        auth["result_description"] = "Not Available"

    # Fix application fields
    app = event.get("application", {})
    if app.get("app_display_name") is None:
        app["app_display_name"] = "Unknown"
    if app.get("app_id") is None:
        app["app_id"] = "Unknown"

    # Fix event metadata fields
    if event.get("event_id") is None:
        event["event_id"] = "Unknown"
    if event.get("timestamp") is None:
        event["timestamp"] = datetime.now().isoformat()
    if event.get("severity") is None:
        event["severity"] = "LOW"
    if event.get("title") is None:
        event["title"] = "Untitled Event"
    if event.get("raw_event_summary") is None:
        event["raw_event_summary"] = "No summary available"

    # Ensure all required correlation_analysis fields exist
    corr = event.get("correlation_analysis", {})
    if "threat_indicators" not in corr or not isinstance(
        corr["threat_indicators"], list
    ):
        corr["threat_indicators"] = []
    if "behavioral_patterns" not in corr or not isinstance(
        corr["behavioral_patterns"], list
    ):
        corr["behavioral_patterns"] = []
    if "risk_score" not in corr:
        corr["risk_score"] = 1
    if "recommended_actions" not in corr or not isinstance(
        corr["recommended_actions"], list
    ):
        corr["recommended_actions"] = []
    if "related_events" not in corr or not isinstance(corr["related_events"], list):
        corr["related_events"] = []

    # Limit array sizes
    corr["threat_indicators"] = corr["threat_indicators"][:10]
    corr["behavioral_patterns"] = corr["behavioral_patterns"][:10]
    corr["recommended_actions"] = corr["recommended_actions"][:10]
    corr["related_events"] = corr["related_events"][:10]

    return event


def parse_events_from_crew_output(
    crew_output: str, log_data: dict
) -> SecurityCorrelationReport:
    """
    Parse the crew output and structure it into SecurityEvent objects.
    OPTIMIZED VERSION: Reduced prompt size and increased token limits.
    """
    genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
    model = genai.GenerativeModel("gemini-2.0-flash-exp")

    # Extract only essential log context (not full logs)
    log_summary = {
        "total_events": len(log_data.get("SigninLogs", [])),
        "sample_event_ids": [
            log.get("CorrelationId") for log in log_data.get("SigninLogs", [])[:20]
        ],
    }

    # Truncate crew output to prevent token overflow
    max_crew_output_length = 12000
    truncated_crew_output = crew_output[:max_crew_output_length]
    if len(crew_output) > max_crew_output_length:
        print(
            f"⚠️ Crew output truncated from {len(crew_output)} to {max_crew_output_length} chars"
        )

    structured_prompt = f"""You are a security data extraction specialist. Output ONLY valid, complete JSON.

Extract security events from the analysis below and structure them into JSON.

CRITICAL RULES:
1. Output MUST be valid, complete JSON - no truncation
2. ALL strings must be properly terminated and escaped
3. LIMIT to max 8 events per priority level (high/medium/low)
4. Keep all descriptions under 150 characters
5. Keep all arrays under 8 items each
6. Use "Unknown" for missing required string fields, null for optional fields
7. Ensure ALL brackets and braces are closed
8. NO trailing commas
9. Double-check the last event in each array is properly closed

JSON SCHEMA:
{{
  "high_priority_events": [ /* max 8 events */ ],
  "medium_priority_events": [ /* max 8 events */ ],
  "low_priority_events": [ /* max 8 events */ ],
  "executive_summary": "Brief summary under 400 chars"
}}

Each event needs: event_id, timestamp, severity, title, user (user_principal_name, user_id, user_type, user_display_name), location (city, state, country, ip_address, isp), authentication (authentication_method, authentication_requirement, mfa_detail, result_type, result_description), application (app_display_name, app_id, resource_display_name, resource_id), behavioral_flags (booleans for first_time_* and uncommonly_used_*, investigation_priority, action_type), correlation_analysis (threat_indicators array, behavioral_patterns array, risk_score 1-10, recommended_actions array, related_events array, attack_vector), raw_event_summary

ANALYSIS OUTPUT:
{truncated_crew_output}

LOG CONTEXT:
Total events analyzed: {log_summary['total_events']}
Sample event IDs: {', '.join(log_summary['sample_event_ids'][:10])}

IMPORTANT: Return ONLY the JSON object. Ensure it is complete and valid. Double-check the closing braces.
"""

    try:
        print("🔄 Generating structured output from Gemini...")
        response = generate_with_retry(model, structured_prompt)
        response_text = response.text.strip()

        # Enhanced JSON cleaning
        def clean_json_string(json_str: str) -> str:
            """Clean JSON string and fix common issues"""
            # Remove markdown code blocks
            if json_str.startswith("```json"):
                json_str = json_str[7:]
            if json_str.startswith("```"):
                json_str = json_str[3:]
            if json_str.endswith("```"):
                json_str = json_str[:-3]

            json_str = json_str.strip()

            # Remove trailing commas before closing brackets
            json_str = re.sub(r",\s*}", "}", json_str)
            json_str = re.sub(r",\s*]", "]", json_str)

            return json_str

        cleaned_response = clean_json_string(response_text)

        # Save for debugging
        with open("debug_cleaned_response.json", "w", encoding="utf-8") as f:
            f.write(cleaned_response)
        print("💾 Cleaned response saved to 'debug_cleaned_response.json'")

        # Parse JSON
        parsed_data = json.loads(cleaned_response)

        # Clean all events
        for priority in [
            "high_priority_events",
            "medium_priority_events",
            "low_priority_events",
        ]:
            if priority in parsed_data:
                parsed_data[priority] = [
                    clean_event(event) for event in parsed_data[priority]
                ]
            else:
                parsed_data[priority] = []

        # Build final report
        report_data = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "log_file": "sentinel_user_data.json",
                "analysis_engine": "CrewAI + Gemini 2.0 Flash (Optimized)",
                "total_events_analyzed": len(log_data.get("SigninLogs", [])),
            },
            "summary_statistics": {
                "high_priority_count": len(parsed_data.get("high_priority_events", [])),
                "medium_priority_count": len(
                    parsed_data.get("medium_priority_events", [])
                ),
                "low_priority_count": len(parsed_data.get("low_priority_events", [])),
            },
            **parsed_data,
        }

        print("✅ Successfully parsed structured output")
        return SecurityCorrelationReport(**report_data)

    except json.JSONDecodeError as e:
        print(f"❌ JSON parsing error: {e}")
        print(f"Error at position {e.pos}: {e.msg}")
        print(f"Response length: {len(response_text)}")
        print(f"First 300 chars: {response_text[:300]}...")
        print(f"Last 300 chars: ...{response_text[-300:]}")

        # Save for debugging
        with open("debug_failed_response.txt", "w", encoding="utf-8") as f:
            f.write(response_text)
        print("💾 Failed response saved to 'debug_failed_response.txt'")

        raise

    except Exception as e:
        print(f"❌ Error creating report: {e}")
        if "parsed_data" in locals():
            print(f"Parsed data keys: {list(parsed_data.keys())}")
        raise


def generate_markdown_report(report: SecurityCorrelationReport, output_path: str):
    """Generate beautiful markdown report from structured data"""

    md_content = f"""# 🔒 Security Correlation Analysis Report

**Generated:** {report.report_metadata['generated_at']}  
**Analysis Engine:** {report.report_metadata['analysis_engine']}  
**Total Events Analyzed:** {report.report_metadata['total_events_analyzed']}

---

## 📊 Executive Summary

{report.executive_summary}

---

## 📈 Summary Statistics

- 🔴 **High Priority Events:** {report.summary_statistics['high_priority_count']}
- 🟡 **Medium Priority Events:** {report.summary_statistics['medium_priority_count']}
- 🟢 **Low Priority Events:** {report.summary_statistics['low_priority_count']}

---

"""

    # Helper function to format events
    def format_event_section(events: List[SecurityEvent], emoji: str):
        if not events:
            return ""

        section = ""
        for idx, event in enumerate(events, 1):
            section += f"""### {emoji} Event {idx}: {event.title}

**Event ID:** `{event.event_id}`  
**Timestamp:** `{event.timestamp}`  
**Risk Score:** {event.correlation_analysis.risk_score}/10

#### 👤 User Information
- **User:** {event.user.user_principal_name}
- **User ID:** `{event.user.user_id}`
- **Type:** {event.user.user_type}
- **Display Name:** {event.user.user_display_name or 'N/A'}

#### 📍 Location & Network
- **Location:** {event.location.city}, {event.location.country}
- **IP Address:** `{event.location.ip_address}`
- **ISP:** {event.location.isp or 'N/A'}

#### 🔐 Authentication Details
- **Method:** {event.authentication.authentication_method}
- **Requirement:** {event.authentication.authentication_requirement}
- **MFA Detail:** {event.authentication.mfa_detail or 'N/A'}
- **Result Code:** `{event.authentication.result_type}`
- **Result:** {event.authentication.result_description}

#### 💻 Application & Resource
- **Application:** {event.application.app_display_name}
- **App ID:** `{event.application.app_id}`
- **Resource:** {event.application.resource_display_name or 'N/A'}

#### 🎯 Behavioral Flags
- First Time Device: {'✅' if event.behavioral_flags.first_time_device else '❌'}
- First Time Browser: {'✅' if event.behavioral_flags.first_time_browser else '❌'}
- First Time App: {'✅' if event.behavioral_flags.first_time_app else '❌'}
- First Time Resource: {'✅' if event.behavioral_flags.first_time_resource else '❌'}
- First Time Country: {'✅' if event.behavioral_flags.first_time_country else '❌'}
- First Time ISP: {'✅' if event.behavioral_flags.first_time_isp else '❌'}
- Uncommonly Used Browser: {'✅' if event.behavioral_flags.uncommonly_used_browser else '❌'}
- Investigation Priority: {event.behavioral_flags.investigation_priority or 'N/A'}

#### 🔍 Correlation Analysis

**Threat Indicators:**
{chr(10).join(f'- {indicator}' for indicator in event.correlation_analysis.threat_indicators)}

**Behavioral Patterns:**
{chr(10).join(f'- {pattern}' for pattern in event.correlation_analysis.behavioral_patterns)}

**Attack Vector:** {event.correlation_analysis.attack_vector or 'Not identified'}

**Recommended Actions:**
{chr(10).join(f'{i}. {action}' for i, action in enumerate(event.correlation_analysis.recommended_actions, 1))}

**Related Events:** {', '.join(event.correlation_analysis.related_events) if event.correlation_analysis.related_events else 'None identified'}

**Raw Event Summary:** {event.raw_event_summary}

---

"""
        return section

    # Add high priority events
    if report.high_priority_events:
        md_content += "## 🔴 HIGH PRIORITY EVENTS (Immediate Action Required)\n\n"
        md_content += format_event_section(report.high_priority_events, "🚨")

    # Add medium priority events
    if report.medium_priority_events:
        md_content += "## 🟡 MEDIUM PRIORITY EVENTS (Investigation Recommended)\n\n"
        md_content += format_event_section(report.medium_priority_events, "⚠️")

    # Add low priority events
    if report.low_priority_events:
        md_content += "## 🟢 LOW PRIORITY EVENTS (Informational)\n\n"
        md_content += format_event_section(report.low_priority_events, "ℹ️")

    # Add footer
    md_content += """
---

## 📝 Notes

This report was generated using AI-powered security correlation analysis. All events have been 
analyzed for behavioral anomalies, authentication patterns, and threat indicators. Please review 
high-priority events immediately and validate medium-priority events with the respective users.

**Report Generated By:** Advanced Security Correlation Engine v2.0 (Optimized)
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    print(f"✅ Markdown report saved to {output_path}")


def main():
    """Main execution function"""
    print("🚀 Starting Advanced Security Correlation Engine (OPTIMIZED)\n")

    # Find sentinel_logs directory
    sentinel_logs_dir = "sentinel_logs"
    if not os.path.exists(sentinel_logs_dir):
        print(f"❌ Directory not found: {sentinel_logs_dir}")
        return

    # Get all subdirectories (time intervals)
    subdirs = [
        d
        for d in os.listdir(sentinel_logs_dir)
        if os.path.isdir(os.path.join(sentinel_logs_dir, d))
    ]

    if not subdirs:
        print(f"❌ No subdirectories found in {sentinel_logs_dir}")
        return

    print(f"📁 Found {len(subdirs)} time intervals to process\n")

    # Create agents once
    print("🤖 Initializing security analyst agents...")
    agents = create_security_analysts()

    # Process each subdirectory
    for subdir in sorted(subdirs):
        subdir_path = os.path.join(sentinel_logs_dir, subdir)
        print(f"\n{'='*70}")
        print(f"📂 Processing interval: {subdir}")
        print(f"{'='*70}\n")

        # Find sentinel_user_data_*.json files
        user_data_files = [
            f
            for f in os.listdir(subdir_path)
            if f.startswith("sentinel_user_data_") and f.endswith(".json")
        ]

        if not user_data_files:
            print(f"⚠️ No sentinel_user_data_*.json files found in {subdir_path}")
            continue

        for json_file in user_data_files:
            json_path = os.path.join(subdir_path, json_file)
            print(f"📄 Processing: {json_file}")

            # Load log data
            log_data = load_json(json_path)
            if not log_data:
                continue

            print(f"✅ Loaded {len(log_data.get('SigninLogs', []))} sign-in events\n")

            # Create tasks
            print("📋 Creating analysis tasks...")
            tasks = create_analysis_tasks(log_data, agents)

            # Create and run crew
            print("🔄 Running correlation analysis...\n")
            crew = Crew(
                agents=list(agents),
                tasks=tasks,
                process=Process.sequential,
                verbose=False,
            )

            result = run_crew_with_retry(crew)
            print("\n✅ Analysis complete!\n")

            # Generate output filenames in same directory
            base_name = json_file.replace("sentinel_user_data_", "").replace(
                ".json", ""
            )
            md_output_path = os.path.join(
                subdir_path, f"structured_correlation_report_{base_name}.md"
            )
            json_output_path = os.path.join(
                subdir_path, f"structured_correlation_report_{base_name}.json"
            )
            fallback_md_path = os.path.join(
                subdir_path, f"crew_raw_output_{base_name}.md"
            )

            # Parse results into structured format
            print("📊 Structuring results...")
            try:
                structured_report = parse_events_from_crew_output(str(result), log_data)

                # Save structured JSON
                with open(json_output_path, "w", encoding="utf-8") as f:
                    json.dump(structured_report.model_dump(), f, indent=2)
                print(f"✅ Structured JSON saved to {json_output_path}")

                # Generate markdown report
                print("📝 Generating markdown report...")
                generate_markdown_report(structured_report, md_output_path)

                # Print summary
                print("\n" + "=" * 60)
                print("📊 ANALYSIS SUMMARY")
                print("=" * 60)
                print(
                    f"🔴 High Priority Events: {len(structured_report.high_priority_events)}"
                )
                print(
                    f"🟡 Medium Priority Events: {len(structured_report.medium_priority_events)}"
                )
                print(
                    f"🟢 Low Priority Events: {len(structured_report.low_priority_events)}"
                )
                print("=" * 60)
                print(f"\n📄 Reports generated:")
                print(f"   - Markdown: {md_output_path}")
                print(f"   - JSON: {json_output_path}")

            except Exception as e:
                print(f"\n⚠️ Failed to create structured report: {e}")
                print(f"💾 Saving raw crew output as fallback...")

                fallback_content = f"""# 🔒 Security Correlation Analysis Report (Raw Output)

**Generated:** {datetime.now().isoformat()}  
**Status:** ⚠️ Fallback Mode - Structured parsing failed  
**Analysis Engine:** CrewAI + Gemini 2.0 Flash

---

## ⚠️ Notice

This report contains the raw output from the security analysis crew. 
The structured JSON parsing failed due to data validation errors.

**Error Details:**
```
{str(e)}
```

---

## 📊 Raw Analysis Output

{str(result)}

---

## 📝 Next Steps

1. Review the raw analysis output above
2. Manual triage of identified events
3. Check the Pydantic validation errors and adjust data cleaning logic
4. Re-run the analysis after fixing data issues

**Report Generated By:** Advanced Security Correlation Engine v2.0 (Fallback Mode)
"""

                with open(fallback_md_path, "w", encoding="utf-8") as f:
                    f.write(fallback_content)

                print(f"✅ Raw output saved to {fallback_md_path}")

    print("\n" + "=" * 70)
    print("🎉 All intervals processed successfully!")
    print("=" * 70)


if __name__ == "__main__":
    main()
