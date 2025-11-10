import json
import os
import re
import time
from threading import Lock
from dotenv import load_dotenv
from typing import List, Optional, Dict, Tuple
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
from collections import defaultdict
import numpy as np
import google.generativeai as genai



os.environ["CREWAI_TELEMETRY"] = "false"
load_dotenv()


class RateLimiter:
    """
    Rate limiter for Gemini API calls
    Implements token bucket algorithm with request tracking
    """
    
    def __init__(self, requests_per_minute=15, requests_per_day=1500):
        """
        Initialize rate limiter
        
        Args:
            requests_per_minute: Max requests per minute (Gemini free tier: 15 RPM)
            requests_per_day: Max requests per day (Gemini free tier: 1500 RPD)
        """
        self.requests_per_minute = requests_per_minute
        self.requests_per_day = requests_per_day
        
        
        # Track recent requests (timestamp of each request)
        from collections import deque
        self.minute_requests = deque()
        self.day_requests = deque()
        
        # Thread-safe lock
        self.lock = Lock()
        
        # Tracking
        self.total_requests = 0
        self.total_wait_time = 0
        self.rate_limit_exceeded = False  # Flag to switch to fallback
        
    def wait_if_needed(self):
        """
        Check rate limits and wait if necessary
        Returns the time waited in seconds
        """
        if self.rate_limit_exceeded:
            return 0  # Skip waiting if we've already exceeded limits
            
        with self.lock:
            current_time = time.time()
            wait_time = 0
            
            # Clean up old requests (older than 1 minute)
            while self.minute_requests and current_time - self.minute_requests[0] > 60:
                self.minute_requests.popleft()
            
            # Clean up old requests (older than 24 hours)
            while self.day_requests and current_time - self.day_requests[0] > 86400:
                self.day_requests.popleft()
            
            # Check per-minute limit - with conservative buffer
            if len(self.minute_requests) >= self.requests_per_minute - 2:  # Leave 2 request buffer
                # Need to wait until oldest request is 60 seconds old
                oldest_request = self.minute_requests[0]
                wait_time = 60 - (current_time - oldest_request) + 2  # Add 2s buffer
                
                if wait_time > 0:
                    print(f"   ⏳ Rate limit: Waiting {wait_time:.1f}s (RPM limit)")
                    time.sleep(wait_time)
                    current_time = time.time()
                    self.total_wait_time += wait_time
            
            # Check per-day limit
            if len(self.day_requests) >= self.requests_per_day:
                # Mark as exceeded and stop using Gemini
                self.rate_limit_exceeded = True
                print(f"   ⚠️ Daily quota reached. Switching to fallback for remaining requests.")
                return 0
            
            # Record this request
            self.minute_requests.append(current_time)
            self.day_requests.append(current_time)
            self.total_requests += 1
            
            return wait_time
    
    def get_stats(self):
        """Get rate limiter statistics"""
        with self.lock:
            return {
                "total_requests": self.total_requests,
                "total_wait_time": self.total_wait_time,
                "requests_last_minute": len(self.minute_requests),
                "requests_today": len(self.day_requests),
                "rpm_limit": self.requests_per_minute,
                "rpd_limit": self.requests_per_day,
                "rate_limit_exceeded": self.rate_limit_exceeded
            }

# Configure Gemini API with rate limiting
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_CHAT", "llama2")

gemini_rate_limiter = RateLimiter(
    requests_per_minute=15,  # Free tier: 15, Paid tier: 1000
    requests_per_day=1500    # Free tier: 1500, Paid tier: 50000
)

# Try to configure Gemini
gemini_model = None
if GOOGLE_API_KEY:
    try:
        genai.configure(api_key=GOOGLE_API_KEY)
        gemini_model = genai.GenerativeModel('gemini-2.0-flash-exp')
        print("✅ Gemini API configured with rate limiting (15 RPM, 1500 RPD)")
    except Exception as e:
        print(f"⚠️ Failed to configure Gemini: {e}")
        gemini_model = None

# Check if Ollama is available
ollama_available = False
try:
    import requests
    response = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=2)
    if response.status_code == 200:
        ollama_available = True
        print(f"✅ Ollama available at {OLLAMA_BASE_URL} (model: {OLLAMA_MODEL})")
except:
    ollama_available = False

if not gemini_model and not ollama_available:
    print("⚠️ Warning: Neither Gemini nor Ollama configured. Alert descriptions will use fallback mode.")

# ============================================================================
# ENHANCED USER GROUPING & CORRELATION MODELS
# ============================================================================


class EventDetails(BaseModel):
    """Complete event with all available data"""

    event_id: str
    timestamp: str
    user_principal_name: str
    user_id: str
    user_display_name: str
    user_type: str

    # Enhanced authentication tracking
    authentication_method: str
    authentication_requirement: str
    result_type: str
    result_signature: str
    result_description: str

    # Location
    ip_address: str
    location_city: Optional[str]
    location_state: Optional[str]
    location_country: str

    # Application
    app_display_name: str
    app_id: str
    resource_display_name: Optional[str]

    # Device
    operating_system: Optional[str]
    browser: Optional[str]

    # Classification
    is_success: bool
    failure_reason: Optional[str]


class EventCluster(BaseModel):
    """Group of related events based on time proximity"""

    cluster_id: str
    events: List[EventDetails]
    start_time: str
    end_time: str
    duration_seconds: int
    event_count: int
    unique_apps: int
    unique_locations: int
    has_failures: bool
    failure_count: int


class UserActivityGroup(BaseModel):
    """All activities for a single user grouped by clusters"""

    user_principal_name: str
    user_id: str
    user_display_name: str
    user_type: str
    total_events: int

    # Cluster analysis
    total_clusters: int
    clusters: List[Dict]

    # Location analysis
    locations: List[Dict]
    unique_locations: int

    # Application analysis
    applications: List[Dict]
    unique_apps: int

    # Authentication analysis
    authentication_summary: Dict

    # Failure analysis
    failure_analysis: Dict

    # Risk assessment
    behavioral_anomalies: List[str]
    risk_score: int
    risk_factors: List[str]

    # Timeline
    timeline: List[Dict]


# ============================================================================
# DATA EXTRACTION - IMPROVED VERSION WITH UNKNOWN DATA HANDLING
# ============================================================================


def safe_get(data: dict, key: str, default="Unknown") -> str:
    """Safely extract data with proper Unknown handling"""
    value = data.get(key, default)
    
    # Handle various empty cases
    if value is None or value == "" or value == {} or value == []:
        return default
    
    # Handle nested empty strings in dicts
    if isinstance(value, dict) and not any(v for v in value.values() if v):
        return default
        
    return str(value) if value != default else default


def extract_failure_reason(signin_log: dict) -> Tuple[bool, Optional[str]]:
    """Extract failure reason from multiple possible fields - FIXED"""
    
    result_type = safe_get(signin_log, "ResultType", "Unknown")
    is_success = result_type == "0"
    failure_reason = None

    if not is_success:
        # Primary source: ResultDescription - NOW PROPERLY EXTRACTED
        result_desc = safe_get(signin_log, "ResultDescription", "")
        
        if result_desc and result_desc != "Unknown" and result_desc.strip():
            failure_reason = result_desc.strip()
        else:
            # Fallback: ActionType
            action_type = safe_get(signin_log, "ActionType", "")
            if action_type and action_type != "Unknown" and action_type.strip():
                failure_reason = action_type.strip()
            else:
                # Fallback: ResultSignature
                result_sig = safe_get(signin_log, "ResultSignature", "")
                if result_sig and result_sig != "Unknown":
                    failure_reason = f"Error: {result_sig}"
                else:
                    failure_reason = f"Authentication failure (Code: {result_type})"

    return is_success, failure_reason


def extract_authentication_method(signin_log: dict) -> str:
    """Extract authentication method with better fallback handling"""
    
    auth_details = signin_log.get("AuthenticationDetails", [])
    
    if auth_details and isinstance(auth_details, list):
        for detail in auth_details:
            if isinstance(detail, dict):
                method = detail.get("authenticationMethod", "")
                if method and method not in ["Unknown", "", "Previously satisfied"]:
                    return method
                elif method == "Previously satisfied":
                    # Look for the actual method in detail
                    actual_method = detail.get("authenticationMethodDetail", "")
                    if actual_method and actual_method != "Unknown":
                        return f"Previously satisfied ({actual_method})"
    
    # Fallback to AuthenticationMethodsUsed
    auth_methods_used = signin_log.get("AuthenticationMethodsUsed", "")
    if auth_methods_used and auth_methods_used != "":
        return auth_methods_used
    
    return "Single Sign-On"


def extract_complete_event_data(signin_log: dict) -> EventDetails:
    """Extract all available data from a sign-in log entry - FIXED"""

    auth_method = extract_authentication_method(signin_log)

    location_details = signin_log.get("LocationDetails", {})
    device_detail = signin_log.get("DeviceDetail", {})

    is_success, failure_reason = extract_failure_reason(signin_log)

    # Extract location with proper fallback
    city = safe_get(location_details, "city", None)
    state = safe_get(location_details, "state", None)
    country = safe_get(location_details, "countryOrRegion", "Unknown")

    # Extract device info
    os_info = safe_get(device_detail, "operatingSystem", None)
    browser_info = safe_get(device_detail, "browser", None)

    return EventDetails(
        event_id=safe_get(signin_log, "Id", safe_get(signin_log, "CorrelationId", "Unknown")),
        timestamp=safe_get(signin_log, "TimeGenerated", safe_get(signin_log, "CreatedDateTime", "Unknown")),
        user_principal_name=safe_get(signin_log, "UserPrincipalName", "Unknown"),
        user_id=safe_get(signin_log, "UserId", "Unknown"),
        user_display_name=safe_get(signin_log, "UserDisplayName", safe_get(signin_log, "Identity", "Unknown")),
        user_type=safe_get(signin_log, "UserType", "Unknown"),
        authentication_method=auth_method,
        authentication_requirement=safe_get(signin_log, "AuthenticationRequirement", "Unknown"),
        result_type=safe_get(signin_log, "ResultType", "Unknown"),
        result_signature=safe_get(signin_log, "ResultSignature", "Unknown"),
        result_description=failure_reason if not is_success else "Success",
        ip_address=safe_get(signin_log, "IPAddress", "Unknown"),
        location_city=city,
        location_state=state,
        location_country=country,
        app_display_name=safe_get(signin_log, "AppDisplayName", "Unknown"),
        app_id=safe_get(signin_log, "AppId", "Unknown"),
        resource_display_name=safe_get(signin_log, "ResourceDisplayName", None),
        operating_system=os_info,
        browser=browser_info,
        is_success=is_success,
        failure_reason=failure_reason if not is_success else None,
    )


# ============================================================================
# INTELLIGENT TIME GAP ANALYSIS - USING OUTLIER DETECTION
# ============================================================================

def generate_alert_description_with_llm(group: "UserActivityGroup", max_retries: int = 3) -> str:
    """
    Generate a detailed, easy-to-understand alert description using LLM
    Tries Gemini with retries, falls back to Ollama, then to template-based fallback

    Args:
        group: UserActivityGroup object with all activity details
        max_retries: Maximum number of retry attempts for Gemini (default: 3)

    Returns:
        2-3 sentence alert description in plain language
    """

    # Check if we should skip Gemini due to daily quota exhaustion
    if gemini_model and not gemini_rate_limiter.rate_limit_exceeded:
        retry_count = 0
        last_error = None
        
        while retry_count < max_retries:
            try:
                # Apply rate limiting
                wait_time = gemini_rate_limiter.wait_if_needed()
                
                # Check if rate limit was exceeded during wait
                if gemini_rate_limiter.rate_limit_exceeded:
                    print(f"   ⚠️ Gemini daily quota exhausted, switching to {'Ollama' if ollama_available else 'fallback'}")
                    break
                
                # Show retry attempt if this is a retry
                if retry_count > 0:
                    print(f"   🔄 Retry attempt {retry_count}/{max_retries} for Gemini API...")

                # Prepare context for LLM
                context = f"""You are a security analyst explaining a potential security incident to a non-technical manager. 
Generate a clear, concise 2-3 sentence description that explains what happened and why it's concerning.

USER DETAILS:
- Name: {group.user_display_name}
- Email: {group.user_principal_name}
- User Type: {group.user_type}
- Total Events: {group.total_events}
- Risk Score: {group.risk_score}/10

SECURITY FINDINGS:
- Risk Factors: {', '.join(group.risk_factors[:5]) if group.risk_factors else 'None detected'}
- Total Failures: {group.failure_analysis.get('total_failures', 0)}
- Success Rate: {group.failure_analysis.get('success_rate', 100)}%
- Critical Failures: {group.failure_analysis.get('critical_failures', 0)}
- Unique Locations: {group.unique_locations}
- Applications Accessed: {group.unique_apps}
- Activity Clusters: {group.total_clusters}

FAILURE DETAILS:
{', '.join([f"{f['reason']} ({f['count']}x)" for f in group.failure_analysis.get('failure_reasons', [])[:3]])}

BEHAVIORAL ANOMALIES:
{', '.join(group.behavioral_anomalies[:3]) if group.behavioral_anomalies else 'None detected'}

Generate a 2-3 sentence description that:
1. Explains what unusual activity was detected
2. Mentions the key risk factors (failures, locations, or behavior)
3. Uses simple, non-technical language
4. Does NOT use bullet points or lists
5. Focuses on the most concerning aspects"""

                # Generate description using Gemini
                response = gemini_model.generate_content(
                    context,
                    generation_config=genai.types.GenerationConfig(
                        temperature=0.3,
                        max_output_tokens=150,
                    ),
                )

                description = response.text.strip()

                # Basic validation
                if len(description) >= 50 and len(description) <= 500:
                    # Success! Return the description
                    if retry_count > 0:
                        print(f"   ✅ Gemini API succeeded after {retry_count} retries")
                    return description
                else:
                    # Invalid response, but not an API error - don't retry
                    print(f"   ⚠️ Gemini returned invalid response (length: {len(description)}), using fallback")
                    break

            except Exception as e:
                last_error = e
                error_msg = str(e).lower()
                
                # Check for PERMANENT errors that shouldn't be retried
                if "429" in error_msg or "quota" in error_msg or "resource_exhausted" in error_msg:
                    print(f"   ⚠️ Gemini quota/rate limit hit. Marking as exhausted.")
                    gemini_rate_limiter.rate_limit_exceeded = True
                    break
                
                # Check for API key errors (permanent)
                if "api key" in error_msg or "invalid_api_key" in error_msg or "authentication" in error_msg:
                    print(f"   ❌ Gemini API key error: {str(e)[:100]}")
                    print(f"   ⚠️ Disabling Gemini for this session")
                    gemini_rate_limiter.rate_limit_exceeded = True
                    break
                
                # TRANSIENT errors that should be retried
                transient_errors = [
                    "timeout", "503", "502", "500",  # Server errors
                    "connection", "network",         # Network errors
                    "unavailable", "overloaded"      # Service errors
                ]
                
                is_transient = any(err in error_msg for err in transient_errors)
                
                if is_transient and retry_count < max_retries - 1:
                    # Wait with exponential backoff before retrying
                    backoff_time = min(2 ** retry_count, 10)  # Max 10 seconds
                    print(f"   ⚠️ Gemini error (transient): {str(e)[:100]}")
                    print(f"   ⏳ Waiting {backoff_time}s before retry...")
                    time.sleep(backoff_time)
                    retry_count += 1
                    continue
                else:
                    # Non-transient error or max retries reached
                    print(f"   ⚠️ Gemini error: {str(e)[:100]}")
                    if retry_count >= max_retries - 1:
                        print(f"   ❌ Max retries ({max_retries}) reached for Gemini")
                    break
        
        # If we exited the retry loop without success, log it
        if retry_count > 0 and last_error:
            print(f"   ⚠️ Gemini failed after {retry_count} retries. Switching to {'Ollama' if ollama_available else 'fallback'}")

    # Fallback to Ollama if available
    if ollama_available:
        return generate_alert_description_with_ollama(group)
    
    # Final fallback to template-based
    return generate_fallback_alert_description(group)


def generate_alert_description_with_ollama(group: "UserActivityGroup", max_retries: int = 2) -> str:
    """
    Generate alert description using Ollama with retry logic
    
    Args:
        group: UserActivityGroup object
        max_retries: Maximum retry attempts
        
    Returns:
        Alert description string
    """
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            import requests
            
            if retry_count > 0:
                print(f"   🔄 Retry attempt {retry_count}/{max_retries} for Ollama...")
            
            # Prepare context
            context = f"""You are a security analyst. Generate a clear 2-3 sentence description of this security incident.

USER: {group.user_display_name} ({group.user_principal_name})
RISK SCORE: {group.risk_score}/10
EVENTS: {group.total_events}
FAILURES: {group.failure_analysis.get('total_failures', 0)}
SUCCESS RATE: {group.failure_analysis.get('success_rate', 100)}%
LOCATIONS: {group.unique_locations}
APPS: {group.unique_apps}

KEY ISSUES: {', '.join(group.risk_factors[:3])}

Generate only 2-3 sentences explaining what happened and why it's concerning. Use simple language."""

            response = requests.post(
                f"{OLLAMA_BASE_URL}/api/generate",
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": context,
                    "stream": False,
                    "options": {
                        "temperature": 0.3,
                        "num_predict": 150
                    }
                },
                timeout=30  # Reduced timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                description = result.get("response", "").strip()
                
                if len(description) >= 50:
                    if retry_count > 0:
                        print(f"   ✅ Ollama succeeded after {retry_count} retries")
                    return description
            
            # Failed but no exception - try next retry
            if retry_count < max_retries - 1:
                print(f"   ⚠️ Ollama returned invalid response, retrying...")
                time.sleep(1)
                retry_count += 1
                continue
            else:
                break
                    
        except Exception as e:
            error_msg = str(e).lower()
            
            # Check for connection errors
            if "connection" in error_msg or "timeout" in error_msg:
                if retry_count < max_retries - 1:
                    print(f"   ⚠️ Ollama connection error, retrying...")
                    time.sleep(2)
                    retry_count += 1
                    continue
            
            print(f"   ⚠️ Ollama error: {str(e)[:100]}")
            break
    
    print(f"   ⚠️ Ollama failed after {retry_count + 1} attempts, using template fallback")
    return generate_fallback_alert_description(group)


def test_gemini_connection() -> bool:
    """
    Test Gemini API connection at startup
    Returns True if successful, False otherwise
    """
    if not gemini_model:
        return False
    
    try:
        print("🧪 Testing Gemini API connection...")
        response = gemini_model.generate_content(
            "Say 'OK' if you can read this.",
            generation_config=genai.types.GenerationConfig(
                temperature=0.1,
                max_output_tokens=10,
            ),
        )
        
        if response and response.text:
            print("✅ Gemini API connection successful")
            return True
        else:
            print("⚠️ Gemini API returned empty response")
            return False
            
    except Exception as e:
        error_msg = str(e).lower()
        print(f"❌ Gemini API test failed: {str(e)[:100]}")
        
        # Check if it's an API key error
        if "api key" in error_msg or "invalid_api_key" in error_msg:
            print("⚠️ Invalid or missing API key. Please check your GOOGLE_API_KEY in .env")
        elif "quota" in error_msg or "429" in error_msg:
            print("⚠️ API quota exceeded. Check your quota at https://aistudio.google.com/app/apikey")
        
        return False


def generate_fallback_alert_description(group: "UserActivityGroup") -> str:
    """
    Fallback method to generate alert description when LLM is unavailable
    
    Args:
        group: UserActivityGroup object
        
    Returns:
        Alert description string
    """

    user_name = group.user_display_name
    failures = group.failure_analysis.get('total_failures', 0)
    success_rate = group.failure_analysis.get('success_rate', 100)
    locations = group.unique_locations
    apps = group.unique_apps
    clusters = group.total_clusters

    # Build description based on primary risk factors
    sentences = []

    # Sentence 1: Primary concern
    if failures > 5:
        sentences.append(
            f"User {user_name} experienced {failures} authentication failures "
            f"with a {success_rate}% success rate, indicating potential credential issues or attack attempts."
        )
    elif locations > 2:
        sentences.append(
            f"User {user_name} accessed systems from {locations} different geographic locations "
            f"during the monitored period, which may indicate unusual travel or account sharing."
        )
    elif apps > 7:
        sentences.append(
            f"User {user_name} accessed {apps} different applications in rapid succession, "
            f"which deviates from typical usage patterns."
        )
    elif clusters > 3:
        sentences.append(
            f"User {user_name} showed {clusters} distinct activity sessions with varied patterns, "
            f"suggesting possible irregular access behavior."
        )
    else:
        sentences.append(
            f"User {user_name} exhibited activity patterns that deviated from normal baseline behavior."
        )

    # Sentence 2: Supporting details
    if group.failure_analysis.get('critical_failures', 0) > 0:
        sentences.append(
            f"The activity includes {group.failure_analysis['critical_failures']} critical authentication failures "
            f"requiring immediate attention."
        )
    elif group.risk_factors:
        primary_risk = group.risk_factors[0]
        sentences.append(f"Analysis shows {primary_risk.lower()}.")
    elif group.behavioral_anomalies:
        sentences.append(f"Detected {group.behavioral_anomalies[0].lower()}.")

    # Sentence 3: Recommendation (optional, only if high risk)
    if group.risk_score >= 7:
        sentences.append("Immediate investigation is recommended to verify account security.")

    return " ".join(sentences[:3])  # Return max 3 sentences


def process_cleaned_user_data(json_path: str, output_folder: str = None):
    """
    Process a single cleaned user data file and generate reports

    Args:
        json_path: Path to cleaned JSON file
        output_folder: Folder to save reports (defaults to same folder as input)

    Returns:
        Tuple of (markdown_path, json_path) or (None, None) if failed
    """

    if not os.path.exists(json_path):
        print(f"❌ File not found: {json_path}")
        return None, None

    print(f"📊 Processing: {os.path.basename(json_path)}")

    # Load data
    log_data = load_json(json_path)
    if not log_data:
        return None, None

    signin_count = len(log_data.get("SigninLogs", []))
    print(f"   ✅ Loaded {signin_count} sign-in events")

    # Group events by user
    print("   📊 Grouping events by user...")
    user_events = group_events_by_user(log_data)
    print(f"   ✅ Found {len(user_events)} unique users")

    # Create activity summaries
    print("   📊 Creating activity summaries...")
    user_groups = {}
    for upn, events in user_events.items():
        summary = create_user_activity_summary(upn, events)
        if summary:
            user_groups[upn] = summary
    print(f"   ✅ Analyzed {len(user_groups)} users")

    if not user_groups:
        print("   ⚠️  No user groups created")
        return None, None

    # Determine output folder
    if output_folder is None:
        output_folder = os.path.dirname(json_path)

    # Generate output filenames
    base_name = os.path.basename(json_path).replace(".json", "").replace("cleaned_", "")
    md_output = os.path.join(output_folder, f"correlation_analysis_{base_name}.md")
    json_output = os.path.join(output_folder, f"correlation_analysis_{base_name}.json")

    # Generate reports
    print("   📝 Generating reports...")
    try:
        generate_markdown_report(user_groups, md_output)
        generate_json_report(user_groups, json_output)
        print(f"   ✅ Reports generated successfully")
        return md_output, json_output
    except Exception as e:
        print(f"   ❌ Error generating reports: {e}")
        return None, None


def calculate_intelligent_time_gap(events: List[EventDetails]) -> Tuple[int, Dict]:
    """
    Calculate time gap using statistical outlier detection
    Returns: (threshold_seconds, analysis_metadata)
    """

    if len(events) < 2:
        return 300, {"method": "default", "reason": "insufficient_events"}

    # Calculate all time gaps
    time_gaps = []
    for i in range(len(events) - 1):
        try:
            t1 = datetime.fromisoformat(events[i].timestamp.replace("Z", "+00:00"))
            t2 = datetime.fromisoformat(events[i + 1].timestamp.replace("Z", "+00:00"))
            gap_seconds = abs((t2 - t1).total_seconds())
            if gap_seconds > 0:  # Only positive gaps
                time_gaps.append(gap_seconds)
        except Exception as e:
            continue

    if not time_gaps:
        return 300, {"method": "default", "reason": "parsing_error"}

    time_gaps.sort()

    # Calculate statistics
    q1 = np.percentile(time_gaps, 25)
    q2 = np.percentile(time_gaps, 50)  # Median
    q3 = np.percentile(time_gaps, 75)
    iqr = q3 - q1
    mean = np.mean(time_gaps)
    std_dev = np.std(time_gaps)

    # IQR-based outlier detection
    lower_bound = q1 - 1.5 * iqr
    upper_bound = q3 + 1.5 * iqr

    # Filter normal gaps (non-outliers)
    normal_gaps = [g for g in time_gaps if lower_bound <= g <= upper_bound]

    if not normal_gaps:
        # All gaps are outliers - use median with safety factor
        threshold = q2 * 2
        metadata = {
            "method": "median_fallback",
            "reason": "all_outliers",
            "median": q2,
            "total_gaps": len(time_gaps)
        }
    else:
        # Use 75th percentile of normal gaps as threshold
        # This groups frequent activities while separating distinct sessions
        threshold = np.percentile(normal_gaps, 75)
        metadata = {
            "method": "iqr_outlier_detection",
            "q1": q1,
            "q2": q2,
            "q3": q3,
            "iqr": iqr,
            "mean": mean,
            "std_dev": std_dev,
            "normal_gaps_count": len(normal_gaps),
            "outlier_count": len(time_gaps) - len(normal_gaps),
            "total_gaps": len(time_gaps)
        }

    # Apply safety bounds: 30 seconds to 30 minutes
    threshold = max(30, min(1800, threshold))
    
    metadata["final_threshold"] = threshold

    return int(threshold), metadata


def cluster_user_events_intelligent(
    events: List[EventDetails]
) -> Tuple[List[EventCluster], Dict]:
    """
    Cluster events using intelligent time gap detection
    Returns: (clusters, metadata)
    """

    if not events:
        return [], {}

    # Calculate intelligent threshold
    dynamic_gap, gap_metadata = calculate_intelligent_time_gap(events)

    events_sorted = sorted(events, key=lambda e: e.timestamp)
    clusters = []
    current_cluster = [events_sorted[0]]

    for i in range(1, len(events_sorted)):
        try:
            t_prev = datetime.fromisoformat(
                events_sorted[i - 1].timestamp.replace("Z", "+00:00")
            )
            t_curr = datetime.fromisoformat(
                events_sorted[i].timestamp.replace("Z", "+00:00")
            )
            gap = abs((t_curr - t_prev).total_seconds())

            if gap <= dynamic_gap:
                # Add to current cluster (frequent activity)
                current_cluster.append(events_sorted[i])
            else:
                # Gap too large - start new cluster
                if current_cluster:
                    clusters.append(create_cluster(current_cluster, len(clusters)))
                current_cluster = [events_sorted[i]]
        except Exception as e:
            current_cluster.append(events_sorted[i])

    # Add final cluster
    if current_cluster:
        clusters.append(create_cluster(current_cluster, len(clusters)))

    return clusters, gap_metadata


def create_cluster(events: List[EventDetails], cluster_idx: int) -> EventCluster:
    """Create an EventCluster from a list of events"""

    times = []
    for e in events:
        try:
            times.append(datetime.fromisoformat(e.timestamp.replace("Z", "+00:00")))
        except:
            continue
    
    if not times:
        # Fallback to current time
        times = [datetime.now()]
    
    start_time = min(times)
    end_time = max(times)
    duration = int((end_time - start_time).total_seconds())

    unique_apps = len(set(e.app_id for e in events if e.app_id != "Unknown"))
    
    unique_locs = set()
    for e in events:
        if e.location_city and e.location_city != "Unknown":
            unique_locs.add(f"{e.location_city},{e.location_country}")
        elif e.location_country != "Unknown":
            unique_locs.add(e.location_country)
    unique_locations = len(unique_locs) if unique_locs else 1

    failures = [e for e in events if not e.is_success]

    return EventCluster(
        cluster_id=f"CLUSTER_{cluster_idx:03d}",
        events=events,
        start_time=start_time.isoformat(),
        end_time=end_time.isoformat(),
        duration_seconds=duration,
        event_count=len(events),
        unique_apps=unique_apps,
        unique_locations=unique_locations,
        has_failures=len(failures) > 0,
        failure_count=len(failures),
    )


# ============================================================================
# ENHANCED FAILURE ANALYSIS - NOW PROPERLY USING ResultDescription
# ============================================================================


def analyze_failures(events: List[EventDetails]) -> Dict:
    """Analyze failure patterns with detailed reasons from ResultDescription"""

    failures = [e for e in events if not e.is_success]

    if not failures:
        return {
            "total_failures": 0,
            "success_rate": 100.0,
            "failure_reasons": [],
            "critical_failures": 0,
            "failed_event_timeline": [],
            "failure_categories": {}
        }

    # Group failures by exact reason (from ResultDescription)
    failure_groups = defaultdict(list)
    for failure in failures:
        reason = failure.failure_reason or failure.result_description or "Unknown error"
        failure_groups[reason].append(failure)

    # Classify severity based on error content
    critical_keywords = [
        "strong authentication required",
        "account does not exist",
        "permission denied",
        "unauthorized",
        "access denied",
        "password",
        "locked",
        "disabled",
        "expired"
    ]
    
    warning_keywords = [
        "keep me signed in",
        "interrupt",
        "session",
        "timeout"
    ]

    critical_count = 0
    warning_count = 0
    
    failure_reasons_list = []
    for reason, fail_list in failure_groups.items():
        reason_lower = reason.lower()
        
        # Determine severity
        if any(keyword in reason_lower for keyword in critical_keywords):
            severity = "CRITICAL"
            critical_count += len(fail_list)
        elif any(keyword in reason_lower for keyword in warning_keywords):
            severity = "WARNING"
            warning_count += len(fail_list)
        else:
            severity = "INFO"
        
        failure_reasons_list.append({
            "reason": reason,
            "count": len(fail_list),
            "severity": severity,
            "result_codes": list(set(f.result_type for f in fail_list))
        })

    # Sort by count descending
    failure_reasons_list.sort(key=lambda x: x["count"], reverse=True)

    # Create detailed timeline
    failure_timeline = []
    for f in sorted(failures, key=lambda e: e.timestamp):
        failure_timeline.append({
            "timestamp": f.timestamp,
            "app": f.app_display_name,
            "reason": f.failure_reason or f.result_description,
            "result_code": f.result_type,
            "location": f"{f.location_city or 'Unknown'}, {f.location_country}",
            "ip_address": f.ip_address,
            "auth_method": f.authentication_method
        })

    success_rate = ((len(events) - len(failures)) / len(events) * 100) if events else 0

    # Categorize failures
    failure_categories = {
        "authentication_failures": 0,
        "session_failures": 0,
        "access_denied": 0,
        "user_errors": 0,
        "other": 0
    }
    
    for f in failures:
        reason_lower = (f.failure_reason or "").lower()
        categorized = False
        
        if any(kw in reason_lower for kw in ["authentication", "password", "credential", "mfa"]):
            failure_categories["authentication_failures"] += 1
            categorized = True
        
        if any(kw in reason_lower for kw in ["session", "expired", "timeout"]):
            failure_categories["session_failures"] += 1
            categorized = True
        
        if any(kw in reason_lower for kw in ["denied", "unauthorized", "permission"]):
            failure_categories["access_denied"] += 1
            categorized = True
        
        if any(kw in reason_lower for kw in ["not exist", "not found", "invalid"]):
            failure_categories["user_errors"] += 1
            categorized = True
        
        if not categorized:
            failure_categories["other"] += 1

    return {
        "total_failures": len(failures),
        "success_rate": round(success_rate, 2),
        "failure_reasons": failure_reasons_list,
        "critical_failures": critical_count,
        "warning_failures": warning_count,
        "failed_event_timeline": failure_timeline[:10],  # Last 10 failures
        "failure_categories": failure_categories
    }


# ============================================================================
# RISK SCORING - UPDATED VERSION
# ============================================================================

def calculate_user_risk_score(
    upn: str, events: List[EventDetails], clusters: List[EventCluster]
) -> Tuple[int, List[str]]:
    """Enhanced risk scoring with failure consideration - FIXED VERSION"""

    risk_score = 1
    risk_factors = []

    # Ensure we have events to analyze
    if not events:
        return 1, ["Insufficient data for risk assessment"]

    # Factor 1: Cluster-based anomalies
    if len(clusters) > 3:
        risk_score += 2
        risk_factors.append(f"Multiple activity clusters: {len(clusters)}")

    # Factor 2: Failure analysis (ENHANCED)
    failure_info = analyze_failures(events)

    if failure_info["total_failures"] > 2:
        risk_score += 3
        risk_factors.append(
            f"High failure count: {failure_info['total_failures']} "
            f"({failure_info['success_rate']}% success rate)"
        )

    if failure_info["critical_failures"] > 0:
        risk_score += 3
        risk_factors.append(
            f"Critical authentication failures: {failure_info['critical_failures']}"
        )
    
    # Specific failure categories
    if failure_info.get("failure_categories", {}).get("access_denied", 0) > 0:
        risk_score += 2
        risk_factors.append(
            f"Access denied attempts: {failure_info['failure_categories']['access_denied']}"
        )

    # Factor 3: Geographic anomalies
    unique_locations = len(
        set(f"{e.location_city},{e.location_country}" for e in events 
            if e.location_city and e.location_city != "Unknown")
    )
    if unique_locations > 2:
        risk_score += 2
        risk_factors.append(
            f"Geographically diverse access: {unique_locations} locations"
        )

    # Factor 4: Within-cluster rapid access
    for cluster in clusters:
        if cluster.event_count > 5 and cluster.duration_seconds < 300:
            risk_score += 2
            risk_factors.append(
                f"Rapid event cluster: {cluster.event_count} events in {cluster.duration_seconds}s"
            )
            break

    # Factor 5: Single factor authentication
    single_factor = sum(
        1 for e in events if "single" in e.authentication_requirement.lower()
    )
    multi_factor = sum(
        1 for e in events if "multi" in e.authentication_requirement.lower()
    )

    if single_factor > multi_factor * 2 and single_factor > 0:
        risk_score += 1
        risk_factors.append("Predominantly single-factor authentication")

    # Factor 6: Guest user access
    if events and "guest" in events[0].user_type.lower():
        risk_score += 1
        risk_factors.append("Guest user cross-tenant access")

    # Factor 7: Multiple application access
    unique_apps = len(set(e.app_id for e in events if e.app_id != "Unknown"))
    if unique_apps > 5:
        risk_score += 1
        risk_factors.append(f"Accessing {unique_apps} different applications")

    # Factor 8: Cluster location changes
    location_changes = 0
    for i in range(len(clusters) - 1):
        loc1 = f"{clusters[i].events[0].location_city},{clusters[i].events[0].location_country}"
        loc2 = f"{clusters[i+1].events[0].location_city},{clusters[i+1].events[0].location_country}"
        if loc1 != loc2 and "Unknown" not in loc1 and "Unknown" not in loc2:
            location_changes += 1

    if location_changes > 1:
        risk_score += 1
        risk_factors.append(f"Location changes between clusters: {location_changes}")

    # IMPORTANT FIX: Ensure we always have at least one risk factor
    if not risk_factors:
        if risk_score > 1:
            risk_factors.append("Anomalous user behavior detected")
        else:
            risk_factors.append("Normal user activity pattern")

    # Cap risk score
    risk_score = min(risk_score, 10)

    return risk_score, risk_factors

# ============================================================================
# ACTIVITY GROUP CREATION
# ============================================================================


def generate_alert_title(group: UserActivityGroup) -> str:
    """Generate a Sentinel-style alert title based on risk factors"""
    
    user_name = group.user_display_name
    risk_level = "HIGH" if group.risk_score >= 7 else "MEDIUM" if group.risk_score >= 5 else "LOW"
    
    # Determine primary threat type
    threat_types = []
    
    # Check for authentication failures
    if group.failure_analysis.get("critical_failures", 0) > 0:
        threat_types.append("Critical Authentication Failures")
    elif group.failure_analysis.get("total_failures", 0) > 3:
        threat_types.append("Multiple Failed Sign-ins")
    
    # Check for access denied
    if group.failure_analysis.get("failure_categories", {}).get("access_denied", 0) > 0:
        threat_types.append("Unauthorized Access Attempts")
    
    # Check for geographic anomalies
    if group.unique_locations > 2:
        threat_types.append("Geographically Distributed Access")
    
    # Check for rapid activity
    rapid_clusters = sum(1 for c in group.clusters[1:] if isinstance(c, dict) and c.get('event_count', 0) > 5 and c.get('duration_seconds', 999) < 300)
    if rapid_clusters > 0:
        threat_types.append("Suspicious Rapid Activity")
    
    # Check for multiple applications
    if group.unique_apps > 5:
        threat_types.append("Excessive Application Access")
    
    # Check for guest user
    if "guest" in group.user_type.lower():
        threat_types.append("Cross-Tenant Guest Activity")
    
    # Check for single-factor auth predominance
    auth_summary = group.authentication_summary
    if auth_summary.get("total_single_factor", 0) > auth_summary.get("total_mfa", 0) * 2:
        threat_types.append("Weak Authentication Methods")
    
    # Build title
    if not threat_types:
        threat_types.append("Abnormal User Behavior")
    
    # Create a concise title (max 2 threat types)
    primary_threats = " & ".join(threat_types[:2])
    
    # Add count indicators
    failure_count = group.failure_analysis.get("total_failures", 0)
    event_count = group.total_events
    
    if failure_count > 0:
        title = f"🚨 [{risk_level} RISK] {primary_threats} - {user_name} ({failure_count} failures/{event_count} events)"
    else:
        title = f"⚠️ [{risk_level} RISK] {primary_threats} - {user_name} ({event_count} events)"
    
    return title


def generate_alert_summary(group: UserActivityGroup) -> str:
    """Generate a brief alert summary in Sentinel style"""

    summary_parts = []

    # Failure info
    if group.failure_analysis.get("total_failures", 0) > 0:
        success_rate = group.failure_analysis.get("success_rate", 0)
        summary_parts.append(f"Success rate: {success_rate}%")

    # Location info
    if group.unique_locations > 1:
        summary_parts.append(f"{group.unique_locations} locations")

    # App access
    if group.unique_apps > 3:
        summary_parts.append(f"{group.unique_apps} applications")

    # Cluster info
    if group.total_clusters > 2:
        summary_parts.append(f"{group.total_clusters} activity sessions")

    return " | ".join(summary_parts) if summary_parts else "Normal activity pattern"


def create_user_activity_summary(
    upn: str, events: List[EventDetails]
) -> UserActivityGroup:
    """Create comprehensive activity summary with intelligent cluster analysis"""

    if not events:
        return None

    # Use intelligent clustering
    clusters, gap_metadata = cluster_user_events_intelligent(events)

    # Risk assessment (FIXED VERSION THAT ALWAYS RETURNS RISK FACTORS)
    risk_score, risk_factors = calculate_user_risk_score(upn, events, clusters)

    # Location analysis (exclude Unknown)
    locations = []
    seen_locs = set()
    for event in events:
        if event.location_city and event.location_city != "Unknown":
            loc_key = f"{event.location_city}|{event.ip_address}"
            if loc_key not in seen_locs:
                seen_locs.add(loc_key)
                locations.append(
                    {
                        "city": event.location_city,
                        "state": event.location_state,
                        "country": event.location_country,
                        "ip_address": event.ip_address,
                        "timestamp": event.timestamp,
                    }
                )

    # Application analysis
    applications = []
    app_access_count = defaultdict(int)
    for event in events:
        if event.app_id != "Unknown":
            app_access_count[event.app_id] += 1

    for app_id, count in app_access_count.items():
        app_events = [e for e in events if e.app_id == app_id]
        if app_events:
            first_app = app_events[0]
            applications.append(
                {
                    "app_name": first_app.app_display_name,
                    "app_id": app_id,
                    "resource": first_app.resource_display_name,
                    "access_count": count,
                }
            )

    # Authentication analysis
    auth_methods = list(
        set(
            e.authentication_method
            for e in events
            if e.authentication_method != "Unknown"
        )
    )

    auth_summary = {
        "methods": auth_methods,
        "total_mfa": sum(
            1 for e in events if "multi" in e.authentication_requirement.lower()
        ),
        "total_single_factor": sum(
            1 for e in events if "single" in e.authentication_requirement.lower()
        ),
        "failed_attempts": sum(1 for e in events if not e.is_success),
    }

    # Failure analysis
    failure_analysis = analyze_failures(events)

    # Add gap analysis metadata to cluster details
    cluster_details = []
    for c in clusters:
        cluster_details.append(
            {
                "cluster_id": c.cluster_id,
                "start_time": c.start_time,
                "end_time": c.end_time,
                "duration_seconds": c.duration_seconds,
                "event_count": c.event_count,
                "unique_apps": c.unique_apps,
                "has_failures": c.has_failures,
                "failure_count": c.failure_count,
            }
        )

    if gap_metadata:
        cluster_details.insert(0, {"clustering_metadata": gap_metadata})

    # Timeline
    timeline = []
    for e in events:
        timeline.append(
            {
                "timestamp": e.timestamp,
                "app": e.app_display_name,
                "location": f"{e.location_city or 'Unknown'}, {e.location_country}",
                "ip_address": e.ip_address,
                "browser": e.browser or "Unknown",
                "os": e.operating_system or "Unknown",
                "result": (
                    "✅ Success"
                    if e.is_success
                    else f"❌ Failed: {e.failure_reason or e.result_description}"
                ),
                "auth_method": e.authentication_method,
            }
        )

    # Behavioral anomalies
    anomalies = []

    if failure_analysis["total_failures"] > 3:
        anomalies.append(
            f"Suspicious failure pattern: {failure_analysis['total_failures']} failures "
            f"({failure_analysis['success_rate']}% success rate)"
        )

    if failure_analysis["critical_failures"] > 0:
        anomalies.append(
            f"Critical authentication failures: {failure_analysis['critical_failures']}"
        )

    if len(clusters) > 3:
        anomalies.append(
            f"Multiple distinct activity sessions: {len(clusters)} clusters"
        )

    unique_apps = len(applications)
    if unique_apps > 5:
        anomalies.append(f"Access to {unique_apps} applications (unusually high)")

    rapid_failures = sum(
        1 for c in clusters if c.failure_count > 2 and c.duration_seconds < 180
    )
    if rapid_failures > 0:
        anomalies.append(f"Rapid failure clusters detected: {rapid_failures}")

    first_event = events[0]

    # Create the group object
    group = UserActivityGroup(
        user_principal_name=upn,
        user_id=first_event.user_id,
        user_display_name=first_event.user_display_name,
        user_type=first_event.user_type,
        total_events=len(events),
        total_clusters=len(clusters),
        clusters=cluster_details,
        locations=locations,
        unique_locations=len(locations),
        applications=applications,
        unique_apps=len(applications),
        authentication_summary=auth_summary,
        failure_analysis=failure_analysis,
        behavioral_anomalies=anomalies,
        risk_score=risk_score,
        risk_factors=risk_factors,
        timeline=timeline,
    )

    return group


# ============================================================================
# DATA GROUPING
# ============================================================================


def group_events_by_user(log_data: dict) -> Dict[str, List[EventDetails]]:
    """Group all sign-in events by user"""

    user_groups: Dict[str, List[EventDetails]] = defaultdict(list)

    parse_errors = 0

    for signin_log in log_data.get("SigninLogs", []):
        try:
            event = extract_complete_event_data(signin_log)
            if event.user_principal_name != "Unknown":
                user_groups[event.user_principal_name].append(event)
            else:
                parse_errors += 1
        except Exception as e:
            parse_errors += 1
            print(f"⚠️ Error parsing event: {e}")
            continue

    if parse_errors > 0:
        print(f"⚠️ Skipped {parse_errors} events due to parsing errors\n")

    # Sort events by timestamp
    for upn in user_groups:
        user_groups[upn].sort(key=lambda e: e.timestamp)

    return dict(user_groups)


# ============================================================================
# REPORT GENERATION
# ============================================================================


def generate_json_report(user_groups: Dict[str, UserActivityGroup], output_path: str):
    """Generate comprehensive JSON report with LLM-generated descriptions"""

    high_risk = []
    medium_risk = []
    low_risk = []

    print("   🤖 Generating AI-powered alert descriptions...")

    # Track start time for progress
    start_time = time.time()
    total_users = len(user_groups)

    for idx, (upn, group) in enumerate(user_groups.items(), 1):
        # Show progress
        if idx % 5 == 0 or idx == total_users:
            elapsed = time.time() - start_time
            rate = idx / elapsed if elapsed > 0 else 0
            eta = (total_users - idx) / rate if rate > 0 else 0
            print(
                f"   📊 Progress: {idx}/{total_users} users ({idx/total_users*100:.1f}%) - ETA: {eta:.0f}s"
            )

        group_dict = group.model_dump()

        # Add alert title and summary
        group_dict["alert_title"] = generate_alert_title(group)
        group_dict["alert_summary"] = generate_alert_summary(group)

        # Generate LLM-powered description (with rate limiting)
        group_dict["alert_description"] = generate_alert_description_with_llm(group)

        if group.risk_score >= 7:
            high_risk.append(group_dict)
        elif group.risk_score >= 5:
            medium_risk.append(group_dict)
        else:
            low_risk.append(group_dict)

    # Get rate limiter stats
    rate_stats = gemini_rate_limiter.get_stats() if gemini_model else {}

    report = {
        "report_metadata": {
            "generated_at": datetime.now().isoformat(),
            "report_type": "Advanced Security Correlation Analysis v5.1 - AI-Enhanced Edition",
            "total_users": len(user_groups),
            "total_events": sum(g.total_events for g in user_groups.values()),
            "ai_enhanced": True if gemini_model else False,
            "generation_time_seconds": time.time() - start_time,
            "api_stats": rate_stats if rate_stats else None,
            "improvements": [
                "Intelligent time gap detection using outlier analysis",
                "Proper ResultDescription extraction for failures",
                "Enhanced Unknown data handling",
                "Frequent activity grouping (not hardcoded thresholds)",
                "AI-generated alert descriptions with rate limiting",
            ],
        },
        "summary": {
            "high_risk_count": len(high_risk),
            "medium_risk_count": len(medium_risk),
            "low_risk_count": len(low_risk),
        },
        "high_priority_events": sorted(
            high_risk, key=lambda x: x["risk_score"], reverse=True
        ),
        "medium_priority_events": sorted(
            medium_risk, key=lambda x: x["risk_score"], reverse=True
        ),
        "low_priority_events": sorted(
            low_risk, key=lambda x: x["risk_score"], reverse=True
        ),
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    # Print rate limiter stats
    if rate_stats:
        print(f"\n   📊 API Usage Statistics:")
        print(f"      • Total API calls: {rate_stats['total_requests']}")
        print(f"      • Total wait time: {rate_stats['total_wait_time']:.1f}s")
        print(
            f"      • Requests in last minute: {rate_stats['requests_last_minute']}/{rate_stats['rpm_limit']}"
        )
        print(
            f"      • Requests today: {rate_stats['requests_today']}/{rate_stats['rpd_limit']}"
        )

    print(f"   ✅ JSON report saved to {output_path}")


def generate_markdown_report(
    user_groups: Dict[str, UserActivityGroup], output_path: str
):
    """Generate comprehensive markdown report with AI descriptions"""

    md_report = f"""# 🔒 Advanced Security Correlation Analysis Report v5.1 - AI-Enhanced Edition

**Generated:** {datetime.now().isoformat()}  
**Report Type:** Intelligent Cluster-Based User Activity Correlation with AI-Powered Descriptions  
**Total Users:** {len(user_groups)}  
**Total Events:** {sum(g.total_events for g in user_groups.values())}  

## 🔧 Improvements in v5.1
- ✅ **Intelligent Time Gap Detection**: Statistical outlier analysis
- ✅ **Proper Failure Extraction**: ResultDescription correctly parsed
- ✅ **Enhanced Unknown Data Handling**: Better fallback mechanisms
- ✅ **AI-Powered Descriptions**: Easy-to-understand alert explanations using Gemini
- ✅ **Fixed Risk Factors**: Always provides meaningful risk indicators

---

## 📊 EXECUTIVE SUMMARY

"""

    high_risk = [g for g in user_groups.values() if g.risk_score >= 7]
    medium_risk = [g for g in user_groups.values() if 5 <= g.risk_score < 7]
    low_risk = [g for g in user_groups.values() if g.risk_score < 5]

    md_report += f"""
- 🔴 **CRITICAL RISK USERS:** {len(high_risk)}
- 🟡 **MEDIUM RISK USERS:** {len(medium_risk)}
- 🟢 **LOW RISK USERS:** {len(low_risk)}

---

## 🚨 TOP SECURITY ALERTS

"""

    # Show top 5 alerts with AI descriptions
    all_groups = sorted(
        user_groups.values(),
        key=lambda g: (g.risk_score, g.failure_analysis.get("critical_failures", 0)),
        reverse=True,
    )[:5]

    print("   🤖 Generating AI descriptions for top alerts...")

    for idx, group in enumerate(all_groups, 1):
        alert_title = generate_alert_title(group)
        alert_description = generate_alert_description_with_llm(group)

        md_report += f"""
**{idx}. {alert_title}**

{alert_description}

---
"""

    md_report += f"""

## 🔴 CRITICAL PRIORITY - Risk Score 7-10

"""

    for group in sorted(high_risk, key=lambda g: g.risk_score, reverse=True)[:10]:

        # Generate alert components
        alert_title = generate_alert_title(group)
        alert_summary = generate_alert_summary(group)
        alert_description = generate_alert_description_with_llm(group)

        # Get clustering metadata if available
        clustering_info = ""
        if group.clusters and isinstance(group.clusters[0], dict):
            if "clustering_metadata" in group.clusters[0]:
                meta = group.clusters[0]["clustering_metadata"]
                clustering_info = f"""
**🔍 Clustering Analysis:**
- Detection Method: `{meta.get('method', 'Unknown')}`
- Time Gap Threshold: `{meta.get('final_threshold', 'N/A')}` seconds
- Total Time Gaps Analyzed: `{meta.get('total_gaps', 'N/A')}`
"""
                if "normal_gaps_count" in meta:
                    clustering_info += (
                        f"- Normal Activity Gaps: `{meta['normal_gaps_count']}`\n"
                    )
                    clustering_info += f"- Outlier Gaps: `{meta['outlier_count']}`\n"

        md_report += f"""
### {alert_title}

**Alert Summary:** {alert_summary}

**📝 Detailed Description:**  
_{alert_description}_

**User Details:** {group.user_display_name} ({group.user_principal_name}) | Type: {group.user_type}

{clustering_info}

#### 🎯 Key Risk Factors
"""
        # Ensure risk_factors is not empty
        if group.risk_factors:
            for factor in group.risk_factors[:5]:
                md_report += f"- {factor}\n"
        else:
            md_report += "- Normal activity pattern observed\n"

        md_report += f"""
#### ❌ Detailed Failure Analysis
- **Total Failures:** {group.failure_analysis['total_failures']}
- **Success Rate:** {group.failure_analysis['success_rate']}%
- **Critical Failures:** {group.failure_analysis['critical_failures']}
- **Warning Failures:** {group.failure_analysis.get('warning_failures', 0)}

**Failure Categories:**
"""

        # Show failure categories
        if "failure_categories" in group.failure_analysis:
            for cat, count in group.failure_analysis["failure_categories"].items():
                if count > 0:
                    md_report += f"- {cat.replace('_', ' ').title()}: {count}\n"

        md_report += "\n**Top Failure Reasons:**\n"
        for failure in group.failure_analysis["failure_reasons"][:5]:
            severity_emoji = {"CRITICAL": "🔴", "WARNING": "🟡", "INFO": "ℹ️"}.get(
                failure["severity"], "⚪"
            )
            md_report += f"- {severity_emoji} **{failure['reason']}** (Count: {failure['count']}, Severity: {failure['severity']})\n"

        md_report += f"""
#### 📍 Geographic Activity ({group.unique_locations} unique locations)
"""
        if group.locations:
            for loc in group.locations[:5]:
                city_state = f"{loc['city']}"
                if loc.get("state"):
                    city_state += f", {loc['state']}"
                md_report += (
                    f"- {city_state} ({loc['country']}) - IP: `{loc['ip_address']}`\n"
                )
        else:
            md_report += "- No location data available\n"

        md_report += f"""
#### 💻 Applications Accessed ({group.unique_apps})
"""
        for app in sorted(
            group.applications, key=lambda x: x["access_count"], reverse=True
        )[:5]:
            resource = f" → {app['resource']}" if app.get("resource") else ""
            md_report += (
                f"- **{app['app_name']}**{resource} - {app['access_count']} times\n"
            )

        md_report += f"""
#### 🔐 Authentication Summary
- **Methods Used:** {', '.join(group.authentication_summary.get('methods', ['Unknown'])[:3])}
- **MFA Events:** {group.authentication_summary.get('total_mfa', 0)}
- **Single-Factor Events:** {group.authentication_summary.get('total_single_factor', 0)}

#### 📅 Activity Clusters ({group.total_clusters})
"""
        # Skip first entry if it's metadata
        cluster_start_idx = (
            1
            if (
                group.clusters
                and isinstance(group.clusters[0], dict)
                and "clustering_metadata" in group.clusters[0]
            )
            else 0
        )

        for cluster in group.clusters[cluster_start_idx : cluster_start_idx + 5]:
            if isinstance(cluster, dict) and "cluster_id" in cluster:
                duration_min = cluster["duration_seconds"] / 60
                failure_indicator = (
                    f", ❌ {cluster['failure_count']} failures"
                    if cluster["failure_count"] > 0
                    else ""
                )
                md_report += f"- **{cluster['cluster_id']}**: {cluster['event_count']} events over {duration_min:.1f} minutes{failure_indicator}\n"

        # Show recent failed events
        if group.failure_analysis["failed_event_timeline"]:
            md_report += f"""
#### ⚠️ Recent Failed Events
"""
            for fail_event in group.failure_analysis["failed_event_timeline"][:3]:
                md_report += f"- `{fail_event['timestamp']}` - **{fail_event['app']}** - {fail_event['reason']}\n"
                md_report += f"  - Location: {fail_event['location']}, IP: `{fail_event['ip_address']}`\n"

        md_report += "\n---\n"

    # Continue with medium and low priority sections (keep existing code)
    md_report += f"""

## 🟡 MEDIUM PRIORITY - Risk Score 5-6

"""

    for group in sorted(medium_risk, key=lambda g: g.risk_score, reverse=True)[:10]:
        alert_title = generate_alert_title(group)
        alert_summary = generate_alert_summary(group)
        alert_description = generate_alert_description_with_llm(group)

        md_report += f"""
### {alert_title}

**Alert Summary:** {alert_summary}

**📝 Description:** _{alert_description}_

**Risk Factors:** {', '.join(group.risk_factors[:3]) if group.risk_factors else 'Normal activity pattern'}

**Behavioral Anomalies:** {', '.join(group.behavioral_anomalies[:2]) if group.behavioral_anomalies else 'None detected'}

---
"""

    md_report += f"""

## 🟢 LOW PRIORITY - Risk Score 1-4

**Count:** {len(low_risk)} users | Minimal suspicious activity

### Summary of Low-Risk Users
"""

    for group in sorted(low_risk, key=lambda g: g.total_events, reverse=True)[:10]:
        md_report += f"- **{group.user_display_name}**: {group.total_events} events, {group.total_clusters} clusters, Risk: {group.risk_score}/10\n"

    md_report += f"""

---

## 📈 Statistical Overview

### Overall Metrics
- **Total Sign-in Events:** {sum(g.total_events for g in user_groups.values())}
- **Total Activity Clusters:** {sum(g.total_clusters for g in user_groups.values())}
- **Total Failures:** {sum(g.failure_analysis['total_failures'] for g in user_groups.values())}
- **Average Success Rate:** {round(sum(g.failure_analysis['success_rate'] for g in user_groups.values()) / len(user_groups), 2) if user_groups else 0}%

### Risk Distribution
- High Risk (7-10): {len(high_risk)} users
- Medium Risk (5-6): {len(medium_risk)} users
- Low Risk (1-4): {len(low_risk)} users

---

**Report Generated By:** Advanced Security Correlation Engine v5.1 (AI-Enhanced Edition)  
**Analysis Date:** {datetime.now().isoformat()}  
**Key Features:** Intelligent clustering, AI-powered descriptions, Enhanced failure analysis, Fixed risk factors
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(md_report)

    print(f"   ✅ Markdown report saved to {output_path}")


# ============================================================================
# MAIN EXECUTION WITH FOLDER PROCESSING
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


def process_single_file(json_path: str) -> Dict[str, UserActivityGroup]:
    """Process a single JSON file and return user groups"""

    print(f"📄 Processing: {json_path}")
    log_data = load_json(json_path)

    if not log_data:
        return {}

    signin_count = len(log_data.get("SigninLogs", []))
    print(f"✅ Loaded {signin_count} sign-in events\n")

    print("🔄 Grouping events by user...")
    user_events = group_events_by_user(log_data)
    print(f"   ✅ Found {len(user_events)} unique users\n")

    print("📊 Creating activity summaries with intelligent cluster analysis...")
    user_groups = {}
    for upn, events in user_events.items():
        summary = create_user_activity_summary(upn, events)
        if summary:
            user_groups[upn] = summary
    print(f"   ✅ Analyzed {len(user_groups)} users\n")

    return user_groups


def main():
    """Main execution with folder processing"""
    print("🚀 Starting Advanced Security Correlation Engine v5.0 - Fixed Edition\n")
    print("🔧 Key Improvements:")
    print("   ✅ Intelligent time gap detection (no hardcoding)")
    print("   ✅ Proper ResultDescription extraction")
    print("   ✅ Enhanced Unknown data handling")
    print("   ✅ Frequent activity grouping\n")

    sentinel_logs_dir = "sentinel_logs1"

    # Check if sentinel_logs directory exists
    if os.path.exists(sentinel_logs_dir) and os.path.isdir(sentinel_logs_dir):
        print(
            f"📁 Found {sentinel_logs_dir}/ directory. Processing time intervals...\n"
        )

        # Get all subdirectories (time intervals)
        subdirs = [
            d
            for d in os.listdir(sentinel_logs_dir)
            if os.path.isdir(os.path.join(sentinel_logs_dir, d))
        ]

        if subdirs:
            print(f"📂 Found {len(subdirs)} time intervals\n")

            for subdir in sorted(subdirs):
                subdir_path = os.path.join(sentinel_logs_dir, subdir)
                print(f"\n{'='*70}")
                print(f"📂 Processing interval: {subdir}")
                print(f"{'='*70}\n")

                # Find JSON files
                json_files = [
                    f
                    for f in os.listdir(subdir_path)
                    if f.endswith(".json")
                    and "cleaned_sentinel_user_data_" in f.lower()
                ]

                if not json_files:
                    print(f"⚠️ No JSON files found in {subdir}\n")
                    continue

                for json_file in json_files:
                    json_path = os.path.join(subdir_path, json_file)

                    user_groups = process_single_file(json_path)

                    if not user_groups:
                        continue

                    # Generate reports in same directory
                    base_name = json_file.replace(".json", "")
                    md_output = os.path.join(
                        subdir_path, f"correlation_analysis_{base_name}.md"
                    )
                    json_output = os.path.join(
                        subdir_path, f"correlation_analysis_{base_name}.json"
                    )

                    print("📝 Generating reports...")
                    generate_markdown_report(user_groups, md_output)
                    generate_json_report(user_groups, json_output)

                    print(
                        f"✅ Reports generated:\n   - {md_output}\n   - {json_output}\n"
                    )
        else:
            print(f"⚠️ No subdirectories found in {sentinel_logs_dir}")
    else:
        # Fallback: Process single file in current directory
        print("ℹ️ No sentinel_logs directory found. Processing single file...\n")

        json_path = "sentinel_user_data.json"

        if not os.path.exists(json_path):
            print(
                f"❌ Neither directory '{sentinel_logs_dir}' nor file '{json_path}' found"
            )
            return

        user_groups = process_single_file(json_path)

        if not user_groups:
            return

        print("📝 Generating reports...")
        generate_markdown_report(user_groups, "correlation_analysis_report.md")
        generate_json_report(user_groups, "correlation_analysis_report.json")

    print("\n" + "=" * 70)
    print("✅ Analysis complete!")
    print("=" * 70)


if __name__ == "__main__":
    main()
