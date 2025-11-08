import json
import os
import re
from dotenv import load_dotenv
from typing import List, Optional, Dict, Tuple
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
from collections import defaultdict
import statistics
import numpy as np

os.environ["CREWAI_TELEMETRY"] = "false"
load_dotenv()


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
# DATA EXTRACTION - IMPROVED VERSION
# ============================================================================


def extract_failure_reason(signin_log: dict) -> Tuple[bool, Optional[str]]:
    """Extract failure reason from multiple possible fields"""

    is_success = signin_log.get("ResultType") == "0"
    failure_reason = None

    if not is_success:
        # Primary source: ResultDescription
        failure_reason = signin_log.get("ResultDescription", "").strip()

        # Fallback sources
        if not failure_reason:
            failure_reason = (
                signin_log.get("Status", {}).get("failureReason", "").strip()
            )

        if not failure_reason:
            # Parse from ActionType
            action_type = signin_log.get("ActionType", "")
            if action_type:
                failure_reason = action_type

        if not failure_reason:
            failure_reason = f"Unknown failure (Code: {signin_log.get('ResultType')})"

    return is_success, failure_reason


def extract_complete_event_data(signin_log: dict) -> EventDetails:
    """Extract all available data from a sign-in log entry"""

    auth_details = signin_log.get("AuthenticationDetails", [])
    auth_method = "Unknown"
    if auth_details and isinstance(auth_details, list) and len(auth_details) > 0:
        auth_method = auth_details[0].get("authenticationMethod", "Unknown")

    location_details = signin_log.get("LocationDetails", {})
    device_detail = signin_log.get("DeviceDetail", {})

    is_success, failure_reason = extract_failure_reason(signin_log)

    return EventDetails(
        event_id=signin_log.get("CorrelationId", signin_log.get("Id", "Unknown")),
        timestamp=signin_log.get(
            "TimeGenerated", signin_log.get("CreatedDateTime", "Unknown")
        ),
        user_principal_name=signin_log.get("UserPrincipalName", "Unknown"),
        user_id=signin_log.get("UserId", "Unknown"),
        user_display_name=signin_log.get(
            "UserDisplayName", signin_log.get("Identity", "Unknown")
        ),
        user_type=signin_log.get("UserType", "Unknown"),
        authentication_method=auth_method,
        authentication_requirement=signin_log.get(
            "AuthenticationRequirement", "Unknown"
        ),
        result_type=str(signin_log.get("ResultType", "Unknown")),
        result_signature=signin_log.get("ResultSignature", "Unknown"),
        result_description=failure_reason if not is_success else "Success",
        ip_address=signin_log.get("IPAddress", "Unknown"),
        location_city=location_details.get("city"),
        location_state=location_details.get("state"),
        location_country=location_details.get("countryOrRegion", "Unknown"),
        app_display_name=signin_log.get("AppDisplayName", "Unknown"),
        app_id=signin_log.get("AppId", "Unknown"),
        resource_display_name=signin_log.get("ResourceDisplayName"),
        operating_system=device_detail.get("operatingSystem"),
        browser=device_detail.get("browser"),
        is_success=is_success,
        failure_reason=failure_reason if not is_success else None,
    )


# ============================================================================
# DYNAMIC TIME GAP ANALYSIS - NO HARDCODING
# ============================================================================


def calculate_dynamic_time_gap(events: List[EventDetails]) -> int:
    """
    Dynamically calculate optimal time gap for clustering events
    Based on inter-event time distribution analysis
    """

    if len(events) < 2:
        return 300  # Default 5 minutes for single event

    # Calculate time gaps between consecutive events
    time_gaps = []
    for i in range(len(events) - 1):
        try:
            t1 = datetime.fromisoformat(events[i].timestamp.replace("Z", "+00:00"))
            t2 = datetime.fromisoformat(events[i + 1].timestamp.replace("Z", "+00:00"))
            gap_seconds = (t2 - t1).total_seconds()
            if gap_seconds >= 0:  # Only positive gaps
                time_gaps.append(gap_seconds)
        except:
            continue

    if not time_gaps:
        return 300  # Default if parsing fails

    # Statistical analysis of gaps
    time_gaps.sort()

    # Calculate percentiles and statistics
    q1 = np.percentile(time_gaps, 25)
    q3 = np.percentile(time_gaps, 75)
    iqr = q3 - q1
    median = np.percentile(time_gaps, 50)
    mean = statistics.mean(time_gaps)

    # Outlier detection using IQR method
    lower_bound = q1 - 1.5 * iqr
    upper_bound = q3 + 1.5 * iqr

    normal_gaps = [g for g in time_gaps if lower_bound <= g <= upper_bound]

    if normal_gaps:
        # Use 1.5x the median of normal gaps as clustering threshold
        threshold = median * 1.5
    else:
        # Fallback to mean if all gaps are outliers
        threshold = mean * 1.5

    # Cap threshold between 60 seconds (1 min) and 3600 seconds (1 hour)
    threshold = max(60, min(3600, threshold))

    return int(threshold)


def cluster_user_events(
    events: List[EventDetails], dynamic_gap: Optional[int] = None
) -> List[EventCluster]:
    """
    Cluster events based on temporal proximity
    Uses dynamic time gap if not provided
    """

    if not events:
        return []

    if dynamic_gap is None:
        dynamic_gap = calculate_dynamic_time_gap(events)

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
            gap = (t_curr - t_prev).total_seconds()

            if gap <= dynamic_gap:
                # Add to current cluster
                current_cluster.append(events_sorted[i])
            else:
                # Start new cluster
                if current_cluster:
                    clusters.append(create_cluster(current_cluster, len(clusters)))
                current_cluster = [events_sorted[i]]
        except:
            current_cluster.append(events_sorted[i])

    # Add final cluster
    if current_cluster:
        clusters.append(create_cluster(current_cluster, len(clusters)))

    return clusters


def create_cluster(events: List[EventDetails], cluster_idx: int) -> EventCluster:
    """Create an EventCluster from a list of events"""

    times = [datetime.fromisoformat(e.timestamp.replace("Z", "+00:00")) for e in events]
    start_time = min(times)
    end_time = max(times)
    duration = int((end_time - start_time).total_seconds())

    unique_apps = len(set(e.app_id for e in events))
    unique_locations = len(
        set(f"{e.location_city},{e.location_country}" for e in events)
    )

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
# ENHANCED FAILURE ANALYSIS
# ============================================================================


def analyze_failures(events: List[EventDetails]) -> Dict:
    """Analyze failure patterns with detailed reasons"""

    failures = [e for e in events if not e.is_success]

    if not failures:
        return {
            "total_failures": 0,
            "success_rate": 100.0,
            "failure_reasons": [],
            "critical_failures": 0,
            "failed_event_timeline": [],
        }

    # Group failures by reason
    failure_groups = defaultdict(list)
    for failure in failures:
        reason = failure.result_description or "Unknown"
        failure_groups[reason].append(failure)

    # Classify severity
    critical_keywords = [
        "strong authentication required",
        "account does not exist",
        "permission denied",
        "unauthorized",
        "access denied",
    ]

    critical_count = 0
    for reason, fail_list in failure_groups.items():
        if any(keyword in reason.lower() for keyword in critical_keywords):
            critical_count += len(fail_list)

    failure_timeline = [
        {
            "timestamp": f.timestamp,
            "app": f.app_display_name,
            "reason": f.result_description,
            "location": f"{f.location_city}, {f.location_country}",
        }
        for f in sorted(failures, key=lambda e: e.timestamp)
    ]

    success_rate = ((len(events) - len(failures)) / len(events) * 100) if events else 0

    return {
        "total_failures": len(failures),
        "success_rate": round(success_rate, 2),
        "failure_reasons": [
            {
                "reason": reason,
                "count": len(fail_list),
                "severity": (
                    "CRITICAL"
                    if any(keyword in reason.lower() for keyword in critical_keywords)
                    else "WARNING"
                ),
            }
            for reason, fail_list in failure_groups.items()
        ],
        "critical_failures": critical_count,
        "failed_event_timeline": failure_timeline[:10],  # Last 10 failures
    }


# ============================================================================
# RISK SCORING - UPDATED VERSION
# ============================================================================


def calculate_user_risk_score(
    upn: str, events: List[EventDetails], clusters: List[EventCluster]
) -> Tuple[int, List[str]]:
    """Enhanced risk scoring with failure consideration"""

    risk_score = 1
    risk_factors = []

    # Factor 1: Cluster-based anomalies
    if len(clusters) > 3:
        risk_score += 2
        risk_factors.append(f"Multiple activity clusters: {len(clusters)}")

    # Factor 2: Failure analysis
    failure_info = analyze_failures(events)

    if failure_info["total_failures"] > 2:
        risk_score += 3
        risk_factors.append(
            f"High failure count: {failure_info['total_failures']} "
            f"({failure_info['success_rate']}% success rate)"
        )

    if failure_info["critical_failures"] > 0:
        risk_score += 2
        risk_factors.append(
            f"Critical failures detected: {failure_info['critical_failures']}"
        )

    # Factor 3: Geographic anomalies
    unique_locations = len(
        set(f"{e.location_city},{e.location_country}" for e in events)
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

    if single_factor > multi_factor * 2:
        risk_score += 1
        risk_factors.append("Predominantly single-factor authentication")

    # Factor 6: Guest user access
    if events and "guest" in events[0].user_type.lower():
        risk_score += 1
        risk_factors.append("Guest user cross-tenant access")

    # Factor 7: Multiple application access
    unique_apps = len(set(e.app_id for e in events))
    if unique_apps > 5:
        risk_score += 1
        risk_factors.append(f"Accessing {unique_apps} different applications")

    # Factor 8: Cluster location changes
    location_changes = 0
    for i in range(len(clusters) - 1):
        loc1 = f"{clusters[i].events[0].location_city},{clusters[i].events[0].location_country}"
        loc2 = f"{clusters[i+1].events[0].location_city},{clusters[i+1].events[0].location_country}"
        if loc1 != loc2:
            location_changes += 1

    if location_changes > 1:
        risk_score += 1
        risk_factors.append(f"Location changes between clusters: {location_changes}")

    # Cap risk score
    risk_score = min(risk_score, 10)

    return risk_score, risk_factors


# ============================================================================
# ACTIVITY GROUP CREATION
# ============================================================================


def create_user_activity_summary(
    upn: str, events: List[EventDetails]
) -> UserActivityGroup:
    """Create comprehensive activity summary with cluster analysis"""

    if not events:
        return None

    # Calculate dynamic time gap
    dynamic_gap = calculate_dynamic_time_gap(events)

    # Create clusters
    clusters = cluster_user_events(events, dynamic_gap)

    # Risk assessment
    risk_score, risk_factors = calculate_user_risk_score(upn, events, clusters)

    # Location analysis
    locations = []
    for event in events:
        loc = {
            "city": event.location_city,
            "state": event.location_state,
            "country": event.location_country,
            "ip_address": event.ip_address,
            "timestamp": event.timestamp,
        }
        if loc not in locations:
            locations.append(loc)

    # Application analysis
    applications = []
    app_access_count = defaultdict(int)
    for event in events:
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
    auth_summary = {
        "methods": list(
            set(
                e.authentication_method
                for e in events
                if e.authentication_method != "Unknown"
            )
        ),
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

    # Cluster details for timeline
    cluster_details = [
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
        for c in clusters
    ]

    # Timeline
    timeline = [
        {
            "timestamp": e.timestamp,
            "app": e.app_display_name,
            "location": f"{e.location_city}, {e.location_country}",
            "ip_address": e.ip_address,
            "browser": e.browser,
            "os": e.operating_system,
            "result": (
                "✅ Success" if e.is_success else f"❌ Failed: {e.result_description}"
            ),
            "auth_method": e.authentication_method,
        }
        for e in events
    ]

    # Behavioral anomalies
    anomalies = []

    if failure_analysis["total_failures"] > 3:
        anomalies.append(
            f"Suspicious failure pattern: {failure_analysis['total_failures']} failures"
        )

    if len(clusters) > 3:
        anomalies.append(
            f"Multiple distinct activity sessions: {len(clusters)} clusters"
        )
        
    unique_apps = len(set(e.app_id for e in events))
    if unique_apps > 5:
        anomalies.append(f"Access to {unique_apps} applications (unusually high)")

    first_event = events[0]

    return UserActivityGroup(
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


# ============================================================================
# DATA GROUPING
# ============================================================================


def group_events_by_user(log_data: dict) -> Dict[str, List[EventDetails]]:
    """Group all sign-in events by user"""

    user_groups: Dict[str, List[EventDetails]] = defaultdict(list)

    for signin_log in log_data.get("SigninLogs", []):
        try:
            event = extract_complete_event_data(signin_log)
            user_groups[event.user_principal_name].append(event)
        except Exception as e:
            print(f"⚠️ Error parsing event: {e}")
            continue

    # Sort events by timestamp
    for upn in user_groups:
        user_groups[upn].sort(key=lambda e: e.timestamp)

    return dict(user_groups)


# ============================================================================
# REPORT GENERATION
# ============================================================================


def generate_json_report(user_groups: Dict[str, UserActivityGroup], output_path: str):
    """Generate comprehensive JSON report"""

    high_risk = []
    medium_risk = []
    low_risk = []

    for upn, group in user_groups.items():
        group_dict = group.model_dump()

        if group.risk_score >= 7:
            high_risk.append(group_dict)
        elif group.risk_score >= 5:
            medium_risk.append(group_dict)
        else:
            low_risk.append(group_dict)

    report = {
        "report_metadata": {
            "generated_at": datetime.now().isoformat(),
            "report_type": "Advanced Security Correlation Analysis v4.0",
            "total_users": len(user_groups),
            "total_events": sum(g.total_events for g in user_groups.values()),
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

    print(f"✅ JSON report saved to {output_path}")


def generate_markdown_report(
    user_groups: Dict[str, UserActivityGroup], output_path: str
):
    """Generate comprehensive markdown report"""

    md_report = f"""# 🔒 Advanced Security Correlation Analysis Report v4.0

**Generated:** {datetime.now().isoformat()}  
**Report Type:** Enhanced Cluster-Based User Activity Correlation with Failure Analysis  
**Total Users:** {len(user_groups)}  
**Total Events:** {sum(g.total_events for g in user_groups.values())}  

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

## 🔴 CRITICAL PRIORITY - Risk Score 7-10

"""

    for group in sorted(high_risk, key=lambda g: g.risk_score, reverse=True)[:5]:
        md_report += f"""
### {group.user_display_name} ({group.user_principal_name})

**Risk Score:** {group.risk_score}/10 | **Events:** {group.total_events} | **Clusters:** {group.total_clusters}

#### 🎯 Key Risk Factors
{chr(10).join(f"- {factor}" for factor in group.risk_factors[:5])}

#### ❌ Failure Analysis
- **Total Failures:** {group.failure_analysis['total_failures']}
- **Success Rate:** {group.failure_analysis['success_rate']}%
- **Critical Failures:** {group.failure_analysis['critical_failures']}

**Failure Reasons:**
"""
        for failure in group.failure_analysis["failure_reasons"][:3]:
            md_report += f"- {failure['reason']} (Count: {failure['count']}, Severity: {failure['severity']})\n"

        md_report += f"""
#### 📍 Geographic Activity
"""
        for loc in group.locations[:5]:
            md_report += f"- {loc['city']}, {loc['state']} ({loc['country']}) - IP: {loc['ip_address']}\n"

        md_report += f"""
#### 💻 Applications ({group.unique_apps})
"""
        for app in sorted(
            group.applications, key=lambda x: x["access_count"], reverse=True
        )[:5]:
            md_report += f"- {app['app_name']} - {app['access_count']} accesses\n"

        md_report += f"""
#### 📅 Activity Clusters ({group.total_clusters})
"""
        for cluster in group.clusters[:3]:
            md_report += f"- {cluster['cluster_id']}: {cluster['event_count']} events, {cluster['duration_seconds']}s duration, Failures: {cluster['failure_count']}\n"

        md_report += "\n---\n"

    md_report += f"""

## 🟡 MEDIUM PRIORITY - Risk Score 5-6

"""

    for group in sorted(medium_risk, key=lambda g: g.risk_score, reverse=True)[:10]:
        md_report += f"""
### {group.user_display_name}

**Score:** {group.risk_score}/10 | **Events:** {group.total_events} | **Failures:** {group.failure_analysis['total_failures']} | **Clusters:** {group.total_clusters}

**Risk Factors:** {', '.join(group.risk_factors[:3])}

---
"""

    md_report += f"""

## 🟢 LOW PRIORITY - Risk Score 1-4

**Count:** {len(low_risk)} users | Minimal suspicious activity

---

**Report Generated By:** Advanced Security Correlation Engine v4.0  
**Analysis Date:** {datetime.now().isoformat()}
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(md_report)

    print(f"✅ Markdown report saved to {output_path}")


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

    print("📊 Creating activity summaries with cluster analysis...")
    user_groups = {}
    for upn, events in user_events.items():
        summary = create_user_activity_summary(upn, events)
        if summary:
            user_groups[upn] = summary
    print(f"   ✅ Analyzed {len(user_groups)} users\n")

    return user_groups


def main():
    """Main execution with folder processing"""
    print("🚀 Starting Advanced Security Correlation Engine v4.0\n")

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
