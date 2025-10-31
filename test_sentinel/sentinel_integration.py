import os
import json
import requests
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential
from datetime import datetime

load_dotenv()

subscription_id = os.getenv("SUBSCRIPTION_ID")
resource_group = os.getenv("RESOURCE_GROUP")
workspace_name = os.getenv("WORKSPACE_NAME")

credential = DefaultAzureCredential()
token = credential.get_token("https://management.azure.com/.default").token

headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

# Sample incident ID
incident_id = "3e308218-8fbc-4084-b8c0-e7001e6a58c1" 
# incident_id = "5841af33-a201-4621-a206-f3f037c5e5f8"
# incident_id = "3e308218-8fbc-4084-b8c0-e7001e6a58c1"

# Construct full incident resource ID
incident_resource_id = (
    f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/"
    f"Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/"
    f"Microsoft.SecurityInsights/Incidents/{incident_id}"
)

base_workspace_url = (
    f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/"
    f"Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights"
)


def save_to_file(data, filename):
    """Save data to a JSON file"""
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print(f"✓ Saved to {filename}")


def fetch_with_error_handling(url, method="GET", data=None):
    """Fetch data with error handling"""
    try:
        if method == "POST":
            response = requests.post(url, headers=headers, json=data)
        else:
            response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            print(f"  ⚠ Failed: {response.status_code} - {response.text[:200]}")
            return None
    except Exception as e:
        print(f"  ✗ Error: {str(e)}")
        return None


# Create output directory
output_dir = f"incident_{incident_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
os.makedirs(output_dir, exist_ok=True)
print(f"\n📁 Creating output directory: {output_dir}\n")

all_data = {"fetched_at": datetime.now().isoformat(), "incident_id": incident_id}

# 1. Fetch Incident Details
print("1️⃣  Fetching Incident Details...")
incident_url = (
    f"https://management.azure.com{incident_resource_id}?api-version=2025-09-01"
)
incident_details = fetch_with_error_handling(incident_url)
if incident_details:
    all_data["incident_details"] = incident_details
    save_to_file(incident_details, f"{output_dir}/01_incident_details.json")

# 2. Fetch Related Alerts
print("\n2️⃣  Fetching Related Alerts...")
alerts_url = (
    f"https://management.azure.com{incident_resource_id}/alerts?api-version=2025-09-01"
)
alerts = fetch_with_error_handling(alerts_url, method="POST")
if alerts:
    all_data["alerts"] = alerts
    save_to_file(alerts, f"{output_dir}/02_related_alerts.json")

# 3. Fetch Related Entities
print("\n3️⃣  Fetching Related Entities (Users, IPs, Hosts, etc.)...")
entities_url = f"https://management.azure.com{incident_resource_id}/entities?api-version=2025-09-01"
entities = fetch_with_error_handling(entities_url, method="POST")
if entities:
    all_data["entities"] = entities
    save_to_file(entities, f"{output_dir}/03_related_entities.json")

    # Print entity summary
    if "entities" in entities:
        entity_types = {}
        for entity in entities.get("entities", []):
            kind = entity.get("kind", "Unknown")
            entity_types[kind] = entity_types.get(kind, 0) + 1
        print(f"  Found entities: {dict(entity_types)}")

# 4. Fetch Incident Comments
print("\n4️⃣  Fetching Incident Comments...")
comments_url = f"https://management.azure.com{incident_resource_id}/comments?api-version=2025-09-01"
comments = fetch_with_error_handling(comments_url)
if comments:
    all_data["comments"] = comments
    save_to_file(comments, f"{output_dir}/04_incident_comments.json")

# 5. Fetch Related Bookmarks
print("\n5️⃣  Fetching Related Bookmarks...")
bookmarks_url = f"https://management.azure.com{incident_resource_id}/bookmarks?api-version=2025-09-01"
bookmarks = fetch_with_error_handling(bookmarks_url, method="POST")
if bookmarks:
    all_data["bookmarks"] = bookmarks
    save_to_file(bookmarks, f"{output_dir}/05_related_bookmarks.json")

# 6. Fetch Incident Relations
print("\n6️⃣  Fetching Incident Relations...")
relations_url = f"https://management.azure.com{incident_resource_id}/relations?api-version=2025-09-01"
relations = fetch_with_error_handling(relations_url)
if relations:
    all_data["relations"] = relations
    save_to_file(relations, f"{output_dir}/06_incident_relations.json")

# 7. Fetch Alert Rules (Analytics Rules)
print("\n7️⃣  Fetching Related Alert Rules...")
if incident_details and "properties" in incident_details:
    rule_ids = incident_details["properties"].get("relatedAnalyticRuleIds", [])
    alert_rules = []
    for rule_id in rule_ids:
        rule_url = f"https://management.azure.com{rule_id}?api-version=2025-09-01"
        rule_data = fetch_with_error_handling(rule_url)
        if rule_data:
            alert_rules.append(rule_data)

    if alert_rules:
        all_data["alert_rules"] = alert_rules
        save_to_file(alert_rules, f"{output_dir}/07_alert_rules.json")

# 8. Fetch Alert Evidence/Entities (Extended Details)
print("\n8️⃣  Fetching Alert Evidence and Extended Properties...")
if alerts and "value" in alerts:
    alert_evidence = []
    for idx, alert in enumerate(alerts["value"]):
        alert_id = alert.get("name")
        props = alert.get("properties", {})

        # Collect extended evidence
        evidence = {
            "alert_id": alert_id,
            "alert_name": props.get("alertDisplayName"),
            "confidence_level": props.get("confidenceLevel"),
            "confidence_score": props.get("confidenceScore"),
            "confidence_score_status": props.get("confidenceScoreStatus"),
            "remediation_steps": props.get("remediationSteps", []),
            "alert_link": props.get("alertLink"),
            "resource_identifiers": props.get("resourceIdentifiers", []),
            "additional_data": props.get("additionalData", {}),
            "compromised_entity": props.get("compromisedEntity"),
            "intent": props.get("intent"),
            "techniques": props.get("techniques", []),
            "sub_techniques": props.get("subTechniques", []),
        }
        alert_evidence.append(evidence)

    if alert_evidence:
        all_data["alert_evidence"] = alert_evidence
        save_to_file(alert_evidence, f"{output_dir}/08_alert_evidence.json")

# 9. Query Log Analytics for Raw Logs (if we have alert details)
print("\n9️⃣  Preparing Log Analytics Query...")
if alerts and "value" in alerts and len(alerts["value"]) > 0:
    alert_data = alerts["value"][0]
    alert_properties = alert_data.get("properties", {})

    # Extract time range
    start_time = alert_properties.get("startTimeUtc")
    end_time = alert_properties.get("endTimeUtc")
    system_alert_id = alert_properties.get("systemAlertId")

    # Extract entities for filtering
    entity_filter_info = {
        "timeRange": {"start": start_time, "end": end_time},
        "alertId": system_alert_id,
        "providerAlertId": alert_properties.get("providerAlertId"),
        "severity": alert_properties.get("severity"),
        "alertType": alert_properties.get("alertType"),
        "tactics": alert_properties.get("tactics", []),
        "techniques": alert_properties.get("techniques", []),
    }

    # Save query information
    save_to_file(entity_filter_info, f"{output_dir}/09_log_query_info.json")

    print("\n  📝 Log Analytics Query Templates:")
    print(
        f"""
    // Query 1: Fetch SecurityAlert details
    SecurityAlert
    | where TimeGenerated between (datetime({start_time}) .. datetime({end_time}))
    | where SystemAlertId == "{system_alert_id}"
    | extend ParsedEntities = parse_json(Entities)
    | extend ParsedExtendedProperties = parse_json(ExtendedProperties)
    | project TimeGenerated, AlertName, AlertSeverity, Description, 
              Entities, ExtendedProperties, CompromisedEntity, 
              RemediationSteps, Tactics, Techniques
    
    // Query 2: Fetch related sign-in logs
    SigninLogs
    | where TimeGenerated between (datetime({start_time}) .. datetime({end_time}))
    | where ResultType != 0  // Failed sign-ins
    | project TimeGenerated, UserPrincipalName, IPAddress, Location, 
              AppDisplayName, ResultType, ResultDescription, 
              AuthenticationRequirement, RiskState, RiskLevelDuringSignIn,
              DeviceDetail, Status, ConditionalAccessStatus
    
    // Query 3: Fetch Azure AD audit logs
    AuditLogs
    | where TimeGenerated between (datetime({start_time}) .. datetime({end_time}))
    | where Result == "failure"
    | project TimeGenerated, OperationName, Result, ResultDescription,
              InitiatedBy, TargetResources, AdditionalDetails
    """
    )

# 10. Fetch Automation Rules triggered by this incident
print("\n🔟 Fetching Automation Rules...")
automation_rules_url = f"{base_workspace_url}/automationRules?api-version=2025-09-01"
automation_rules = fetch_with_error_handling(automation_rules_url)
if automation_rules:
    # Filter rules that might have triggered for this incident
    relevant_rules = []
    if "value" in automation_rules:
        for rule in automation_rules["value"]:
            rule_props = rule.get("properties", {})
            # Check if rule is enabled and matches incident criteria
            if rule_props.get("triggering_logic", {}).get("is_enabled", False):
                relevant_rules.append(rule)

    if relevant_rules:
        all_data["automation_rules"] = relevant_rules
        save_to_file(relevant_rules, f"{output_dir}/10_automation_rules.json")

# 11. Fetch Threat Intelligence Indicators related to entities
print("\n1️⃣1️⃣  Fetching Threat Intelligence Indicators...")
threat_intel_url = (
    f"{base_workspace_url}/threatIntelligence/main/indicators?api-version=2025-09-01"
)
threat_intel = fetch_with_error_handling(threat_intel_url)
if threat_intel:
    all_data["threat_intelligence"] = threat_intel
    save_to_file(threat_intel, f"{output_dir}/11_threat_intelligence.json")

# 12. Fetch Watchlists that might be related
print("\n1️⃣2️⃣  Fetching Watchlists...")
watchlists_url = f"{base_workspace_url}/watchlists?api-version=2025-09-01"
watchlists = fetch_with_error_handling(watchlists_url)
if watchlists:
    all_data["watchlists"] = watchlists
    save_to_file(watchlists, f"{output_dir}/12_watchlists.json")

# 13. Fetch Workspace Details
print("\n1️⃣3️⃣  Fetching Workspace Information...")
workspace_url = (
    f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/"
    f"Microsoft.OperationalInsights/workspaces/{workspace_name}?api-version=2022-10-01"
)
workspace_info = fetch_with_error_handling(workspace_url)
if workspace_info:
    all_data["workspace_info"] = workspace_info
    save_to_file(workspace_info, f"{output_dir}/13_workspace_info.json")

# Save combined data
print("\n💾 Saving Complete Dataset...")
save_to_file(all_data, f"{output_dir}/00_complete_incident_data.json")

# Generate Summary Report
print("\n" + "=" * 80)
print("📊 INCIDENT SUMMARY REPORT")
print("=" * 80)

if incident_details:
    props = incident_details.get("properties", {})
    print(f"\n🎯 Incident: {props.get('title')}")
    print(f"   ID: {props.get('incidentNumber')}")
    print(f"   Severity: {props.get('severity')}")
    print(f"   Status: {props.get('status')}")
    print(f"   Created: {props.get('createdTimeUtc')}")
    print(f"   First Activity: {props.get('firstActivityTimeUtc')}")
    print(f"   Last Activity: {props.get('lastActivityTimeUtc')}")

    additional = props.get("additionalData", {})
    print(f"\n📈 Statistics:")
    print(f"   Alerts: {additional.get('alertsCount', 0)}")
    print(f"   Comments: {additional.get('commentsCount', 0)}")
    print(f"   Bookmarks: {additional.get('bookmarksCount', 0)}")

    if entities and "entities" in entities:
        print(f"   Entities: {len(entities['entities'])}")

print(f"\n✅ All data saved to: {output_dir}/")
print(f"📄 Main file: {output_dir}/00_complete_incident_data.json")
print("\n" + "=" * 80)
