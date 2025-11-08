import json
import os
from datetime import datetime
from typing import Dict, List, Optional


def parse_timestamp(timestamp_str: str) -> datetime:
    """Parse ISO timestamp string to datetime object"""
    try:
        # Handle both with and without microseconds
        if '.' in timestamp_str:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        else:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
    except Exception as e:
        print(f"⚠️ Error parsing timestamp {timestamp_str}: {e}")
        return None


def match_behavior_to_signin(signin_log: Dict, behavior_analytics: List[Dict]) -> Optional[Dict]:
    """
    Match a SigninLog entry with corresponding BehaviorAnalytics entry
    Based on UserPrincipalName and TimeGenerated
    """
    signin_upn = signin_log.get('UserPrincipalName', '').lower()
    signin_time = parse_timestamp(signin_log.get('TimeGenerated', ''))
    
    if not signin_upn or not signin_time:
        return None
    
    # Find matching behavior analytics entry
    for behavior in behavior_analytics:
        behavior_upn = behavior.get('UserPrincipalName', '').lower()
        behavior_time = parse_timestamp(behavior.get('TimeGenerated', ''))
        
        if not behavior_upn or not behavior_time:
            continue
        
        # Match on UserPrincipalName and exact TimeGenerated
        if signin_upn == behavior_upn and signin_time == behavior_time:
            devices_insights = behavior.get('DevicesInsights', {})
            activity_insights = behavior.get('ActivityInsights', {})
            action_type = behavior.get('ActionType', '')
            activity_type = behavior.get('ActivityType', '')
            return devices_insights, activity_insights, action_type, activity_type
    
    return None


def remove_specified_columns(signin_log: Dict, columns_to_remove: List[str]) -> Dict:
    """
    Remove specified columns from a signin log entry
    """
    cleaned_log = signin_log.copy()
    
    for column in columns_to_remove:
        if column in cleaned_log:
            del cleaned_log[column]
    
    return cleaned_log


def clean_azure_logs(
    input_file_path: str, 
    output_file_path: str = None,
    columns_to_remove: List[str] = None
) -> Dict:
    """
    Clean Azure AD logs by:
    1. Removing BehaviorAnalytics table
    2. Adding DevicesInsights to SigninLogs
    3. Optionally removing specified columns from SigninLogs
    """
    if not os.path.exists(input_file_path):
        print(f"❌ File not found: {input_file_path}")
        return None

    try:
        # Load the original JSON data
        with open(input_file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)

        print(f"\n{'='*60}")
        print(f"📊 Processing: {os.path.basename(input_file_path)}")
        print(f"{'='*60}")
        print(f"📋 Original tables: {list(data.keys())}")

        # Extract BehaviorAnalytics before removing it
        behavior_analytics = data.get('BehaviorAnalytics', [])
        print(f"📱 Found {len(behavior_analytics)} BehaviorAnalytics entries")

        # Create cleaned data structure
        cleaned_data = {}
        
        # Process each table
        for table_name, table_data in data.items():
            if table_name == 'BehaviorAnalytics':
                print(f"🗑️  Removing BehaviorAnalytics table")
                continue
            
            elif table_name == 'SigninLogs':
                print(f"🔄 Processing SigninLogs...")
                cleaned_signin_logs = []
                matched_count = 0
                
                for signin_log in table_data:
                    # Create a copy of the signin log
                    cleaned_log = signin_log.copy()
                    
                    # Try to match with BehaviorAnalytics
                    result = match_behavior_to_signin(signin_log, behavior_analytics)

                    if result:
                        devices_insights, activity_insights, action_type, activity_type = result
                        if devices_insights:
                            cleaned_log['DevicesInsights'] = devices_insights
                            matched_count += 1
                        else:
                            cleaned_log['DevicesInsights'] = {}
                        if activity_insights:
                            cleaned_log['ActivityInsights'] = activity_insights
                            matched_count += 1
                        else:
                            cleaned_log['ActivityInsights'] = {}
                        cleaned_log['ActionType'] = action_type
                        cleaned_log['ActivityType'] = activity_type
                    else:
                        cleaned_log['DevicesInsights'] = {}
                        cleaned_log['ActivityInsights'] = {}
                        cleaned_log['ActionType'] = ''
                        cleaned_log['ActivityType'] = ''
                    
                    # Remove specified columns if provided
                    if columns_to_remove:
                        cleaned_log = remove_specified_columns(cleaned_log, columns_to_remove)
                    
                    cleaned_signin_logs.append(cleaned_log)
                
                cleaned_data[table_name] = cleaned_signin_logs
                print(f"   ✅ Processed {len(cleaned_signin_logs)} SigninLogs")
                print(f"   ✅ Matched {matched_count} entries with DevicesInsights ({matched_count/len(cleaned_signin_logs)*100:.1f}%)")
                
                if columns_to_remove:
                    print(f"   ✅ Removed {len(columns_to_remove)} columns from each entry")
                
            else:
                # Keep all other tables as-is
                cleaned_data[table_name] = table_data
                entry_count = len(table_data) if isinstance(table_data, list) else 'N/A'
                print(f"   ✅ Kept {table_name}: {entry_count} entries")

        # Generate output filename if not provided
        if output_file_path is None:
            input_dir = os.path.dirname(input_file_path)
            input_filename = os.path.basename(input_file_path)
            output_filename = f"cleaned_{input_filename}"
            output_file_path = os.path.join(input_dir, output_filename)

        # Save cleaned data
        with open(output_file_path, 'w', encoding='utf-8') as file:
            json.dump(cleaned_data, file, indent=2, ensure_ascii=False)

        print(f"\n✅ Cleaned data saved to: {output_file_path}")

        # Show statistics
        original_size = os.path.getsize(input_file_path)
        cleaned_size = os.path.getsize(output_file_path)
        reduction = ((original_size - cleaned_size) / original_size) * 100

        print(f"\n📦 Size comparison:")
        print(f"   Original: {original_size:,} bytes")
        print(f"   Cleaned:  {cleaned_size:,} bytes")
        print(f"   Reduction: {reduction:.1f}%")
        print(f"{'='*60}\n")

        return cleaned_data

    except Exception as e:
        print(f"❌ Error processing file: {e}")
        import traceback
        traceback.print_exc()
        return None


def process_directory(
    directory_path: str, 
    file_pattern: str = "sentinel_user_data_",
    columns_to_remove: List[str] = None
):
    """Process all JSON files in a directory"""
    if not os.path.exists(directory_path):
        print(f"❌ Directory not found: {directory_path}")
        return

    json_files = [
        f for f in os.listdir(directory_path)
        if f.startswith(file_pattern) and f.endswith('.json') and not f.startswith('cleaned_')
    ]

    if not json_files:
        print(f"⚠️  No files found matching pattern: {file_pattern}*.json")
        return

    print(f"\n📁 Processing directory: {directory_path}")
    print(f"📄 Found {len(json_files)} files to process\n")

    processed_count = 0
    for json_file in sorted(json_files):
        input_path = os.path.join(directory_path, json_file)
        result = clean_azure_logs(input_path, columns_to_remove=columns_to_remove)
        
        if result:
            processed_count += 1

    print(f"\n{'🎉'*20}")
    print(f"✅ Successfully processed {processed_count}/{len(json_files)} files")
    print(f"{'🎉'*20}\n")


def process_sentinel_logs_structure(
    base_directory: str = "sentinel_logs1",
    columns_to_remove: List[str] = None
):
    """Process entire directory structure"""
    if not os.path.exists(base_directory):
        print(f"❌ Base directory not found: {base_directory}")
        return

    print(f"\n{'='*60}")
    print(f"🌳 Processing directory structure: {base_directory}")
    print(f"{'='*60}")

    if columns_to_remove:
        print(f"🗑️  Will remove {len(columns_to_remove)} columns from SigninLogs:")
        for i, col in enumerate(columns_to_remove, 1):
            print(f"   {i}. {col}")
        print(f"{'='*60}\n")

    subdirs = [
        d for d in os.listdir(base_directory)
        if os.path.isdir(os.path.join(base_directory, d))
    ]

    if not subdirs:
        print(f"⚠️  No subdirectories found in {base_directory}")
        return

    print(f"📂 Found {len(subdirs)} subdirectories to process\n")

    total_processed = 0
    for subdir in sorted(subdirs):
        subdir_path = os.path.join(base_directory, subdir)
        print(f"\n{'='*60}")
        print(f"📂 Processing subdirectory: {subdir}")
        print(f"{'='*60}")
        
        process_directory(subdir_path, columns_to_remove=columns_to_remove)
        
        # Count cleaned files
        cleaned_files = [
            f for f in os.listdir(subdir_path)
            if f.startswith('cleaned_') and f.endswith('.json')
        ]
        total_processed += len(cleaned_files)

    print(f"\n{'🎉'*20}")
    print(f"COMPLETE: Processed {total_processed} files across {len(subdirs)} directories")
    print(f"{'🎉'*20}\n")


def analyze_cleaned_file(cleaned_file_path: str):
    """Analyze a cleaned file to verify changes"""
    if not os.path.exists(cleaned_file_path):
        print(f"❌ File not found: {cleaned_file_path}")
        return

    with open(cleaned_file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)

    print(f"\n{'='*60}")
    print(f"📊 Analysis: {os.path.basename(cleaned_file_path)}")
    print(f"{'='*60}")
    
    print(f"📋 Tables present: {[k for k in data.keys() if k != 'CleaningMetadata']}")
    
    # Check if BehaviorAnalytics was removed
    has_behavior = 'BehaviorAnalytics' in data
    print(f"🗑️  BehaviorAnalytics removed: {'❌ NO (still present)' if has_behavior else '✅ YES'}")
    
    # Analyze SigninLogs
    signin_logs = data.get('SigninLogs', [])
    if signin_logs:
        print(f"\n📝 SigninLogs analysis:")
        print(f"   Total entries: {len(signin_logs)}")
        print(f"   Fields per entry: {len(signin_logs[0])}")
        
        # Count entries with DevicesInsights
        with_insights = sum(1 for log in signin_logs if log.get('DevicesInsights') and log['DevicesInsights'])
        print(f"   Entries with DevicesInsights: {with_insights} ({with_insights/len(signin_logs)*100:.1f}%)")
        
        # Show sample DevicesInsights
        sample_with_insights = next((log for log in signin_logs if log.get('DevicesInsights') and log['DevicesInsights']), None)
        if sample_with_insights:
            print(f"\n   Sample DevicesInsights fields:")
            for key, value in sample_with_insights['DevicesInsights'].items():
                print(f"      - {key}: {value}")
        
        # Show remaining fields
        print(f"\n   Fields in cleaned SigninLogs:")
        for i, field in enumerate(sorted(signin_logs[0].keys()), 1):
            print(f"      {i}. {field}")
    
    # Show metadata
    metadata = data.get('CleaningMetadata', {})
    if metadata:
        print(f"\n🔧 Cleaning details:")
        print(f"   Cleaned at: {metadata.get('cleaned_at', 'N/A')}")
        print(f"   Tables removed: {metadata.get('tables_removed', [])}")
        print(f"   Fields removed: {len(metadata.get('fields_removed_from_signinlogs', []))}")
        print(f"   Matching criteria: {metadata.get('matching_criteria', 'N/A')}")
    
    print(f"{'='*60}\n")


def main():
    """Main execution function"""
    print("\n" + "="*60)
    print("🚀 Azure AD Logs Cleaner Tool")
    print("="*60)
    print("📋 Operations:")
    print("   1. ❌ Remove BehaviorAnalytics table")
    print("   2. ✅ Add DevicesInsights to SigninLogs")
    print("   3. 🔗 Match by UserPrincipalName + TimeGenerated")
    print("   4. 🗑️  Remove specified columns (optional)")
    print("="*60 + "\n")

    # CUSTOMIZE HERE: Add columns you want to remove from SigninLogs
    columns_to_remove = [
        "TenantId",
        "SourceSystem",
        "ResourceId",
        "AlternateSignInName",
        "ServicePrincipalId",
        "AADTenantId",
        "ResourceTenantId",
        "HomeTenantId",
        "AppOwnerTenantId",
        "ResourceOwnerTenantId",
        "FlaggedForReview",
        "xy_CF",
        "OperationVersion",
        "Category",
        "DurationMs",
        "CorrelationId",
        "Resource",
        "ResourceGroup",
        "AuthenticationContextClassReferences",
        "ResourceProvider",
        "IsInteractive",
        "ProcessingTimeInMilliseconds",
        "TokenIssuerName",
        "AuthenticationProtocol",
        "IsTenantRestricted",
        "AppliedEventListeners",
        "AuthenticationRequirementPolicies",
        "IsRisky",
        "RiskEventTypes",
        "RiskDetail",
        "RiskLevelAggregated",
        "RiskLevelDuringSignIn",
        "ServicePrincipalId",
        "Type",
        "RiskLevel",
        "SourceAppClientId",
        "Agent",
        "OriginalTransferMethod",
        "IsThroughGlobalSecureAccess",
        "IncomingTokenType",
        "HomeTenantName",
        "CrossTenantAccessType",
        "Level",
        "RiskState",
        "RiskEventTypes_V2",
        "TokenIssuerType",
        "ClientCredentialType",
        "FederatedCredentialId",
        "Status",
        "ResourceIdentity",
        "ResourceServicePrincipalId",
        "ServicePrincipalName",
        "IPAddressFromResourceProvider",
        "SignInIdentifier",
        "SignInIdentifierType",
        "SessionLifetimePolicies",
        "AutonomousSystemNumber",
        "AuthenticationAppDeviceDetails",
        "Location",
        # Add more columns here...
    ]

    # Process entire directory structure
    process_sentinel_logs_structure("sentinel_logs1", columns_to_remove=columns_to_remove)

    # Optional: Analyze a specific cleaned file
    # analyze_cleaned_file("path/to/cleaned_file.json")


if __name__ == "__main__":
    main()
