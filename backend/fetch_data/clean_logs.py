import json
import os
from datetime import datetime
from typing import Dict, List, Optional


def parse_timestamp(timestamp_str: str) -> datetime:
    """Parse ISO timestamp string to datetime object"""
    try:
        # Handle both with and without microseconds
        if "." in timestamp_str:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        else:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    except Exception as e:
        print(f"⚠️ Error parsing timestamp {timestamp_str}: {e}")
        return None


def clean_user_data_file(input_file_path: str, output_path: str = None) -> str:
    """
    Clean a single user data file (simplified for workflow)

    Args:
        input_file_path: Path to the input JSON file
        output_path: Optional output path (auto-generated if None)

    Returns:
        Path to cleaned file, or None if failed
    """

    # Define columns to remove
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
    ]

    result = clean_azure_logs(
        input_file_path,
        output_file_path=output_path,
        columns_to_remove=columns_to_remove,
    )

    if result:
        # Return the output path
        if output_path:
            return output_path
        else:
            # Generate the auto-created filename
            input_dir = os.path.dirname(input_file_path)
            input_filename = os.path.basename(input_file_path)
            output_filename = f"cleaned_{input_filename}"
            return os.path.join(input_dir, output_filename)

    return None


def match_behavior_to_signin(
    signin_log: Dict, behavior_analytics: List[Dict]
) -> Optional[Dict]:
    """
    Match a SigninLog entry with corresponding BehaviorAnalytics entry
    Based on UserPrincipalName and TimeGenerated
    """
    signin_upn = signin_log.get("UserPrincipalName", "").lower()
    signin_time = parse_timestamp(signin_log.get("TimeGenerated", ""))

    if not signin_upn or not signin_time:
        return None

    # Find matching behavior analytics entry
    for behavior in behavior_analytics:
        behavior_upn = behavior.get("UserPrincipalName", "").lower()
        behavior_time = parse_timestamp(behavior.get("TimeGenerated", ""))

        if not behavior_upn or not behavior_time:
            continue

        # Match on UserPrincipalName and exact TimeGenerated
        if signin_upn == behavior_upn and signin_time == behavior_time:
            devices_insights = behavior.get("DevicesInsights", {})
            activity_insights = behavior.get("ActivityInsights", {})
            action_type = behavior.get("ActionType", "")
            activity_type = behavior.get("ActivityType", "")
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
    columns_to_remove: List[str] = None,
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
        with open(input_file_path, "r", encoding="utf-8") as file:
            data = json.load(file)

        print(f"\n{'='*60}")
        print(f"📊 Processing: {os.path.basename(input_file_path)}")
        print(f"{'='*60}")
        print(f"📋 Original tables: {list(data.keys())}")

        # Extract BehaviorAnalytics before removing it
        behavior_analytics = data.get("BehaviorAnalytics", [])
        print(f"📱 Found {len(behavior_analytics)} BehaviorAnalytics entries")

        # Create cleaned data structure
        cleaned_data = {}

        # Process each table
        for table_name, table_data in data.items():
            if table_name == "BehaviorAnalytics":
                print(f"🗑️  Removing BehaviorAnalytics table")
                continue

            elif table_name == "SigninLogs":
                print(f"🔄 Processing SigninLogs...")
                cleaned_signin_logs = []
                matched_count = 0

                for signin_log in table_data:
                    # Create a copy of the signin log
                    cleaned_log = signin_log.copy()

                    # Try to match with BehaviorAnalytics
                    result = match_behavior_to_signin(signin_log, behavior_analytics)

                    if result:
                        (
                            devices_insights,
                            activity_insights,
                            action_type,
                            activity_type,
                        ) = result
                        if devices_insights:
                            cleaned_log["DevicesInsights"] = devices_insights
                            matched_count += 1
                        else:
                            cleaned_log["DevicesInsights"] = {}
                        if activity_insights:
                            cleaned_log["ActivityInsights"] = activity_insights
                            matched_count += 1
                        else:
                            cleaned_log["ActivityInsights"] = {}
                        cleaned_log["ActionType"] = action_type
                        cleaned_log["ActivityType"] = activity_type
                    else:
                        cleaned_log["DevicesInsights"] = {}
                        cleaned_log["ActivityInsights"] = {}
                        cleaned_log["ActionType"] = ""
                        cleaned_log["ActivityType"] = ""

                    # Remove specified columns if provided
                    if columns_to_remove:
                        cleaned_log = remove_specified_columns(
                            cleaned_log, columns_to_remove
                        )

                    cleaned_signin_logs.append(cleaned_log)

                cleaned_data[table_name] = cleaned_signin_logs
                print(f"   ✅ Processed {len(cleaned_signin_logs)} SigninLogs")
                print(
                    f"   ✅ Matched {matched_count} entries with DevicesInsights ({matched_count/len(cleaned_signin_logs)*100:.1f}%)"
                )

                if columns_to_remove:
                    print(
                        f"   ✅ Removed {len(columns_to_remove)} columns from each entry"
                    )

            else:
                # Keep all other tables as-is
                cleaned_data[table_name] = table_data
                entry_count = len(table_data) if isinstance(table_data, list) else "N/A"
                print(f"   ✅ Kept {table_name}: {entry_count} entries")

        # Generate output filename if not provided
        if output_file_path is None:
            input_dir = os.path.dirname(input_file_path)
            input_filename = os.path.basename(input_file_path)
            output_filename = f"cleaned_{input_filename}"
            output_file_path = os.path.join(input_dir, output_filename)

        # Save cleaned data
        with open(output_file_path, "w", encoding="utf-8") as file:
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


def main():
    """
    Standalone execution mode (for testing individual files)
    For workflow execution, use clean_user_data_file() function instead
    """
    print("\n" + "=" * 60)
    print("🧹 Azure AD Logs Cleaner - Standalone Mode")
    print("=" * 60)
    print("ℹ️  This is standalone mode for testing.")
    print("ℹ️  For automated workflow, use main_workflow.py instead.")
    print("=" * 60 + "\n")

    # Example: Process a single file
    input_file = "sentinel_logs1/sentinel_logs_2025-11-07 05:00-06:00/sentinel_user_data_20251107_0500_0600.json"

    if os.path.exists(input_file):
        print(f"📄 Processing: {input_file}\n")
        output_file = clean_user_data_file(input_file)

        if output_file:
            print(f"\n✅ Success! Cleaned file: {output_file}")
        else:
            print("\n❌ Cleaning failed")
    else:
        print(f"❌ File not found: {input_file}")
        print("\nTo process files, either:")
        print("  1. Update the 'input_file' path in this main() function")
        print("  2. Use main_workflow.py for automated processing")


if __name__ == "__main__":
    main()
