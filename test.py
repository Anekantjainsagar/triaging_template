"""
Test script to show KQL cleaning before/after
"""

from src.web_llm_enhancer import WebLLMEnhancer

# Example messy KQL from your template
messy_kql = """To generate a KQL query for this investigation step, I have outlined the following steps:
1. **Retrieve username information**: Use the `SigninLogs` table to identify usernames involved in the incident.
2. **Filter by specific events or patterns**: Utilize the provided tables (`IdentityInfo`, `DeviceInfo`) and relevant operators to filter for specific events (e.g., 'Add member to role') related to the target users.
3. **Extend results with additional data**: Ensure that only the necessary columns are extended, in this case, extending the usernames found in the first step.
Here is the complete KQL query:
SigninLogs | extend username = tostring(UserPrincipalName) -- Find usernames using SigninLogs table
IdentityInfo | extend ip_address = to_string(TargetResources[0].IPAddress) -- Target IP address from the IdentityInfo table
DeviceInfo | extend device_id = to_string(DeviceID) -- Device ID from the DeviceInfo table
AuditLogs | where TimeGenerated > ago(<TIMESPAN>) & Filter(username in usernames) -- Filter for usernames found in SigninLogs
### Explanation:
- **SigninLogs** table contains usernames and their associated details.
- **IdentityInfo** table has IP addresses, which can be used to filter by IP addresses.
- **DeviceInfo** table stores device IDs, helping to match the usernames with devices.
This query will provide a KQL query that meets the requirements specified. If there are any specific events or patterns in the `SigninLogs` table you need to address further, I'd be happy to assist in refining this query according to those details."""

print("=" * 80)
print("KQL CLEANING TEST")
print("=" * 80)

print("\n📝 ORIGINAL (MESSY) KQL:")
print("=" * 80)
print(messy_kql)
print(f"\nLength: {len(messy_kql)} characters")

# Clean it
enhancer = WebLLMEnhancer()
cleaned_kql = enhancer._deep_clean_kql(messy_kql)

print("\n\n✨ CLEANED KQL:")
print("=" * 80)
print(cleaned_kql)
print(f"\nLength: {len(cleaned_kql)} characters")

print("\n\n📊 RESULT:")
print("=" * 80)
print(f"✅ Removed {len(messy_kql) - len(cleaned_kql)} characters of junk")
print(
    f"✅ Reduced by {((len(messy_kql) - len(cleaned_kql)) / len(messy_kql) * 100):.1f}%"
)

# Test with another example
messy_kql2 = """I now understand that I need to generate an accurate Microsoft Sentinel KQL query for the given requirements. The key elements are:
1. Use only the specified table names: SigninLogs, AuditLogs, IdentityInfo.
2. Include placeholders for user email, IP address, device ID, and time span.
3. Ensure proper KQL operators (where, extend, project, summarize, join).
4. Focus on security investigation data.
Since this is a detailed step-by-step process, I will create a KQL query that meets these criteria and return it as the final answer:
SigninLogs | where UserPrincipalName == "<USER_EMAIL>" |
extend LoginTimestamp = if(ActiveTrustedLoginProvider == "WindowsIdentity") '2018-09-15 06:47:41.357385' else '2018-09-15 06:47:41.357385'
| extend DeviceID = if(ActiveTrustedDeviceID == "WindowsIdentity") '12345678-1234-1234-1234-12345678901' else '12345678-1234-1234-1234-12345678901'
| extend DeviceType = if(ActiveTrustedDeviceID == "WindowsIdentity") "Desktop" else "Other"
|
AuditLogs | where OperationName == "UserLogin" | join IdentityInfo, [device_id] on (SigninLogs.UserPrincipalName) and (AuditLogs.DeviceID)
This KQL query:
- `SignInLogs` table includes user login information.
- `IdentityInfo` contains the device ID of the user who logged in.
- The `join` operator is used to combine data from both tables based on common attributes (`UserPrincipalName`, `DeviceID`, etc.).
- `AuditLogs` table includes security incident logs, and it's joined with `IdentityInfo` based on the `device_id`.
This query ensures that all necessary information is collected for a thorough Microsoft Sentinel investigation."""

print("\n\n" + "=" * 80)
print("TEST 2: Another messy KQL")
print("=" * 80)
print(f"Original length: {len(messy_kql2)} characters")

cleaned_kql2 = enhancer._deep_clean_kql(messy_kql2)

print("\n✨ CLEANED:")
print("=" * 80)
print(cleaned_kql2)
print(f"\nLength: {len(cleaned_kql2)} characters")
print(
    f"✅ Reduced by {((len(messy_kql2) - len(cleaned_kql2)) / len(messy_kql2) * 100):.1f}%"
)
