import re
import pandas as pd
from typing import Dict
from datetime import datetime, timedelta


class AlertEntityExtractor:
    """Extract entity data from alert_data as it comes from main.py"""

    def __init__(self, alert_data: Dict):
        self.alert_data = alert_data
        self.users = []
        self.ips = []
        self.hosts = []
        self.reference_datetime = None
        self.reference_datetime_obj = None
        self.extract()

    def extract(self):
        """Extract all entities from alert_data"""

        # Extract datetime - use timeGenerated as reference, look back from that date
        try:
            full_alert = self.alert_data.get("full_alert", {})
            if isinstance(full_alert, dict):
                props = full_alert.get("properties", {})
                time_str = props.get("timeGenerated")
                if time_str:
                    # Parse the timeGenerated date
                    self.reference_datetime_obj = datetime.fromisoformat(
                        time_str.replace("Z", "+00:00")
                    )
                    # Store as reference_datetime (the alert was generated at this time)
                    self.reference_datetime = self.reference_datetime_obj.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
        except Exception as e:
            print(f"⚠️ Error parsing datetime: {e}")
            self.reference_datetime_obj = datetime.utcnow()
            self.reference_datetime = self.reference_datetime_obj.strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        # Extract entities
        entities = self.alert_data.get("entities", {})
        entities_list = (
            entities.get("entities", [])
            if isinstance(entities, dict)
            else (entities if isinstance(entities, list) else [])
        )

        for entity in entities_list:
            kind = entity.get("kind", "").lower()
            props = entity.get("properties", {})

            if kind == "account":
                account_name = props.get("accountName", "")
                upn_suffix = props.get("upnSuffix", "")
                if account_name and upn_suffix:
                    self.users.append(f"{account_name}@{upn_suffix}")
                elif account_name:
                    self.users.append(account_name)

            elif kind == "ip":
                address = props.get("address", "")
                if address:
                    self.ips.append(address)

            elif kind == "host":
                hostname = props.get("hostName") or props.get("netBiosName", "")
                if hostname:
                    self.hosts.append(hostname)


class TemplateKQLInjector:
    def __init__(self, alert_data: Dict):
        self.alert_data = alert_data
        self.extractor = AlertEntityExtractor(alert_data)
        self.users = self.extractor.users
        self.ips = self.extractor.ips
        self.hosts = self.extractor.hosts
        self.reference_datetime = self.extractor.reference_datetime
        self.reference_datetime_obj = self.extractor.reference_datetime_obj

    def _convert_ago_to_absolute_datetime(self, kql: str) -> str:
        """
        Convert ago(Xd/h/m) to absolute datetime ranges based on reference_datetime

        Examples:
        - ago(7d) → reference_datetime - 7 days to reference_datetime
        - ago(24h) → reference_datetime - 24 hours to reference_datetime
        """
        if not self.reference_datetime_obj:
            return kql

        # Find all ago() patterns and replace them
        def replace_ago(match):
            ago_value = int(match.group(1))
            ago_unit = match.group(2).lower()

            # Calculate the start datetime
            if ago_unit == "d":
                start_dt = self.reference_datetime_obj - timedelta(days=ago_value)
            elif ago_unit == "h":
                start_dt = self.reference_datetime_obj - timedelta(hours=ago_value)
            elif ago_unit == "m":
                start_dt = self.reference_datetime_obj - timedelta(minutes=ago_value)
            elif ago_unit == "s":
                start_dt = self.reference_datetime_obj - timedelta(seconds=ago_value)
            else:
                return match.group(0)

            start_dt_str = start_dt.strftime("%Y-%m-%d %H:%M:%S")

            # Return the replacement: datetime(start) and TimeGenerated <= datetime(end)
            return f"datetime({start_dt_str}Z) and TimeGenerated <= datetime({self.reference_datetime}Z)"

        # Replace: TimeGenerated > ago(7d)
        # With: TimeGenerated > datetime(2025-09-26 12:45:00Z) and TimeGenerated <= datetime(2025-10-03 12:45:00Z)
        ago_pattern = r"TimeGenerated\s*>\s*ago\((\d+)([dhms])\)"
        kql = re.sub(
            ago_pattern,
            lambda m: f"TimeGenerated > {replace_ago(m)}",
            kql,
            flags=re.IGNORECASE,
        )

        return kql

    def inject_kql(self, template_kql: str) -> str:
        """
        Inject real data into template KQL

        Replaces:
        - <USER_EMAIL> → actual user UPNs from alert
        - <IP_ADDRESS> → actual IPs from alert
        - ago(7d) → absolute datetime range based on reference_datetime
        - "UserPrincipalName == <USER_EMAIL>" → "UserPrincipalName in (...)"
        """

        if not template_kql or pd.isna(template_kql):
            return ""

        injected = str(template_kql)

        # ===== CONVERT ago() TO ABSOLUTE DATETIME =====
        injected = self._convert_ago_to_absolute_datetime(injected)

        # ===== INJECT REFERENCE DATETIME =====
        if self.reference_datetime:
            injected = re.sub(
                r"let reference_datetime = datetime\([^)]*\)",
                f"let reference_datetime = datetime({self.reference_datetime}Z)",
                injected,
                flags=re.IGNORECASE,
            )

        # ===== INJECT USERS =====
        if self.users:
            users_in_format = ", ".join([f'"{user}"' for user in self.users])

            # Pattern 1: where UserPrincipalName == "<USER_EMAIL>"
            injected = re.sub(
                r'where\s+UserPrincipalName\s*==\s*"<USER_EMAIL>"',
                f"where UserPrincipalName in ({users_in_format})",
                injected,
                flags=re.IGNORECASE,
            )

            # Pattern 2: | where UserPrincipalName == "<USER_EMAIL>"
            injected = re.sub(
                r'\|\s*where\s+UserPrincipalName\s*==\s*"<USER_EMAIL>"',
                f"| where UserPrincipalName in ({users_in_format})",
                injected,
                flags=re.IGNORECASE,
            )

            # Pattern 3: UserPrincipalName == "<USER_EMAIL>" (without where)
            injected = re.sub(
                r'UserPrincipalName\s*==\s*"<USER_EMAIL>"',
                f"UserPrincipalName in ({users_in_format})",
                injected,
                flags=re.IGNORECASE,
            )

            # Pattern 4: just <USER_EMAIL> as a value
            injected = re.sub(r'"<USER_EMAIL>"', users_in_format, injected)

        # ===== INJECT IPS =====
        if self.ips:
            ips_in_format = ", ".join([f'"{ip}"' for ip in self.ips])

            # Pattern 1: where IPAddress == "<IP_ADDRESS>"
            injected = re.sub(
                r'where\s+IPAddress\s*==\s*"<IP_ADDRESS>"',
                f"where IPAddress in ({ips_in_format})",
                injected,
                flags=re.IGNORECASE,
            )

            # Pattern 2: | where IPAddress == "<IP_ADDRESS>"
            injected = re.sub(
                r'\|\s*where\s+IPAddress\s*==\s*"<IP_ADDRESS>"',
                f"| where IPAddress in ({ips_in_format})",
                injected,
                flags=re.IGNORECASE,
            )

            # Pattern 3: IPAddress == "<IP_ADDRESS>" (without where)
            injected = re.sub(
                r'IPAddress\s*==\s*"<IP_ADDRESS>"',
                f"IPAddress in ({ips_in_format})",
                injected,
                flags=re.IGNORECASE,
            )

            # Pattern 4: just <IP_ADDRESS> as a value
            injected = re.sub(r'"<IP_ADDRESS>"', ips_in_format, injected)

        # ===== INJECT HOSTS =====
        if self.hosts:
            hosts_in_format = ", ".join([f'"{host}"' for host in self.hosts])

            injected = re.sub(
                r'DeviceName\s*==\s*"<DEVICE_NAME>"',
                f"DeviceName in ({hosts_in_format})",
                injected,
                flags=re.IGNORECASE,
            )

        # ===== CLEANUP =====
        injected = re.sub(r"\|\s*where\s*\|", "|", injected)
        injected = re.sub(r"\|\s*where\s*$", "", injected, flags=re.MULTILINE)

        return injected.strip()

    def inject_template_dataframe(self, template_df: pd.DataFrame) -> pd.DataFrame:
        """
        Inject data into entire template DataFrame

        Args:
            template_df: DataFrame from template_generator with KQL Query column

        Returns:
            DataFrame with injected KQL queries
        """

        df_copy = template_df.copy()

        # Inject KQL for each row
        df_copy["KQL Query"] = df_copy["KQL Query"].apply(
            lambda kql: self.inject_kql(kql) if pd.notna(kql) else ""
        )

        print(f"✅ KQL Injection Complete")
        print(f"   Users Extracted: {len(self.users)}")
        for user in self.users:
            print(f"      • {user}")
        print(f"   IPs Extracted: {len(self.ips)}")
        for ip in self.ips:
            print(f"      • {ip}")
        print(f"   Reference DateTime: {self.reference_datetime}")

        return df_copy


class TemplateProcessorWithInjection:
    """
    Complete flow: Generate template → Inject data into KQL

    Use this in your template_generator.py instead of existing flow
    """

    def __init__(self, alert_data: Dict):
        self.alert_data = alert_data
        self.injector = TemplateKQLInjector(alert_data)

    def process_template(self, template_df: pd.DataFrame) -> pd.DataFrame:
        """
        Main processing function

        Args:
            template_df: DataFrame from ImprovedTemplateGenerator.generate_intelligent_template()

        Returns:
            DataFrame with injected KQL queries ready to execute
        """

        print("\n" + "=" * 80)
        print("🔄 KQL DATA INJECTION PHASE")
        print("=" * 80)

        # Inject data
        injected_df = self.injector.inject_template_dataframe(template_df)

        print("\n📊 Sample of Injected Queries:")
        print("-" * 80)

        for idx, row in injected_df.iterrows():
            if pd.notna(row.get("KQL Query")) and str(row["KQL Query"]).strip():
                step_name = row.get("Name", f"Step {idx+1}")
                kql = row["KQL Query"]

                print(f"\n✅ {step_name}")
                print(f"   Original placeholders: <USER_EMAIL>, <IP_ADDRESS>, ago(7d)")
                print(
                    f"   Injected with real data: {len(self.injector.users)} users, {len(self.injector.ips)} IPs"
                )
                print(f"   Query length: {len(kql)} chars")
                if len(kql) < 400:
                    print(f"   Query:\n   {kql}")
                else:
                    print(f"   Query:\n   {kql[:400]}...")

        return injected_df


if __name__ == "__main__":
    # Alert data from main.py
    alert_data = {
        "title": "Test-Suspicious signins",
        "description": "Testing the suspicious Sign in logs.",
        "full_alert": {"properties": {"timeGenerated": "2025-10-03T12:45:00Z"}},
        "entities": {
            "entities": [
                {
                    "kind": "Account",
                    "properties": {
                        "accountName": "aarushi.trivedi",
                        "upnSuffix": "yashtechnologies841.onmicrosoft.com",
                    },
                },
                {
                    "kind": "Account",
                    "properties": {
                        "accountName": "shrish.s",
                        "upnSuffix": "yashtechnologies841.onmicrosoft.com",
                    },
                },
                {
                    "kind": "Ip",
                    "properties": {
                        "address": "49.249.104.218",
                    },
                },
                {
                    "kind": "Ip",
                    "properties": {
                        "address": "14.143.131.254",
                    },
                },
            ]
        },
    }

    # Template KQL queries (from your document)
    template_queries = [
        'SigninLogs | where TimeGenerated > ago(7d) | where UserPrincipalName == "<USER_EMAIL>" | summarize SignInCount = count(), UniqueIPs = dcount(IPAddress), FailedAttempts = countif(ResultType != "0"), UniqueLocations = dcount(tostring(LocationDetails.countryOrRegion)) by UserPrincipalName',
        'SigninLogs | where TimeGenerated > ago(7d) | where IPAddress == "<IP_ADDRESS>" | summarize SignInAttempts = count(), UniqueUsers = dcount(UserPrincipalName), FailedLogins = countif(ResultType != "0") by IPAddress',
    ]

    # Test injection
    injector = TemplateKQLInjector(alert_data)

    print("=" * 80)
    print("BEFORE INJECTION (with placeholders)")
    print("=" * 80)
    for i, kql in enumerate(template_queries, 1):
        print(f"\n{i}. {kql[:100]}...")

    print("\n\n" + "=" * 80)
    print("AFTER INJECTION (with real data and absolute dates)")
    print("=" * 80)

    for i, kql in enumerate(template_queries, 1):
        injected = injector.inject_kql(kql)
        print(f"\n{i}. {injected}\n")

    print("\n" + "=" * 80)
    print("EXTRACTED DATA SUMMARY")
    print("=" * 80)
    print(f"Users: {injector.users}")
    print(f"IPs: {injector.ips}")
    print(f"Reference DateTime: {injector.reference_datetime}")
