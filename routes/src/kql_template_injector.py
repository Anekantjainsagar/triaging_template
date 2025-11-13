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
        """Extract all entities from alert_data with comprehensive debug logging"""

        print(f"\n{'='*80}")
        print(f"🔍 ENTITY EXTRACTION DEBUG")
        print(f"{'='*80}\n")

        # ===== DATETIME EXTRACTION =====
        try:
            print(f"📅 Extracting Reference DateTime...")

            # Try multiple paths to find timeGenerated
            full_alert = self.alert_data.get("full_alert", {})

            if isinstance(full_alert, dict):
                props = full_alert.get("properties", {})
                time_str = props.get("timeGenerated")

                if time_str:
                    print(
                        f"   ✅ Found timeGenerated in full_alert.properties: {time_str}"
                    )
                    self.reference_datetime_obj = datetime.fromisoformat(
                        time_str.replace("Z", "+00:00")
                    )
                    self.reference_datetime = self.reference_datetime_obj.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                else:
                    print(f"   ⚠️ timeGenerated not found in full_alert.properties")

            # Fallback: Check top-level
            if not self.reference_datetime:
                time_str = self.alert_data.get("timeGenerated") or self.alert_data.get(
                    "time_generated"
                )
                if time_str:
                    print(f"   ✅ Found timeGenerated at top level: {time_str}")
                    self.reference_datetime_obj = datetime.fromisoformat(
                        time_str.replace("Z", "+00:00")
                    )
                    self.reference_datetime = self.reference_datetime_obj.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )

            # Last fallback: Use current time
            if not self.reference_datetime:
                print(f"   ⚠️ No timeGenerated found, using current UTC time")
                self.reference_datetime_obj = datetime.utcnow()
                self.reference_datetime = self.reference_datetime_obj.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

            print(f"   📅 Reference DateTime: {self.reference_datetime}")

        except Exception as e:
            print(f"   ❌ Error parsing datetime: {e}")
            self.reference_datetime_obj = datetime.utcnow()
            self.reference_datetime = self.reference_datetime_obj.strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            print(f"   🔄 Fallback to current time: {self.reference_datetime}")

        # ===== ENTITY EXTRACTION =====
        print(f"\n👥 Extracting Entities...")

        entities = self.alert_data.get("entities", {})
        print(f"   📦 Entities container type: {type(entities)}")

        # Handle different entity structures
        if isinstance(entities, dict):
            entities_list = entities.get("entities", [])
            print(f"   📋 Found entities.entities list: {len(entities_list)} items")
        elif isinstance(entities, list):
            entities_list = entities
            print(f"   📋 Entities is already a list: {len(entities_list)} items")
        else:
            entities_list = []
            print(f"   ⚠️ Unexpected entities structure: {entities}")

        if not entities_list:
            print(f"   ⚠️ No entities found in alert_data")
            print(f"   🔍 Alert data keys: {list(self.alert_data.keys())}")

        # Process each entity
        for idx, entity in enumerate(entities_list):
            kind = entity.get("kind", "").lower()
            props = entity.get("properties", {})

            print(f"\n   🔹 Entity {idx + 1}: {kind.upper()}")
            print(f"      Properties keys: {list(props.keys())}")

            # ===== ACCOUNT ENTITIES =====
            if kind == "account":
                account_name = props.get("accountName", "")
                upn_suffix = props.get("upnSuffix", "")
                friendly_name = props.get("friendlyName", "")

                print(f"      👤 Account Details:")
                print(f"         accountName: {account_name}")
                print(f"         upnSuffix: {upn_suffix}")
                print(f"         friendlyName: {friendly_name}")

                if account_name and upn_suffix:
                    full_upn = f"{account_name}@{upn_suffix}"
                    self.users.append(full_upn)
                    print(f"         ✅ Added UPN: {full_upn}")
                elif account_name:
                    self.users.append(account_name)
                    print(f"         ✅ Added account name: {account_name}")
                elif friendly_name:
                    self.users.append(friendly_name)
                    print(f"         ✅ Added friendly name: {friendly_name}")
                else:
                    print(f"         ⚠️ No valid account identifier found")

            # ===== IP ENTITIES =====
            elif kind == "ip":
                address = props.get("address", "")
                location = props.get("location", {})

                print(f"      🌐 IP Details:")
                print(f"         address: {address}")
                if location:
                    print(
                        f"         location: {location.get('countryName', 'Unknown')}"
                    )

                if address:
                    self.ips.append(address)
                    print(f"         ✅ Added IP: {address}")
                else:
                    print(f"         ⚠️ No IP address found")

            # ===== HOST ENTITIES =====
            elif kind == "host":
                hostname = props.get("hostName") or props.get("netBiosName", "")
                dns_domain = props.get("dnsDomain", "")

                print(f"      💻 Host Details:")
                print(f"         hostName: {hostname}")
                print(f"         dnsDomain: {dns_domain}")

                if hostname:
                    self.hosts.append(hostname)
                    print(f"         ✅ Added host: {hostname}")
                else:
                    print(f"         ⚠️ No hostname found")

            else:
                print(f"      ℹ️ Unsupported entity type, skipping")

        # ===== EXTRACTION SUMMARY =====
        print(f"\n{'='*80}")
        print(f"📊 EXTRACTION SUMMARY")
        print(f"{'='*80}")
        print(f"✅ Users: {len(self.users)}")
        for user in self.users:
            print(f"   • {user}")
        print(f"✅ IPs: {len(self.ips)}")
        for ip in self.ips:
            print(f"   • {ip}")
        print(f"✅ Hosts: {len(self.hosts)}")
        for host in self.hosts:
            print(f"   • {host}")
        print(f"✅ Reference DateTime: {self.reference_datetime}")
        print(f"{'='*80}\n")


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
        Convert ago(Xd/h/m) to absolute datetime ranges with smart windowing around alert time
        
        For 7 days: Creates window from (alert_time - 4 days) to (alert_time + 3 days)
        If alert is recent (within 3 days of now): Uses (alert_time - 7 days) to alert_time
        """
        if not self.reference_datetime_obj:
            print(f"   ⚠️ No reference datetime available for ago() conversion")
            return kql

        print(f"   🔄 Converting ago() patterns to smart datetime windows...")
        conversion_count = 0
        now = datetime.utcnow().replace(tzinfo=self.reference_datetime_obj.tzinfo)

        def replace_ago(match):
            nonlocal conversion_count
            ago_value = int(match.group(1))
            ago_unit = match.group(2).lower()

            # Calculate time delta
            if ago_unit == "d":
                delta = timedelta(days=ago_value)
                unit_name = "days"
            elif ago_unit == "h":
                delta = timedelta(hours=ago_value)
                unit_name = "hours"
            elif ago_unit == "m":
                delta = timedelta(minutes=ago_value)
                unit_name = "minutes"
            elif ago_unit == "s":
                delta = timedelta(seconds=ago_value)
                unit_name = "seconds"
            else:
                print(f"      ⚠️ Unknown ago unit: {ago_unit}")
                return match.group(0)

            # Smart windowing logic
            days_from_now = (now - self.reference_datetime_obj).days
            
            if ago_unit == "d" and ago_value >= 7:
                # For 7+ day queries, use smart windowing
                if days_from_now <= 3:
                    # Alert is recent - look back from alert time
                    start_dt = self.reference_datetime_obj - delta
                    end_dt = self.reference_datetime_obj
                    window_type = "lookback"
                else:
                    # Alert is older - create window around alert time
                    past_days = ago_value // 2 + 1  # 4 days for 7-day window
                    future_days = ago_value - past_days  # 3 days for 7-day window
                    start_dt = self.reference_datetime_obj - timedelta(days=past_days)
                    end_dt = self.reference_datetime_obj + timedelta(days=future_days)
                    window_type = "centered"
            else:
                # For shorter periods, use traditional lookback
                start_dt = self.reference_datetime_obj - delta
                end_dt = self.reference_datetime_obj
                window_type = "lookback"

            start_dt_str = start_dt.strftime("%Y-%m-%d %H:%M:%S")
            end_dt_str = end_dt.strftime("%Y-%m-%d %H:%M:%S")

            conversion_count += 1
            print(f"      ✅ Converted ago({ago_value}{ago_unit}) → {start_dt_str} to {end_dt_str}")
            print(f"         Window type: {window_type} ({ago_value} {unit_name})")
            print(f"         Alert age: {days_from_now} days from now")

            return f"datetime({start_dt_str}Z) and TimeGenerated <= datetime({end_dt_str}Z)"

        # Replace: TimeGenerated > ago(7d)
        ago_pattern = r"TimeGenerated\s*>\s*ago\((\d+)([dhms])\)"
        kql_converted = re.sub(
            ago_pattern,
            lambda m: f"TimeGenerated > {replace_ago(m)}",
            kql,
            flags=re.IGNORECASE,
        )

        if conversion_count > 0:
            print(f"   ✅ Converted {conversion_count} ago() pattern(s) with smart windowing")
        else:
            print(f"   ℹ️ No ago() patterns found in query")

        return kql_converted

    def inject_kql(self, template_kql: str) -> str:
        """
        Inject real data into template KQL with comprehensive debug logging

        Replaces:
        - <USER_EMAIL> → actual user UPNs from alert
        - <IP_ADDRESS> → actual IPs from alert
        - <DEVICE_NAME> → actual hosts from alert
        - ago(7d) → absolute datetime range based on reference_datetime
        - "UserPrincipalName == <USER_EMAIL>" → "UserPrincipalName in (...)"
        """

        if not template_kql or pd.isna(template_kql):
            return ""

        injected = str(template_kql)
        original_length = len(injected)

        print(f"\n   🔧 Processing KQL Query ({original_length} chars)")
        print(f"   {'─'*60}")

        # ===== CONVERT ago() TO ABSOLUTE DATETIME =====
        injected = self._convert_ago_to_absolute_datetime(injected)

        # ===== INJECT REFERENCE DATETIME =====
        if self.reference_datetime:
            datetime_pattern = r"let reference_datetime = datetime\([^)]*\)"
            if re.search(datetime_pattern, injected, re.IGNORECASE):
                injected = re.sub(
                    datetime_pattern,
                    f"let reference_datetime = datetime({self.reference_datetime}Z)",
                    injected,
                    flags=re.IGNORECASE,
                )
                print(f"   ✅ Injected reference_datetime: {self.reference_datetime}")

        # ===== INJECT USERS =====
        if self.users:
            users_in_format = ", ".join([f'"{user}"' for user in self.users])
            print(f"\n   👤 Injecting {len(self.users)} user(s):")
            for user in self.users:
                print(f"      • {user}")

            # Pattern 1: where UserPrincipalName == "<USER_EMAIL>"
            pattern1 = r'where\s+UserPrincipalName\s*==\s*"<USER_EMAIL>"'
            if re.search(pattern1, injected, re.IGNORECASE):
                injected = re.sub(
                    pattern1,
                    f"where UserPrincipalName in ({users_in_format})",
                    injected,
                    flags=re.IGNORECASE,
                )
                print(f"      ✅ Replaced 'where UserPrincipalName ==' pattern")

            # Pattern 2: | where UserPrincipalName == "<USER_EMAIL>"
            pattern2 = r'\|\s*where\s+UserPrincipalName\s*==\s*"<USER_EMAIL>"'
            if re.search(pattern2, injected, re.IGNORECASE):
                injected = re.sub(
                    pattern2,
                    f"| where UserPrincipalName in ({users_in_format})",
                    injected,
                    flags=re.IGNORECASE,
                )
                print(f"      ✅ Replaced '| where UserPrincipalName ==' pattern")

            # Pattern 3: UserPrincipalName == "<USER_EMAIL>" (without where)
            pattern3 = r'UserPrincipalName\s*==\s*"<USER_EMAIL>"'
            if re.search(pattern3, injected, re.IGNORECASE):
                injected = re.sub(
                    pattern3,
                    f"UserPrincipalName in ({users_in_format})",
                    injected,
                    flags=re.IGNORECASE,
                )
                print(f"      ✅ Replaced standalone 'UserPrincipalName ==' pattern")

            # Pattern 4: just <USER_EMAIL> as a value
            if "<USER_EMAIL>" in injected:
                injected = re.sub(r'"<USER_EMAIL>"', users_in_format, injected)
                print(f"      ✅ Replaced <USER_EMAIL> placeholder")
        else:
            if "<USER_EMAIL>" in injected or "UserPrincipalName" in injected:
                print(f"   ⚠️ Query contains user placeholders but no users extracted!")

        # ===== INJECT IPS =====
        if self.ips:
            ips_in_format = ", ".join([f'"{ip}"' for ip in self.ips])
            print(f"\n   🌐 Injecting {len(self.ips)} IP(s):")
            for ip in self.ips:
                print(f"      • {ip}")

            # Pattern 1: where IPAddress == "<IP_ADDRESS>"
            pattern1 = r'where\s+IPAddress\s*==\s*"<IP_ADDRESS>"'
            if re.search(pattern1, injected, re.IGNORECASE):
                injected = re.sub(
                    pattern1,
                    f"where IPAddress in ({ips_in_format})",
                    injected,
                    flags=re.IGNORECASE,
                )
                print(f"      ✅ Replaced 'where IPAddress ==' pattern")

            # Pattern 2: | where IPAddress == "<IP_ADDRESS>"
            pattern2 = r'\|\s*where\s+IPAddress\s*==\s*"<IP_ADDRESS>"'
            if re.search(pattern2, injected, re.IGNORECASE):
                injected = re.sub(
                    pattern2,
                    f"| where IPAddress in ({ips_in_format})",
                    injected,
                    flags=re.IGNORECASE,
                )
                print(f"      ✅ Replaced '| where IPAddress ==' pattern")

            # Pattern 3: IPAddress == "<IP_ADDRESS>" (without where)
            pattern3 = r'IPAddress\s*==\s*"<IP_ADDRESS>"'
            if re.search(pattern3, injected, re.IGNORECASE):
                injected = re.sub(
                    pattern3,
                    f"IPAddress in ({ips_in_format})",
                    injected,
                    flags=re.IGNORECASE,
                )
                print(f"      ✅ Replaced standalone 'IPAddress ==' pattern")

            # Pattern 4: just <IP_ADDRESS> as a value
            if "<IP_ADDRESS>" in injected:
                injected = re.sub(r'"<IP_ADDRESS>"', ips_in_format, injected)
                print(f"      ✅ Replaced <IP_ADDRESS> placeholder")
        else:
            if "<IP_ADDRESS>" in injected or "IPAddress" in injected:
                print(f"   ⚠️ Query contains IP placeholders but no IPs extracted!")

        # ===== INJECT HOSTS =====
        if self.hosts:
            hosts_in_format = ", ".join([f'"{host}"' for host in self.hosts])
            print(f"\n   💻 Injecting {len(self.hosts)} host(s):")
            for host in self.hosts:
                print(f"      • {host}")

            pattern = r'DeviceName\s*==\s*"<DEVICE_NAME>"'
            if re.search(pattern, injected, re.IGNORECASE):
                injected = re.sub(
                    pattern,
                    f"DeviceName in ({hosts_in_format})",
                    injected,
                    flags=re.IGNORECASE,
                )
                print(f"      ✅ Replaced DeviceName pattern")
        else:
            if "<DEVICE_NAME>" in injected:
                print(
                    f"   ⚠️ Query contains device placeholders but no hosts extracted!"
                )

        # ===== CLEANUP =====
        # Remove duplicate pipe where clauses
        injected = re.sub(r"\|\s*where\s*\|", "|", injected)
        injected = re.sub(r"\|\s*where\s*$", "", injected, flags=re.MULTILINE)

        final_length = len(injected)
        change_percent = (
            ((final_length - original_length) / original_length * 100)
            if original_length > 0
            else 0
        )

        print(f"\n   📊 Injection Summary:")
        print(f"      Original length: {original_length} chars")
        print(f"      Final length: {final_length} chars")
        print(f"      Change: {change_percent:+.1f}%")
        print(f"   {'─'*60}")

        return injected.strip()

    def inject_template_dataframe(self, template_df: pd.DataFrame) -> pd.DataFrame:
        """
        Inject data into entire template DataFrame with step-by-step debug

        Args:
            template_df: DataFrame from template_generator with KQL Query column

        Returns:
            DataFrame with injected KQL queries
        """

        print(f"\n{'='*80}")
        print(f"🔄 TEMPLATE DATAFRAME INJECTION")
        print(f"{'='*80}\n")

        df_copy = template_df.copy()

        print(f"📋 Template has {len(df_copy)} rows")

        injected_count = 0
        skipped_count = 0
        error_count = 0

        # Inject KQL for each row
        for idx, row in df_copy.iterrows():
            step_num = row.get("Step", idx + 1)
            step_name = row.get("Name", f"Step {step_num}")
            kql = row.get("KQL Query", "")

            # Skip empty KQL
            if (
                pd.isna(kql)
                or str(kql).strip() == ""
                or str(kql).strip().lower() in ["nan", "none"]
            ):
                skipped_count += 1
                continue

            print(f"\n🔹 Step {step_num}: {step_name}")

            try:
                injected_kql = self.inject_kql(kql)
                df_copy.at[idx, "KQL Query"] = injected_kql
                injected_count += 1
                print(f"   ✅ Injection successful")

            except Exception as e:
                error_count += 1
                print(f"   ❌ Injection failed: {str(e)}")
                import traceback

                print(f"   🔍 Error trace:\n{traceback.format_exc()}")

        print(f"\n{'='*80}")
        print(f"📊 INJECTION COMPLETE")
        print(f"{'='*80}")
        print(f"✅ Injected: {injected_count} queries")
        print(f"⏭️  Skipped: {skipped_count} (no KQL)")
        print(f"❌ Errors: {error_count}")
        print(f"{'='*80}\n")

        return df_copy
