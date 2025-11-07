import json
import os
from collections import defaultdict
from typing import Dict, List, Any, Set
from datetime import datetime
import copy


class UserActivityCorrelator:
    """Correlate all user activities with 10-minute time windows and folder organization"""

    def __init__(self, json_file_path: str = None, json_data: str = None):
        """Initialize with JSON file or raw JSON data"""
        if json_file_path:
            with open(json_file_path, "r") as f:
                self.data = json.load(f)
        elif json_data:
            self.data = json.loads(json_data)
        else:
            self.data = {}

        self.correlation_keys = [
            "UserPrincipalName",
            "UserId",
            "AccountName",
            "UserName",
        ]
        self.user_activities = defaultdict(dict)

    def extract_field(self, record: Dict, *field_names) -> Any:
        """Extract field value from nested dictionaries"""
        for field in field_names:
            if isinstance(record, dict) and field in record:
                return record[field]
        return None

    def parse_nested_json(self, value: Any) -> Dict:
        """Parse JSON strings embedded in fields"""
        if isinstance(value, str):
            try:
                return json.loads(value)
            except:
                return {}
        return value if isinstance(value, dict) else {}

    def parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse various timestamp formats"""
        if not timestamp_str:
            return None

        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
        ]

        for fmt in formats:
            try:
                return datetime.strptime(str(timestamp_str)[:26], fmt[:26])
            except:
                continue
        return None

    def get_time_window_key(self, timestamp: datetime, window_minutes: int = 10) -> str:
        """Group timestamps into 10-minute time windows"""
        if not timestamp:
            return "Unknown"

        window = timestamp.replace(
            minute=timestamp.minute // window_minutes * window_minutes,
            second=0,
            microsecond=0,
        )
        return window.isoformat()

    def extract_user_identifier(self, record: Dict) -> str:
        """Extract primary user identifier from record"""
        for key in self.correlation_keys:
            value = self.extract_field(record, key)
            if value:
                return value
        return None

    def extract_user_from_entities(self, entities: Any) -> List[str]:
        """Extract user identifiers from SecurityAlert/SecurityIncident entities"""
        users = []
        entities = self.parse_nested_json(entities)
        if isinstance(entities, list):
            for entity in entities:
                if entity.get("Type") == "account":
                    user = entity.get("Name")
                    if user:
                        users.append(user)
        return users

    def correlate_activities(self):
        """Correlate all activities by user with 10-minute time windows"""
        print("[*] Correlating all activities by user with 10-minute time windows...")

        # Process SigninLogs
        for record in self.data.get("SigninLogs", []):
            user = self.extract_user_identifier(record)
            if user:
                if user not in self.user_activities:
                    self.user_activities[user] = {
                        "user_info": {},
                        "time_windows": defaultdict(lambda: defaultdict(list)),
                        "all_records": defaultdict(list),
                        "statistics": {},
                    }

                timestamp = self.parse_timestamp(
                    self.extract_field(record, "TimeGenerated")
                )
                window_key = self.get_time_window_key(timestamp)

                self.user_activities[user]["time_windows"][window_key][
                    "SigninLogs"
                ].append(record)
                self.user_activities[user]["all_records"]["SigninLogs"].append(record)

                if not self.user_activities[user]["user_info"]:
                    self.user_activities[user]["user_info"] = {
                        "UserPrincipalName": self.extract_field(
                            record, "UserPrincipalName"
                        ),
                        "UserId": self.extract_field(record, "UserId"),
                        "UserDisplayName": self.extract_field(
                            record, "UserDisplayName"
                        ),
                        "UserType": self.extract_field(record, "UserType"),
                    }

        # Process BehaviorAnalytics
        for record in self.data.get("BehaviorAnalytics", []):
            user = self.extract_user_identifier(record)
            if user:
                if user not in self.user_activities:
                    self.user_activities[user] = {
                        "user_info": {},
                        "time_windows": defaultdict(lambda: defaultdict(list)),
                        "all_records": defaultdict(list),
                        "statistics": {},
                    }

                timestamp = self.parse_timestamp(
                    self.extract_field(record, "TimeGenerated")
                )
                window_key = self.get_time_window_key(timestamp)

                self.user_activities[user]["time_windows"][window_key][
                    "BehaviorAnalytics"
                ].append(record)
                self.user_activities[user]["all_records"]["BehaviorAnalytics"].append(
                    record
                )

        # Process DeviceProcessEvents
        for record in self.data.get("DeviceProcessEvents", []):
            user = self.extract_user_identifier(record)
            if user:
                if user not in self.user_activities:
                    self.user_activities[user] = {
                        "user_info": {},
                        "time_windows": defaultdict(lambda: defaultdict(list)),
                        "all_records": defaultdict(list),
                        "statistics": {},
                    }

                timestamp = self.parse_timestamp(
                    self.extract_field(record, "TimeGenerated")
                )
                window_key = self.get_time_window_key(timestamp)

                self.user_activities[user]["time_windows"][window_key][
                    "DeviceProcessEvents"
                ].append(record)
                self.user_activities[user]["all_records"]["DeviceProcessEvents"].append(
                    record
                )

        # Process DeviceFileEvents
        for record in self.data.get("DeviceFileEvents", []):
            user = self.extract_user_identifier(record)
            if user:
                if user not in self.user_activities:
                    self.user_activities[user] = {
                        "user_info": {},
                        "time_windows": defaultdict(lambda: defaultdict(list)),
                        "all_records": defaultdict(list),
                        "statistics": {},
                    }

                timestamp = self.parse_timestamp(
                    self.extract_field(record, "TimeGenerated")
                )
                window_key = self.get_time_window_key(timestamp)

                self.user_activities[user]["time_windows"][window_key][
                    "DeviceFileEvents"
                ].append(record)
                self.user_activities[user]["all_records"]["DeviceFileEvents"].append(
                    record
                )

        # Process DeviceNetworkInfo
        for record in self.data.get("DeviceNetworkInfo", []):
            user = self.extract_user_identifier(record)
            if user:
                if user not in self.user_activities:
                    self.user_activities[user] = {
                        "user_info": {},
                        "time_windows": defaultdict(lambda: defaultdict(list)),
                        "all_records": defaultdict(list),
                        "statistics": {},
                    }

                timestamp = self.parse_timestamp(
                    self.extract_field(record, "TimeGenerated")
                )
                window_key = self.get_time_window_key(timestamp)

                self.user_activities[user]["time_windows"][window_key][
                    "DeviceNetworkInfo"
                ].append(record)
                self.user_activities[user]["all_records"]["DeviceNetworkInfo"].append(
                    record
                )

        # Process SecurityAlert
        for record in self.data.get("SecurityAlert", []):
            users = self.extract_user_from_entities(
                self.extract_field(record, "Entities")
            )
            for user in users:
                if user:
                    if user not in self.user_activities:
                        self.user_activities[user] = {
                            "user_info": {},
                            "time_windows": defaultdict(lambda: defaultdict(list)),
                            "all_records": defaultdict(list),
                            "statistics": {},
                        }

                    timestamp = self.parse_timestamp(
                        self.extract_field(record, "TimeGenerated")
                    )
                    window_key = self.get_time_window_key(timestamp)

                    self.user_activities[user]["time_windows"][window_key][
                        "SecurityAlert"
                    ].append(record)
                    self.user_activities[user]["all_records"]["SecurityAlert"].append(
                        record
                    )

        # Process SecurityIncident
        for record in self.data.get("SecurityIncident", []):
            users = self.extract_user_from_entities(
                self.extract_field(record, "Entities")
            )
            for user in users:
                if user:
                    if user not in self.user_activities:
                        self.user_activities[user] = {
                            "user_info": {},
                            "time_windows": defaultdict(lambda: defaultdict(list)),
                            "all_records": defaultdict(list),
                            "statistics": {},
                        }

                    timestamp = self.parse_timestamp(
                        self.extract_field(record, "TimeGenerated")
                    )
                    window_key = self.get_time_window_key(timestamp)

                    self.user_activities[user]["time_windows"][window_key][
                        "SecurityIncident"
                    ].append(record)
                    self.user_activities[user]["all_records"][
                        "SecurityIncident"
                    ].append(record)

    def calculate_statistics(self):
        """Calculate statistics for each user"""
        print("[*] Calculating statistics...")

        for user, data in self.user_activities.items():
            stats = {
                "total_events": 0,
                "total_time_windows": len(data["time_windows"]),
                "by_table": {},
            }

            for table, records in data["all_records"].items():
                count = len(records)
                stats["by_table"][table] = count
                stats["total_events"] += count

            data["statistics"] = stats

    def safe_convert_to_serializable(self, obj: Any) -> Any:
        """Convert non-serializable objects to serializable format"""
        if isinstance(obj, (set, frozenset)):
            return list(obj)
        elif isinstance(obj, defaultdict):
            return {k: self.safe_convert_to_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, dict):
            return {k: self.safe_convert_to_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self.safe_convert_to_serializable(item) for item in obj]
        return obj

    def create_folder_structure(self, base_folder: str = "user_activities"):
        """Create folder structure for each user with their activities organized by 10-minute windows"""
        print(f"[*] Creating folder structure in '{base_folder}'...")

        if os.path.exists(base_folder):
            import shutil

            shutil.rmtree(base_folder)

        os.makedirs(base_folder)

        for user, data in self.user_activities.items():
            # Sanitize user folder name
            user_folder_name = (
                user.replace("@", "_").replace(".", "_").replace("/", "_")
            )
            user_folder = os.path.join(base_folder, user_folder_name)
            os.makedirs(user_folder, exist_ok=True)

            # Create user summary file
            user_summary = {
                "user_identifier": user,
                "user_info": data["user_info"],
                "statistics": data["statistics"],
                "time_windows": sorted(data["time_windows"].keys()),
            }

            summary_file = os.path.join(user_folder, "user_summary.json")
            with open(summary_file, "w") as f:
                json.dump(
                    self.safe_convert_to_serializable(user_summary),
                    f,
                    indent=2,
                    default=str,
                )

            # Create time window files
            time_windows_folder = os.path.join(user_folder, "time_windows")
            os.makedirs(time_windows_folder, exist_ok=True)

            for window_key in sorted(data["time_windows"].keys()):
                window_data = data["time_windows"][window_key]

                window_file_name = window_key.replace(":", "-").replace(".", "_")
                window_file = os.path.join(
                    time_windows_folder, f"{window_file_name}.json"
                )

                window_content = {
                    "time_window": window_key,
                    "activities": self.safe_convert_to_serializable(dict(window_data)),
                    "event_summary": {
                        table: len(records) for table, records in window_data.items()
                    },
                }

                with open(window_file, "w") as f:
                    json.dump(window_content, f, indent=2, default=str)

            # Create consolidated file with all activities by table
            all_tables_folder = os.path.join(user_folder, "activities_by_table")
            os.makedirs(all_tables_folder, exist_ok=True)

            for table, records in data["all_records"].items():
                table_file = os.path.join(all_tables_folder, f"{table}.json")
                table_content = {
                    "table": table,
                    "total_records": len(records),
                    "records": self.safe_convert_to_serializable(records),
                }

                with open(table_file, "w") as f:
                    json.dump(table_content, f, indent=2, default=str)

            print(f"  ✓ Created folder for user: {user}")

        print(f"[+] Folder structure created successfully in '{base_folder}'")

    def generate_index_report(self, base_folder: str = "user_activities"):
        """Generate index report for all users"""
        print("[*] Generating index report...")

        index_report = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "total_users": len(self.user_activities),
            },
            "users": {},
        }

        for user, data in self.user_activities.items():
            index_report["users"][user] = {
                "statistics": data["statistics"],
                "time_windows_count": len(data["time_windows"]),
                "user_info": data["user_info"],
            }

        index_file = os.path.join(base_folder, "index_report.json")
        with open(index_file, "w") as f:
            json.dump(
                self.safe_convert_to_serializable(index_report),
                f,
                indent=2,
                default=str,
            )

        print(f"[+] Index report saved to {index_file}")

    def print_summary(self):
        """Print summary of correlations"""
        print("\n" + "=" * 100)
        print("USER ACTIVITY CORRELATION SUMMARY")
        print("=" * 100)

        print(f"\nTotal Users: {len(self.user_activities)}\n")

        for user, data in sorted(self.user_activities.items())[:10]:
            print(f"User: {user}")
            print(f"  - Total Events: {data['statistics']['total_events']}")
            print(
                f"  - Time Windows (10-min): {data['statistics']['total_time_windows']}"
            )
            print(f"  - Events by Table:")
            for table, count in data["statistics"]["by_table"].items():
                print(f"      • {table}: {count}")
            print()

        print("=" * 100)


def main():
    """Main execution"""
    import sys

    if len(sys.argv) > 1:
        json_file = sys.argv[1]
    else:
        json_file = "sentinel_logs.json"

    try:
        correlator = UserActivityCorrelator(json_file_path=json_file)
        print(f"[+] Loaded data from {json_file}\n")

        correlator.correlate_activities()
        correlator.calculate_statistics()
        correlator.create_folder_structure("user_activities")
        correlator.generate_index_report("user_activities")

        correlator.print_summary()

        print("[+] All output organized in 'user_activities' folder")

    except FileNotFoundError:
        print(f"[!] File not found: {json_file}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
