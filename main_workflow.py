import os
from datetime import datetime

# Import functions from other modules
from backend.fetch_data.clean_logs import clean_user_data_file
from backend.fetch_data.get_tables_sentinel import fetch_sentinel_data
from backend.fetch_data.endpoint.correlate import generate_complete_report
from backend.fetch_data.structured_correlation_users import process_cleaned_user_data
from backend.fetch_data.endpoint.clean_endpoint_logs import clean_endpoint_security_file


class SelectiveWorkflowOrchestrator:
    def __init__(self, base_output_dir: str = "sentinel_logs1"):
        self.base_output_dir = base_output_dir
        self.workflow_log = []
        os.makedirs(base_output_dir, exist_ok=True)

    def log_step(self, message: str, level: str = "INFO"):
        """Log workflow steps"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        print(log_entry)
        self.workflow_log.append(log_entry)

    def run_selective_workflow(
        self,
        start_date: str,
        end_date: str,
        start_hour: int,
        end_hour: int,
        interval_minutes: int = 60,
        process_user_data: bool = True,
        process_endpoint_security: bool = False,
        skip_fetch: bool = False,
        skip_clean: bool = False,
        skip_correlation: bool = False,  # NEW: Skip correlation if already exists
    ):
        """
        Selective workflow execution

        Args:
            process_user_data: Process user data files
            process_endpoint_security: Process endpoint security files
        """
        self.log_step("=" * 80, "HEADER")
        self.log_step("🎯 SELECTIVE AZURE SENTINEL LOG ANALYSIS", "HEADER")
        self.log_step("=" * 80, "HEADER")
        self.log_step(
            f"Configuration: {start_date} to {end_date}, "
            f"{start_hour}:00 - {end_hour}:00, {interval_minutes}min intervals"
        )
        self.log_step(f"Process User Data: {process_user_data}")
        self.log_step(f"Process Endpoint Security: {process_endpoint_security}")
        self.log_step(f"Skip Fetch: {skip_fetch}")
        self.log_step(f"Skip Clean: {skip_clean}")
        self.log_step(f"Skip Correlation: {skip_correlation}")  # NEW

        # Parse dates
        start_dt = datetime.strptime(start_date, "%Y-%m-%d").date()
        end_dt = datetime.strptime(end_date, "%Y-%m-%d").date()

        # Step 1: Fetch data from Sentinel (if needed)
        if not skip_fetch:
            self.log_step("\n" + "=" * 80, "HEADER")
            self.log_step("STEP 1: FETCHING DATA FROM AZURE SENTINEL", "HEADER")
            self.log_step("=" * 80, "HEADER")

            try:
                fetched_paths = fetch_sentinel_data(
                    start_date=start_dt,
                    end_date=end_dt,
                    start_hour=start_hour,
                    end_hour=end_hour,
                    interval_minutes=interval_minutes,
                    base_folder=self.base_output_dir,
                    skip_if_exists=skip_fetch,
                )
                self.log_step(
                    f"✅ Data fetching complete. Processed {len(fetched_paths)} intervals",
                    "SUCCESS",
                )
            except Exception as e:
                self.log_step(f"❌ Data fetching failed: {e}", "ERROR")
                return
        else:
            # Use existing files
            fetched_paths = self.discover_existing_intervals()
            self.log_step(
                f"✅ Using existing data from {len(fetched_paths)} intervals", "SUCCESS"
            )

        results = {}

        # Step 2: Clean files based on selection
        if process_user_data:
            user_results = self.process_user_data(
                fetched_paths, skip_clean, skip_correlation
            )
            results["user_data"] = user_results

        if process_endpoint_security:
            endpoint_results = self.process_endpoint_security(
                fetched_paths, skip_clean, skip_correlation
            )
            results["endpoint_security"] = endpoint_results

        # Final Summary
        self.log_step("\n" + "=" * 80, "HEADER")
        self.log_step("🎉 SELECTIVE WORKFLOW COMPLETED", "HEADER")
        self.log_step("=" * 80, "HEADER")

        # Save workflow log
        self.save_workflow_log()

        return results

    def discover_existing_intervals(self):
        """Discover existing interval folders"""
        intervals = {}
        if os.path.exists(self.base_output_dir):
            for item in os.listdir(self.base_output_dir):
                item_path = os.path.join(self.base_output_dir, item)
                if os.path.isdir(item_path) and item.startswith("sentinel_logs_"):
                    intervals[item_path] = self.discover_files_in_interval(item_path)
        return intervals

    def discover_files_in_interval(self, interval_path):
        """Discover files in an interval folder"""
        files = {}
        if os.path.exists(interval_path):
            for file in os.listdir(interval_path):
                file_path = os.path.join(interval_path, file)

                # Discover raw JSON files
                if (
                    file.endswith(".json")
                    and not file.startswith("cleaned_")
                    and not file.startswith("correlation_")
                    and not file.startswith("endpoint_correlation_")
                ):
                    if "user_data" in file:
                        files["user_data"] = file_path
                    elif "endpoint_security" in file:
                        files["endpointsecurity"] = file_path
                    elif "platform_operations" in file:
                        files["platformoperations"] = file_path

                # Discover cleaned files
                elif file.startswith("cleaned_") and file.endswith(".json"):
                    if "user_data" in file:
                        files["cleaned_user_data"] = file_path
                    elif "endpoint_security" in file:
                        files["cleaned_endpoint_security"] = file_path

                # Discover correlation files (markdown)
                elif file.startswith("correlation_analysis_") and file.endswith(".md"):
                    files["user_correlation_md"] = file_path
                elif file.startswith("endpoint_correlation_") and file.endswith(".md"):
                    files["endpoint_correlation_md"] = file_path

                # Discover correlation files (JSON)
                elif file.startswith("correlation_analysis_") and file.endswith(
                    ".json"
                ):
                    files["user_correlation_json"] = file_path
                elif file.startswith("endpoint_correlation_") and file.endswith(
                    ".json"
                ):
                    files["endpoint_correlation_json"] = file_path

        return files

    def process_user_data(self, fetched_paths, skip_clean, skip_correlation=False):
        """Process user data files"""
        self.log_step("\n" + "=" * 80, "HEADER")
        self.log_step("PROCESSING USER DATA FILES", "HEADER")
        self.log_step("=" * 80, "HEADER")

        cleaned_paths = []
        correlation_results = []

        for interval_folder, files in fetched_paths.items():
            user_data_file = files.get("user_data")

            if not user_data_file or not os.path.exists(user_data_file):
                self.log_step(
                    f"⚠️  No user data file found in {interval_folder}", "WARNING"
                )
                continue

            # Clean user data
            cleaned_filename = os.path.join(
                interval_folder, f"cleaned_{os.path.basename(user_data_file)}"
            )

            if skip_clean and os.path.exists(cleaned_filename):
                self.log_step(
                    f"⏭️  Skipping clean (already cleaned): {cleaned_filename}", "INFO"
                )
                cleaned_file = cleaned_filename
            else:
                try:
                    self.log_step(f"🧹 Cleaning: {user_data_file}", "INFO")
                    cleaned_file = clean_user_data_file(
                        user_data_file, output_path=cleaned_filename
                    )
                    if not cleaned_file:
                        self.log_step(f"❌ Cleaning failed: {user_data_file}", "ERROR")
                        continue
                except Exception as e:
                    self.log_step(f"❌ Error cleaning {user_data_file}: {e}", "ERROR")
                    continue

            cleaned_paths.append((interval_folder, cleaned_file))

            # Check if correlation already exists
            base_name = (
                os.path.basename(cleaned_file)
                .replace("cleaned_", "")
                .replace(".json", "")
            )
            md_output = os.path.join(
                interval_folder, f"correlation_analysis_{base_name}.md"
            )
            json_output = os.path.join(
                interval_folder, f"correlation_analysis_{base_name}.json"
            )

            if (
                skip_correlation
                and os.path.exists(md_output)
                and os.path.exists(json_output)
            ):
                self.log_step(
                    f"⏭️  Skipping correlation (already exists): {os.path.basename(md_output)}",
                    "INFO",
                )
                correlation_results.append(
                    {
                        "interval": interval_folder,
                        "markdown": md_output,
                        "json": json_output,
                    }
                )
                continue

            # Run correlation analysis
            try:
                self.log_step(f"📊 Analyzing: {cleaned_file}", "INFO")
                md_output, json_output = process_cleaned_user_data(
                    cleaned_file, output_folder=interval_folder
                )

                if md_output and json_output:
                    correlation_results.append(
                        {
                            "interval": interval_folder,
                            "markdown": md_output,
                            "json": json_output,
                        }
                    )
                    self.log_step(
                        f"✅ Analysis complete: {os.path.basename(md_output)}",
                        "SUCCESS",
                    )
                else:
                    self.log_step(f"❌ Analysis failed: {cleaned_file}", "ERROR")

            except Exception as e:
                self.log_step(f"❌ Error analyzing {cleaned_file}: {e}", "ERROR")

        self.log_step(
            f"✅ User data processing complete: {len(cleaned_paths)} files cleaned, {len(correlation_results)} analyzed",
            "SUCCESS",
        )

        return {"cleaned": cleaned_paths, "analyzed": correlation_results}

    def process_endpoint_security(
        self, fetched_paths, skip_clean, skip_correlation=False
    ):
        """Process endpoint security files with correlation analysis"""
        self.log_step("\n" + "=" * 80, "HEADER")
        self.log_step("PROCESSING ENDPOINT SECURITY FILES", "HEADER")
        self.log_step("=" * 80, "HEADER")

        cleaned_paths = []
        correlation_results = []

        for interval_folder, files in fetched_paths.items():
            endpoint_file = files.get("endpointsecurity")

            if not endpoint_file or not os.path.exists(endpoint_file):
                self.log_step(
                    f"⚠️  No endpoint security file found in {interval_folder}",
                    "WARNING",
                )
                continue

            # Clean endpoint security data
            cleaned_filename = os.path.join(
                interval_folder, f"cleaned_{os.path.basename(endpoint_file)}"
            )

            if skip_clean and os.path.exists(cleaned_filename):
                self.log_step(
                    f"⏭️  Skipping clean (already cleaned): {cleaned_filename}", "INFO"
                )
                cleaned_file = cleaned_filename
            else:
                try:
                    self.log_step(f"🔒 Cleaning: {endpoint_file}", "INFO")
                    cleaned_file = clean_endpoint_security_file(
                        endpoint_file, output_path=cleaned_filename
                    )

                    if cleaned_file and os.path.exists(cleaned_file):
                        self.log_step(
                            f"✅ Cleaned successfully: {cleaned_filename}", "SUCCESS"
                        )
                    else:
                        self.log_step(f"❌ Cleaning failed: {endpoint_file}", "ERROR")
                        continue

                except Exception as e:
                    self.log_step(f"❌ Error cleaning {endpoint_file}: {e}", "ERROR")
                    import traceback

                    self.log_step(f"DEBUG: {traceback.format_exc()}", "DEBUG")
                    continue

            cleaned_paths.append((interval_folder, cleaned_file))

            # Check if correlation already exists
            base_name = (
                os.path.basename(cleaned_file)
                .replace("cleaned_", "")
                .replace(".json", "")
            )
            md_output = os.path.join(
                interval_folder, f"endpoint_correlation_{base_name}.md"
            )
            json_output = os.path.join(
                interval_folder, f"endpoint_correlation_{base_name}.json"
            )

            if (
                skip_correlation
                and os.path.exists(md_output)
                and os.path.exists(json_output)
            ):
                self.log_step(
                    f"⏭️  Skipping correlation (already exists): {os.path.basename(md_output)}",
                    "INFO",
                )

                # Load existing results to get alert count
                try:
                    import json

                    with open(json_output, "r", encoding="utf-8") as f:
                        report_json = json.load(f)

                    correlation_results.append(
                        {
                            "interval": interval_folder,
                            "markdown": md_output,
                            "json": json_output,
                            "alerts_generated": len(
                                report_json.get("security_alerts", [])
                            ),
                        }
                    )

                    self.log_step(
                        f"✅ Found existing correlation: {len(report_json.get('security_alerts', []))} alerts",
                        "INFO",
                    )
                except Exception as e:
                    self.log_step(
                        f"⚠️  Could not load existing correlation: {e}", "WARNING"
                    )

                continue

            # Run correlation analysis
            try:
                self.log_step(f"🔗 Correlating: {cleaned_file}", "INFO")

                # Load cleaned data
                import json

                with open(cleaned_file, "r", encoding="utf-8") as f:
                    endpoint_data = json.load(f)

                # Generate correlation report
                report_md, report_json = generate_complete_report(endpoint_data)

                # Write markdown report
                with open(md_output, "w", encoding="utf-8") as f:
                    f.write(report_md)

                # Write JSON report
                with open(json_output, "w", encoding="utf-8") as f:
                    json.dump(report_json, f, indent=2, ensure_ascii=False)

                correlation_results.append(
                    {
                        "interval": interval_folder,
                        "markdown": md_output,
                        "json": json_output,
                        "alerts_generated": len(report_json.get("security_alerts", [])),
                    }
                )

                self.log_step(
                    f"✅ Correlation complete: {len(report_json.get('security_alerts', []))} alerts generated",
                    "SUCCESS",
                )

            except Exception as e:
                self.log_step(f"❌ Error correlating {cleaned_file}: {e}", "ERROR")
                import traceback

                self.log_step(f"DEBUG: {traceback.format_exc()}", "DEBUG")

        self.log_step(
            f"✅ Endpoint security processing complete: {len(cleaned_paths)} files cleaned, {len(correlation_results)} correlated",
            "SUCCESS",
        )

        return {"cleaned": cleaned_paths, "correlated": correlation_results}

    def save_workflow_log(self):
        """Save workflow log to file"""
        log_file = os.path.join(
            self.base_output_dir,
            f"selective_workflow_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
        )

        with open(log_file, "w", encoding="utf-8") as f:
            f.write("\n".join(self.workflow_log))

        print(f"\n📝 Selective workflow log saved to: {log_file}")


def main():
    """Main execution with selective configuration"""

    # ============================================================================
    # SELECTIVE CONFIGURATION - CHOOSE WHAT TO PROCESS
    # ============================================================================

    config = {
        "start_date": "2025-11-07",
        "end_date": "2025-11-07",
        "start_hour": 6,
        "end_hour": 7,
        "interval_minutes": 60,
        "base_output_dir": "sentinel_logs1",
        "skip_fetch": True,  # Use existing files
        "skip_clean": True,  # Set to True if files already cleaned
        "skip_correlation": False,  # NEW: Set to True to skip correlation if already done
        # SELECT WHAT TO PROCESS:
        "process_user_data": False,  # Set to True to process user data
        "process_endpoint_security": True,  # Set to True to process endpoint security
    }

    # ============================================================================
    # RUN SELECTIVE WORKFLOW
    # ============================================================================

    orchestrator = SelectiveWorkflowOrchestrator(
        base_output_dir=config["base_output_dir"]
    )

    results = orchestrator.run_selective_workflow(
        start_date=config["start_date"],
        end_date=config["end_date"],
        start_hour=config["start_hour"],
        end_hour=config["end_hour"],
        interval_minutes=config["interval_minutes"],
        process_user_data=config["process_user_data"],
        process_endpoint_security=config["process_endpoint_security"],
        skip_fetch=config["skip_fetch"],
        skip_clean=config["skip_clean"],
        skip_correlation=config.get("skip_correlation", False),  # NEW
    )

    # Print results summary
    if results:
        print("\n" + "=" * 80)
        print("📊 SELECTIVE PROCESSING RESULTS:")
        print("=" * 80)

        if "user_data" in results:
            user_data = results["user_data"]
            print(f"\n👤 USER DATA PROCESSING:")
            print(f"  • Files cleaned: {len(user_data.get('cleaned', []))}")
            print(f"  • Analyses completed: {len(user_data.get('analyzed', []))}")

        if "endpoint_security" in results:
            endpoint_data = results["endpoint_security"]
            print(f"\n🔒 ENDPOINT SECURITY PROCESSING:")
            print(f"  • Files cleaned: {len(endpoint_data.get('cleaned', []))}")
            print(
                f"  • Correlations completed: {len(endpoint_data.get('correlated', []))}"
            )

            # Show alert summary
            if endpoint_data.get("correlated"):
                total_alerts = sum(
                    r.get("alerts_generated", 0) for r in endpoint_data["correlated"]
                )
                print(f"  • Total alerts generated: {total_alerts}")

        print(f"\n📁 Output directory: {config['base_output_dir']}")


if __name__ == "__main__":
    main()
