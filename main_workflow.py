"""
Main Workflow Orchestrator for Azure Sentinel Log Analysis
Handles: Data Extraction → Cleaning → Correlation Analysis
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Tuple

# Import functions from other modules
from backend.fetch_data.clean_logs import clean_user_data_file
from backend.fetch_data.get_tables_sentinel import fetch_sentinel_data
from backend.fetch_data.structured_correlation_users import process_cleaned_user_data


class SentinelWorkflowOrchestrator:
    """Orchestrates the complete workflow for Sentinel log analysis"""

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

    def run_workflow(
        self,
        start_date: str,  # Format: "YYYY-MM-DD"
        end_date: str,  # Format: "YYYY-MM-DD"
        start_hour: int,  # Starting hour (0-23)
        end_hour: int,  # Ending hour (0-23)
        interval_minutes: int = 60,  # Interval in minutes
        skip_fetch: bool = False,  # Skip data fetching if files exist
        skip_clean: bool = False,  # Skip cleaning if cleaned files exist
    ):
        """
        Main workflow execution

        Args:
            start_date: Start date in "YYYY-MM-DD" format
            end_date: End date in "YYYY-MM-DD" format
            start_hour: Starting hour (0-23)
            end_hour: Ending hour (0-23)
            interval_minutes: Time interval in minutes (default: 60)
            skip_fetch: Skip fetching if data exists (default: False)
            skip_clean: Skip cleaning if cleaned data exists (default: False)
        """
        self.log_step("=" * 80, "HEADER")
        self.log_step("🚀 AZURE SENTINEL LOG ANALYSIS WORKFLOW", "HEADER")
        self.log_step("=" * 80, "HEADER")
        self.log_step(
            f"Configuration: {start_date} to {end_date}, "
            f"{start_hour}:00 - {end_hour}:00, {interval_minutes}min intervals"
        )

        # Parse dates
        start_dt = datetime.strptime(start_date, "%Y-%m-%d").date()
        end_dt = datetime.strptime(end_date, "%Y-%m-%d").date()

        # Step 1: Fetch data from Sentinel
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

        # Step 2: Clean User Data files
        self.log_step("\n" + "=" * 80, "HEADER")
        self.log_step("STEP 2: CLEANING USER DATA FILES", "HEADER")
        self.log_step("=" * 80, "HEADER")

        cleaned_paths = []
        for interval_folder, files in fetched_paths.items():
            user_data_file = files.get("user_data")

            if not user_data_file:
                self.log_step(
                    f"⚠️  No user data file found in {interval_folder}", "WARNING"
                )
                continue

            if not os.path.exists(user_data_file):
                self.log_step(f"⚠️  File not found: {user_data_file}", "WARNING")
                continue

            # Check if already cleaned
            cleaned_filename = os.path.join(
                interval_folder, f"cleaned_{os.path.basename(user_data_file)}"
            )

            if skip_clean and os.path.exists(cleaned_filename):
                self.log_step(
                    f"⏭️  Skipping (already cleaned): {cleaned_filename}", "INFO"
                )
                cleaned_paths.append((interval_folder, cleaned_filename))
                continue

            try:
                self.log_step(f"🧹 Cleaning: {user_data_file}", "INFO")
                cleaned_file = clean_user_data_file(
                    user_data_file, output_path=cleaned_filename
                )

                if cleaned_file:
                    cleaned_paths.append((interval_folder, cleaned_file))
                    self.log_step(
                        f"✅ Cleaned successfully: {cleaned_filename}", "SUCCESS"
                    )
                else:
                    self.log_step(f"❌ Cleaning failed: {user_data_file}", "ERROR")

            except Exception as e:
                self.log_step(f"❌ Error cleaning {user_data_file}: {e}", "ERROR")

        self.log_step(
            f"\n✅ Cleaning complete. Processed {len(cleaned_paths)} files", "SUCCESS"
        )

        # Step 3: Run Correlation Analysis
        self.log_step("\n" + "=" * 80, "HEADER")
        self.log_step("STEP 3: RUNNING CORRELATION ANALYSIS", "HEADER")
        self.log_step("=" * 80, "HEADER")

        correlation_results = []
        for interval_folder, cleaned_file in cleaned_paths:
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

        # Final Summary
        self.log_step("\n" + "=" * 80, "HEADER")
        self.log_step("🎉 WORKFLOW COMPLETED SUCCESSFULLY", "HEADER")
        self.log_step("=" * 80, "HEADER")

        self.log_step(f"\n📊 SUMMARY:", "INFO")
        self.log_step(f"  • Intervals Processed: {len(fetched_paths)}", "INFO")
        self.log_step(f"  • Files Cleaned: {len(cleaned_paths)}", "INFO")
        self.log_step(f"  • Correlations Analyzed: {len(correlation_results)}", "INFO")

        # Save workflow log
        self.save_workflow_log()

        return {
            "fetched": fetched_paths,
            "cleaned": cleaned_paths,
            "analyzed": correlation_results,
        }

    def save_workflow_log(self):
        """Save workflow log to file"""
        log_file = os.path.join(
            self.base_output_dir,
            f"workflow_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
        )

        with open(log_file, "w", encoding="utf-8") as f:
            f.write("\n".join(self.workflow_log))

        print(f"\n📝 Workflow log saved to: {log_file}")


def main():
    """Main execution with example configuration"""

    # ============================================================================
    # CONFIGURATION - CUSTOMIZE HERE
    # ============================================================================

    config = {
        "start_date": "2025-10-29",  # YYYY-MM-DD
        "end_date": "2025-10-29",  # YYYY-MM-DD
        "start_hour": 12,  # 0-23
        "end_hour": 13,  # 0-23
        "interval_minutes": 60,  # Minutes per interval
        "base_output_dir": "sentinel_logs_test",  # Output directory
        "skip_fetch": True,  # Set True to skip fetching if files exist
        "skip_clean": True,  # Set True to skip cleaning if files exist
    }

    # ============================================================================
    # RUN WORKFLOW
    # ============================================================================

    orchestrator = SentinelWorkflowOrchestrator(
        base_output_dir=config["base_output_dir"]
    )

    results = orchestrator.run_workflow(
        start_date=config["start_date"],
        end_date=config["end_date"],
        start_hour=config["start_hour"],
        end_hour=config["end_hour"],
        interval_minutes=config["interval_minutes"],
        skip_fetch=config["skip_fetch"],
        skip_clean=config["skip_clean"],
    )

    # Optional: Print detailed results
    if results:
        print("\n" + "=" * 80)
        print("📁 OUTPUT FILES GENERATED:")
        print("=" * 80)

        for result in results.get("analyzed", []):
            print(f"\n📂 {os.path.basename(result['interval'])}:")
            print(f"  • Markdown Report: {os.path.basename(result['markdown'])}")
            print(f"  • JSON Report: {os.path.basename(result['json'])}")


if __name__ == "__main__":
    main()
