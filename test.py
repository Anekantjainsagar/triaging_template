"""
KQL Pipeline Integration Test with Individual Result Files
Tests: api_kql_generation → hardcode_kql_queries → template_injector → KQL Executor

This script:
1. Generates KQL queries using EnhancedKQLGenerator
2. Tests hardcoded queries from HardcodedKQLQueries
3. Injects real alert data using TemplateKQLInjector
4. Executes each query using KQLExecutor
5. Saves EACH query result to a SEPARATE file with FULL data
"""

import os
import json
import time
from datetime import datetime
from typing import Dict, List, Tuple
from dotenv import load_dotenv

# Import the modules we're testing
from routes.src.api_kql_generation import EnhancedKQLGenerator
from routes.src.hardcode_kql_queries import HardcodedKQLQueries, KQLQueryManager
from routes.src.kql_template_injector import TemplateKQLInjector
from components.triaging.kql_executor import KQLExecutor

load_dotenv()


class KQLPipelineTester:
    """Comprehensive tester for KQL generation → injection → execution pipeline"""

    def __init__(self, output_dir: str = "kql_test_results"):
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Create output directory structure
        os.makedirs(self.output_dir, exist_ok=True)

        # Create subdirectories for different query types
        self.hardcoded_dir = os.path.join(
            self.output_dir, f"{self.timestamp}_hardcoded_queries"
        )
        self.generated_dir = os.path.join(
            self.output_dir, f"{self.timestamp}_generated_queries"
        )
        self.manager_dir = os.path.join(
            self.output_dir, f"{self.timestamp}_manager_queries"
        )

        os.makedirs(self.hardcoded_dir, exist_ok=True)
        os.makedirs(self.generated_dir, exist_ok=True)
        os.makedirs(self.manager_dir, exist_ok=True)

        # Initialize components
        self.kql_generator = EnhancedKQLGenerator(enable_standardization=True)
        self.query_manager = KQLQueryManager(enable_api_fallback=True)
        self.kql_executor = KQLExecutor()

        # Test results storage
        self.test_results = {
            "test_metadata": {
                "timestamp": self.timestamp,
                "total_tests": 0,
                "passed": 0,
                "failed": 0,
                "skipped": 0,
            },
            "query_tests": [],
        }

        # Sample alert data for testing
        self.sample_alert_data = self._create_sample_alert_data()

    def _create_sample_alert_data(self) -> dict:
        """Create realistic sample alert data for testing"""
        return {
            "title": "Test-Suspicious sign-ins from unusual locations",
            "description": "Multiple sign-in attempts from different geographic locations",
            "severity": "High",
            "status": "Active",
            "full_alert": {"properties": {"timeGenerated": "2025-11-03T10:30:00Z"}},
            "entities": {
                "entities": [
                    {
                        "kind": "Account",
                        "properties": {
                            "accountName": "shivendra.sharma",
                            "upnSuffix": "yash.com",
                            "friendlyName": "Test User",
                        },
                    },
                    {"kind": "Ip", "properties": {"address": "14.194.129.210"}},
                ]
            },
        }

    def _save_query_result_to_file(
        self, query_result: Dict, query_name: str, query_type: str
    ):
        """Save individual query result to a separate file with FULL data"""

        # Determine directory based on query type
        if query_type == "hardcoded":
            base_dir = self.hardcoded_dir
        elif query_type == "generated":
            base_dir = self.generated_dir
        elif query_type == "query_manager":
            base_dir = self.manager_dir
        else:
            base_dir = self.output_dir

        # Sanitize filename
        safe_name = "".join(
            c if c.isalnum() or c in (" ", "_", "-") else "_" for c in query_name
        )
        safe_name = safe_name.replace(" ", "_")[:100]  # Limit length

        # Save JSON file with complete data
        json_filename = f"{safe_name}.json"
        json_path = os.path.join(base_dir, json_filename)

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(query_result, f, indent=2, ensure_ascii=False)

        # Save TXT file with human-readable format
        txt_filename = f"{safe_name}.txt"
        txt_path = os.path.join(base_dir, txt_filename)

        with open(txt_path, "w", encoding="utf-8") as f:
            self._write_individual_result_txt(f, query_result)

        print(f"      📄 Saved: {json_filename}")

        return json_path, txt_path

    def _write_individual_result_txt(self, f, result: Dict):
        """Write detailed text report for individual query result"""
        f.write("=" * 100 + "\n")
        f.write(f"Query: {result.get('query_name', 'Unknown')}\n")
        f.write(f"Type: {result.get('query_type', 'Unknown')}\n")
        f.write(f"Status: {result.get('status', 'Unknown')}\n")
        f.write(f"Timestamp: {result.get('timestamp', 'Unknown')}\n")
        f.write("=" * 100 + "\n\n")

        # Stage Results
        f.write("STAGE RESULTS:\n")
        f.write("-" * 100 + "\n")
        for stage_name, stage_data in result.get("stages", {}).items():
            f.write(f"\n{stage_name.upper()}:\n")
            for key, value in stage_data.items():
                # Don't truncate - show full data
                if isinstance(value, str) and len(value) > 200:
                    f.write(f"  {key}:\n")
                    f.write(f"    {value}\n")
                else:
                    f.write(f"  {key}: {value}\n")

        # Original Query (if generated)
        if "generated_query" in result:
            f.write("\n" + "=" * 100 + "\n")
            f.write("ORIGINAL GENERATED QUERY:\n")
            f.write("=" * 100 + "\n")
            f.write(result["generated_query"] + "\n")

        # Injected Query
        if "injected_query" in result:
            f.write("\n" + "=" * 100 + "\n")
            f.write("INJECTED QUERY (READY TO EXECUTE):\n")
            f.write("=" * 100 + "\n")
            f.write(result["injected_query"] + "\n")

        # Execution Results - FULL DATA
        execution = result.get("stages", {}).get("execution", {})
        if execution.get("formatted_output"):
            f.write("\n" + "=" * 100 + "\n")
            f.write("QUERY EXECUTION RESULTS:\n")
            f.write("=" * 100 + "\n")
            f.write(f"Execution Time: {execution.get('execution_time', 0)} seconds\n")
            f.write(f"Result Rows: {execution.get('result_rows', 0)}\n")
            f.write(f"Success: {execution.get('success', False)}\n")
            f.write("\nFORMATTED OUTPUT:\n")
            f.write("-" * 100 + "\n")
            # Write FULL formatted output without truncation
            f.write(execution["formatted_output"] + "\n")

        # Raw Results (if available)
        if "raw_results" in execution:
            f.write("\n" + "=" * 100 + "\n")
            f.write("RAW RESULTS (JSON):\n")
            f.write("=" * 100 + "\n")
            f.write(
                json.dumps(execution["raw_results"], indent=2, ensure_ascii=False)
                + "\n"
            )

        # Error Information
        if execution.get("error"):
            f.write("\n" + "=" * 100 + "\n")
            f.write("ERROR DETAILS:\n")
            f.write("=" * 100 + "\n")
            f.write(execution["error"] + "\n")

    def run_all_tests(self):
        """Run complete test suite"""
        print("=" * 80)
        print("🧪 KQL PIPELINE INTEGRATION TEST")
        print("=" * 80)
        print(f"Timestamp: {self.timestamp}")
        print(f"Output Directory: {self.output_dir}")
        print("=" * 80)

        # Test 1: Hardcoded Queries
        print("\n📋 TEST SUITE 1: Hardcoded KQL Queries")
        print("-" * 80)
        self._test_hardcoded_queries()

        # Test 2: Generated Queries with Template Injection
        print("\n📋 TEST SUITE 2: Generated KQL with Template Injection")
        print("-" * 80)
        self._test_generated_queries_with_injection()

        # Test 3: Query Manager with API Fallback
        print("\n📋 TEST SUITE 3: Query Manager (Hardcoded + API Fallback)")
        print("-" * 80)
        self._test_query_manager()

        # Generate summary reports
        self._generate_summary_reports()

        print("\n" + "=" * 80)
        print("✅ TEST SUITE COMPLETED")
        print("=" * 80)
        self._print_summary()

    def _test_hardcoded_queries(self):
        """Test all hardcoded KQL queries"""

        hardcoded_queries = {
            "Role & Permission Analysis": HardcodedKQLQueries.ROLE_PERMISSION_ANALYSIS,
            "Initial Scope Analysis": HardcodedKQLQueries.INITIAL_SCOPE_ANALYSIS,
            "Authentication Method Analysis": HardcodedKQLQueries.AUTH_METHOD_ANALYSIS,
            "VIP Account Verification": HardcodedKQLQueries.VIP_ACCOUNT_VERIFICATION,
            "Geographic/Impossible Travel": HardcodedKQLQueries.GEOGRAPHIC_IMPOSSIBLE_TRAVEL,
            "IP Threat Intelligence": HardcodedKQLQueries.IP_THREAT_INTELLIGENCE,
            "Behavioral Anomaly Detection": HardcodedKQLQueries.BEHAVIORAL_ANOMALY_DETECTION,
            "Device Health & Compliance": HardcodedKQLQueries.DEVICE_HEALTH_COMPLIANCE,
            "MFA Configuration Status": HardcodedKQLQueries.MFA_CONFIGURATION_STATUS,
            "Conditional Access Analysis": HardcodedKQLQueries.CONDITIONAL_ACCESS_ANALYSIS,
            "Failed Sign-in Analysis": HardcodedKQLQueries.FAILED_SIGNIN_ANALYSIS,
            "Application Access Analysis": HardcodedKQLQueries.APPLICATION_ACCESS_ANALYSIS,
            "Risky Sign-in Details": HardcodedKQLQueries.RISKY_SIGNIN_DETAILS,
            "Legacy Authentication Usage": HardcodedKQLQueries.LEGACY_AUTH_USAGE,
        }

        for query_name, query_template in hardcoded_queries.items():
            print(f"\n🔍 Testing: {query_name}")
            print("-" * 60)

            test_result = {
                "query_name": query_name,
                "query_type": "hardcoded",
                "timestamp": datetime.now().isoformat(),
                "stages": {},
            }

            # Stage 1: Template Validation
            print("   Stage 1: Validating template...")
            is_valid_template = self._validate_query_template(query_template)
            test_result["stages"]["template_validation"] = {
                "passed": is_valid_template,
                "query_length": len(query_template),
            }

            if not is_valid_template:
                test_result["status"] = "SKIPPED"
                test_result["reason"] = "Invalid template structure"
                self.test_results["query_tests"].append(test_result)
                self.test_results["test_metadata"]["skipped"] += 1
                print("   ⚠️  SKIPPED: Invalid template")

                # Still save the result
                self._save_query_result_to_file(test_result, query_name, "hardcoded")
                continue

            # Stage 2: Data Injection
            print("   Stage 2: Injecting alert data...")
            injector = TemplateKQLInjector(self.sample_alert_data)
            injected_query = injector.inject_kql(query_template)

            test_result["stages"]["data_injection"] = {
                "passed": len(injected_query) > 30,
                "injected_query_length": len(injected_query),
                "users_injected": len(injector.users),
                "ips_injected": len(injector.ips),
                "reference_datetime": injector.reference_datetime,
            }

            # Stage 3: Query Execution - Get FULL results
            print("   Stage 3: Executing query...")
            execution_result = self._execute_query_with_full_results(
                injected_query, query_name
            )

            test_result["stages"]["execution"] = execution_result
            test_result["injected_query"] = injected_query

            # Determine overall status
            if execution_result["success"]:
                test_result["status"] = "PASSED"
                self.test_results["test_metadata"]["passed"] += 1
                print("   ✅ PASSED")
            else:
                test_result["status"] = "FAILED"
                self.test_results["test_metadata"]["failed"] += 1
                print(f"   ❌ FAILED: {execution_result.get('error', 'Unknown')}")

            # Save individual result to file
            self._save_query_result_to_file(test_result, query_name, "hardcoded")

            self.test_results["query_tests"].append(test_result)
            self.test_results["test_metadata"]["total_tests"] += 1

            time.sleep(0.5)

    def _test_generated_queries_with_injection(self):
        """Test KQL generation with EnhancedKQLGenerator + Template Injection"""

        test_scenarios = [
            {
                "step_name": "Initial User Activity Assessment",
                "explanation": "Review sign-in patterns to understand normal behavior",
                "rule_context": "Suspicious sign-in activity",
            },
            {
                "step_name": "Geographic Origin Analysis",
                "explanation": "Check for impossible travel patterns across locations",
                "rule_context": "Multiple locations detected",
            },
            {
                "step_name": "IP Threat Intelligence Lookup",
                "explanation": "Verify reputation of source IP addresses",
                "rule_context": "Unknown IP addresses detected",
            },
            {
                "step_name": "MFA Configuration Review",
                "explanation": "Check if multi-factor authentication is enabled",
                "rule_context": "Authentication security review",
            },
            {
                "step_name": "VIP Account Verification",
                "explanation": "Verify if affected users are VIP or executive accounts",
                "rule_context": "High-priority account check",
            },
            {
                "step_name": "Behavioral Anomaly Detection",
                "explanation": "Identify unusual activity patterns and timing",
                "rule_context": "Anomaly detection",
            },
        ]

        reference_datetime_obj = None
        try:
            time_str = self.sample_alert_data["full_alert"]["properties"][
                "timeGenerated"
            ]
            reference_datetime_obj = datetime.fromisoformat(
                time_str.replace("Z", "+00:00")
            )
        except:
            reference_datetime_obj = datetime.utcnow()

        for scenario in test_scenarios:
            print(f"\n🔍 Testing: {scenario['step_name']}")
            print("-" * 60)

            test_result = {
                "query_name": scenario["step_name"],
                "query_type": "generated",
                "timestamp": datetime.now().isoformat(),
                "stages": {},
            }

            # Stage 1: Query Generation
            print("   Stage 1: Generating KQL query...")
            kql_query, kql_explanation = self.kql_generator.generate_kql_query(
                step_name=scenario["step_name"],
                explanation=scenario["explanation"],
                rule_context=scenario["rule_context"],
                reference_datetime_obj=reference_datetime_obj,
            )

            test_result["stages"]["query_generation"] = {
                "passed": len(kql_query) > 30,
                "query_length": len(kql_query),
                "explanation": kql_explanation,
            }

            if len(kql_query) < 30:
                test_result["status"] = "SKIPPED"
                test_result["reason"] = "No KQL generated for this step"
                self.test_results["query_tests"].append(test_result)
                self.test_results["test_metadata"]["skipped"] += 1
                print("   ⚠️  SKIPPED: No KQL needed")

                # Save the result
                self._save_query_result_to_file(
                    test_result, scenario["step_name"], "generated"
                )
                continue

            # Stage 2: Data Injection
            print("   Stage 2: Injecting alert data...")
            injector = TemplateKQLInjector(self.sample_alert_data)
            injected_query = injector.inject_kql(kql_query)

            test_result["stages"]["data_injection"] = {
                "passed": len(injected_query) > 30,
                "injected_query_length": len(injected_query),
                "users_injected": len(injector.users),
                "ips_injected": len(injector.ips),
            }

            # Stage 3: Query Execution - Get FULL results
            print("   Stage 3: Executing query...")
            execution_result = self._execute_query_with_full_results(
                injected_query, scenario["step_name"]
            )

            test_result["stages"]["execution"] = execution_result
            test_result["generated_query"] = kql_query
            test_result["injected_query"] = injected_query

            # Determine overall status
            if execution_result["success"]:
                test_result["status"] = "PASSED"
                self.test_results["test_metadata"]["passed"] += 1
                print("   ✅ PASSED")
            else:
                test_result["status"] = "FAILED"
                self.test_results["test_metadata"]["failed"] += 1
                print(f"   ❌ FAILED: {execution_result.get('error', 'Unknown')}")

            # Save individual result to file
            self._save_query_result_to_file(
                test_result, scenario["step_name"], "generated"
            )

            self.test_results["query_tests"].append(test_result)
            self.test_results["test_metadata"]["total_tests"] += 1

            time.sleep(0.5)

    def _test_query_manager(self):
        """Test KQLQueryManager with hardcoded queries + API fallback"""

        query_types = [
            "initial_scope",
            "vip_verification",
            "geographic",
            "ip_threat",
            "behavioral",
            "mfa_config",
        ]

        for query_type in query_types:
            print(f"\n🔍 Testing Query Type: {query_type}")
            print("-" * 60)

            test_result = {
                "query_name": f"Query Manager: {query_type}",
                "query_type": "query_manager",
                "timestamp": datetime.now().isoformat(),
                "stages": {},
            }

            # Stage 1: Query Retrieval
            print("   Stage 1: Retrieving query from manager...")
            query, source = self.query_manager.get_query(query_type, use_fallback=True)

            test_result["stages"]["query_retrieval"] = {
                "passed": query is not None,
                "source": source,
                "query_length": len(query) if query else 0,
            }

            if not query:
                test_result["status"] = "FAILED"
                test_result["reason"] = "Query not found in manager"
                self.test_results["query_tests"].append(test_result)
                self.test_results["test_metadata"]["failed"] += 1
                print("   ❌ FAILED: Query not found")

                # Save the result
                self._save_query_result_to_file(
                    test_result, f"manager_{query_type}", "query_manager"
                )
                continue

            # Stage 2: Parameter Injection
            print("   Stage 2: Injecting parameters...")
            query_with_params = self.query_manager.inject_parameters(
                query,
                user_email="test.user@testcompany.onmicrosoft.com",
                ip_address="203.197.238.210",
            )

            test_result["stages"]["parameter_injection"] = {
                "passed": "<USER_EMAIL>" not in query_with_params
                and "<IP_ADDRESS>" not in query_with_params,
                "injected_query_length": len(query_with_params),
            }

            # Stage 3: Query Execution - Get FULL results
            print("   Stage 3: Executing query...")
            execution_result = self._execute_query_with_full_results(
                query_with_params, f"{query_type}_manager"
            )

            test_result["stages"]["execution"] = execution_result
            test_result["retrieved_query"] = query
            test_result["injected_query"] = query_with_params

            # Determine overall status
            if execution_result["success"]:
                test_result["status"] = "PASSED"
                self.test_results["test_metadata"]["passed"] += 1
                print("   ✅ PASSED")
            else:
                test_result["status"] = "FAILED"
                self.test_results["test_metadata"]["failed"] += 1
                print(f"   ❌ FAILED: {execution_result.get('error', 'Unknown')}")

            # Save individual result to file
            self._save_query_result_to_file(
                test_result, f"manager_{query_type}", "query_manager"
            )

            self.test_results["query_tests"].append(test_result)
            self.test_results["test_metadata"]["total_tests"] += 1

            time.sleep(0.5)

    def _validate_query_template(self, query: str) -> bool:
        """Validate that query template has basic structure"""
        if not query or len(query.strip()) < 30:
            return False

        has_table = any(
            table in query for table in ["SigninLogs", "AuditLogs", "DeviceInfo"]
        )
        has_pipe = "|" in query
        has_where = "where" in query.lower()

        return has_table and (has_pipe or has_where)

    def _execute_query_with_full_results(self, query: str, query_name: str) -> Dict:
        """Execute query with error handling and capture FULL results (no truncation)"""

        workspace_id = os.getenv("LOG_ANALYTICS_WORKSPACE_ID")
        if not workspace_id:
            return {
                "success": False,
                "error": "LOG_ANALYTICS_WORKSPACE_ID not configured",
                "execution_time": 0,
                "result_rows": 0,
            }

        try:
            start_time = time.time()
            success, formatted_output, raw_results = self.kql_executor.execute_query(
                query
            )
            execution_time = time.time() - start_time

            result = {
                "success": success,
                "execution_time": round(execution_time, 2),
                "formatted_output": formatted_output,  # NO TRUNCATION - Full data
                "raw_results": raw_results,  # Include raw results
                "result_rows": len(raw_results) if success and raw_results else 0,
            }

            if not success:
                result["error"] = formatted_output

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e),  # Full error message
                "execution_time": 0,
                "result_rows": 0,
            }

    def _generate_summary_reports(self):
        """Generate overall summary JSON and TXT reports"""

        # Summary JSON Report
        json_path = os.path.join(self.output_dir, f"SUMMARY_{self.timestamp}.json")

        # Create a summary without full results (to keep it manageable)
        summary_data = {
            "test_metadata": self.test_results["test_metadata"],
            "query_tests": [
                {
                    "query_name": t["query_name"],
                    "query_type": t["query_type"],
                    "status": t["status"],
                    "timestamp": t["timestamp"],
                    "execution_time": t.get("stages", {})
                    .get("execution", {})
                    .get("execution_time", 0),
                    "result_rows": t.get("stages", {})
                    .get("execution", {})
                    .get("result_rows", 0),
                }
                for t in self.test_results["query_tests"]
            ],
        }

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(summary_data, f, indent=2, ensure_ascii=False)

        print(f"\n💾 Summary JSON saved: {json_path}")

        # Summary TXT Report
        txt_path = os.path.join(self.output_dir, f"SUMMARY_{self.timestamp}.txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            self._write_summary_text_report(f)

        print(f"💾 Summary TXT saved: {txt_path}")

    def _write_summary_text_report(self, f):
        """Write human-readable summary text report"""
        f.write("=" * 100 + "\n")
        f.write("KQL PIPELINE INTEGRATION TEST - SUMMARY REPORT\n")
        f.write("=" * 100 + "\n")
        f.write(f"Timestamp: {self.timestamp}\n")
        f.write(f"Total Tests: {self.test_results['test_metadata']['total_tests']}\n")
        f.write(f"Passed: {self.test_results['test_metadata']['passed']}\n")
        f.write(f"Failed: {self.test_results['test_metadata']['failed']}\n")
        f.write(f"Skipped: {self.test_results['test_metadata']['skipped']}\n")

        if self.test_results["test_metadata"]["total_tests"] > 0:
            pass_rate = (
                self.test_results["test_metadata"]["passed"]
                / self.test_results["test_metadata"]["total_tests"]
            ) * 100
            f.write(f"Pass Rate: {pass_rate:.1f}%\n")

        f.write("=" * 100 + "\n\n")

        f.write("DIRECTORY STRUCTURE:\n")
        f.write("-" * 100 + "\n")
        f.write(f"Hardcoded Queries: {self.hardcoded_dir}\n")
        f.write(f"Generated Queries: {self.generated_dir}\n")
        f.write(f"Manager Queries: {self.manager_dir}\n")
        f.write("\n")

        f.write("TEST RESULTS BY QUERY:\n")
        f.write("-" * 100 + "\n")
        for test in self.test_results["query_tests"]:
            status_icon = (
                "✅"
                if test["status"] == "PASSED"
                else "❌" if test["status"] == "FAILED" else "⚠️"
            )
            f.write(
                f"{status_icon} {test['query_name']} [{test['query_type']}] - {test['status']}\n"
            )

            execution = test.get("stages", {}).get("execution", {})
            if execution:
                f.write(f"   Execution Time: {execution.get('execution_time', 0)}s | ")
                f.write(f"Rows: {execution.get('result_rows', 0)}\n")

            if test.get("reason"):
                f.write(f"   Reason: {test['reason']}\n")

            f.write("\n")

    def _print_summary(self):
        """Print test summary to console"""
        metadata = self.test_results["test_metadata"]

        print(f"\n📊 Test Summary:")
        print(f"   Total Tests: {metadata['total_tests']}")
        print(f"   ✅ Passed: {metadata['passed']}")
        print(f"   ❌ Failed: {metadata['failed']}")
        print(f"   ⚠️  Skipped: {metadata['skipped']}")

        if metadata["total_tests"] > 0:
            pass_rate = (metadata["passed"] / metadata["total_tests"]) * 100
            print(f"   📈 Pass Rate: {pass_rate:.1f}%")

        print(f"\n📁 Individual query results saved in:")
        print(f"   • {self.hardcoded_dir}")
        print(f"   • {self.generated_dir}")
        print(f"   • {self.manager_dir}")
        print(f"\n📁 Summary reports in: {self.output_dir}/")


def main():
    """Main test runner"""

    print("\n🚀 Starting KQL Pipeline Integration Tests...\n")

    workspace_id = os.getenv("LOG_ANALYTICS_WORKSPACE_ID")
    if not workspace_id:
        print("⚠️  WARNING: LOG_ANALYTICS_WORKSPACE_ID not configured")
        print("   Query execution will be skipped\n")

    tester = KQLPipelineTester()
    tester.run_all_tests()

    print("\n✅ Testing completed successfully!")
    print(f"📁 Each query result saved in separate files")
    print(f"📁 Check subdirectories for complete results\n")


if __name__ == "__main__":
    main()
