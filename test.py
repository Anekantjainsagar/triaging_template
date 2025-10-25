# test_integration.py
import sys

sys.path.append(".")

from routes.src.enhanced_kql_generation import EnhancedKQLGenerator


def test_unique_generation():
    generator = EnhancedKQLGenerator()

    # Simulate your 4 steps
    steps = [
        {
            "name": "Verify User Count Impact",
            "explanation": "Gather details of all users - (By adding sheet to this excel)",
            "number": 1,
        },
        {
            "name": "Verify Users Against VIP List",
            "explanation": "Verify user activity against VIP list by reviewing login logs",
            "number": 2,
        },
        {
            "name": "Verify User & IP Address Details",
            "explanation": "Review login event details (user account, IP address, time, Geo location)",
            "number": 3,
        },
        {
            "name": "Verify IP Reputation using VirusTotal",
            "explanation": "Check IP reputation using VirusTotal If bad score, take a screenshot",
            "number": 4,
        },
    ]

    print("🔍 Testing KQL Generation for Each Step\n")
    print("=" * 80)

    generated_queries = []

    for step in steps:
        kql, explanation = generator.generate_kql_query(
            step_name=step["name"],
            explanation=step["explanation"],
            step_number=step["number"],
            rule_context="User authentication and access investigation",
        )

        generated_queries.append(
            {
                "step": step["number"],
                "name": step["name"],
                "kql": kql,
                "explanation": explanation,
            }
        )

        print(f"\n📌 STEP {step['number']}: {step['name']}")
        print("-" * 80)
        if kql:
            print(f"✅ KQL Query ({len(kql)} chars):")
            print(kql)
            print(f"\n💡 Explanation: {explanation}")
        else:
            print("⏭️  No KQL needed (manual step)")
        print("=" * 80)

    # Verify uniqueness
    kql_queries = [q["kql"] for q in generated_queries if q["kql"]]

    if len(kql_queries) != len(set(kql_queries)):
        print("\n❌ FAILED: Some queries are duplicates!")
        return False
    else:
        print(f"\n✅ SUCCESS: All {len(kql_queries)} queries are unique!")
        return True


if __name__ == "__main__":
    success = test_unique_generation()
    sys.exit(0 if success else 1)
