#!/usr/bin/env python3

from routes.src.api_kql_generation import EnhancedKQLGenerator

def test_endpoint_security_conditional():
    print("Testing KQL Generator Conditional Logic")
    print("=" * 50)
    
    # Test 1: Regular alert (should use hardcoded)
    print("\n1. Testing Regular Alert:")
    regular_gen = EnhancedKQLGenerator(alert_source_type="")
    query1, explanation1 = regular_gen.generate_kql_query(
        step_name="Authentication Analysis", 
        explanation="Check user sign-in patterns"
    )
    print(f"   Query generated: {len(query1)} chars")
    print(f"   Uses SigninLogs: {'SigninLogs' in query1}")
    print(f"   Source: {'Hardcoded' if len(query1) > 1500 else 'API/None'}")
    
    # Test 2: Endpoint Security alert (should use API only)
    print("\n2. Testing Endpoint Security Alert:")
    endpoint_gen = EnhancedKQLGenerator(alert_source_type="Endpoint Security")
    query2, explanation2 = endpoint_gen.generate_kql_query(
        step_name="Device Analysis", 
        explanation="Check device configuration and network activity"
    )
    print(f"   Query generated: {len(query2)} chars")
    print(f"   Uses DeviceInfo: {'DeviceInfo' in query2}")
    print(f"   Uses SigninLogs: {'SigninLogs' in query2}")
    print(f"   Source: {'API' if len(query2) > 0 else 'None'}")
    
    # Test 3: Geographic analysis with endpoint
    print("\n3. Testing Geographic Analysis (Endpoint):")
    query3, explanation3 = endpoint_gen.generate_kql_query(
        step_name="Geographic Analysis", 
        explanation="Check for unusual locations and impossible travel"
    )
    print(f"   Query generated: {len(query3)} chars")
    print(f"   Uses DeviceInfo: {'DeviceInfo' in query3}")
    print(f"   Uses SigninLogs: {'SigninLogs' in query3}")
    
    print("\n" + "=" * 50)
    print("Test Complete")

if __name__ == "__main__":
    test_endpoint_security_conditional()