from routes.src.kql_template_injector import TemplateKQLInjector
from datetime import datetime, timedelta

def test_kql_injection():
    print("Testing KQL Time Injection Logic")
    print("=" * 50)
    
    # Test cases
    test_cases = [
        {
            "name": "Alert from today (13th Nov)",
            "alert_time": "2025-11-13T10:00:00.000Z",
            "expected": "Should use lookback (6th-13th Nov)"
        },
        {
            "name": "Alert from yesterday (12th Nov)", 
            "alert_time": "2025-11-12T05:48:08.250Z",
            "expected": "Should use lookback (5th-12th Nov)"
        },
        {
            "name": "Alert from 6th Nov (older)",
            "alert_time": "2025-11-06T10:00:00.000Z", 
            "expected": "Should use centered window (2nd-9th Nov)"
        },
        {
            "name": "Alert from 1st Nov (much older)",
            "alert_time": "2025-11-01T10:00:00.000Z",
            "expected": "Should use centered window (28th Oct - 4th Nov)"
        }
    ]
    
    test_kql = """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "<USER_EMAIL>"
| summarize count() by UserPrincipalName"""
    
    for test in test_cases:
        print(f"\n{test['name']}")
        print(f"Alert time: {test['alert_time']}")
        print(f"Expected: {test['expected']}")
        
        # Create alert data
        alert_data = {
            "full_alert": {
                "properties": {
                    "timeGenerated": test['alert_time']
                }
            },
            "entities": {
                "entities": [
                    {
                        "kind": "account",
                        "properties": {
                            "accountName": "test.user",
                            "upnSuffix": "company.com"
                        }
                    }
                ]
            }
        }
        
        # Test injection
        injector = TemplateKQLInjector(alert_data)
        result = injector.inject_kql(test_kql)
        
        # Extract time range from result
        import re
        time_pattern = r'TimeGenerated > datetime\(([^)]+)\) and TimeGenerated <= datetime\(([^)]+)\)'
        match = re.search(time_pattern, result)
        
        if match:
            start_time = match.group(1)
            end_time = match.group(2)
            print(f"Actual range: {start_time} to {end_time}")
        else:
            print("No time range found in result")
        
        print("-" * 30)

if __name__ == "__main__":
    test_kql_injection()