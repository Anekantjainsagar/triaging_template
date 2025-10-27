import requests
import json

# API endpoint
api_url = "https://www.kqlsearch.com/api/querygenerator"

# Input payload
payload = {
    "input": "Verify User & IP Address Details\tReview login event details (user account, IP address, time, Geo location & User agent) Analyze audit and signin logs to identify successful and failed attempts for last 7 days & device history."
}

# Make the POST request
try:
    response = requests.post(api_url, json=payload, timeout=30)
    response.raise_for_status()  # Raise exception for bad status codes

    # Parse the JSON response
    result = response.json()

    print("API Response:")
    print("=" * 80)
    print(json.dumps(result, indent=2))
    print("=" * 80)

    # Extract and display the KQL query if available
    if "content" in result:
        print("\nExtracted KQL Query:")
        print("-" * 80)
        # Remove the ```kql markers if present
        kql_query = result["content"]
        if "```kql" in kql_query:
            kql_query = kql_query.split("```kql")[1].split("```")[0].strip()
        print(kql_query)
        print("-" * 80)

except requests.exceptions.RequestException as e:
    print(f"Error making API request: {e}")
except json.JSONDecodeError as e:
    print(f"Error parsing JSON response: {e}")
    print(f"Raw response: {response.text}")
