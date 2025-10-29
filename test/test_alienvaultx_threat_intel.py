import requests
import json
from datetime import datetime


class OTXThreatIntel:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers = {"X-OTX-API-KEY": api_key, "Content-Type": "application/json"}

    def search_pulses(self, query):
        """Search for threat pulses related to the query"""
        url = f"{self.base_url}/search/pulses"
        params = {"q": query, "page": 1, "limit": 20}

        try:
            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error searching pulses: {e}")
            return None

    def get_subscribed_pulses(self):
        """Get subscribed pulses for monitoring"""
        url = f"{self.base_url}/pulses/subscribed"
        params = {"limit": 20, "page": 1}

        try:
            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error getting subscribed pulses: {e}")
            return None

    def get_pulse_details(self, pulse_id):
        """Get detailed information about a specific pulse"""
        url = f"{self.base_url}/pulses/{pulse_id}"

        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error getting pulse details: {e}")
            return None

    def get_pulse_indicators(self, pulse_id):
        """Get indicators from a specific pulse"""
        url = f"{self.base_url}/pulses/{pulse_id}/indicators"

        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error getting pulse indicators: {e}")
            return None

    def search_related_threats(self, keywords):
        """Search for threats related to multiple keywords"""
        all_results = []

        for keyword in keywords:
            print(f"\n{'='*60}")
            print(f"Searching for: {keyword}")
            print(f"{'='*60}")

            results = self.search_pulses(keyword)

            if results and "results" in results:
                print(f"Found {len(results['results'])} pulses")
                all_results.extend(results["results"])

                for pulse in results["results"][:5]:  # Show top 5
                    print(f"\n  Title: {pulse.get('name', 'N/A')}")
                    print(f"  ID: {pulse.get('id', 'N/A')}")
                    print(f"  Created: {pulse.get('created', 'N/A')}")
                    print(f"  Tags: {', '.join(pulse.get('tags', []))}")
                    print(f"  Description: {pulse.get('description', 'N/A')[:200]}...")
            else:
                print(f"No results found for '{keyword}'")

        return all_results

    def get_detailed_threat_report(self, pulse_id):
        """Get comprehensive threat report including indicators"""
        print(f"\n{'='*60}")
        print(f"Detailed Threat Report for Pulse ID: {pulse_id}")
        print(f"{'='*60}")

        # Get pulse details
        pulse = self.get_pulse_details(pulse_id)
        if pulse:
            print(f"\nName: {pulse.get('name', 'N/A')}")
            print(f"Created: {pulse.get('created', 'N/A')}")
            print(f"Modified: {pulse.get('modified', 'N/A')}")
            print(f"Author: {pulse.get('author_name', 'N/A')}")
            print(f"Tags: {', '.join(pulse.get('tags', []))}")
            print(f"\nDescription:\n{pulse.get('description', 'N/A')}")

            # Get indicators
            indicators = self.get_pulse_indicators(pulse_id)
            if indicators:
                print(f"\n--- Indicators of Compromise (IoCs) ---")
                for idx, indicator in enumerate(indicators[:10], 1):
                    print(f"\n{idx}. Type: {indicator.get('type', 'N/A')}")
                    print(f"   Indicator: {indicator.get('indicator', 'N/A')}")
                    print(f"   Description: {indicator.get('description', 'N/A')}")


def main():
    # Initialize the OTX client
    API_KEY = "b5a8f6ef8a76de67d064c1645446e0b9d96bac5d14e1a07e6814e3a82f93c86e"
    otx = OTXThreatIntel(API_KEY)

    # Define search keywords related to unusual login patterns and behavioral analytics
    keywords = [
        "unusual login",
        "login anomaly",
        "credential abuse",
        "brute force login",
        "account takeover",
        "suspicious authentication",
        "failed login attempts",
        "impossible travel",
        "behavioral analytics",
        "user behavior analytics",
    ]

    print("=" * 60)
    print("AlienVault OTX Threat Intelligence Search")
    print("Topic: Unusual Login Patterns & Behavioral Analytics")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # Search for related threats
    all_threats = otx.search_related_threats(keywords)

    # Get detailed report for the first relevant pulse
    if all_threats:
        print(f"\n\n{'='*60}")
        print(f"Total unique pulses found: {len(set(p['id'] for p in all_threats))}")
        print(f"{'='*60}")

        # Get detailed report for the most recent pulse
        if all_threats:
            most_recent = sorted(
                all_threats, key=lambda x: x.get("modified", ""), reverse=True
            )[0]
            otx.get_detailed_threat_report(most_recent["id"])

    # Optional: Get subscribed pulses for ongoing monitoring
    print(f"\n\n{'='*60}")
    print("Checking Subscribed Pulses for Monitoring")
    print(f"{'='*60}")
    subscribed = otx.get_subscribed_pulses()
    if subscribed and "results" in subscribed:
        print(f"You are subscribed to {len(subscribed['results'])} pulses")
        for pulse in subscribed["results"][:3]:
            print(f"\n  - {pulse.get('name', 'N/A')}")

    print("\n\n" + "=" * 60)
    print("Search Complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
