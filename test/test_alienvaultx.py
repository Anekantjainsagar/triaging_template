"""
AlienVault OTX API Testing Script
Tests various endpoints and shows what data can be extracted for SOC operations
"""

import requests
import json
from typing import Dict, List, Optional
from datetime import datetime

class OTXClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers = {
            "X-OTX-API-KEY": api_key,
            "Content-Type": "application/json"
        }
    
    def _make_request(self, endpoint: str, method: str = "GET", data: dict = None) -> dict:
        """Make API request with error handling"""
        url = f"{self.base_url}/{endpoint}"
        try:
            if method == "GET":
                response = requests.get(url, headers=self.headers, timeout=30)
            elif method == "POST":
                response = requests.post(url, headers=self.headers, json=data, timeout=30)
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}
    
    # ============ INDICATOR ENDPOINTS ============
    
    def get_ip_general(self, ip: str) -> dict:
        """Get general information about an IP address"""
        return self._make_request(f"indicators/IPv4/{ip}/general")
    
    def get_ip_reputation(self, ip: str) -> dict:
        """Get reputation data for an IP"""
        return self._make_request(f"indicators/IPv4/{ip}/reputation")
    
    def get_ip_geo(self, ip: str) -> dict:
        """Get geolocation data for an IP"""
        return self._make_request(f"indicators/IPv4/{ip}/geo")
    
    def get_ip_malware(self, ip: str) -> dict:
        """Get malware samples associated with an IP"""
        return self._make_request(f"indicators/IPv4/{ip}/malware")
    
    def get_ip_url_list(self, ip: str) -> dict:
        """Get URLs hosted on this IP"""
        return self._make_request(f"indicators/IPv4/{ip}/url_list")
    
    def get_ip_passive_dns(self, ip: str) -> dict:
        """Get passive DNS data for an IP"""
        return self._make_request(f"indicators/IPv4/{ip}/passive_dns")
    
    def get_domain_general(self, domain: str) -> dict:
        """Get general information about a domain"""
        return self._make_request(f"indicators/domain/{domain}/general")
    
    def get_domain_malware(self, domain: str) -> dict:
        """Get malware associated with a domain"""
        return self._make_request(f"indicators/domain/{domain}/malware")
    
    def get_domain_url_list(self, domain: str) -> dict:
        """Get URLs on this domain"""
        return self._make_request(f"indicators/domain/{domain}/url_list")
    
    def get_domain_passive_dns(self, domain: str) -> dict:
        """Get passive DNS for a domain"""
        return self._make_request(f"indicators/domain/{domain}/passive_dns")
    
    def get_domain_whois(self, domain: str) -> dict:
        """Get WHOIS data for a domain"""
        return self._make_request(f"indicators/domain/{domain}/whois")
    
    def get_file_hash_analysis(self, file_hash: str) -> dict:
        """Get analysis of a file hash"""
        return self._make_request(f"indicators/file/{file_hash}/analysis")
    
    def get_file_hash_general(self, file_hash: str) -> dict:
        """Get general information about a file hash"""
        return self._make_request(f"indicators/file/{file_hash}/general")
    
    def get_url_general(self, url: str) -> dict:
        """Get general information about a URL"""
        return self._make_request(f"indicators/url/{url}/general")
    
    def get_url_url_list(self, url: str) -> dict:
        """Get related URLs"""
        return self._make_request(f"indicators/url/{url}/url_list")
    
    def get_cve_info(self, cve: str) -> dict:
        """Get information about a CVE"""
        return self._make_request(f"indicators/cve/{cve}/general")
    
    # ============ PULSES (Threat Intelligence Reports) ============
    
    def get_subscribed_pulses(self, limit: int = 10) -> dict:
        """Get pulses you're subscribed to"""
        return self._make_request(f"pulses/subscribed?limit={limit}")
    
    def get_pulse_by_id(self, pulse_id: str) -> dict:
        """Get detailed information about a specific pulse"""
        return self._make_request(f"pulses/{pulse_id}")
    
    def get_pulse_indicators(self, pulse_id: str) -> dict:
        """Get all indicators from a pulse"""
        return self._make_request(f"pulses/{pulse_id}/indicators")
    
    def get_pulse_related(self, pulse_id: str) -> dict:
        """Get related pulses"""
        return self._make_request(f"pulses/{pulse_id}/related")
    
    def get_my_pulses(self) -> dict:
        """Get your created pulses"""
        return self._make_request("pulses/my")
    
    def search_pulses(self, query: str, limit: int = 10) -> dict:
        """Search for pulses"""
        return self._make_request(f"search/pulses?q={query}&limit={limit}")
    
    # ============ USER ENDPOINTS ============
    
    def get_my_info(self) -> dict:
        """Get your user information"""
        return self._make_request("user/me")
    
    def get_user_info(self, username: str) -> dict:
        """Get information about a specific user"""
        return self._make_request(f"users/{username}")
    
    # ============ UTILITY FUNCTIONS ============
    
    def submit_url(self, url: str, tlp: str = "white") -> dict:
        """Submit a URL for analysis"""
        data = {"url": url, "tlp": tlp}
        return self._make_request("indicators/submit_url", method="POST", data=data)
    
    def get_indicator_types(self) -> dict:
        """Get available indicator types"""
        return self._make_request("pulses/indicators/types")


# ============ TESTING & DEMONSTRATION ============

def test_otx_api():
    """Test various OTX API endpoints and display results"""
    
    # Initialize client
    API_KEY = "b5a8f6ef8a76de67d064c1645446e0b9d96bac5d14e1a07e6814e3a82f93c86e"
    client = OTXClient(API_KEY)
    
    print("=" * 80)
    print("AlienVault OTX API Testing - SOC Use Cases")
    print("=" * 80)
    
    # Test 1: User Info
    print("\n[1] Testing User Info")
    print("-" * 80)
    user_info = client.get_my_info()
    if "error" not in user_info:
        print(f"✓ User: {user_info.get('username', 'N/A')}")
        print(f"✓ Member Since: {user_info.get('member_since', 'N/A')}")
        print(f"✓ Followers: {user_info.get('follower_count', 0)}")
    else:
        print(f"✗ Error: {user_info['error']}")
    
    # Test 2: Malicious IP Analysis (Example: known bad IP)
    print("\n[2] Testing IP Reputation Analysis")
    print("-" * 80)
    test_ip = "185.220.101.1"  # Known Tor exit node
    
    print(f"Analyzing IP: {test_ip}")
    
    # General info
    ip_general = client.get_ip_general(test_ip)
    if "error" not in ip_general:
        print(f"✓ Pulse Count: {ip_general.get('pulse_info', {}).get('count', 0)}")
        print(f"✓ Reputation: {ip_general.get('reputation', 0)}")
    
    # Geolocation
    ip_geo = client.get_ip_geo(test_ip)
    if "error" not in ip_geo and ip_geo:
        print(f"✓ Country: {ip_geo.get('country_name', 'N/A')}")
        print(f"✓ City: {ip_geo.get('city', 'N/A')}")
        print(f"✓ ASN: {ip_geo.get('asn', 'N/A')}")
    
    # Malware associations
    ip_malware = client.get_ip_malware(test_ip)
    if "error" not in ip_malware and ip_malware.get('data'):
        print(f"✓ Associated Malware Samples: {len(ip_malware.get('data', []))}")
    
    # Test 3: Domain Analysis
    print("\n[3] Testing Domain Analysis")
    print("-" * 80)
    test_domain = "example.com"
    
    domain_general = client.get_domain_general(test_domain)
    if "error" not in domain_general:
        print(f"✓ Domain: {test_domain}")
        print(f"✓ Pulses: {domain_general.get('pulse_info', {}).get('count', 0)}")
    
    # Test 4: File Hash Analysis (Example: known malware hash)
    print("\n[4] Testing File Hash Analysis")
    print("-" * 80)
    # Emotet malware hash example
    test_hash = "44d88612fea8a8f36de82e1278abb02f"
    
    file_info = client.get_file_hash_general(test_hash)
    if "error" not in file_info:
        print(f"✓ Hash: {test_hash}")
        print(f"✓ Pulses: {file_info.get('pulse_info', {}).get('count', 0)}")
    
    # Test 5: CVE Information
    print("\n[5] Testing CVE Information")
    print("-" * 80)
    test_cve = "CVE-2021-44228"  # Log4Shell
    
    cve_info = client.get_cve_info(test_cve)
    if "error" not in cve_info:
        print(f"✓ CVE: {test_cve}")
        print(f"✓ Pulses: {cve_info.get('pulse_info', {}).get('count', 0)}")
    
    # Test 6: Subscribed Pulses
    print("\n[6] Testing Subscribed Pulses (Threat Intelligence)")
    print("-" * 80)
    
    pulses = client.get_subscribed_pulses(limit=5)
    if "error" not in pulses and pulses.get('results'):
        print(f"✓ Found {len(pulses['results'])} recent pulses:")
        for i, pulse in enumerate(pulses['results'][:3], 1):
            print(f"  {i}. {pulse.get('name', 'N/A')}")
            print(f"     Author: {pulse.get('author_name', 'N/A')}")
            print(f"     Tags: {', '.join(pulse.get('tags', [])[:5])}")
            print(f"     Indicators: {pulse.get('indicator_count', 0)}")
    
    # Test 7: Search Pulses
    print("\n[7] Testing Pulse Search")
    print("-" * 80)
    
    search_results = client.search_pulses("ransomware", limit=3)
    if "error" not in search_results and search_results.get('results'):
        print(f"✓ Found {len(search_results['results'])} ransomware-related pulses")
    
    # Test 8: Indicator Types
    print("\n[8] Available Indicator Types")
    print("-" * 80)
    
    indicator_types = client.get_indicator_types()
    if "error" not in indicator_types:
        print("✓ Available indicator types:")
        for ioc_type in indicator_types:
            print(f"  - {ioc_type}")
    
    print("\n" + "=" * 80)
    print("Testing Complete!")
    print("=" * 80)


# ============ SOC USE CASE EXAMPLES ============

def soc_use_case_examples():
    """Demonstrate practical SOC use cases"""
    
    print("\n\n")
    print("=" * 80)
    print("SOC USE CASE EXAMPLES")
    print("=" * 80)
    
    print("""
    
1. ALERT ENRICHMENT - IP Investigation
   ----------------------------------------
   When you receive an alert with suspicious IP:
   - get_ip_general() → Check reputation & pulse count
   - get_ip_geo() → Identify source country/ASN
   - get_ip_malware() → Find associated malware
   - get_ip_passive_dns() → Discover related domains
   - get_ip_url_list() → Find hosted malicious URLs
   
   USE: Add to "Technical Overview" and "Business Impact"

2. MALWARE ANALYSIS - File Hash Lookup
   ----------------------------------------
   When analyzing suspicious files:
   - get_file_hash_general() → Get basic info & pulses
   - get_file_hash_analysis() → Detailed malware analysis
   
   USE: Identify malware family for "Threat Actors" section

3. DOMAIN/URL INVESTIGATION
   ----------------------------------------
   For phishing or C2 analysis:
   - get_domain_general() → Domain reputation
   - get_domain_whois() → Registration info
   - get_domain_passive_dns() → DNS history
   - get_url_general() → URL reputation
   
   USE: Build "Attack Story" for phishing campaigns

4. CVE THREAT INTELLIGENCE
   ----------------------------------------
   For vulnerability management:
   - get_cve_info() → Get exploit information
   - Search related pulses → Find active exploits
   
   USE: Link to "MITRE ATT&CK Techniques"

5. THREAT HUNTING - Pulse Subscriptions
   ----------------------------------------
   Proactive threat intelligence:
   - get_subscribed_pulses() → Latest threat intel
   - get_pulse_indicators() → Extract IOCs
   - get_pulse_related() → Find related campaigns
   
   USE: Create "Triaging Steps" based on known TTPs

6. IOC CORRELATION
   ----------------------------------------
   Link related indicators:
   - Start with one IOC (IP/domain/hash)
   - Get associated pulses
   - Extract all indicators from those pulses
   - Build relationship graph
   
   USE: Complete "Attack Story Building"
    """)


# ============ MAIN EXECUTION ============

if __name__ == "__main__":
    # Run tests
    test_otx_api()
    
    # Show use cases
    soc_use_case_examples()
    
    print("\n\nNOTE: Replace the test indicators with actual IOCs from your alerts")
    print("for real-time threat intelligence enrichment in your L1 SOC agent.")