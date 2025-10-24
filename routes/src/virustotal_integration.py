import os
import requests
from typing import Dict, Optional
from crewai import LLM, Agent, Task, Crew
from crewai_tools import SerperDevTool, ScrapeWebsiteTool
from dotenv import load_dotenv
import time
import re

load_dotenv()


class VirusTotalChecker:
    """
    Handles IP reputation checks using VirusTotal
    Supports multiple methods: API (preferred), Web Scraping (fallback), Manual
    """

    def __init__(self):
        self.vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.use_api = bool(self.vt_api_key)

        if self.use_api:
            print("✅ VirusTotal API mode enabled")
        else:
            print("⚠️ No API key found, will use web scraping")

        # Initialize LLM for web scraping
        ollama_model = os.getenv("OLLAMA_CHAT", "ollama/qwen2.5:3b")
        if not ollama_model.startswith("ollama/"):
            ollama_model = f"ollama/{ollama_model}"

        self.llm = LLM(model=ollama_model, base_url="http://localhost:11434")

        try:
            self.scraper = ScrapeWebsiteTool()
            self.has_scraper = True
        except:
            self.scraper = None
            self.has_scraper = False

    def check_ip_reputation(self, ip_address: str, method: str = "auto") -> Dict:
        """
        Check IP reputation using specified method

        Args:
            ip_address: IP to check
            method: "api", "scrape", "auto" (tries API first, then scrape)

        Returns:
            Dictionary with reputation data and formatted output
        """

        if not self._is_valid_ip(ip_address):
            return {
                "success": False,
                "error": "Invalid IP address format",
                "formatted_output": "❌ Invalid IP address",
            }

        # Auto mode: try API first, then scraping
        if method == "auto":
            if self.use_api:
                return self._check_via_api(ip_address)
            elif self.has_scraper:
                return self._check_via_scraping(ip_address)
            else:
                return self._generate_manual_instructions(ip_address)

        # Specific method requested
        if method == "api":
            return self._check_via_api(ip_address)
        elif method == "scrape":
            return self._check_via_scraping(ip_address)
        else:
            return self._generate_manual_instructions(ip_address)

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        if not re.match(pattern, ip):
            return False

        # Check each octet is 0-255
        octets = ip.split(".")
        return all(0 <= int(octet) <= 255 for octet in octets)

    def _check_via_api(self, ip_address: str) -> Dict:
        """
        Check IP using VirusTotal API v3
        """

        if not self.vt_api_key:
            return {
                "success": False,
                "error": "No API key configured",
                "formatted_output": "❌ VirusTotal API key not found",
            }

        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
            headers = {"x-apikey": self.vt_api_key, "Accept": "application/json"}

            print(f"🔍 Checking {ip_address} via VirusTotal API...")
            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                return self._parse_api_response(ip_address, data)
            elif response.status_code == 404:
                return {
                    "success": True,
                    "ip_address": ip_address,
                    "reputation": "Unknown",
                    "malicious_count": 0,
                    "suspicious_count": 0,
                    "harmless_count": 0,
                    "formatted_output": self._format_unknown_ip(ip_address),
                }
            else:
                return {
                    "success": False,
                    "error": f"API returned status {response.status_code}",
                    "formatted_output": f"❌ API Error: {response.status_code}",
                }

        except Exception as e:
            print(f"⚠️ API check failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "formatted_output": f"❌ API Error: {str(e)}",
            }

    def _format_for_excel(self, ip_address: str, data: Dict) -> str:
        """
        Format VirusTotal results for Excel export (plain text, no markdown)
        """
        try:
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total_scans = malicious + suspicious + harmless + undetected

            # Determine reputation (plain text)
            if malicious > 0:
                reputation = "MALICIOUS"
                risk_level = "HIGH"
                risk_symbol = "[!]"
            elif suspicious > 0:
                reputation = "SUSPICIOUS"
                risk_level = "MEDIUM"
                risk_symbol = "[*]"
            elif harmless > 0:
                reputation = "CLEAN"
                risk_level = "LOW"
                risk_symbol = "[OK]"
            else:
                reputation = "UNKNOWN"
                risk_level = "UNKNOWN"
                risk_symbol = "[?]"

            # Get additional details
            country = attributes.get("country", "Unknown")
            asn = attributes.get("asn", "Unknown")
            as_owner = attributes.get("as_owner", "Unknown")

            # Format for Excel (plain text with clear structure)
            formatted_output = f"""VirusTotal IP Reputation Check
    {"="*50}

    IP Address: {ip_address}
    Reputation: {risk_symbol} {reputation}
    Risk Level: {risk_level}

    Detection Results:
    • Malicious: {malicious}/{total_scans}
    • Suspicious: {suspicious}/{total_scans}
    • Harmless: {harmless}/{total_scans}
    • Undetected: {undetected}/{total_scans}

    Network Details:
    • Country: {country}
    • ASN: {asn}
    • Owner: {as_owner}

    Recommendation:
    {self._get_recommendation_plain(risk_level)}

    Verified: {time.strftime("%Y-%m-%d %H:%M:%S")}
    VirusTotal URL: https://www.virustotal.com/gui/ip-address/{ip_address}
    """
            return formatted_output.strip()

        except Exception as e:
            return f"VirusTotal Check Result:\nIP: {ip_address}\nError parsing results: {str(e)}"

    def _get_recommendation_plain(self, risk_level: str) -> str:
        """Plain text recommendations for Excel"""
        recommendations = {
            "HIGH": "[ACTION REQUIRED] Block this IP and investigate all related activity. Known malicious IP.",
            "MEDIUM": "[CAUTION] Monitor closely. Consider blocking and investigate before allowing access.",
            "LOW": "[NO ACTION] IP appears clean. Continue with standard investigation.",
            "UNKNOWN": "[INVESTIGATE] No reputation data available. Verify through other means.",
        }
        return recommendations.get(risk_level, "Continue investigation")

    def _parse_api_response(self, ip_address: str, data: Dict) -> Dict:
        """Parse VirusTotal API response"""

        try:
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total_scans = malicious + suspicious + harmless + undetected

            # Determine reputation
            if malicious > 0:
                reputation = "🔴 MALICIOUS"
                risk_level = "HIGH"
            elif suspicious > 0:
                reputation = "🟡 SUSPICIOUS"
                risk_level = "MEDIUM"
            elif harmless > 0:
                reputation = "🟢 CLEAN"
                risk_level = "LOW"
            else:
                reputation = "⚪ UNKNOWN"
                risk_level = "UNKNOWN"

            country = attributes.get("country", "Unknown")
            asn = attributes.get("asn", "Unknown")
            as_owner = attributes.get("as_owner", "Unknown")

            # Markdown format for UI display
            formatted_output_ui = f"""
    🔍 **VirusTotal IP Reputation Report**

    **IP Address:** {ip_address}
    **Reputation:** {reputation}
    **Risk Level:** {risk_level}

    **Detection Statistics:**
    - Malicious: {malicious}/{total_scans}
    - Suspicious: {suspicious}/{total_scans}
    - Harmless: {harmless}/{total_scans}
    - Undetected: {undetected}/{total_scans}

    **Network Information:**
    - Country: {country}
    - ASN: {asn}
    - Owner: {as_owner}

    **Recommendation:**
    {self._get_recommendation(risk_level)}

    **VirusTotal Link:** https://www.virustotal.com/gui/ip-address/{ip_address}
    """

            # Plain text format for Excel
            formatted_output_excel = self._format_for_excel(ip_address, data)

            return {
                "success": True,
                "ip_address": ip_address,
                "reputation": reputation,
                "risk_level": risk_level,
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "harmless_count": harmless,
                "total_scans": total_scans,
                "country": country,
                "asn": asn,
                "as_owner": as_owner,
                "formatted_output": formatted_output_ui.strip(),  # For UI display
                "formatted_output_excel": formatted_output_excel,  # For Excel export
            }

        except Exception as e:
            print(f"⚠️ Failed to parse API response: {str(e)}")
            return {
                "success": False,
                "error": f"Failed to parse response: {str(e)}",
                "formatted_output": f"❌ Error parsing VirusTotal data",
                "formatted_output_excel": f"VirusTotal Check Failed\nError: {str(e)}",
            }

    def _check_via_scraping(self, ip_address: str) -> Dict:
        """
        Check IP using CrewAI web scraping (fallback method)
        """

        if not self.has_scraper:
            return self._generate_manual_instructions(ip_address)

        try:
            url = f"https://www.virustotal.com/gui/ip-address/{ip_address}"

            print(f"🕷️ Scraping VirusTotal page for {ip_address}...")

            # Create scraping agent
            scraper_agent = Agent(
                role="Web Scraping Analyst",
                goal="Extract IP reputation data from VirusTotal",
                backstory="Expert in web scraping and data extraction",
                llm=self.llm,
                tools=[self.scraper],
                verbose=False,
            )

            scraping_task = Task(
                description=f"""
Scrape the VirusTotal page: {url}

Extract:
1. Detection statistics (malicious, suspicious, clean counts)
2. Total number of security vendors
3. Country and ASN information
4. Overall reputation assessment

Return structured data.
""",
                expected_output="IP reputation data",
                agent=scraper_agent,
            )

            crew = Crew(agents=[scraper_agent], tasks=[scraping_task], verbose=False)

            result = str(crew.kickoff())

            # Parse the scraped result
            # Note: This is simplified - actual parsing would be more robust
            return {
                "success": True,
                "ip_address": ip_address,
                "reputation": "Unknown (Scraped)",
                "formatted_output": f"""
🕷️ **VirusTotal Web Scraping Result**

**IP Address:** {ip_address}
**Method:** Web Scraping

**Scraped Data:**
{result}

**Manual Verification:**
Please verify at: {url}
""",
            }

        except Exception as e:
            print(f"⚠️ Scraping failed: {str(e)}")
            return self._generate_manual_instructions(ip_address)

    def _generate_manual_instructions(self, ip_address: str) -> Dict:
        """
        Generate manual check instructions
        """

        url = f"https://www.virustotal.com/gui/ip-address/{ip_address}"

        formatted_output = f"""
📋 **Manual VirusTotal IP Check Required**

**IP Address to Check:** {ip_address}

**Steps:**
1. Open VirusTotal: {url}
2. Review the detection statistics:
   - Look for "Malicious" count (red)
   - Look for "Suspicious" count (yellow)
   - Look for "Clean" count (green)
3. Check the Community Score and comments
4. Review the WHOIS information (Country, ASN, Owner)
5. Document your findings below

**What to Look For:**
- ✅ Clean: 0 malicious detections, recognized organization
- ⚠️ Suspicious: Low malicious count (1-3), unknown ASN
- 🔴 Malicious: High detection count (4+), known bad reputation

**Paste your findings in the Output field above**
"""

        return {
            "success": True,
            "ip_address": ip_address,
            "reputation": "Manual Check Required",
            "manual_check": True,
            "url": url,
            "formatted_output": formatted_output.strip(),
        }

    def _format_unknown_ip(self, ip_address: str) -> str:
        """Format output for unknown IPs"""
        return f"""
⚪ **IP Not Found in VirusTotal Database**

**IP Address:** {ip_address}

This IP address has not been analyzed by VirusTotal yet or has no detection history.

**This could mean:**
- New or rarely-used IP address
- Private/internal IP address
- Not previously reported as malicious

**Recommendation:**
Proceed with other investigation steps to determine legitimacy. Check:
- User confirmation
- Sign-in patterns
- Geographic location consistency
- Historical user behavior
"""

    def _get_recommendation(self, risk_level: str) -> str:
        """Get recommendation based on risk level"""

        recommendations = {
            "HIGH": "🚨 **IMMEDIATE ACTION REQUIRED** - Block this IP address and investigate all related activity. This IP is known to be malicious.",
            "MEDIUM": "⚠️ **CAUTION RECOMMENDED** - Monitor this IP closely. Consider temporary blocking and investigate further before allowing access.",
            "LOW": "✅ **NO IMMEDIATE ACTION** - This IP appears clean. Continue with standard investigation procedures.",
            "UNKNOWN": "❓ **FURTHER INVESTIGATION NEEDED** - No reputation data available. Verify through other means.",
        }

        return recommendations.get(risk_level, "Continue investigation")


# Streamlit Integration Helper
def create_virustotal_step_ui(ip_address: str):
    """
    Helper function for Streamlit integration
    Can be called from step2_enhance.py
    """
    import streamlit as st

    if "vt_checker" not in st.session_state:
        st.session_state.vt_checker = VirusTotalChecker()

    checker = st.session_state.vt_checker

    col1, col2 = st.columns([3, 1])

    with col1:
        ip_input = st.text_input(
            "Enter IP Address to Check:", value=ip_address, key="vt_ip_input"
        )

    with col2:
        check_method = st.selectbox(
            "Method:", ["auto", "api", "scrape", "manual"], key="vt_method"
        )

    if st.button("🔍 Check IP Reputation", type="primary"):
        with st.spinner("Checking VirusTotal..."):
            result = checker.check_ip_reputation(ip_input, method=check_method)

        if result.get("success"):
            st.markdown(result.get("formatted_output"))

            # Auto-populate output field
            if "output_input" in st.session_state:
                st.session_state["output_input"] = result.get("formatted_output")
                st.success("✅ Output auto-populated!")
        else:
            st.error(f"❌ {result.get('error')}")
