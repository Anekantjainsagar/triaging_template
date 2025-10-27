import os
import requests
from typing import Dict, Optional, List
from crewai import LLM, Agent, Task, Crew
from crewai_tools import SerperDevTool, ScrapeWebsiteTool
from dotenv import load_dotenv
import time
import re

load_dotenv()


class IPReputationChecker:
    """
    Unified IP reputation checker using multiple sources:
    - VirusTotal
    - AbuseIPDB
    Provides aggregated risk assessment
    """

    def __init__(self):
        self.vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.abuseipdb_key = os.getenv("ABUSE_DB_KEY")

        self.use_vt = bool(self.vt_api_key)
        self.use_abuseipdb = bool(self.abuseipdb_key)

        if self.use_vt:
            print("✅ VirusTotal API enabled")
        else:
            print("⚠️ VirusTotal API key not found")

        if self.use_abuseipdb:
            print("✅ AbuseIPDB API enabled")
        else:
            print("⚠️ AbuseIPDB API key not found")

        # Initialize LLM for web scraping fallback
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
        Check IP reputation using multiple sources

        Args:
            ip_address: IP to check
            method: "api" (both APIs), "auto" (tries APIs, falls back to manual)

        Returns:
            Dictionary with aggregated reputation data
        """

        if not self._is_valid_ip(ip_address):
            return {
                "success": False,
                "error": "Invalid IP address format",
                "formatted_output": "❌ Invalid IP address",
            }

        # Check both sources in parallel
        results = {}

        if method == "auto" or method == "api":
            if self.use_vt:
                print(f"🔍 Checking VirusTotal for {ip_address}...")
                results["virustotal"] = self._check_virustotal(ip_address)

            if self.use_abuseipdb:
                print(f"🔍 Checking AbuseIPDB for {ip_address}...")
                results["abuseipdb"] = self._check_abuseipdb(ip_address)

        # If no API keys available, return manual instructions
        if not results:
            return self._generate_manual_instructions(ip_address)

        # Aggregate results
        return self._aggregate_results(ip_address, results)

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        if not re.match(pattern, ip):
            return False

        octets = ip.split(".")
        return all(0 <= int(octet) <= 255 for octet in octets)

    def _check_virustotal(self, ip_address: str) -> Dict:
        """Check IP using VirusTotal API v3"""
        if not self.vt_api_key:
            return {"success": False, "error": "No API key"}

        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
            headers = {"x-apikey": self.vt_api_key, "Accept": "application/json"}

            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total_scans = malicious + suspicious + harmless + undetected

                return {
                    "success": True,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "total_scans": total_scans,
                    "country": attributes.get("country", "Unknown"),
                    "asn": attributes.get("asn", "Unknown"),
                    "as_owner": attributes.get("as_owner", "Unknown"),
                }
            elif response.status_code == 404:
                return {
                    "success": True,
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0,
                    "total_scans": 0,
                    "country": "Unknown",
                    "not_found": True,
                }
            else:
                return {"success": False, "error": f"API error {response.status_code}"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _check_abuseipdb(self, ip_address: str) -> Dict:
        """Check IP using AbuseIPDB API v2"""
        if not self.abuseipdb_key:
            return {"success": False, "error": "No API key"}

        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}
            params = {"ipAddress": ip_address, "maxAgeInDays": 90, "verbose": True}

            response = requests.get(url, headers=headers, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json().get("data", {})

                return {
                    "success": True,
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "num_distinct_users": data.get("numDistinctUsers", 0),
                    "last_reported": data.get("lastReportedAt", "Never"),
                    "country_code": data.get("countryCode", "Unknown"),
                    "usage_type": data.get("usageType", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "domain": data.get("domain", "Unknown"),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "is_public": data.get("isPublic", True),
                }
            else:
                return {"success": False, "error": f"API error {response.status_code}"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _aggregate_results(self, ip_address: str, results: Dict) -> Dict:
        """Aggregate results from multiple sources"""

        vt_data = results.get("virustotal", {})
        abuse_data = results.get("abuseipdb", {})

        # Calculate overall risk level
        risk_level, risk_score = self._calculate_risk_level(vt_data, abuse_data)

        # Format for UI (with markdown)
        formatted_output_ui = self._format_for_ui(
            ip_address, vt_data, abuse_data, risk_level, risk_score
        )

        # Format for Excel (plain text)
        formatted_output_excel = self._format_for_excel(
            ip_address, vt_data, abuse_data, risk_level, risk_score
        )

        return {
            "success": True,
            "ip_address": ip_address,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "virustotal": vt_data,
            "abuseipdb": abuse_data,
            "formatted_output": formatted_output_ui,
            "formatted_output_excel": formatted_output_excel,
        }

    def _calculate_risk_level(self, vt_data: Dict, abuse_data: Dict) -> tuple:
        """
        Calculate overall risk level based on multiple sources

        Returns: (risk_level_str, risk_score_int)
        """
        score = 0

        # VirusTotal scoring (0-40 points)
        if vt_data.get("success"):
            malicious = vt_data.get("malicious", 0)
            suspicious = vt_data.get("suspicious", 0)

            if malicious > 5:
                score += 40
            elif malicious > 2:
                score += 30
            elif malicious > 0:
                score += 20
            elif suspicious > 3:
                score += 15
            elif suspicious > 0:
                score += 10

        # AbuseIPDB scoring (0-60 points)
        if abuse_data.get("success"):
            confidence = abuse_data.get("abuse_confidence_score", 0)
            reports = abuse_data.get("total_reports", 0)

            # Confidence score (0-40 points)
            if confidence >= 75:
                score += 40
            elif confidence >= 50:
                score += 30
            elif confidence >= 25:
                score += 20
            elif confidence > 0:
                score += 10

            # Report count (0-20 points)
            if reports >= 10:
                score += 20
            elif reports >= 5:
                score += 15
            elif reports >= 1:
                score += 10

        # Determine risk level
        if score >= 60:
            return "HIGH", score
        elif score >= 30:
            return "MEDIUM", score
        elif score >= 10:
            return "LOW", score
        else:
            return "CLEAN", score

    def _format_for_ui(
        self, ip: str, vt: Dict, abuse: Dict, risk_level: str, risk_score: int
    ) -> str:
        """Format results for UI display (markdown)"""

        # Risk indicator
        risk_emoji = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟠", "CLEAN": "🟢"}.get(
            risk_level, "⚪"
        )

        output = f"""
🔍 **IP Reputation Analysis Report**

**IP Address:** {ip}
**Overall Risk:** {risk_emoji} **{risk_level}** (Score: {risk_score}/100)

---

### 📊 VirusTotal Analysis
"""

        if vt.get("success"):
            if vt.get("not_found"):
                output += "\n⚪ IP not found in VirusTotal database\n"
            else:
                output += f"""
- **Malicious Detections:** {vt.get('malicious', 0)}/{vt.get('total_scans', 0)}
- **Suspicious Detections:** {vt.get('suspicious', 0)}/{vt.get('total_scans', 0)}
- **Clean Detections:** {vt.get('harmless', 0)}/{vt.get('total_scans', 0)}
- **Country:** {vt.get('country', 'Unknown')}
- **ASN:** {vt.get('asn', 'Unknown')}
- **Owner:** {vt.get('as_owner', 'Unknown')}
"""
        else:
            output += (
                f"\n❌ VirusTotal check failed: {vt.get('error', 'Unknown error')}\n"
            )

        output += "\n### 🛡️ AbuseIPDB Analysis\n"

        if abuse.get("success"):
            confidence = abuse.get("abuse_confidence_score", 0)
            reports = abuse.get("total_reports", 0)

            confidence_emoji = (
                "🔴"
                if confidence >= 75
                else "🟡" if confidence >= 50 else "🟠" if confidence >= 25 else "🟢"
            )

            output += f"""
- **Abuse Confidence:** {confidence_emoji} {confidence}%
- **Total Reports:** {reports} reports
- **Distinct Reporters:** {abuse.get('num_distinct_users', 0)} users
- **Last Reported:** {abuse.get('last_reported', 'Never')}
- **Country:** {abuse.get('country_code', 'Unknown')}
- **ISP:** {abuse.get('isp', 'Unknown')}
- **Usage Type:** {abuse.get('usage_type', 'Unknown')}
- **Whitelisted:** {'Yes ✅' if abuse.get('is_whitelisted') else 'No'}
"""
        else:
            output += (
                f"\n❌ AbuseIPDB check failed: {abuse.get('error', 'Unknown error')}\n"
            )

        output += f"""
---

### 💡 Recommendation

{self._get_recommendation(risk_level)}

**Links:**
- [VirusTotal Report](https://www.virustotal.com/gui/ip-address/{ip})
- [AbuseIPDB Report](https://www.abuseipdb.com/check/{ip})

*Checked: {time.strftime("%Y-%m-%d %H:%M:%S")}*
"""

        return output.strip()

    def _format_for_excel(
        self, ip: str, vt: Dict, abuse: Dict, risk_level: str, risk_score: int
    ) -> str:
        """Format results for Excel export (plain text)"""

        output = f"""IP Reputation Analysis Report
{'='*60}

IP Address: {ip}
Overall Risk: {risk_level} (Score: {risk_score}/100)
Timestamp: {time.strftime("%Y-%m-%d %H:%M:%S")}

{'='*60}
VIRUSTOTAL RESULTS
{'='*60}
"""

        if vt.get("success"):
            if vt.get("not_found"):
                output += "\nStatus: IP not found in database\n"
            else:
                output += f"""
Malicious Detections: {vt.get('malicious', 0)}/{vt.get('total_scans', 0)}
Suspicious Detections: {vt.get('suspicious', 0)}/{vt.get('total_scans', 0)}
Clean Detections: {vt.get('harmless', 0)}/{vt.get('total_scans', 0)}
Country: {vt.get('country', 'Unknown')}
ASN: {vt.get('asn', 'Unknown')}
Owner: {vt.get('as_owner', 'Unknown')}
"""
        else:
            output += f"\nError: {vt.get('error', 'Check failed')}\n"

        output += f"""
{'='*60}
ABUSEIPDB RESULTS
{'='*60}
"""

        if abuse.get("success"):
            output += f"""
Abuse Confidence Score: {abuse.get('abuse_confidence_score', 0)}%
Total Reports: {abuse.get('total_reports', 0)}
Distinct Reporters: {abuse.get('num_distinct_users', 0)}
Last Reported: {abuse.get('last_reported', 'Never')}
Country Code: {abuse.get('country_code', 'Unknown')}
ISP: {abuse.get('isp', 'Unknown')}
Usage Type: {abuse.get('usage_type', 'Unknown')}
Whitelisted: {'Yes' if abuse.get('is_whitelisted') else 'No'}
Public IP: {'Yes' if abuse.get('is_public') else 'No'}
"""
        else:
            output += f"\nError: {abuse.get('error', 'Check failed')}\n"

        output += f"""
{'='*60}
RECOMMENDATION
{'='*60}

{self._get_recommendation_plain(risk_level)}

VERIFICATION LINKS:
• VirusTotal: https://www.virustotal.com/gui/ip-address/{ip}
• AbuseIPDB: https://www.abuseipdb.com/check/{ip}

{'='*60}
"""

        return output.strip()

    def _get_recommendation(self, risk_level: str) -> str:
        """Get recommendation with markdown formatting"""
        recommendations = {
            "HIGH": "🚨 **IMMEDIATE ACTION REQUIRED**\n\nThis IP is flagged as high-risk by multiple threat intelligence sources. Recommend:\n• Block IP immediately\n• Investigate all related activity\n• Review access logs\n• Escalate to security team",
            "MEDIUM": "⚠️ **CAUTION RECOMMENDED**\n\nThis IP shows suspicious indicators. Recommend:\n• Monitor closely\n• Consider temporary block\n• Verify legitimacy with user\n• Continue investigation",
            "LOW": "🔍 **FURTHER INVESTIGATION NEEDED**\n\nThis IP has some concerning indicators but may not be malicious. Recommend:\n• Investigate user activity patterns\n• Check for policy violations\n• Verify with user if needed\n• Document findings",
            "CLEAN": "✅ **NO IMMEDIATE ACTION**\n\nThis IP appears clean based on available threat intelligence. Recommend:\n• Continue standard investigation\n• Monitor for anomalies\n• Document as part of incident record",
        }
        return recommendations.get(risk_level, "Continue investigation")

    def _get_recommendation_plain(self, risk_level: str) -> str:
        """Get recommendation in plain text for Excel"""
        recommendations = {
            "HIGH": "[CRITICAL] Block IP immediately and investigate all activity. This IP is flagged as high-risk by multiple sources.",
            "MEDIUM": "[WARNING] Monitor closely and consider blocking. IP shows suspicious indicators.",
            "LOW": "[INVESTIGATE] Further review needed. Some concerning indicators detected.",
            "CLEAN": "[NO ACTION] IP appears clean. Continue standard investigation procedures.",
        }
        return recommendations.get(risk_level, "Continue investigation")

    def _generate_manual_instructions(self, ip_address: str) -> Dict:
        """Generate manual check instructions when APIs unavailable"""

        vt_url = f"https://www.virustotal.com/gui/ip-address/{ip_address}"
        abuse_url = f"https://www.abuseipdb.com/check/{ip_address}"

        formatted_output = f"""
📋 **Manual IP Reputation Check Required**

**IP Address:** {ip_address}

### VirusTotal Check:
1. Visit: {vt_url}
2. Review detection statistics
3. Check community score
4. Note WHOIS information

### AbuseIPDB Check:
1. Visit: {abuse_url}
2. Check abuse confidence score
3. Review report history
4. Note ISP and country

**Document your findings in the Output field**
"""

        return {
            "success": True,
            "ip_address": ip_address,
            "reputation": "Manual Check Required",
            "manual_check": True,
            "formatted_output": formatted_output.strip(),
        }


# Backward compatibility wrapper
class VirusTotalChecker(IPReputationChecker):
    """Maintains backward compatibility with existing code"""

    pass


# Streamlit Integration Helper
