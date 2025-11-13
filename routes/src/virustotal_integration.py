import os
import time
import requests
from typing import Dict, List, Tuple


class IPReputationChecker:
    def __init__(self):
        self.vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.abuseipdb_key = os.getenv("ABUSE_DB_KEY")
        self.abstract_api_key = os.getenv("ABSTRACT_API_KEY", "b8935bde22bf4a48b8380065cfcef6e1")
        print(self.vt_api_key)
        print(self.abuseipdb_key)
        print(self.abuseipdb_key)

        self.use_vt = bool(self.vt_api_key)
        self.use_abuseipdb = bool(self.abuseipdb_key)
        self.use_vpn_check = bool(self.abstract_api_key)

        if self.use_vt:
            print("✅ VirusTotal API enabled")
        else:
            print("⚠️ VirusTotal API key not found")

        if self.use_abuseipdb:
            print("✅ AbuseIPDB API enabled")
        else:
            print("⚠️ AbuseIPDB API key not found")

        if self.use_vpn_check:
            print("✅ VPN Detection API enabled")
        else:
            print("⚠️ Abstract API key not found - VPN detection disabled")

    def _check_vpn_detection(self, ip_address: str) -> Dict:
        """Check if IP is from VPN/proxy using Abstract API"""
        if not self.abstract_api_key:
            return {"success": False, "error": "No API key configured"}

        try:
            url = f"https://ipgeolocation.abstractapi.com/v1/?api_key={self.abstract_api_key}&ip_address={ip_address}"

            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                security = data.get("security", {})

                return {
                    "success": True,
                    "is_vpn": security.get("is_vpn", False),
                    "is_proxy": security.get("is_proxy", False),
                    "is_tor": security.get("is_tor", False),
                    "is_relay": False,  # Not available in this API
                    "is_hosting": False,  # Not available in this API
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("connection", {}).get("isp_name", "Unknown"),
                    "connection_type": data.get("connection", {}).get(
                        "connection_type", "Unknown"
                    ),
                }
            elif response.status_code == 401:
                # Disable VPN checking on auth failure
                self.use_vpn_check = False
                return {
                    "success": False,
                    "error": "Invalid API key - VPN detection disabled",
                }
            elif response.status_code == 429:
                return {"success": False, "error": "Rate limit exceeded"}
            else:
                return {"success": False, "error": f"API error {response.status_code}"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _classify_ip_type(self, ip_address: str) -> str:
        """Classify IP as Public, Private, IPv6, Loopback, or Invalid"""
        import ipaddress

        try:
            ip_obj = ipaddress.ip_address(ip_address)

            if isinstance(ip_obj, ipaddress.IPv6Address):
                if ip_obj.is_loopback:
                    return "Loopback"
                elif ip_obj.is_private or ip_obj.is_link_local:
                    return "Private"
                elif ip_obj.is_reserved:
                    return "Reserved"
                else:
                    return "IPv6"
            else:
                if ip_obj.is_private:
                    return "Private"
                elif ip_obj.is_loopback:
                    return "Loopback"
                elif ip_obj.is_reserved:
                    return "Reserved"
                else:
                    return "Public"

        except ValueError:
            return "Invalid"

    def check_multiple_ips(self, ip_list: List[str], method: str = "auto") -> Dict:
        """Check reputation for multiple IPs"""
        results = {}

        print(f"\n🔍 Checking {len(ip_list)} IP address(es)...")

        for idx, ip in enumerate(ip_list, 1):
            ip = ip.strip()
            ip_type = self._classify_ip_type(ip)

            if ip_type == "Invalid":
                print(f"   [{idx}/{len(ip_list)}] ❌ {ip} - Invalid format")
                results[ip] = {
                    "success": False,
                    "ip_type": "Invalid",
                    "error": "Invalid IP address format",
                    "formatted_output": "Invalid IP address format",
                    "formatted_output_excel": f"IP: {ip}\nStatus: Invalid IP address format\n",
                }
                continue

            print(f"   [{idx}/{len(ip_list)}] 🔍 {ip} ({ip_type})")

            # Skip private/loopback/reserved IPs
            if ip_type in ["Private", "Loopback", "Reserved"]:
                print(f"      ℹ️  {ip_type} IP - No reputation check needed")
                results[ip] = {
                    "success": True,
                    "ip_type": ip_type,
                    "risk_level": "N/A",
                    "message": f"{ip_type} IP - No reputation check needed",
                    "skip_check": True,
                    "formatted_output": f"{ip_type} IP Address - No external reputation check required for {ip_type.lower()} addresses.",
                    "formatted_output_excel": f"{'='*60}\nIP: {ip}\nType: {ip_type}\nStatus: No external reputation check needed\n{'='*60}\n",
                }
                continue

            # Check Public/IPv6 IPs
            try:
                result = self.check_ip_reputation(ip, method)
                result["ip_type"] = ip_type
                results[ip] = result

                if idx < len(ip_list):
                    time.sleep(0.5)

                if result.get("success"):
                    risk = result.get("risk_level", "UNKNOWN")
                    print(f"      ✅ Risk Level: {risk}")
                else:
                    print(f"      ⚠️  Check failed: {result.get('error', 'Unknown')}")

            except Exception as e:
                print(f"      ❌ Exception: {str(e)[:100]}")
                results[ip] = {
                    "success": False,
                    "ip_type": ip_type,
                    "error": str(e),
                    "formatted_output": f"Error checking {ip}: {str(e)[:200]}",
                    "formatted_output_excel": f"IP: {ip}\nType: {ip_type}\nStatus: Check failed - {str(e)[:200]}\n",
                }

        print(f"\n✅ Completed checking {len(ip_list)} IP(s)")
        return results

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format (IPv4 or IPv6)"""
        import ipaddress

        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

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

    def check_ip_reputation(self, ip_address: str, method: str = "auto") -> Dict:
        """Check IP reputation using multiple sources including VPN detection"""
        if not self._is_valid_ip(ip_address):
            return {
                "success": False,
                "error": "Invalid IP address format",
                "formatted_output": "Invalid IP address",
            }

        results = {}

        if method == "auto" or method == "api":
            if self.use_vt:
                print(f"🔍 Checking VirusTotal for {ip_address}...")
                results["virustotal"] = self._check_virustotal(ip_address)

            if self.use_abuseipdb:
                print(f"🔍 Checking AbuseIPDB for {ip_address}...")
                results["abuseipdb"] = self._check_abuseipdb(ip_address)

            # VPN detection (skip if disabled)
            if self.use_vpn_check:
                print(f"🔍 Checking VPN status for {ip_address}...")
                vpn_result = self._check_vpn_detection(ip_address)
                if not vpn_result.get("success"):
                    print(f"⚠️ VPN check failed: {vpn_result.get('error')}")
                results["vpn_detection"] = vpn_result

        if not results:
            return self._generate_manual_instructions(ip_address)

        return self._aggregate_results(ip_address, results)

    def _aggregate_results(self, ip_address: str, results: Dict) -> Dict:
        """Aggregate results from multiple sources"""
        vt_data = results.get("virustotal", {})
        abuse_data = results.get("abuseipdb", {})
        vpn_data = results.get("vpn_detection", {})

        risk_level, risk_score = self._calculate_risk_level(
            vt_data, abuse_data, vpn_data
        )

        # Plain text for UI (NO MARKDOWN)
        formatted_output_ui = self._format_for_ui(
            ip_address, vt_data, abuse_data, vpn_data, risk_level, risk_score
        )

        # Plain text for Excel
        formatted_output_excel = self._format_for_excel(
            ip_address, vt_data, abuse_data, vpn_data, risk_level, risk_score
        )

        return {
            "success": True,
            "ip_address": ip_address,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "virustotal": vt_data,
            "abuseipdb": abuse_data,
            "vpn_detection": vpn_data,
            "formatted_output": formatted_output_ui,
            "formatted_output_excel": formatted_output_excel,
        }

    def _calculate_risk_level(
        self, vt_data: Dict, abuse_data: Dict, vpn_data: Dict
    ) -> Tuple[str, int]:
        """Calculate overall risk level"""
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

        # AbuseIPDB scoring (0-40 points)
        if abuse_data.get("success"):
            confidence = abuse_data.get("abuse_confidence_score", 0)
            reports = abuse_data.get("total_reports", 0)

            if confidence >= 75:
                score += 30
            elif confidence >= 50:
                score += 20
            elif confidence >= 25:
                score += 15
            elif confidence > 0:
                score += 10

            if reports >= 10:
                score += 10
            elif reports >= 5:
                score += 7
            elif reports >= 1:
                score += 5

        # VPN/Proxy scoring (0-20 points)
        if vpn_data.get("success"):
            if vpn_data.get("is_tor"):
                score += 20
            elif vpn_data.get("is_vpn") or vpn_data.get("is_proxy"):
                score += 15
            elif vpn_data.get("is_hosting"):
                score += 10

        # Determine risk level
        if score >= 60:
            return "HIGH", score
        elif score >= 35:
            return "MEDIUM", score
        elif score >= 15:
            return "LOW", score
        else:
            return "CLEAN", score

    def _format_for_ui(
        self,
        ip: str,
        vt: Dict,
        abuse: Dict,
        vpn: Dict,
        risk_level: str,
        risk_score: int,
    ) -> str:
        """Format results for UI display - PLAIN TEXT ONLY, NO MARKDOWN"""
        lines = []
        lines.append(f"IP ADDRESS: {ip}")
        lines.append(f"OVERALL RISK: {risk_level} (Score: {risk_score}/100)")
        lines.append("")
        lines.append("=" * 60)
        lines.append("VIRUSTOTAL ANALYSIS")
        lines.append("=" * 60)

        if vt.get("success"):
            if vt.get("not_found"):
                lines.append("Status: Not found in database")
            else:
                lines.append(
                    f"Malicious Detections: {vt.get('malicious', 0)}/{vt.get('total_scans', 0)}"
                )
                lines.append(
                    f"Suspicious Detections: {vt.get('suspicious', 0)}/{vt.get('total_scans', 0)}"
                )
                lines.append(
                    f"Clean Detections: {vt.get('harmless', 0)}/{vt.get('total_scans', 0)}"
                )
                lines.append(f"Country: {vt.get('country', 'Unknown')}")
                lines.append(f"ASN: {vt.get('asn', 'Unknown')}")
                lines.append(f"Owner: {vt.get('as_owner', 'Unknown')}")
        else:
            lines.append(f"Error: {vt.get('error', 'Check failed')}")

        lines.append("")
        lines.append("=" * 60)
        lines.append("ABUSEIPDB ANALYSIS")
        lines.append("=" * 60)

        if abuse.get("success"):
            lines.append(
                f"Abuse Confidence Score: {abuse.get('abuse_confidence_score', 0)}%"
            )
            lines.append(f"Total Reports: {abuse.get('total_reports', 0)}")
            lines.append(f"Distinct Reporters: {abuse.get('num_distinct_users', 0)}")
            lines.append(f"Last Reported: {abuse.get('last_reported', 'Never')}")
            lines.append(f"Country: {abuse.get('country_code', 'Unknown')}")
            lines.append(f"ISP: {abuse.get('isp', 'Unknown')}")
            lines.append(f"Usage Type: {abuse.get('usage_type', 'Unknown')}")
        else:
            lines.append(f"Error: {abuse.get('error', 'Check failed')}")

        lines.append("")
        lines.append("=" * 60)
        lines.append("VPN/PROXY DETECTION")
        lines.append("=" * 60)

        if vpn.get("success"):
            is_vpn = vpn.get("is_vpn", False)
            is_proxy = vpn.get("is_proxy", False)
            is_tor = vpn.get("is_tor", False)

            if is_tor:
                lines.append("Connection Type: TOR EXIT NODE (High Risk)")
            elif is_vpn:
                lines.append("Connection Type: VPN DETECTED (Medium-High Risk)")
            elif is_proxy:
                lines.append("Connection Type: PROXY DETECTED (Medium Risk)")
            else:
                lines.append("Connection Type: DIRECT CONNECTION (Low Risk)")

            lines.append(f"Country: {vpn.get('country', 'Unknown')}")
            lines.append(f"City: {vpn.get('city', 'Unknown')}")
            lines.append(f"ISP: {vpn.get('isp', 'Unknown')}")
        else:
            lines.append(
                f"VPN check unavailable: {vpn.get('error', 'Service not configured')}"
            )

        return "\n".join(lines)

    def _format_for_excel(
        self,
        ip: str,
        vt: Dict,
        abuse: Dict,
        vpn: Dict,
        risk_level: str,
        risk_score: int,
    ) -> str:
        """Format results for Excel export"""
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
VPN/PROXY DETECTION
{'='*60}
"""

        if vpn.get("success"):
            is_vpn = vpn.get("is_vpn", False)
            is_proxy = vpn.get("is_proxy", False)
            is_tor = vpn.get("is_tor", False)

            connection_type = (
                "TOR EXIT NODE (High Risk)"
                if is_tor
                else (
                    "VPN Connection (Medium-High Risk)"
                    if is_vpn
                    else (
                        "Proxy Connection (Medium Risk)"
                        if is_proxy
                        else "Direct Connection (Low Risk)"
                    )
                )
            )

            output += f"""
Connection Type: {connection_type}

VPN Detected: {'Yes' if is_vpn else 'No'}
Proxy Detected: {'Yes' if is_proxy else 'No'}
Tor Exit Node: {'Yes' if is_tor else 'No'}
Country: {vpn.get('country', 'Unknown')}
City: {vpn.get('city', 'Unknown')}
ISP: {vpn.get('isp', 'Unknown')}
Connection Type: {vpn.get('connection_type', 'Unknown')}
"""
        else:
            output += f"\nError: {vpn.get('error', 'Service not configured')}\n"

        output += f"""
{'='*60}
RECOMMENDATION
{'='*60}

{self._get_recommendation_plain(risk_level, vpn.get("is_vpn", False), vpn.get("is_tor", False))}

VERIFICATION LINKS:
• VirusTotal: https://www.virustotal.com/gui/ip-address/{ip}
• AbuseIPDB: https://www.abuseipdb.com/check/{ip}

{'='*60}
"""
        return output.strip()

    def _get_recommendation_plain(
        self, risk_level: str, is_vpn: bool, is_tor: bool
    ) -> str:
        """Get recommendation in plain text"""
        recommendations = {
            "HIGH": "[CRITICAL] Block IP immediately and investigate all activity.",
            "MEDIUM": "[WARNING] Monitor closely and consider blocking.",
            "LOW": "[INVESTIGATE] Further review needed.",
            "CLEAN": "[NO ACTION] IP appears clean. Continue standard procedures.",
        }

        base_rec = recommendations.get(risk_level, "Continue investigation")

        if is_tor:
            base_rec += "\n\n[TOR DETECTED] This is a Tor exit node. Block immediately if unauthorized."
        elif is_vpn:
            base_rec += (
                "\n\n[VPN DETECTED] User connecting via VPN. Verify if authorized."
            )

        return base_rec

    def _generate_manual_instructions(self, ip_address: str) -> Dict:
        """Generate manual check instructions when APIs unavailable"""
        vt_url = f"https://www.virustotal.com/gui/ip-address/{ip_address}"
        abuse_url = f"https://www.abuseipdb.com/check/{ip_address}"

        formatted_output = f"""Manual IP Reputation Check Required

IP Address: {ip_address}

VirusTotal Check:
1. Visit: {vt_url}
2. Review detection statistics
3. Check community score
4. Note WHOIS information

AbuseIPDB Check:
1. Visit: {abuse_url}
2. Check abuse confidence score
3. Review report history
4. Note ISP and country

Document your findings in the Output field
"""

        return {
            "success": True,
            "ip_address": ip_address,
            "reputation": "Manual Check Required",
            "manual_check": True,
            "formatted_output": formatted_output.strip(),
        }
