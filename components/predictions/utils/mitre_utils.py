def get_mitre_technique_ids():
    """
    Returns a mapping of technique names to their actual MITRE ATT&CK IDs.
    Expanded with more techniques for comprehensive coverage.
    """
    return {
        # Initial Access
        "Valid Accounts": "T1078",
        "Phishing": "T1566",
        "External Remote Services": "T1133",
        "Exploit Public-Facing Application": "T1190",
        "Drive-by Compromise": "T1189",
        "Hardware Additions": "T1200",
        "Replication Through Removable Media": "T1091",
        "Supply Chain Compromise": "T1195",
        "Trusted Relationship": "T1199",
        # Execution
        "Command and Scripting Interpreter": "T1059",
        "Container Administration Command": "T1609",
        "Deploy Container": "T1610",
        "Exploitation for Client Execution": "T1203",
        "Inter-Process Communication": "T1559",
        "Native API": "T1106",
        "Scheduled Task/Job": "T1053",
        "Shared Modules": "T1129",
        "Software Deployment Tools": "T1072",
        "System Services": "T1569",
        "User Execution": "T1204",
        "Windows Management Instrumentation": "T1047",
        # Persistence
        "Account Manipulation": "T1098",
        "Create Account": "T1136",
        "Create or Modify System Process": "T1543",
        "Boot or Logon Autostart Execution": "T1547",
        "Boot or Logon Initialization Scripts": "T1037",
        "Browser Extensions": "T1176",
        "Compromise Client Software Binary": "T1554",
        "Event Triggered Execution": "T1546",
        "External Remote Services": "T1133",
        "Hijack Execution Flow": "T1574",
        "Implant Internal Image": "T1525",
        "Modify Authentication Process": "T1556",
        "Office Application Startup": "T1137",
        "Pre-OS Boot": "T1542",
        "Server Software Component": "T1505",
        "Traffic Signaling": "T1205",
        # Privilege Escalation
        "Abuse Elevation Control Mechanism": "T1548",
        "Access Token Manipulation": "T1134",
        "Domain Policy Modification": "T1484",
        "Escape to Host": "T1611",
        "Exploitation for Privilege Escalation": "T1068",
        "Process Injection": "T1055",
        # Defense Evasion
        "Impair Defenses": "T1562",
        "Hide Artifacts": "T1564",
        "Indicator Removal": "T1070",
        "Masquerading": "T1036",
        "Modify Cloud Compute Infrastructure": "T1578",
        "Modify Registry": "T1112",
        "Obfuscated Files or Information": "T1027",
        "Reflective Code Loading": "T1620",
        "Rootkit": "T1014",
        "Subvert Trust Controls": "T1553",
        "System Binary Proxy Execution": "T1218",
        "Template Injection": "T1221",
        "Trusted Developer Utilities Proxy Execution": "T1127",
        "Virtualization/Sandbox Evasion": "T1497",
        "Weaken Encryption": "T1600",
        "XSL Script Processing": "T1220",
        # Credential Access
        "Brute Force": "T1110",
        "Multi-Factor Authentication Interception": "T1111",
        "Multi-Factor Authentication Request Generation": "T1621",
        "OS Credential Dumping": "T1003",
        "Steal Application Access Token": "T1528",
        "Adversary-in-the-Middle": "T1557",
        "Credentials from Password Stores": "T1555",
        "Exploitation for Credential Access": "T1212",
        "Forced Authentication": "T1187",
        "Forge Web Credentials": "T1606",
        "Input Capture": "T1056",
        "Network Sniffing": "T1040",
        "Steal or Forge Authentication Certificates": "T1649",
        "Steal or Forge Kerberos Tickets": "T1558",
        "Steal Web Session Cookie": "T1539",
        "Unsecured Credentials": "T1552",
        # Discovery
        "Account Discovery": "T1087",
        "Application Window Discovery": "T1010",
        "Browser Information Discovery": "T1217",
        "Cloud Infrastructure Discovery": "T1580",
        "Cloud Service Dashboard": "T1538",
        "Cloud Service Discovery": "T1526",
        "Cloud Storage Object Discovery": "T1530",
        "Container and Resource Discovery": "T1613",
        "Debugger Evasion": "T1622",
        "Device Driver Discovery": "T1652",
        "Domain Trust Discovery": "T1482",
        "File and Directory Discovery": "T1083",
        "Group Policy Discovery": "T1615",
        "Network Service Discovery": "T1046",
        "Network Share Discovery": "T1135",
        "Password Policy Discovery": "T1201",
        "Peripheral Device Discovery": "T1120",
        "Permission Groups Discovery": "T1069",
        "Process Discovery": "T1057",
        "Query Registry": "T1012",
        "Remote System Discovery": "T1018",
        "Software Discovery": "T1518",
        "System Information Discovery": "T1082",
        "System Location Discovery": "T1614",
        "System Network Configuration Discovery": "T1016",
        "System Network Connections Discovery": "T1049",
        "System Owner/User Discovery": "T1033",
        "System Service Discovery": "T1007",
        "System Time Discovery": "T1124",
        "Virtual Machine Discovery": "T1497",
        # Lateral Movement
        "Remote Services": "T1021",
        "Use Alternate Authentication Material": "T1550",
        "Exploitation of Remote Services": "T1210",
        "Internal Spearphishing": "T1534",
        "Lateral Tool Transfer": "T1570",
        "Remote Service Session Hijacking": "T1563",
        "Taint Shared Content": "T1080",
        # Collection
        "Data from Cloud Storage": "T1530",
        "Email Collection": "T1114",
        "Archive Collected Data": "T1560",
        "Audio Capture": "T1123",
        "Automated Collection": "T1119",
        "Browser Session Hijacking": "T1185",
        "Clipboard Data": "T1115",
        "Data from Configuration Repository": "T1602",
        "Data from Information Repositories": "T1213",
        "Data from Local System": "T1005",
        "Data from Network Shared Drive": "T1039",
        "Data from Removable Media": "T1025",
        "Data Staged": "T1074",
        "Input Capture": "T1056",
        "Screen Capture": "T1113",
        "Video Capture": "T1125",
        # Command and Control
        "Application Layer Protocol": "T1071",
        "Communication Through Removable Media": "T1092",
        "Data Encoding": "T1132",
        "Data Obfuscation": "T1001",
        "Dynamic Resolution": "T1568",
        "Encrypted Channel": "T1573",
        "Fallback Channels": "T1008",
        "Ingress Tool Transfer": "T1105",
        "Multi-Stage Channels": "T1104",
        "Non-Application Layer Protocol": "T1095",
        "Non-Standard Port": "T1571",
        "Protocol Tunneling": "T1572",
        "Proxy": "T1090",
        "Remote Access Software": "T1219",
        "Web Service": "T1102",
        # Exfiltration
        "Exfiltration Over Web Service": "T1567",
        "Transfer Data to Cloud Account": "T1537",
        "Automated Exfiltration": "T1020",
        "Data Transfer Size Limits": "T1030",
        "Exfiltration Over Alternative Protocol": "T1048",
        "Exfiltration Over C2 Channel": "T1041",
        "Exfiltration Over Other Network Medium": "T1011",
        "Exfiltration Over Physical Medium": "T1052",
        "Scheduled Transfer": "T1029",
        # Impact
        "Data Encrypted for Impact": "T1486",
        "Account Access Removal": "T1531",
        "Data Destruction": "T1485",
        "Data Manipulation": "T1565",
        "Defacement": "T1491",
        "Disk Wipe": "T1561",
        "Endpoint Denial of Service": "T1499",
        "Financial Theft": "T1657",
        "Firmware Corruption": "T1495",
        "Inhibit System Recovery": "T1490",
        "Network Denial of Service": "T1498",
        "Resource Hijacking": "T1496",
        "Service Stop": "T1489",
        "System Shutdown/Reboot": "T1529",
    }


def get_mitre_subtechnique_ids():
    """
    Returns a mapping of sub-technique names to their IDs.
    Format: "Parent Technique > Sub-technique": "T####.###"
    """
    return {
        # Valid Accounts sub-techniques
        "Valid Accounts > Default Accounts": "T1078.001",
        "Valid Accounts > Domain Accounts": "T1078.002",
        "Valid Accounts > Local Accounts": "T1078.003",
        "Valid Accounts > Cloud Accounts": "T1078.004",
        # Account Manipulation sub-techniques
        "Account Manipulation > Additional Cloud Credentials": "T1098.001",
        "Account Manipulation > Additional Email Delegate Permissions": "T1098.002",
        "Account Manipulation > Additional Cloud Roles": "T1098.003",
        "Account Manipulation > SSH Authorized Keys": "T1098.004",
        "Account Manipulation > Device Registration": "T1098.005",
        # Exfiltration Over Web Service
        "Exfiltration Over Web Service > Exfiltration to Code Repository": "T1567.001",
        "Exfiltration Over Web Service > Exfiltration to Cloud Storage": "T1567.002",
        "Exfiltration Over Web Service > Exfiltration to Text Storage Sites": "T1567.003",
    }


def create_complete_mitre_matrix(
    techniques_data: list, predicted_steps: list = None
) -> str:
    """
    Create compact MITRE ATT&CK matrix showing only TIDs in blocks.
    Full details appear on hover. All techniques shown in grey by default,
    with observed and predicted techniques highlighted.
    """
    from backend.predictions.backend import MITREAttackAnalyzer

    # Get the complete MITRE data structure
    temp_analyzer = MITREAttackAnalyzer(api_key="dummy")
    mitre_full_data = temp_analyzer.mitre_data

    # Get technique ID mappings
    technique_ids = get_mitre_technique_ids()

    # Define all 14 MITRE ATT&CK tactics
    tactics = [
        "Reconnaissance",
        "Resource Development",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command and Control",
        "Exfiltration",
        "Impact",
    ]

    # Create lookup for observed/predicted techniques by name
    observed_map = {}
    for tech in techniques_data:
        key = f"{tech.get('tactic')}||{tech.get('technique')}"
        observed_map[key] = {
            "severity": tech.get("severity", "GREY"),
            "confidence": tech.get("confidence", 0),
            "type": "observed",
            "sub_technique": tech.get("sub_technique", ""),
            "sub_technique_id": tech.get("sub_technique_id", ""),
            "description": tech.get("evidence", ""),
            "procedure": tech.get("procedure", ""),
            "timestamp": tech.get("timestamp", ""),
            "indicators": tech.get("indicators", []),
        }

    predicted_map = {}
    if predicted_steps:
        for pred in predicted_steps:
            key = f"{pred.get('tactic')}||{pred.get('technique')}"
            predicted_map[key] = {
                "severity": "BLUE",
                "confidence": 0,
                "type": "predicted",
                "sub_technique": pred.get("sub_technique", ""),
                "sub_technique_id": pred.get("sub_technique_id", ""),
                "description": pred.get("description", ""),
                "rationale": pred.get("rationale", ""),
                "likelihood": pred.get("likelihood", "Unknown"),
            }

    # Build complete technique list with ALL MITRE techniques
    tactic_techniques = {tactic: [] for tactic in tactics}

    for tactic in tactics:
        if tactic not in mitre_full_data:
            continue

        for technique_name, sub_techniques_list in mitre_full_data[tactic].items():
            lookup_key = f"{tactic}||{technique_name}"

            # Check if observed or predicted
            if lookup_key in observed_map:
                status = observed_map[lookup_key]
            elif lookup_key in predicted_map:
                status = predicted_map[lookup_key]
            else:
                status = {"severity": "GREY", "confidence": 0, "type": "default"}

            # Get technique ID
            tech_id = technique_ids.get(technique_name, "T????")

            tech_data = {
                "technique": technique_name,
                "technique_id": tech_id,
                "sub_technique": status.get("sub_technique", ""),
                "sub_technique_id": status.get("sub_technique_id", ""),
                "severity": status.get("severity", "GREY"),
                "confidence": status.get("confidence", 0),
                "type": status.get("type", "default"),
                "has_subtechniques": len(sub_techniques_list) > 0,
                "subtechniques_count": len(sub_techniques_list),
                "description": status.get("description", ""),
                "procedure": status.get("procedure", ""),
                "rationale": status.get("rationale", ""),
                "timestamp": status.get("timestamp", ""),
                "indicators": status.get("indicators", []),
                "likelihood": status.get("likelihood", ""),
            }

            tactic_techniques[tactic].append(tech_data)

    # Build compact HTML with hover functionality
    html = """
    <style>
    .mitre-matrix-container {
        overflow-x: auto;
        margin: 1rem 0;
        max-height: 70vh;
        overflow-y: auto;
    }
    .mitre-matrix {
        width: 100%;
        border-collapse: collapse;
        font-size: 0.7rem;
        table-layout: fixed;
    }
    .mitre-matrix th {
        background-color: #667eea;
        color: white;
        padding: 0.5rem 0.25rem;
        text-align: center;
        font-weight: bold;
        position: sticky;
        top: 0;
        z-index: 10;
        font-size: 0.65rem;
        border: 1px solid #5568d3;
    }
    .mitre-matrix td {
        border: 1px solid #e5e7eb;
        padding: 0.15rem;
        vertical-align: top;
        width: 7.14%;
    }
    .technique-block {
        padding: 0.3rem 0.2rem;
        border-radius: 3px;
        cursor: pointer;
        transition: all 0.2s;
        position: relative;
        min-height: 35px;
        display: flex;
        align-items: center;
        justify-content: center;
        text-align: center;
        font-weight: 600;
        font-size: 0.65rem;
        margin: 2px 0;
    }
    .technique-block:hover {
        transform: scale(1.1);
        z-index: 100;
        box-shadow: 0 4px 12px rgba(0,0,0,0.2);
    }
    
    /* Severity colors */
    .severity-red {
        background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%);
        border: 2px solid #dc2626;
        color: #991b1b;
    }
    .severity-amber {
        background: linear-gradient(135deg, #fed7aa 0%, #fdba74 100%);
        border: 2px solid #f59e0b;
        color: #92400e;
    }
    .severity-green {
        background: linear-gradient(135deg, #d1fae5 0%, #a7f3d0 100%);
        border: 2px solid #10b981;
        color: #065f46;
    }
    .severity-blue {
        background: linear-gradient(135deg, #dbeafe 0%, #bfdbfe 100%);
        border: 2px solid #3b82f6;
        color: #1e40af;
    }
    .severity-grey {
        background: #f9fafb;
        border: 1px solid #d1d5db;
        color: #6b7280;
        font-weight: 400;
    }
    
    /* Hover tooltip */
    .technique-block .hover-tooltip {
        display: none;
        position: absolute;
        left: 50%;
        top: 100%;
        transform: translateX(-50%);
        margin-top: 10px;
        background: white;
        border: 3px solid #667eea;
        border-radius: 8px;
        padding: 1rem;
        width: 400px;
        box-shadow: 0 10px 30px rgba(0,0,0,0.25);
        z-index: 1000;
        font-size: 0.85rem;
        line-height: 1.5;
        text-align: left;
        font-weight: normal;
    }
    .technique-block:hover .hover-tooltip {
        display: block;
    }
    .hover-tooltip h4 {
        margin: 0 0 0.75rem 0;
        color: #667eea;
        font-size: 1rem;
        font-weight: 700;
        border-bottom: 2px solid #667eea;
        padding-bottom: 0.5rem;
    }
    .hover-tooltip .detail-row {
        margin: 0.5rem 0;
        padding: 0.4rem;
        background-color: #f9fafb;
        border-radius: 4px;
        border-left: 3px solid #667eea;
    }
    .hover-tooltip .detail-label {
        font-weight: 700;
        color: #374151;
        margin-bottom: 0.25rem;
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .hover-tooltip .detail-value {
        color: #1f2937;
        font-size: 0.8rem;
    }
    .hover-tooltip .confidence-badge {
        display: inline-block;
        background: #667eea;
        color: white;
        padding: 0.25rem 0.5rem;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .hover-tooltip .indicator-tag {
        display: inline-block;
        background: #e0e7ff;
        color: #4338ca;
        padding: 0.2rem 0.5rem;
        border-radius: 4px;
        font-size: 0.7rem;
        margin: 0.2rem;
        font-weight: 500;
    }
    </style>
    """

    html += '<div class="mitre-matrix-container">'
    html += '<table class="mitre-matrix">'

    # Header
    html += "<tr>"
    for tactic in tactics:
        html += f"<th>{tactic}</th>"
    html += "</tr>"

    # Find max techniques
    max_techniques = max([len(techs) for techs in tactic_techniques.values()] or [1])

    # Build rows
    for row_idx in range(max_techniques):
        html += "<tr>"
        for tactic in tactics:
            techniques = tactic_techniques[tactic]

            if row_idx < len(techniques):
                tech = techniques[row_idx]

                # Determine color
                severity = tech["severity"].upper()
                tech_type = tech["type"]

                if tech_type == "predicted":
                    color_class = "severity-blue"
                elif severity == "RED":
                    color_class = "severity-red"
                elif severity == "AMBER":
                    color_class = "severity-amber"
                elif severity == "GREEN":
                    color_class = "severity-green"
                else:
                    color_class = "severity-grey"

                # Build compact block showing only TID
                cell = f'<div class="technique-block {color_class}">'
                cell += f'{tech["technique_id"]}'

                # Add tooltip for non-grey techniques
                if tech["type"] != "default":
                    cell += '<div class="hover-tooltip">'
                    cell += f'<h4>{tech["technique"]} ({tech["technique_id"]})</h4>'

                    if tech["sub_technique"]:
                        cell += '<div class="detail-row">'
                        cell += '<div class="detail-label">🎯 Sub-Technique</div>'
                        cell += f'<div class="detail-value">{tech["sub_technique"]} ({tech["sub_technique_id"]})</div>'
                        cell += "</div>"

                    if tech["timestamp"]:
                        cell += '<div class="detail-row">'
                        cell += '<div class="detail-label">⏰ Timestamp</div>'
                        cell += f'<div class="detail-value">{tech["timestamp"]}</div>'
                        cell += "</div>"

                    if tech["description"]:
                        cell += '<div class="detail-row">'
                        cell += '<div class="detail-label">📝 Evidence</div>'
                        desc = (
                            tech["description"][:250] + "..."
                            if len(tech["description"]) > 250
                            else tech["description"]
                        )
                        cell += f'<div class="detail-value">{desc}</div>'
                        cell += "</div>"

                    if tech.get("procedure"):
                        cell += '<div class="detail-row">'
                        cell += '<div class="detail-label">🔧 Procedure</div>'
                        proc = (
                            tech["procedure"][:250] + "..."
                            if len(tech["procedure"]) > 250
                            else tech["procedure"]
                        )
                        cell += f'<div class="detail-value">{proc}</div>'
                        cell += "</div>"

                    if tech.get("rationale"):
                        cell += '<div class="detail-row">'
                        cell += (
                            '<div class="detail-label">🧠 Prediction Rationale</div>'
                        )
                        cell += f'<div class="detail-value">{tech["rationale"][:200]}...</div>'
                        cell += "</div>"

                    if tech["confidence"] > 0:
                        cell += '<div class="detail-row">'
                        cell += f'<span class="confidence-badge">Confidence: {tech["confidence"]}%</span>'
                        cell += "</div>"

                    if tech.get("indicators"):
                        cell += '<div class="detail-row">'
                        cell += '<div class="detail-label">🔍 Indicators</div>'
                        cell += "<div>"
                        for indicator in tech["indicators"][:5]:
                            cell += f'<span class="indicator-tag">{indicator}</span>'
                        cell += "</div></div>"

                    cell += "</div>"  # Close tooltip

                cell += "</div>"
                html += f"<td>{cell}</td>"
            else:
                html += "<td></td>"

        html += "</tr>"

    html += "</table></div>"

    # Legend
    html += """
    <div style="margin-top: 1rem; padding: 1rem; background-color: #f3f4f6; border-radius: 0.5rem;">
        <strong>🗺️ Compact MITRE ATT&CK Matrix - Legend:</strong>
        <div style="margin-top: 0.5rem;">
            <span style="display: inline-block; margin: 0.25rem;">
                <span style="background-color: #dc2626; color: white; padding: 4px 10px; border-radius: 3px; font-weight: 600;">RED</span> Confirmed Observed
            </span>
            <span style="display: inline-block; margin: 0.25rem;">
                <span style="background-color: #f59e0b; color: white; padding: 4px 10px; border-radius: 3px; font-weight: 600;">AMBER</span> Likely Observed
            </span>
            <span style="display: inline-block; margin: 0.25rem;">
                <span style="background-color: #10b981; color: white; padding: 4px 10px; border-radius: 3px; font-weight: 600;">GREEN</span> Possible Observed
            </span>
            <span style="display: inline-block; margin: 0.25rem;">
                <span style="background-color: #3b82f6; color: white; padding: 4px 10px; border-radius: 3px; font-weight: 600;">BLUE</span> Predicted Next Step
            </span>
            <span style="display: inline-block; margin: 0.25rem;">
                <span style="background-color: #9ca3af; color: white; padding: 4px 10px; border-radius: 3px; font-weight: 600;">GREY</span> Available Techniques (Not Observed)
            </span>
        </div>
        <div style="margin-top: 0.75rem; font-size: 0.9rem; color: #6b7280;">
            💡 <strong>Hover over any technique ID</strong> to see detailed information including sub-techniques, procedures, evidence, and indicators
        </div>
    </div>
    """

    return html
