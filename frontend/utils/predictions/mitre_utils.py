def get_mitre_technique_ids():
    """
    Returns a mapping of technique names to their actual MITRE ATT&CK IDs.
    This should ideally be loaded from the official MITRE ATT&CK JSON/STIX data.
    """
    return {
        # Initial Access
        "Valid Accounts": "T1078",
        "Phishing": "T1566",
        "External Remote Services": "T1133",
        "Exploit Public-Facing Application": "T1190",
        # Persistence
        "Account Manipulation": "T1098",
        "Create Account": "T1136",
        "Valid Accounts": "T1078",
        # Privilege Escalation
        "Account Manipulation": "T1098",
        "Valid Accounts": "T1078",
        "Abuse Elevation Control Mechanism": "T1548",
        # Defense Evasion
        "Impair Defenses": "T1562",
        "Valid Accounts": "T1078",
        "Modify Authentication Process": "T1556",
        # Credential Access
        "Brute Force": "T1110",
        "Multi-Factor Authentication Interception": "T1111",
        "OS Credential Dumping": "T1003",
        "Steal Application Access Token": "T1528",
        # Discovery
        "Account Discovery": "T1087",
        "Cloud Infrastructure Discovery": "T1580",
        "Cloud Service Discovery": "T1526",
        "Cloud Storage Object Discovery": "T1530",
        # Lateral Movement
        "Remote Services": "T1021",
        "Use Alternate Authentication Material": "T1550",
        # Collection
        "Data from Cloud Storage": "T1530",
        "Email Collection": "T1114",
        # Exfiltration
        "Exfiltration Over Web Service": "T1567",
        "Transfer Data to Cloud Account": "T1537",
        # Impact
        "Data Encrypted for Impact": "T1486",
        "Account Access Removal": "T1531",
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
        # Add more as needed...
    }


def create_complete_mitre_matrix(
    techniques_data: list, predicted_steps: list = None
) -> str:
    """
    Create complete MITRE ATT&CK matrix with ALL techniques shown in grey,
    then highlight observed (RED/AMBER/GREEN) and predicted (BLUE) techniques.
    """
    from backend.predictions_backend import MITREAttackAnalyzer

    # Get the complete MITRE data structure
    temp_analyzer = MITREAttackAnalyzer(api_key="dummy")
    mitre_full_data = temp_analyzer.mitre_data

    # Get technique ID mappings
    technique_ids = get_mitre_technique_ids()
    subtechnique_ids = get_mitre_subtechnique_ids()

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
                "subtechniques_list": sub_techniques_list,
            }

            tactic_techniques[tactic].append(tech_data)

    # Build HTML
    html = '<div class="mitre-matrix-container">'
    html += '<table class="mitre-matrix">'

    # Header
    html += "<tr>"
    for tactic in tactics:
        html += f"<th>{tactic}<br/><span style='font-size:0.8em;'>({len(tactic_techniques[tactic])} techniques)</span></th>"
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

                # Build cell
                cell = f'<div class="technique-cell {color_class}">'
                cell += f'<strong>{tech["technique"]}</strong><br/>'
                cell += f'<span class="technique-id">{tech["technique_id"]}</span>'

                # Show sub-technique if highlighted
                if tech["sub_technique"] and tech["type"] in ["observed", "predicted"]:
                    cell += f'<br/><span style="font-size:0.65rem;">↳ {tech["sub_technique"]}</span>'
                    if tech["sub_technique_id"]:
                        cell += f'<br/><span class="technique-id">{tech["sub_technique_id"]}</span>'

                # Show count of sub-techniques for grey techniques
                if tech["has_subtechniques"] and tech["type"] == "default":
                    count = len(tech["subtechniques_list"])
                    cell += f'<br/><span style="font-size:0.6rem;opacity:0.6;">({count} sub-techs)</span>'

                if tech["confidence"] > 0:
                    cell += f'<br/><span style="font-size:0.6rem;">Conf: {tech["confidence"]}%</span>'
                elif tech_type == "predicted":
                    cell += '<br/><span style="font-size:0.6rem;">Predicted</span>'

                cell += "</div>"
                html += f"<td>{cell}</td>"
            else:
                html += "<td></td>"

        html += "</tr>"

    html += "</table></div>"

    # Legend
    html += """
    <div style="margin-top: 1rem; padding: 1rem; background-color: #f3f4f6; border-radius: 0.5rem;">
        <strong>Complete MITRE ATT&CK Matrix - Legend:</strong>
        <span style="display: inline-block; margin-left: 1rem;">
            <span style="background-color: #dc2626; color: white; padding: 2px 8px; border-radius: 3px; margin: 0 5px;">RED</span> Confirmed Observed
        </span>
        <span style="display: inline-block; margin-left: 1rem;">
            <span style="background-color: #f59e0b; color: white; padding: 2px 8px; border-radius: 3px; margin: 0 5px;">AMBER</span> Likely Observed
        </span>
        <span style="display: inline-block; margin-left: 1rem;">
            <span style="background-color: #10b981; color: white; padding: 2px 8px; border-radius: 3px; margin: 0 5px;">GREEN</span> Possible Observed
        </span>
        <span style="display: inline-block; margin-left: 1rem;">
            <span style="background-color: #3b82f6; color: white; padding: 2px 8px; border-radius: 3px; margin: 0 5px;">BLUE</span> Predicted Next Step
        </span>
        <span style="display: inline-block; margin-left: 1rem;">
            <span style="background-color: #9ca3af; color: white; padding: 2px 8px; border-radius: 3px; margin: 0 5px;">GREY</span> All Other MITRE Techniques (Not Observed)
        </span>
    </div>
    """

    return html
