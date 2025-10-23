import re
import json
import pandas as pd
from datetime import datetime
import google.generativeai as genai
from typing import Dict, List, Any, Optional


class MITREAttackAnalyzer:
    """Handles MITRE ATT&CK framework analysis with sub-techniques"""

    def __init__(self, api_key: str):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel("gemini-2.0-flash-exp")

        # High-risk countries for geolocation analysis
        self.high_risk_countries = [
            "russia",
            "china",
            "north korea",
            "iran",
            "syria",
            "belarus",
            "venezuela",
            "cuba",
            "afghanistan",
        ]

        # Load MITRE ATT&CK techniques and sub-techniques from document
        self.mitre_data = self._load_mitre_data()

    def _load_mitre_data(self) -> Dict[str, Any]:
        """Load MITRE ATT&CK framework data from the document"""
        # This will be populated from the MITRE ATT&CK document provided
        # Structure: {tactic: {technique: [sub-techniques]}}

        mitre_structure = {
            "Reconnaissance": {
                "Active Scanning": [
                    "Scanning IP Blocks",
                    "Vulnerability Scanning",
                    "Wordlist Scanning",
                ],
                "Gather Victim Host Information": [
                    "Hardware",
                    "Software",
                    "Firmware",
                    "Client Configurations",
                ],
                "Gather Victim Identity Information": [
                    "Credentials",
                    "Email Addresses",
                    "Employee Names",
                ],
                "Gather Victim Network Information": [
                    "Domain Properties",
                    "DNS",
                    "Network Trust Dependencies",
                    "Network Topology",
                    "IP Addresses",
                    "Network Security Appliances",
                ],
                "Gather Victim Org Information": [
                    "Determine Physical Locations",
                    "Business Relationships",
                    "Identify Business Tempo",
                    "Identify Roles",
                ],
                "Phishing for Information": [
                    "Spearphishing Service",
                    "Spearphishing Attachment",
                    "Spearphishing Link",
                    "Spearphishing Voice",
                ],
                "Search Closed Sources": [
                    "Threat Intel Vendors",
                    "Purchase Technical Data",
                ],
                "Search Open Technical Databases": [
                    "DNS/Passive DNS",
                    "WHOIS",
                    "Digital Certificates",
                    "CDNs",
                    "Scan Databases",
                ],
                "Search Open Websites/Domains": [
                    "Social Media",
                    "Search Engines",
                    "Code Repositories",
                    "Search Victim-Owned Websites",
                ],
            },
            "Resource Development": {
                "Acquire Infrastructure": [
                    "Domains",
                    "DNS Server",
                    "Virtual Private Server",
                    "Server",
                    "Botnet",
                    "Web Services",
                    "Serverless",
                    "Malvertising",
                ],
                "Compromise Accounts": [
                    "Social Media Accounts",
                    "Email Accounts",
                    "Cloud Accounts",
                ],
                "Compromise Infrastructure": [
                    "Domains",
                    "DNS Server",
                    "Virtual Private Server",
                    "Server",
                    "Botnet",
                    "Web Services",
                    "Serverless",
                    "Network Devices",
                ],
                "Develop Capabilities": [
                    "Malware",
                    "Code Signing Certificates",
                    "Digital Certificates",
                    "Exploits",
                ],
                "Establish Accounts": [
                    "Social Media Accounts",
                    "Email Accounts",
                    "Cloud Accounts",
                ],
                "Obtain Capabilities": [
                    "Malware",
                    "Tool",
                    "Code Signing Certificates",
                    "Digital Certificates",
                    "Exploits",
                    "Vulnerabilities",
                    "Artificial Intelligence",
                ],
                "Stage Capabilities": [
                    "Upload Malware",
                    "Upload Tool",
                    "Install Digital Certificate",
                    "Drive-by Target",
                    "Link Target",
                    "SEO Poisoning",
                    "Content Injection",
                ],
            },
            "Initial Access": {
                "Drive-by Compromise": [],
                "Exploit Public-Facing Application": [],
                "External Remote Services": [],
                "Hardware Additions": [],
                "Phishing": [
                    "Spearphishing Attachment",
                    "Spearphishing Link",
                    "Spearphishing via Service",
                    "Spearphishing Voice",
                ],
                "Replication Through Removable Media": [],
                "Supply Chain Compromise": [
                    "Compromise Software Dependencies and Development Tools",
                    "Compromise Software Supply Chain",
                    "Compromise Hardware Supply Chain",
                ],
                "Trusted Relationship": [],
                "Valid Accounts": [
                    "Default Accounts",
                    "Domain Accounts",
                    "Local Accounts",
                    "Cloud Accounts",
                ],
            },
            "Execution": {
                "Cloud Administration Command": [],
                "Command and Scripting Interpreter": [
                    "PowerShell",
                    "AppleScript",
                    "Windows Command Shell",
                    "Unix Shell",
                    "Visual Basic",
                    "Python",
                    "JavaScript",
                    "Network Device CLI",
                    "Cloud API",
                    "AutoHotKey & AutoIT",
                    "Lua",
                    "Hypervisor CLI",
                ],
                "Container Administration Command": [],
                "Deploy Container": [],
                "ESXi Administration Command": [],
                "Exploitation for Client Execution": [],
                "Input Injection": [],
                "Inter-Process Communication": [
                    "Component Object Model",
                    "Dynamic Data Exchange",
                    "XPC Services",
                ],
                "Native API": [],
                "Scheduled Task/Job": [
                    "At",
                    "Cron",
                    "Scheduled Task",
                    "Systemd Timers",
                    "Container Orchestration Job",
                ],
                "Serverless Execution": [],
                "Shared Modules": [],
                "Software Deployment Tools": [],
                "System Services": ["Launchctl", "Service Execution", "Systemctl"],
                "User Execution": [
                    "Malicious Link",
                    "Malicious File",
                    "Malicious Image",
                    "Malicious Copy and Paste",
                ],
                "Windows Management Instrumentation": [],
            },
            "Persistence": {
                "Account Manipulation": [
                    "Additional Cloud Credentials",
                    "Additional Email Delegate Permissions",
                    "Additional Cloud Roles",
                    "SSH Authorized Keys",
                    "Device Registration",
                    "Additional Container Cluster Roles",
                    "Additional Local or Domain Groups",
                ],
                "BITS Jobs": [],
                "Boot or Logon Autostart Execution": [
                    "Registry Run Keys / Startup Folder",
                    "Authentication Package",
                    "Time Providers",
                    "Winlogon Helper DLL",
                    "Security Support Provider",
                    "Kernel Modules and Extensions",
                    "Re-opened Applications",
                    "LSASS Driver",
                    "Shortcut Modification",
                    "Port Monitors",
                    "Print Processors",
                    "XDG Autostart Entries",
                    "Active Setup",
                    "Login Items",
                ],
                "Boot or Logon Initialization Scripts": [
                    "Logon Script (Windows)",
                    "Login Hook",
                    "Network Logon Script",
                    "RC Scripts",
                    "Startup Items",
                ],
                "Cloud Application Integration": [],
                "Compromise Host Software Binary": [],
                "Create Account": ["Local Account", "Domain Account", "Cloud Account"],
                "Create or Modify System Process": [
                    "Launch Agent",
                    "Systemd Service",
                    "Windows Service",
                    "Launch Daemon",
                    "Container Service",
                ],
                "Event Triggered Execution": [
                    "Change Default File Association",
                    "Screensaver",
                    "Windows Management Instrumentation Event Subscription",
                    "Unix Shell Configuration Modification",
                    "Trap",
                    "LC_LOAD_DYLIB Addition",
                    "Netsh Helper DLL",
                    "Accessibility Features",
                    "AppCert DLLs",
                    "AppInit DLLs",
                    "Application Shimming",
                    "Image File Execution Options Injection",
                    "PowerShell Profile",
                    "Emond",
                    "Component Object Model Hijacking",
                    "Installer Packages",
                    "Udev Rules",
                ],
                "Exclusive Control": [],
                "External Remote Services": [],
                "Hijack Execution Flow": [
                    "DLL",
                    "Dylib Hijacking",
                    "Executable Installer File Permissions Weakness",
                    "Dynamic Linker Hijacking",
                    "Path Interception by PATH Environment Variable",
                    "Path Interception by Search Order Hijacking",
                    "Path Interception by Unquoted Path",
                    "Services File Permissions Weakness",
                    "Services Registry Permissions Weakness",
                    "COR_PROFILER",
                    "KernelCallbackTable",
                    "AppDomainManager",
                ],
                "Implant Internal Image": [],
                "Modify Authentication Process": [
                    "Domain Controller Authentication",
                    "Password Filter DLL",
                    "Pluggable Authentication Modules",
                    "Network Device Authentication",
                    "Reversible Encryption",
                    "Multi-Factor Authentication",
                    "Hybrid Identity",
                    "Network Provider DLL",
                    "Conditional Access Policies",
                ],
                "Modify Registry": [],
                "Office Application Startup": [
                    "Office Template Macros",
                    "Office Test",
                    "Outlook Forms",
                    "Outlook Home Page",
                    "Outlook Rules",
                    "Add-ins",
                ],
                "Power Settings": [],
                "Pre-OS Boot": [
                    "System Firmware",
                    "Component Firmware",
                    "Bootkit",
                    "ROMMONkit",
                    "TFTP Boot",
                ],
                "Scheduled Task/Job": [
                    "At",
                    "Cron",
                    "Scheduled Task",
                    "Systemd Timers",
                    "Container Orchestration Job",
                ],
                "Server Software Component": [
                    "SQL Stored Procedures",
                    "Transport Agent",
                    "Web Shell",
                    "IIS Components",
                    "Terminal Services DLL",
                    "vSphere Installation Bundles",
                ],
                "Software Extensions": ["Browser Extensions", "IDE Extensions"],
                "Traffic Signaling": ["Port Knocking", "Socket Filters"],
                "Valid Accounts": [
                    "Default Accounts",
                    "Domain Accounts",
                    "Local Accounts",
                    "Cloud Accounts",
                ],
            },
            "Privilege Escalation": {
                "Abuse Elevation Control Mechanism": [
                    "Setuid and Setgid",
                    "Bypass User Account Control",
                    "Sudo and Sudo Caching",
                    "Elevated Execution with Prompt",
                    "Temporary Elevated Cloud Access",
                    "TCC Manipulation",
                ],
                "Access Token Manipulation": [
                    "Token Impersonation/Theft",
                    "Create Process with Token",
                    "Make and Impersonate Token",
                    "Parent PID Spoofing",
                    "SID-History Injection",
                ],
                "Account Manipulation": [
                    "Additional Cloud Credentials",
                    "Additional Email Delegate Permissions",
                    "Additional Cloud Roles",
                    "SSH Authorized Keys",
                    "Device Registration",
                    "Additional Container Cluster Roles",
                    "Additional Local or Domain Groups",
                ],
                "Boot or Logon Autostart Execution": [
                    "Registry Run Keys / Startup Folder",
                    "Authentication Package",
                    "Time Providers",
                    "Winlogon Helper DLL",
                    "Security Support Provider",
                    "Kernel Modules and Extensions",
                    "Re-opened Applications",
                    "LSASS Driver",
                    "Shortcut Modification",
                    "Port Monitors",
                    "Print Processors",
                    "XDG Autostart Entries",
                    "Active Setup",
                    "Login Items",
                ],
                "Boot or Logon Initialization Scripts": [
                    "Logon Script (Windows)",
                    "Login Hook",
                    "Network Logon Script",
                    "RC Scripts",
                    "Startup Items",
                ],
                "Create or Modify System Process": [
                    "Launch Agent",
                    "Systemd Service",
                    "Windows Service",
                    "Launch Daemon",
                    "Container Service",
                ],
                "Domain or Tenant Policy Modification": [
                    "Group Policy Modification",
                    "Trust Modification",
                ],
                "Escape to Host": [],
                "Event Triggered Execution": [
                    "Change Default File Association",
                    "Screensaver",
                    "Windows Management Instrumentation Event Subscription",
                    "Unix Shell Configuration Modification",
                    "Trap",
                    "LC_LOAD_DYLIB Addition",
                    "Netsh Helper DLL",
                    "Accessibility Features",
                    "AppCert DLLs",
                    "AppInit DLLs",
                    "Application Shimming",
                    "Image File Execution Options Injection",
                    "PowerShell Profile",
                    "Emond",
                    "Component Object Model Hijacking",
                    "Installer Packages",
                    "Udev Rules",
                ],
                "Exploitation for Privilege Escalation": [],
                "Hijack Execution Flow": [
                    "DLL",
                    "Dylib Hijacking",
                    "Executable Installer File Permissions Weakness",
                    "Dynamic Linker Hijacking",
                    "Path Interception by PATH Environment Variable",
                    "Path Interception by Search Order Hijacking",
                    "Path Interception by Unquoted Path",
                    "Services File Permissions Weakness",
                    "Services Registry Permissions Weakness",
                    "COR_PROFILER",
                    "KernelCallbackTable",
                    "AppDomainManager",
                ],
                "Process Injection": [
                    "Dynamic-link Library Injection",
                    "Portable Executable Injection",
                    "Thread Execution Hijacking",
                    "Asynchronous Procedure Call",
                    "Thread Local Storage",
                    "Ptrace System Calls",
                    "Proc Memory",
                    "Extra Window Memory Injection",
                    "Process Hollowing",
                    "Process DoppelgÃ¤nging",
                    "VDSO Hijacking",
                    "ListPlanting",
                ],
                "Scheduled Task/Job": [
                    "At",
                    "Cron",
                    "Scheduled Task",
                    "Systemd Timers",
                    "Container Orchestration Job",
                ],
                "Valid Accounts": [
                    "Default Accounts",
                    "Domain Accounts",
                    "Local Accounts",
                    "Cloud Accounts",
                ],
            },
            "Defense Evasion": {
                "Abuse Elevation Control Mechanism": [
                    "Setuid and Setgid",
                    "Bypass User Account Control",
                    "Sudo and Sudo Caching",
                    "Elevated Execution with Prompt",
                    "Temporary Elevated Cloud Access",
                    "TCC Manipulation",
                ],
                "Access Token Manipulation": [
                    "Token Impersonation/Theft",
                    "Create Process with Token",
                    "Make and Impersonate Token",
                    "Parent PID Spoofing",
                    "SID-History Injection",
                ],
                "BITS Jobs": [],
                "Build Image on Host": [],
                "Debugger Evasion": [],
                "Deobfuscate/Decode Files or Information": [],
                "Deploy Container": [],
                "Direct Volume Access": [],
                "Domain or Tenant Policy Modification": [
                    "Group Policy Modification",
                    "Trust Modification",
                ],
                "Email Spoofing": [],
                "Execution Guardrails": ["Environmental Keying", "Mutual Exclusion"],
                "Exploitation for Defense Evasion": [],
                "File and Directory Permissions Modification": [
                    "Windows File and Directory Permissions Modification",
                    "Linux and Mac File and Directory Permissions Modification",
                ],
                "Hide Artifacts": [
                    "Hidden Files and Directories",
                    "Hidden Users",
                    "Hidden Window",
                    "NTFS File Attributes",
                    "Hidden File System",
                    "Run Virtual Instance",
                    "VBA Stomping",
                    "Email Hiding Rules",
                    "Resource Forking",
                    "Process Argument Spoofing",
                    "Ignore Process Interrupts",
                    "File/Path Exclusions",
                    "Bind Mounts",
                    "Extended Attributes",
                ],
                "Hijack Execution Flow": [
                    "DLL",
                    "Dylib Hijacking",
                    "Executable Installer File Permissions Weakness",
                    "Dynamic Linker Hijacking",
                    "Path Interception by PATH Environment Variable",
                    "Path Interception by Search Order Hijacking",
                    "Path Interception by Unquoted Path",
                    "Services File Permissions Weakness",
                    "Services Registry Permissions Weakness",
                    "COR_PROFILER",
                    "KernelCallbackTable",
                    "AppDomainManager",
                ],
                "Impair Defenses": [
                    "Disable or Modify Tools",
                    "Disable Windows Event Logging",
                    "Impair Command History Logging",
                    "Disable or Modify System Firewall",
                    "Indicator Blocking",
                    "Disable or Modify Cloud Firewall",
                    "Disable or Modify Cloud Logs",
                    "Safe Mode Boot",
                    "Downgrade Attack",
                    "Spoof Security Alerting",
                    "Disable or Modify Linux Audit System",
                ],
                "Impersonation": [],
                "Indicator Removal": [
                    "Clear Windows Event Logs",
                    "Clear Linux or Mac System Logs",
                    "Clear Command History",
                    "File Deletion",
                    "Network Share Connection Removal",
                    "Timestomp",
                    "Clear Network Connection History and Configurations",
                    "Clear Mailbox Data",
                    "Clear Persistence",
                    "Relocate Malware",
                ],
                "Indirect Command Execution": [],
                "Masquerading": [
                    "Invalid Code Signature",
                    "Right-to-Left Override",
                    "Rename Legitimate Utilities",
                    "Masquerade Task or Service",
                    "Match Legitimate Resource Name or Location",
                    "Space after Filename",
                    "Double File Extension",
                    "Masquerade File Type",
                    "Break Process Trees",
                    "Masquerade Account Name",
                    "Overwrite Process Arguments",
                ],
                "Modify Authentication Process": [
                    "Domain Controller Authentication",
                    "Password Filter DLL",
                    "Pluggable Authentication Modules",
                    "Network Device Authentication",
                    "Reversible Encryption",
                    "Multi-Factor Authentication",
                    "Hybrid Identity",
                    "Network Provider DLL",
                    "Conditional Access Policies",
                ],
                "Modify Cloud Compute Infrastructure": [
                    "Create Snapshot",
                    "Create Cloud Instance",
                    "Delete Cloud Instance",
                    "Revert Cloud Instance",
                    "Modify Cloud Compute Configurations",
                ],
                "Modify Cloud Resource Hierarchy": [],
                "Modify Registry": [],
                "Modify System Image": ["Patch System Image", "Downgrade System Image"],
                "Network Boundary Bridging": ["Network Address Translation Traversal"],
                "Obfuscated Files or Information": [
                    "Binary Padding",
                    "Software Packing",
                    "Steganography",
                    "Compile After Delivery",
                    "Indicator Removal from Tools",
                    "HTML Smuggling",
                    "Dynamic API Resolution",
                    "Stripped Payloads",
                    "Embedded Payloads",
                    "Command Obfuscation",
                    "Fileless Storage",
                    "LNK Icon Smuggling",
                    "Encrypted/Encoded File",
                    "Polymorphic Code",
                    "Compression",
                    "Junk Code Insertion",
                    "SVG Smuggling",
                ],
                "Plist File Modification": [],
                "Pre-OS Boot": [
                    "System Firmware",
                    "Component Firmware",
                    "Bootkit",
                    "ROMMONkit",
                    "TFTP Boot",
                ],
                "Process Injection": [
                    "Dynamic-link Library Injection",
                    "Portable Executable Injection",
                    "Thread Execution Hijacking",
                    "Asynchronous Procedure Call",
                    "Thread Local Storage",
                    "Ptrace System Calls",
                    "Proc Memory",
                    "Extra Window Memory Injection",
                    "Process Hollowing",
                    "Process DoppelgÃ¤nging",
                    "VDSO Hijacking",
                    "ListPlanting",
                ],
                "Reflective Code Loading": [],
                "Rogue Domain Controller": [],
                "Rootkit": [],
                "Subvert Trust Controls": [
                    "Gatekeeper Bypass",
                    "Code Signing",
                    "SIP and Trust Provider Hijacking",
                    "Install Root Certificate",
                    "Mark-of-the-Web Bypass",
                    "Code Signing Policy Modification",
                ],
                "System Binary Proxy Execution": [
                    "Compiled HTML File",
                    "Control Panel",
                    "CMSTP",
                    "InstallUtil",
                    "Mshta",
                    "Msiexec",
                    "Odbcconf",
                    "Regsvcs/Regasm",
                    "Regsvr32",
                    "Rundll32",
                    "Verclsid",
                    "Mavinject",
                    "MMC",
                    "Electron Applications",
                ],
                "System Script Proxy Execution": ["PubPrn", "SyncAppvPublishingServer"],
                "Template Injection": [],
                "Traffic Signaling": ["Port Knocking", "Socket Filters"],
                "Trusted Developer Utilities Proxy Execution": [
                    "MSBuild",
                    "ClickOnce",
                    "JamPlus",
                ],
                "Unused/Unsupported Cloud Regions": [],
                "Use Alternate Authentication Material": [
                    "Application Access Token",
                    "Pass the Hash",
                    "Pass the Ticket",
                    "Web Session Cookie",
                ],
                "Valid Accounts": [
                    "Default Accounts",
                    "Domain Accounts",
                    "Local Accounts",
                    "Cloud Accounts",
                ],
                "Virtualization/Sandbox Evasion": [
                    "System Checks",
                    "User Activity Based Checks",
                    "Time Based Evasion",
                ],
                "Weaken Encryption": ["Reduce Key Space", "Disable Crypto Hardware"],
                "XSL Script Processing": [],
            },
            "Credential Access": {
                "Adversary-in-the-Middle": [
                    "LLMNR/NBT-NS Poisoning and SMB Relay",
                    "ARP Cache Poisoning",
                    "DHCP Spoofing",
                    "Evil Twin",
                ],
                "Brute Force": [
                    "Password Guessing",
                    "Password Cracking",
                    "Password Spraying",
                    "Credential Stuffing",
                ],
                "Credentials from Password Stores": [
                    "Keychain",
                    "Securityd Memory",
                    "Credentials from Web Browsers",
                    "Windows Credential Manager",
                    "Password Managers",
                    "Cloud Secrets Management Stores",
                ],
                "Exploitation for Credential Access": [],
                "Forced Authentication": [],
                "Forge Web Credentials": ["Web Cookies", "SAML Tokens"],
                "Input Capture": [
                    "Keylogging",
                    "GUI Input Capture",
                    "Web Portal Capture",
                    "Credential API Hooking",
                ],
                "Modify Authentication Process": [
                    "Domain Controller Authentication",
                    "Password Filter DLL",
                    "Pluggable Authentication Modules",
                    "Network Device Authentication",
                    "Reversible Encryption",
                    "Multi-Factor Authentication",
                    "Hybrid Identity",
                    "Network Provider DLL",
                    "Conditional Access Policies",
                ],
                "Multi-Factor Authentication Interception": [],
                "Multi-Factor Authentication Request Generation": [],
                "Network Sniffing": [],
                "OS Credential Dumping": [
                    "LSASS Memory",
                    "Security Account Manager",
                    "NTDS",
                    "LSA Secrets",
                    "Cached Domain Credentials",
                    "DCSync",
                    "Proc Filesystem",
                    "/etc/passwd and /etc/shadow",
                ],
                "Steal Application Access Token": [],
                "Steal or Forge Authentication Certificates": [],
                "Steal or Forge Kerberos Tickets": [
                    "Golden Ticket",
                    "Silver Ticket",
                    "Kerberoasting",
                    "AS-REP Roasting",
                    "Ccache Files",
                ],
                "Steal Web Session Cookie": [],
                "Unsecured Credentials": [
                    "Credentials In Files",
                    "Credentials in Registry",
                    "Bash History",
                    "Private Keys",
                    "Cloud Instance Metadata API",
                    "Group Policy Preferences",
                    "Container API",
                    "Chat Messages",
                ],
            },
            "Discovery": {
                "Account Discovery": [
                    "Local Account",
                    "Domain Account",
                    "Email Account",
                    "Cloud Account",
                ],
                "Application Window Discovery": [],
                "Browser Information Discovery": [],
                "Cloud Infrastructure Discovery": [],
                "Cloud Service Dashboard": [],
                "Cloud Service Discovery": [],
                "Cloud Storage Object Discovery": [],
                "Container and Resource Discovery": [],
                "Debugger Evasion": [],
                "Device Driver Discovery": [],
                "Domain Trust Discovery": [],
                "File and Directory Discovery": [],
                "Group Policy Discovery": [],
                "Log Enumeration": [],
                "Network Service Discovery": [],
                "Network Share Discovery": [],
                "Network Sniffing": [],
                "Password Policy Discovery": [],
                "Peripheral Device Discovery": [],
                "Permission Groups Discovery": [
                    "Local Groups",
                    "Domain Groups",
                    "Cloud Groups",
                ],
                "Process Discovery": [],
                "Query Registry": [],
                "Remote System Discovery": [],
                "Software Discovery": ["Security Software Discovery"],
                "System Information Discovery": [],
                "System Location Discovery": ["System Language Discovery"],
                "System Network Configuration Discovery": [
                    "Internet Connection Discovery",
                    "Wi-Fi Discovery",
                ],
                "System Network Connections Discovery": [],
                "System Owner/User Discovery": [],
                "System Service Discovery": [],
                "System Time Discovery": [],
                "Virtual Machine Discovery": [],
                "Virtualization/Sandbox Evasion": [
                    "System Checks",
                    "User Activity Based Checks",
                    "Time Based Evasion",
                ],
            },
            "Lateral Movement": {
                "Exploitation of Remote Services": [],
                "Internal Spearphishing": [],
                "Lateral Tool Transfer": [],
                "Remote Service Session Hijacking": ["SSH Hijacking", "RDP Hijacking"],
                "Remote Services": [
                    "Remote Desktop Protocol",
                    "SMB/Windows Admin Shares",
                    "Distributed Component Object Model",
                    "SSH",
                    "VNC",
                    "Windows Remote Management",
                    "Cloud Services",
                    "Direct Cloud VM Connections",
                ],
                "Replication Through Removable Media": [],
                "Software Deployment Tools": [],
                "Taint Shared Content": [],
                "Use Alternate Authentication Material": [
                    "Application Access Token",
                    "Pass the Hash",
                    "Pass the Ticket",
                    "Web Session Cookie",
                ],
            },
            "Collection": {
                "Adversary-in-the-Middle": [
                    "LLMNR/NBT-NS Poisoning and SMB Relay",
                    "ARP Cache Poisoning",
                    "DHCP Spoofing",
                    "Evil Twin",
                ],
                "Archive Collected Data": [
                    "Archive via Utility",
                    "Archive via Library",
                    "Archive via Custom Method",
                ],
                "Audio Capture": [],
                "Automated Collection": [],
                "Browser Session Hijacking": [],
                "Clipboard Data": [],
                "Data from Cloud Storage": [],
                "Data from Configuration Repository": [
                    "SNMP (MIB Dump)",
                    "Network Device Configuration Dump",
                ],
                "Data from Information Repositories": [
                    "Confluence",
                    "Sharepoint",
                    "Code Repositories",
                    "Customer Relationship Management Software",
                    "Messaging Applications",
                ],
                "Data from Local System": [],
                "Data from Network Shared Drive": [],
                "Data from Removable Media": [],
                "Data Staged": ["Local Data Staging", "Remote Data Staging"],
                "Email Collection": [
                    "Local Email Collection",
                    "Remote Email Collection",
                    "Email Forwarding Rule",
                ],
                "Input Capture": [
                    "Keylogging",
                    "GUI Input Capture",
                    "Web Portal Capture",
                    "Credential API Hooking",
                ],
                "Screen Capture": [],
                "Video Capture": [],
            },
            "Command and Control": {
                "Application Layer Protocol": [
                    "Web Protocols",
                    "File Transfer Protocols",
                    "Mail Protocols",
                    "DNS",
                    "Publish/Subscribe Protocols",
                ],
                "Communication Through Removable Media": [],
                "Content Injection": [],
                "Data Encoding": ["Standard Encoding", "Non-Standard Encoding"],
                "Data Obfuscation": [
                    "Junk Data",
                    "Steganography",
                    "Protocol or Service Impersonation",
                ],
                "Dynamic Resolution": [
                    "Fast Flux DNS",
                    "Domain Generation Algorithms",
                    "DNS Calculation",
                ],
                "Encrypted Channel": [
                    "Symmetric Cryptography",
                    "Asymmetric Cryptography",
                ],
                "Fallback Channels": [],
                "Hide Infrastructure": [],
                "Ingress Tool Transfer": [],
                "Multi-Stage Channels": [],
                "Non-Application Layer Protocol": [],
                "Non-Standard Port": [],
                "Protocol Tunneling": [],
                "Proxy": [
                    "Internal Proxy",
                    "External Proxy",
                    "Multi-hop Proxy",
                    "Domain Fronting",
                ],
                "Remote Access Tools": [
                    "IDE Tunneling",
                    "Remote Desktop Software",
                    "Remote Access Hardware",
                ],
                "Traffic Signaling": ["Port Knocking", "Socket Filters"],
                "Web Service": [
                    "Dead Drop Resolver",
                    "Bidirectional Communication",
                    "One-Way Communication",
                ],
            },
            "Exfiltration": {
                "Automated Exfiltration": ["Traffic Duplication"],
                "Data Transfer Size Limits": [],
                "Exfiltration Over Alternative Protocol": [
                    "Exfiltration Over Symmetric Encrypted Non-C2 Protocol",
                    "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
                    "Exfiltration Over Unencrypted Non-C2 Protocol",
                ],
                "Exfiltration Over C2 Channel": [],
                "Exfiltration Over Other Network Medium": [
                    "Exfiltration Over Bluetooth"
                ],
                "Exfiltration Over Physical Medium": ["Exfiltration over USB"],
                "Exfiltration Over Web Service": [
                    "Exfiltration to Code Repository",
                    "Exfiltration to Cloud Storage",
                    "Exfiltration to Text Storage Sites",
                    "Exfiltration Over Webhook",
                ],
                "Scheduled Transfer": [],
                "Transfer Data to Cloud Account": [],
            },
            "Impact": {
                "Account Access Removal": [],
                "Data Destruction": ["Lifecycle-Triggered Deletion"],
                "Data Encrypted for Impact": [],
                "Data Manipulation": [
                    "Stored Data Manipulation",
                    "Transmitted Data Manipulation",
                    "Runtime Data Manipulation",
                ],
                "Defacement": ["Internal Defacement", "External Defacement"],
                "Disk Wipe": ["Disk Content Wipe", "Disk Structure Wipe"],
                "Email Bombing": [],
                "Endpoint Denial of Service": [
                    "OS Exhaustion Flood",
                    "Service Exhaustion Flood",
                    "Application Exhaustion Flood",
                    "Application or System Exploitation",
                ],
                "Financial Theft": [],
                "Firmware Corruption": [],
                "Inhibit System Recovery": [],
                "Network Denial of Service": [
                    "Direct Network Flood",
                    "Reflection Amplification",
                ],
                "Resource Hijacking": [
                    "Compute Hijacking",
                    "Bandwidth Hijacking",
                    "SMS Pumping",
                    "Cloud Service Hijacking",
                ],
                "Service Stop": [],
                "System Shutdown/Reboot": [],
            },
        }

        return mitre_structure

    def extract_geolocation_risk(
        self, investigation_steps: List[Dict]
    ) -> Dict[str, Any]:
        """Extract and analyze geolocation risk from investigation data"""
        geo_risks = {
            "has_high_risk_country": False,
            "high_risk_locations": [],
            "suspicious_ips": [],
        }

        for step in investigation_steps:
            output = str(step.get("output", ""))

            # Check for high-risk countries
            for country in self.high_risk_countries:
                if country in output.lower():
                    geo_risks["has_high_risk_country"] = True

                    # Extract IP addresses from output
                    ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
                    ips = re.findall(ip_pattern, output)

                    geo_risks["high_risk_locations"].append(
                        {
                            "country": country.title(),
                            "step": step.get("step_name", "Unknown"),
                            "context": output[:200],
                        }
                    )

                    if ips:
                        geo_risks["suspicious_ips"].extend(ips)

        geo_risks["suspicious_ips"] = list(set(geo_risks["suspicious_ips"]))
        return geo_risks

    def build_mitre_techniques_reference(self) -> str:
        """Build comprehensive MITRE techniques reference for the AI prompt"""
        reference = "\n## COMPLETE MITRE ATT&CK TECHNIQUES REFERENCE:\n\n"

        for tactic, techniques in self.mitre_data.items():
            reference += f"\n### {tactic}\n"
            for technique, sub_techniques in techniques.items():
                reference += f"- **{technique}**"
                if sub_techniques:
                    reference += f"\n  Sub-techniques: {', '.join(sub_techniques)}"
                reference += "\n"

        return reference

    def build_mitre_analysis_prompt(
        self,
        username: str,
        classification: str,
        investigation_summary: Dict[str, Any],
        geo_risk_data: Dict[str, Any],
        investigation_steps: List[Dict],
    ) -> str:
        """Build prompt for MITRE ATT&CK mapping with attack chain analysis"""

        # Format investigation context
        investigation_context = ""
        for step in investigation_steps:
            # ✅ Include remarks if they exist
            remarks_info = ""
            if step.get("remarks") and len(step.get("remarks", "")) > 0:
                remarks_info = f"""
        **Analyst Notes**: {step['remarks']}
        """

            investigation_context += f"""
        ### {step['step_name']}
        Output: {str(step['output'])}
        {remarks_info}
        ---
        """

        geo_risk_context = ""
        if geo_risk_data["has_high_risk_country"]:
            geo_risk_context = f"""
    **HIGH-RISK GEOLOCATION DETECTED:**
    - High-risk countries: {', '.join([loc['country'] for loc in geo_risk_data['high_risk_locations']])}
    - Suspicious IPs: {', '.join(geo_risk_data['suspicious_ips'])}
    This significantly increases the TRUE POSITIVE likelihood and threat severity.
    """

        # Get MITRE techniques reference
        mitre_reference = self.build_mitre_techniques_reference()

        # FIXED: Changed the timeline example to avoid f-string format issues
        prompt = f"""You are an elite threat intelligence analyst specializing in MITRE ATT&CK framework mapping and cyber attack chain reconstruction.

    # INVESTIGATION CONTEXT
    **User:** {username}
    **Classification:** {classification}
    **Risk Level:** {investigation_summary.get('risk_level', 'UNKNOWN')}
    **Confidence:** {investigation_summary.get('confidence_score', 0)}%

    {geo_risk_context}

    # INVESTIGATION DATA SUMMARY
    {investigation_context}

    # KEY FINDINGS
    {json.dumps(investigation_summary.get('key_findings', []), indent=2)}

    # RISK INDICATORS
    {json.dumps(investigation_summary.get('risk_indicators', []), indent=2)}

    {mitre_reference}

    ---

    # YOUR MISSION: MITRE ATT&CK MAPPING & ATTACK CHAIN RECONSTRUCTION

    You must provide a comprehensive MITRE ATT&CK analysis including:

    1. **Complete Attack Chain Mapping** - Map observed TTPs to MITRE ATT&CK framework
    2. **Attack Progression Timeline** - Reconstruct the attack sequence
    3. **Threat Actor Profiling** - Identify likely threat actor characteristics
    4. **Predicted Next Steps** - Forecast attacker's probable next moves
    5. **Visual Attack Path** - Color-coded technique mapping (Green/Amber/Red)


    ---

    ## ATTACK TIMELINE GENERATION REQUIREMENTS:

    **Create a detailed chronological attack timeline with the following:**

    1. **Chronological Ordering**: Arrange all attack events in time sequence based on actual timestamps from investigation data
    2. **Stage Numbering**: Number each stage sequentially (1, 2, 3, etc.) to show attack progression
    3. **Complete Context**: For each timeline entry include:
    - Exact timestamp from investigation data
    - MITRE tactic and technique (with sub-technique)
    - Clear description of what happened in business terms
    - Specific evidence from investigation outputs
    - Severity assessment (RED/AMBER/GREEN)
    - Impact statement explaining the security implications
    - List of indicators observed at that stage

    4. **Narrative Flow**: Timeline should tell a story - connect each stage to show how the attack progressed
    5. **Evidence-Based**: Every timeline entry must reference specific data from investigation steps
    6. **Business Language**: Describe technical events in terms business stakeholders can understand

    **Timeline Entry Format:**
    - Stage 1 at [timestamp]: Initial Access via compromised credentials
    - Stage 2 at [timestamp]: Privilege escalation through role manipulation  
    - Stage 3 at [timestamp]: Reconnaissance of cloud resources
    - Stage 4 at [timestamp]: Lateral movement to sensitive systems
    - Stage 5 at [timestamp]: Data exfiltration or impact activities

    **Example Timeline Entry Structure:**
    Stage 1: Initial cloud account compromise at 2025-10-08 11:54:20
    Tactic: Initial Access
    Technique: Valid Accounts with Cloud Accounts sub-technique (T1078.004)
    Description: Attacker accessed cloud account using stolen credentials from suspicious location
    Evidence: Authentication log showing sign-in from unknown IP address
    Severity: AMBER
    Impact: Attacker gained foothold in cloud environment with user privileges
    Indicators: Impossible travel, unknown device, high-risk geographic region

    ---

    ## MITRE ATT&CK TACTICS (All 14):
    1. Reconnaissance (TA0043)
    2. Resource Development (TA0042)
    3. Initial Access (TA0001)
    4. Execution (TA0002)
    5. Persistence (TA0003)
    6. Privilege Escalation (TA0004)
    7. Defense Evasion (TA0005)
    8. Credential Access (TA0006)
    9. Discovery (TA0007)
    10. Lateral Movement (TA0008)
    11. Collection (TA0009)
    12. Command and Control (TA0011)
    13. Exfiltration (TA0010)
    14. Impact (TA0040)

    ---

    ## CRITICAL INSTRUCTIONS FOR SUB-TECHNIQUES:

    **ALWAYS include sub-techniques when mapping MITRE techniques:**
    - Use the complete reference provided above to identify appropriate sub-techniques
    - Every technique that has sub-techniques MUST include at least one relevant sub-technique
    - Sub-technique selection must be evidence-based from investigation data
    - Format: "Technique" > "Sub-technique"
    - Example: "Valid Accounts" > "Cloud Accounts" (T1078.004)

    **DO NOT use generic techniques when specific sub-techniques exist**
    - Wrong: "Valid Accounts (T1078)" without sub-technique
    - Correct: "Valid Accounts: Cloud Accounts (T1078.004)"

    ---


    ## CRITICAL INSTRUCTIONS FOR PROCEDURES (TTP Details):

    **ALWAYS include detailed procedures for each technique:**
    - The "procedure" field must explain HOW the attacker executed the technique
    - Include specific tools, methods, commands, or techniques used
    - Reference actual evidence from the investigation data
    - Describe the attack flow step-by-step
    - Make it actionable for defenders to understand the attack methodology

    **Procedure Example Format:**
    "The attacker used stolen credentials (username: john.doe@abc.com) to authenticate from IP 203.0.113.45 located in an unknown geographic region. The authentication occurred at 14:34:34, shortly after a Global Administrator role was assigned to the account. The attacker leveraged the cloud account access to bypass traditional perimeter defenses, utilizing valid authentication tokens to avoid detection by signature-based security tools."

    **DO NOT use generic procedures** - Every procedure must be specific to THIS investigation's evidence.

    ---

    ## ANALYSIS REQUIREMENTS:

    ### For TRUE POSITIVE Cases:
    - Map ALL observed techniques to MITRE ATT&CK framework WITH sub-techniques
    - Identify the current attack stage
    - Predict 3-5 most likely next attacker moves WITH specific sub-techniques
    - Provide detailed kill chain reconstruction
    - Assign severity colors: RED (confirmed), AMBER (likely), GREEN (possible future)
    - Include specific technique IDs and sub-technique IDs (e.g., T1078.004 - Valid Accounts: Cloud Accounts)

    ### For FALSE POSITIVE Cases:
    - Map potential misinterpreted behaviors to MITRE techniques WITH sub-techniques
    - Explain why behaviors appeared suspicious but are benign
    - Provide "what-if" attack scenarios for learning
    - Suggest detection improvements to reduce false positives
    - Color code hypothetical attack paths

    ### For Both Cases:
    - Generate comprehensive attack narrative
    - Include MITRE Navigator layer data with sub-techniques
    - Provide defensive recommendations mapped to MITRE techniques and sub-techniques
    - Identify detection gaps

    ---

    # OUTPUT FORMAT (STRICT JSON):

    {{
        "mitre_attack_analysis": {{
            "overall_assessment": {{
                "attack_stage": "Initial Access | Persistence Established | Privilege Escalation | Lateral Movement | Exfiltration | Impact",
                "attack_stage_explanation": "Detailed 2-3 sentence explanation of what this stage means, why the attacker is at this stage, and what evidence supports this assessment",
                "threat_sophistication": "Low | Medium | High | Advanced Persistent Threat",
                "sophistication_explanation": "Explain the attacker's skill level based on observed techniques, tools used, and operational security practices. Include specific examples from the investigation",
                "attack_confidence": 95,
                "confidence_explanation": "Explain why this confidence level was assigned, what evidence strongly supports the assessment, and what gaps exist",
                "primary_objective": "Credential theft | Data exfiltration | Ransomware | Espionage | Financial fraud",
                "objective_explanation": "Explain what the attacker is trying to achieve based on observed behavior and targeted systems",
                "estimated_dwell_time": "< 1 hour | 1-24 hours | 1-7 days | > 7 days",
                "dwell_time_explanation": "Explain how long the attacker has been in the environment, what evidence suggests this timeframe, and what this means for the investigation",
                "geographic_threat_indicator": "High-risk country detected" or "Standard geographic profile"
            }},
            
            "attack_chain_narrative": "Detailed 5-7 paragraph narrative that tells the complete attack story chronologically. Start with initial compromise, explain each stage of the attack progression, describe the attacker's objectives and methods at each phase, reference specific timestamps and evidence, explain the business impact at each stage, and conclude with the current threat status. Include all sub-techniques observed.",
            
            "mitre_techniques_observed": [
                {{
                    "tactic": "Initial Access",
                    "tactic_id": "TA0001",
                    "technique": "Valid Accounts",
                    "technique_id": "T1078",
                    "sub_technique": "Cloud Accounts",
                    "sub_technique_id": "T1078.004",
                    "severity": "RED | AMBER | GREEN",
                    "confidence": 95,
                    "evidence": "Specific evidence from investigation showing this technique and sub-technique",
                    "timestamp": "2025-10-09 09:54:20",
                    "indicators": ["Impossible travel", "Suspicious IP: 203.0.113.45"],
                    "sub_technique_justification": "Why this specific sub-technique applies",
                    "procedure": "DETAILED step-by-step description of HOW the attacker executed this specific technique. Must include: (1) What credentials/access was used, (2) What systems/accounts were targeted, (3) What tools or methods were employed, (4) What evasion techniques were used if any, (5) What the attacker achieved through this action, (6) Specific evidence from logs/investigation that proves this procedure. Example: The attacker leveraged stolen credentials for user john.doe@abc.com obtained through a prior phishing campaign. At 14:34:34 UTC, they authenticated to the Microsoft 365 tenant from IP address 203.0.113.45 originating from Moscow, Russia. The authentication used valid username and password combination, bypassing initial access controls. The attacker's session presented as a new device with generic browser fingerprint, triggering impossible travel alerts as the legitimate user had authenticated from New York just 30 minutes prior. The cloud account access provided the attacker with initial foothold in the corporate environment, granting access to email, SharePoint, and other cloud resources associated with the compromised account. Evidence includes authentication logs showing successful sign-in with MFA push notification approved, geolocation data indicating high-risk country, and device fingerprint showing previously unknown device characteristics."
                }}
            ],
            
            "attack_timeline": [
                {{
                    "stage": 1,
                    "timestamp": "2025-10-08 11:54:20",
                    "tactic": "Initial Access",
                    "technique": "Valid Accounts: Cloud Accounts (T1078.004)",
                    "description": "Detailed narrative description of what happened at this stage. Explain the attacker's actions, the systems involved, and the security implications. Make it understandable for non-technical stakeholders.",
                    "evidence": "Specific evidence from investigation logs or data that proves this event occurred",
                    "severity": "AMBER",
                    "sub_technique_details": "Explain exactly which sub-technique was used and why it fits this classification",
                    "impact": "Explain the business and security impact of this event. What access did the attacker gain? What risks does this create?",
                    "indicators_observed": ["Impossible travel detected", "Unknown device used", "Geographic anomaly from high-risk region", "Temporal anomaly - access outside business hours"]
                }},
                {{
                    "stage": 2,
                    "timestamp": "2025-10-08 15:34:34",
                    "tactic": "Privilege Escalation",
                    "technique": "Account Manipulation: Additional Cloud Roles (T1098.003)",
                    "description": "Detailed description of privilege escalation activity",
                    "evidence": "Role assignment logs showing Global Administrator role granted",
                    "severity": "RED",
                    "sub_technique_details": "Specific cloud role manipulation technique used",
                    "impact": "Attacker gained full administrative control over cloud environment",
                    "indicators_observed": ["Privilege escalation", "Administrative role assignment", "Unauthorized permission changes"]
                }}
            ],
            
            "predicted_next_steps": [
                {{
                    "sequence": 1,
                    "likelihood": "High | Medium | Low",
                    "tactic": "[Tactic from MITRE framework]",
                    "technique": "[Technique name]",
                    "technique_id": "[T####]",
                    "sub_technique": "[Sub-technique if applicable]",
                    "sub_technique_id": "[T####.###]",
                    "description": "ONLY predict next steps that are LOGICAL based on the ACTUAL investigation data. DO NOT mention cloud storage, AWS, Azure, Google Drive, DropBox, or any specific cloud services UNLESS the investigation explicitly shows the organization uses these services. Base predictions ONLY on what was observed: if you saw role assignments, predict abuse of those roles. If you saw unknown locations, predict lateral movement. DO NOT fabricate scenarios.",
                    "rationale": "Explain WHY this is the predicted next step based on current attack stage, attacker's demonstrated capabilities, and common attack patterns",
                    "indicators_to_watch": ["Specific log entries", "System behaviors", "Network activities to monitor"],
                    "recommended_preventive_action": "Specific actionable steps to prevent this predicted activity",
                    "detection_method": "How to detect if this activity occurs",
                    "business_impact_if_occurs": "What would happen to the business if this predicted step succeeds"
                }}
            ],
            
            "threat_actor_profile": {{
                "sophistication_level": "Low | Medium | High | APT",
                "sophistication_details": "Detailed analysis of attacker capabilities based on observed techniques, operational security, and tool usage",
                "likely_motivation": "Financial | Espionage | Sabotage | Hacktivism",
                "motivation_details": "Why we believe this is the attacker's motivation based on targets, methods, and objectives",
                "probable_attribution": "Individual | Cybercriminal Group | Nation State | Insider",
                "attribution_details": "Evidence supporting this attribution including geographic indicators, TTP patterns, and known threat actor behaviors",
                "geographic_indicators": ["Russia", "China"] or ["No specific indicators"],
                "tactics_signature": "Matches known APT group patterns" or "Generic attack methodology",
                "similar_campaigns": ["Campaign names or TTPs matching known threats"],
                "preferred_sub_techniques": ["List of commonly used sub-techniques by this threat actor"]
            }},
            
            "mitre_navigator_layer": {{
                "name": "Attack Chain - {username}",
                "description": "MITRE ATT&CK Navigator layer for visualized attack path with sub-techniques",
                "domain": "enterprise-attack",
                "versions": {{
                    "attack": "14",
                    "navigator": "4.9"
                }},
                "techniques": [
                    {{
                        "techniqueID": "T1078",
                        "tactic": "initial-access",
                        "color": "#ff0000",
                        "comment": "Observed - Valid Accounts: Cloud Accounts (T1078.004)",
                        "enabled": true,
                        "score": 100,
                        "showSubtechniques": true
                    }},
                    {{
                        "techniqueID": "T1078.004",
                        "tactic": "initial-access",
                        "color": "#ff0000",
                        "comment": "Observed - Cloud Accounts sub-technique",
                        "enabled": true,
                        "score": 100
                    }}
                ],
                "gradient": {{
                    "colors": ["#00ff00", "#ffff00", "#ff0000"],
                    "minValue": 0,
                    "maxValue": 100
                }}
            }},
            
            "attack_path_visualization": {{
                "paths": [
                    {{
                        "path_id": 1,
                        "path_name": "Primary Attack Path",
                        "color_code": "RED",
                        "stages": [
                            {{
                                "stage": "Initial Access",
                                "techniques": ["T1078.004 - Valid Accounts: Cloud Accounts"],
                                "status": "CONFIRMED",
                                "color": "RED",
                                "sub_technique_details": "Cloud account compromise through credential theft"
                            }},
                            {{
                                "stage": "Defense Evasion", 
                                "techniques": ["T1550.004 - Use Alternate Authentication Material: Web Session Cookie"],
                                "status": "LIKELY",
                                "color": "AMBER",
                                "sub_technique_details": "Session hijacking using stolen cookies"
                            }},
                            {{
                                "stage": "Exfiltration",
                                "techniques": ["T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage"],
                                "status": "PREDICTED",
                                "color": "GREEN",
                                "sub_technique_details": "Data exfiltration to attacker-controlled cloud storage"
                            }}
                        ]
                    }}
                ]
            }},
            
            "defensive_recommendations": [
                {{
                    "priority": "CRITICAL | HIGH | MEDIUM | LOW",
                    "mitre_mitigation": "M1027 - Password Policies",
                    "recommendation": "Implement mandatory MFA for all cloud accounts with hardware tokens",
                    "mapped_techniques": ["T1078", "T1078.004"],
                    "mapped_sub_techniques": ["Cloud Accounts (T1078.004)"],
                    "implementation_complexity": "Low | Medium | High",
                    "estimated_effectiveness": "80%"
                }}
            ],
            
            "detection_gaps": [
                {{
                    "gap_description": "No geo-blocking for executive cloud accounts",
                    "affected_techniques": ["T1078.004"],
                    "affected_sub_techniques": ["Cloud Accounts"],
                    "risk_level": "HIGH",
                    "recommended_detection": "Implement conditional access policies based on geolocation for cloud accounts",
                    "mitre_data_source": "DS0028 - Logon Session"
                }}
            ],
            
            "sub_technique_coverage": {{
                "total_techniques_mapped": 0,
                "techniques_with_sub_techniques": 0,
                "sub_technique_percentage": "0%",
                "techniques_requiring_sub_techniques": []
            }}
        }},
        
        "executive_summary": {{
            "one_line_summary": "Account compromise via credential theft from high-risk country with impossible travel pattern",
            "attack_sophistication": "Medium sophistication attack using compromised valid credentials with cloud account access",
            "business_impact": "Critical - CFO account compromised, potential financial data exposure",
            "immediate_actions": ["Disable account", "Reset credentials", "Review access logs", "Enable MFA"],
            "investigation_priority": "P1 - Critical",
            "key_sub_techniques_observed": ["Cloud Accounts (T1078.004)", "Additional sub-techniques as observed"]
        }}
    }}

    ---

    # CRITICAL REQUIREMENTS:

    1. **Evidence-Based**: Every MITRE technique AND sub-technique must be supported by specific evidence from investigation
    2. **NO FABRICATION IN PREDICTIONS**: When predicting next attacker moves:
    - Base predictions ONLY on techniques that logically follow from observed activity
    - DO NOT mention specific cloud services (AWS, Azure, GCP, DropBox, etc.) unless investigation data explicitly mentions them
    - DO NOT assume "cloud storage" exists unless investigation shows cloud environment
    - DO NOT predict "exfiltration to cloud storage" unless investigation shows cloud infrastructure
    - ONLY predict generic follow-up actions based on observed patterns
    - Example: If you saw "Global Administrator assigned" → predict "Discovery of resources" NOT "Discovery of AWS S3 buckets"
    3. **Sub-Technique Mandatory**: ALWAYS include sub-techniques when they exist for a technique
    4. **Detailed Procedures**: Every technique must have a comprehensive procedure describing the exact attack method
    5. **Comprehensive Timeline**: Attack timeline must include ALL stages with detailed narratives for each event
    6. **Explanations**: All assessment fields (attack_stage, sophistication, confidence, dwell_time) must include detailed explanations
    7. **Color Coding**: 
    - RED = Confirmed observed technique/sub-technique
    - AMBER = Highly likely technique/sub-technique in progress
    - GREEN = Predicted future technique/sub-technique
    8. **Completeness**: Map ALL relevant MITRE tactics (1-14) with appropriate sub-techniques
    9. **Specificity**: Use exact MITRE ATT&CK technique IDs and sub-technique IDs (e.g., T1078.004)
    10. **Actionability**: Recommendations must be specific, prioritized, and implementable
    11. **Timeline Accuracy**: Correlate MITRE techniques with actual timestamps from investigation
    12. **Prediction Quality**: Next steps must include specific sub-techniques and be realistic based on observed attacker behavior
    13. **Geographic Context**: If high-risk countries detected, emphasize in threat profiling
    14. **Sub-Technique Justification**: Explain WHY each specific sub-technique was selected based on evidence
    15. **Navigator Compatibility**: Include both parent techniques and sub-techniques in MITRE Navigator layer
    16. **Coverage Tracking**: Track sub-technique coverage percentage in analysis

    **Sub-Technique Selection Rules**:
    - If evidence shows "cloud account" access → Use T1078.004 (Cloud Accounts)
    - If evidence shows "domain account" access → Use T1078.002 (Domain Accounts)
    - If evidence shows "local account" access → Use T1078.003 (Local Accounts)
    - Always match the most specific sub-technique to the evidence
    - If multiple sub-techniques apply, include all relevant ones

    **Geographic Risk Enhancement**: If investigation involves Russia, China, or other high-risk countries, automatically increase threat severity and include nation-state TTPs with specific sub-techniques in analysis.

    ---

    Now analyze the investigation data and provide comprehensive MITRE ATT&CK mapping with detailed sub-techniques, comprehensive procedures, and detailed explanations in VALID JSON format only."""

        return prompt

    def analyze_mitre_attack_chain(
        self,
        username: str,
        classification: str,
        investigation_summary: Dict[str, Any],
        investigation_steps: List[Dict],
    ) -> Optional[Dict[str, Any]]:
        """Generate comprehensive MITRE ATT&CK analysis with sub-techniques"""

        try:
            # Extract geolocation risks
            geo_risk_data = self.extract_geolocation_risk(investigation_steps)

            # Force TRUE POSITIVE if high-risk country detected
            if (
                geo_risk_data["has_high_risk_country"]
                and "FALSE" in classification.upper()
            ):
                classification = "TRUE POSITIVE"
                investigation_summary["classification"] = "TRUE POSITIVE"
                investigation_summary["risk_level"] = "CRITICAL"
                investigation_summary["confidence_score"] = max(
                    investigation_summary.get("confidence_score", 0), 90
                )

                # Add geo-risk to key findings
                if "key_findings" not in investigation_summary:
                    investigation_summary["key_findings"] = []

                investigation_summary["key_findings"].insert(
                    0,
                    {
                        "step_reference": "Geolocation Analysis",
                        "category": "Geographic Anomaly",
                        "severity": "Critical",
                        "details": f"Access from high-risk country: {', '.join([loc['country'] for loc in geo_risk_data['high_risk_locations']])}",
                        "evidence": f"Suspicious IPs: {', '.join(geo_risk_data['suspicious_ips'])}",
                        "impact": "High-risk geographic location significantly increases likelihood of malicious activity",
                    },
                )

            # Build and execute MITRE analysis prompt
            prompt = self.build_mitre_analysis_prompt(
                username,
                classification,
                investigation_summary,
                geo_risk_data,
                investigation_steps,
            )

            response = self.model.generate_content(prompt)
            content = response.text.strip()

            # Clean response
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]

            content = content.strip()

            # Parse JSON
            mitre_analysis = json.loads(content)

            # Add geo-risk metadata
            mitre_analysis["geographic_risk_assessment"] = geo_risk_data

            # Validate sub-technique coverage
            self._validate_subtechnique_coverage(mitre_analysis)

            return mitre_analysis

        except json.JSONDecodeError as e:
            print(f"JSON parsing error in MITRE analysis: {str(e)}")
            return None
        except Exception as e:
            print(f"Error in MITRE analysis: {str(e)}")
            return None

    def _validate_subtechnique_coverage(self, mitre_analysis: Dict[str, Any]):
        """Validate and enhance sub-technique coverage in analysis"""
        if "mitre_attack_analysis" in mitre_analysis:
            analysis = mitre_analysis["mitre_attack_analysis"]

            # Calculate sub-technique coverage
            techniques_observed = analysis.get("mitre_techniques_observed", [])
            total_techniques = len(techniques_observed)
            techniques_with_subtechniques = sum(
                1
                for t in techniques_observed
                if t.get("sub_technique")
                and t.get("sub_technique") != "N/A"
                and t.get("sub_technique").strip()
            )

            coverage = {
                "total_techniques_mapped": total_techniques,
                "techniques_with_sub_techniques": techniques_with_subtechniques,
                "sub_technique_percentage": f"{(techniques_with_subtechniques/total_techniques*100) if total_techniques > 0 else 0:.1f}%",
                "techniques_requiring_sub_techniques": [],
                "quality_score": (
                    "Excellent"
                    if techniques_with_subtechniques / total_techniques >= 0.8
                    else (
                        "Good"
                        if techniques_with_subtechniques / total_techniques >= 0.6
                        else "Needs Improvement"
                    )
                ),
            }

            # Identify techniques that should have sub-techniques
            for technique in techniques_observed:
                technique_name = technique.get("technique", "")
                tactic = technique.get("tactic", "")

                # Check if this technique has available sub-techniques in our data
                if (
                    tactic in self.mitre_data
                    and technique_name in self.mitre_data[tactic]
                ):
                    available_subtechniques = self.mitre_data[tactic][technique_name]
                    if available_subtechniques and (
                        not technique.get("sub_technique")
                        or technique.get("sub_technique") == "N/A"
                    ):
                        coverage["techniques_requiring_sub_techniques"].append(
                            {
                                "technique": technique_name,
                                "technique_id": technique.get("technique_id"),
                                "tactic": tactic,
                                "available_sub_techniques": available_subtechniques[
                                    :3
                                ],  # Show only first 3
                            }
                        )

            analysis["sub_technique_coverage"] = coverage


class InvestigationAnalyzer:
    """Main investigation analyzer combining initial analysis and MITRE mapping"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel("gemini-2.0-flash-exp")
        self.mitre_analyzer = MITREAttackAnalyzer(api_key)

    def extract_investigation_steps(self, df, username: str) -> List[Dict]:
        """Extract investigation steps with their outputs AND remarks for the specific user"""
        investigation_steps = []

        for idx, row in df.iterrows():
            # ✅ Extract ALL relevant columns
            output_value = row.get("Output", "")
            remarks_value = row.get("Remarks/Comments", "")
            step_name = row.get("Name", "Unknown Step")
            explanation = row.get("Explanation", "")
            kql_query = row.get("KQL Query", "")

            # ✅ Clean up values
            output_str = (
                str(output_value)
                if pd.notna(output_value)
                and str(output_value).lower() not in ["nan", "none", ""]
                else ""
            )
            remarks_str = (
                str(remarks_value)
                if pd.notna(remarks_value)
                and str(remarks_value).lower() not in ["nan", "none", ""]
                else ""
            )

            step_data = {
                "step_number": row.get("Step", idx + 1),
                "step_name": str(step_name) if pd.notna(step_name) else "Unknown Step",
                "explanation": str(explanation) if pd.notna(explanation) else "",
                "kql_query": str(kql_query) if pd.notna(kql_query) else "",
                "output": output_str,  # ✅ Query output
                "remarks": remarks_str,  # ✅ Analyst remarks
                "analyst_notes": remarks_str,  # ✅ Additional field for context
            }

            # ✅ Include step if it has meaningful data OR contains the username
            has_meaningful_data = (
                output_str
                or remarks_str
                or username.lower() in str(step_data.get("output", "")).lower()
                or username.lower() in str(step_data.get("remarks", "")).lower()
            )

            if has_meaningful_data:
                investigation_steps.append(step_data)

        # ✅ Debug logging
        print(f"📊 Extracted {len(investigation_steps)} steps for user: {username}")
        for step in investigation_steps[:3]:  # Show first 3 steps
            print(f"  - Step {step['step_number']}: {step['step_name']}")
            print(f"    Output length: {len(step['output'])} chars")
            print(f"    Remarks length: {len(step['remarks'])} chars")

        return investigation_steps

    def build_initial_analysis_prompt(
        self, username: str, investigation_steps: List[Dict]
    ) -> str:
        """Build prompt for initial classification analysis"""

        steps_formatted = ""
        for i, step in enumerate(investigation_steps, 1):
            # ✅ Only show remarks if they exist
            remarks_section = ""
            if step.get("remarks") and len(step["remarks"]) > 0:
                remarks_section = f"""
        **Analyst Remarks/Observations**: 
        {step['remarks']}
        """

            steps_formatted += f"""
        ### STEP {step['step_number']}: {step['step_name']}
        **Purpose**: {step['explanation']}
        **Output Data**:
        {step['output']}
        {remarks_section}
        ---
        """

        prompt = f"""You are an elite cybersecurity analyst specializing in security investigations and threat detection.

# INVESTIGATION TARGET: {username}

# INVESTIGATION STEPS AND OUTPUTS:
{steps_formatted}

---

# CRITICAL ANALYSIS RULES:

**YOU MUST USE BOTH THE OUTPUT DATA AND ANALYST REMARKS to make your determination.**
**DO NOT mention "cloud", "MFA", "authentication" or any technical term UNLESS it appears in the investigation outputs or remarks.**
**IMPORTANT: Pay special attention to "Analyst Remarks/Observations" - these contain critical context and observations made during the investigation.**
**If an analyst remarks that an IP is suspicious or activity is confirmed, treat this as PRIMARY EVIDENCE.**
**Analyst remarks override ambiguous output data - they represent human expert judgment.**

# CLASSIFICATION CRITERIA:

Analyze ONLY what you can see in the investigation outputs:

## TRUE POSITIVE Indicators (only if evidence exists):
- Multiple sign-ins from different locations at impossible times
- Access from high-risk countries (Russia, China, North Korea, Iran, etc.)
- "Unknown Location" mentioned in outputs
- "Unknown Device" mentioned in outputs
- Role changes to high-privilege roles (Global Administrator, etc.)
- Sign-ins from suspicious or unusual IP addresses

## FALSE POSITIVE Indicators (only if evidence exists):
- All activities from same location
- All devices marked as "Trusted" in outputs
- Normal business patterns visible in timestamps
- Expected role assignments for user's job function

## BENIGN POSITIVE Indicators (only if evidence exists):
- Single location access
- Trusted devices only
- Normal timing patterns
- No privilege escalations

**If investigation data does NOT contain information about something (like MFA, cloud, authentication methods), then DO NOT mention it in your analysis.**

---

# OUTPUT FORMAT (STRICT JSON):

{{
    "classification": "TRUE POSITIVE | FALSE POSITIVE | BENIGN POSITIVE",
    "risk_level": "CRITICAL | HIGH | MEDIUM | LOW",
    "confidence_score": 85,
    "summary": "2-3 sentence executive summary",
    "pattern_analysis": {{
        "privilege_escalation_risk": "Based ONLY on actual role assignment data from investigation outputs - quote specific evidence",
        "temporal_anomalies": "Based ONLY on actual timestamp data from investigation outputs - quote specific evidence",
        "geographic_anomalies": "Based ONLY on actual location/IP data from investigation outputs - quote specific evidence",
        "authentication_concerns": "Based ONLY on actual authentication data IF IT EXISTS in investigation outputs - quote specific evidence or state 'No authentication data in investigation'",
        "device_trust_issues": "Based ONLY on actual device information from investigation outputs - quote specific evidence",
        "behavioral_deviations": "Based ONLY on actual behavioral patterns visible in investigation outputs - quote specific evidence"
    }},
    "key_findings": [
        {{
            "step_reference": "STEP X.0: Step name",
            "category": "Category",
            "severity": "Critical | High | Medium | Low",
            "details": "Finding details",
            "evidence": "Evidence from investigation",
            "impact": "Security implication"
        }}
    ],
    "risk_indicators": ["List of specific risk indicators"],
    "timeline_correlation": [
        {{
            "event_sequence": "Event description",
            "timestamps": "Timestamps",
            "significance": "Why this matters"
        }}
    ],
    "step_by_step_analysis": [
        {{
            "step": "Step name",
            "finding": "What was found",
            "contribution_to_classification": "How this supports classification"
        }}
    ],
    "recommendations": ["Prioritized recommendations"],
    "justification": "Detailed classification justification"
}}

Analyze and provide VALID JSON only."""

        return prompt

    def perform_initial_analysis(
        self, username: str, investigation_steps: List[Dict]
    ) -> Optional[Dict[str, Any]]:
        """Perform initial classification analysis"""

        try:
            prompt = self.build_initial_analysis_prompt(username, investigation_steps)
            response = self.model.generate_content(prompt)
            content = response.text.strip()

            # Clean response
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]

            content = content.strip()
            result = json.loads(content)

            return result

        except json.JSONDecodeError as e:
            print(f"JSON parsing error: {str(e)}")
            return None
        except Exception as e:
            print(f"Error in initial analysis: {str(e)}")
            return None

    def perform_complete_analysis(
        self, username: str, investigation_steps: List[Dict]
    ) -> Dict[str, Any]:
        """Perform complete analysis including MITRE ATT&CK mapping with sub-techniques"""

        # Step 1: Initial classification analysis
        initial_analysis = self.perform_initial_analysis(username, investigation_steps)

        if not initial_analysis:
            return {"error": "Initial analysis failed", "status": "failed"}

        # Step 2: MITRE ATT&CK analysis with sub-techniques
        mitre_analysis = self.mitre_analyzer.analyze_mitre_attack_chain(
            username,
            initial_analysis.get("classification", "UNKNOWN"),
            initial_analysis,
            investigation_steps,
        )

        # Combine results
        complete_analysis = {
            "username": username,
            "analysis_timestamp": datetime.now().isoformat(),
            "initial_analysis": initial_analysis,
            "mitre_attack_analysis": (
                mitre_analysis.get("mitre_attack_analysis") if mitre_analysis else None
            ),
            "executive_summary": (
                mitre_analysis.get("executive_summary") if mitre_analysis else None
            ),
            "geographic_risk": (
                mitre_analysis.get("geographic_risk_assessment")
                if mitre_analysis
                else None
            ),
            "status": "success",
        }

        return complete_analysis
