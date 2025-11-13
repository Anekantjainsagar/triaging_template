from routes.src.virustotal_integration import IPReputationChecker

# Test VPN detection
checker = IPReputationChecker()
result = checker.check_ip_reputation("8.8.8.8", method="auto")

print("VPN Detection Test:")
print(f"Success: {result.get('success')}")
print(f"VPN Data: {result.get('vpn_detection', {})}")
print(f"Formatted Output:\n{result.get('formatted_output', 'No output')}")