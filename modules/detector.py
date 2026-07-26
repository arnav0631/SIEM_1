from datetime import datetime
import database

def analyze_log(log, active_rules):
    timestamp = log.get('timestamp')
    ip = log.get('ip')
    event = log.get('event', '')
    severity = log.get('severity')

    # 1. PowerShell Execution Detection Rule
    if active_rules.get('POWERSHELL') and "4104" in event:
        database.add_alert(timestamp, ip, "Suspicious PowerShell Execution", "CRITICAL")
        database.block_ip(ip, timestamp)

    # 2. Port Scan Detection Rule
    elif active_rules.get('PORT_SCAN') and "8001" in event:
        database.add_alert(timestamp, ip, "Reconnaissance Port Scan", "HIGH")
        database.block_ip(ip, timestamp)

    # 3. Brute Force / Failed Logon Detection Rule
    elif active_rules.get('BRUTE_FORCE') and "4625" in event:
        database.add_alert(timestamp, ip, "Brute Force Authentication Attempt", "HIGH")