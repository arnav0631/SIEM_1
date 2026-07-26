from datetime import datetime, timedelta
import database

ACTIVE_RULES = {
    "brute_force": True,
    "powershell": True,
    "port_scan": True,
    "anomaly_spike": True
}

failed_attempts = {}
log_volume_tracker = {}

def toggle_rule(rule_name, status):
    if rule_name in ACTIVE_RULES:
        ACTIVE_RULES[rule_name] = status

def check_rules(timestamp_str, ip, user, event):
    current_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

    # 1. TIME-WINDOW BRUTE FORCE DETECTION (30s)
    if ACTIVE_RULES["brute_force"] and event == "LOGIN_FAILED":
        if ip not in failed_attempts:
            failed_attempts[ip] = []
        
        failed_attempts[ip].append(current_time)
        cutoff_time = current_time - timedelta(seconds=30)
        failed_attempts[ip] = [t for t in failed_attempts[ip] if t >= cutoff_time]

        if len(failed_attempts[ip]) >= 3:
            database.add_alert(timestamp_str, ip, "Brute Force Attack Detected", "CRITICAL")
            database.block_ip(ip, timestamp_str)  # SOAR Action: Auto Block IP
            failed_attempts[ip] = []

    # 2. CRITICAL FILE ACCESS (SOAR Auto Ban)
    elif event == "UNAUTHORIZED_FILE_ACCESS":
        database.add_alert(timestamp_str, ip, "Unauthorized File Access Attempt", "CRITICAL")
        database.block_ip(ip, timestamp_str)  # SOAR Action: Auto Block IP

    # 3. LOG SPIKE ANOMALY DETECTION (10s)
    if ACTIVE_RULES["anomaly_spike"]:
        if ip not in log_volume_tracker:
            log_volume_tracker[ip] = []
            
        log_volume_tracker[ip].append(current_time)
        cutoff_spike = current_time - timedelta(seconds=10)
        log_volume_tracker[ip] = [t for t in log_volume_tracker[ip] if t >= cutoff_spike]

        if len(log_volume_tracker[ip]) >= 5:
            database.add_alert(timestamp_str, ip, "Anomaly Detected: High Log Volume Spike", "HIGH")
            log_volume_tracker[ip] = []

    # 4. PATTERN MATCHING RULES
    if ACTIVE_RULES["powershell"] and event == "POWERSHELL_EXEC":
        database.add_alert(timestamp_str, ip, "Suspicious PowerShell Execution", "HIGH")

    if ACTIVE_RULES["port_scan"] and event == "PORT_SCAN":
        database.add_alert(timestamp_str, ip, "Port Scanning Activity", "HIGH")