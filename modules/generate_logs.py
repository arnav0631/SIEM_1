import random
from datetime import datetime

IP_POOL = ["192.168.1.10", "10.0.0.15", "172.16.0.5", "192.168.1.50", "45.33.32.156"]
USER_POOL = ["admin", "root", "Arnav", "service_account", "guest"]
EVENT_CODES = [
    {"code": "4624", "severity": "INFO", "desc": "Successful Logon"},
    {"code": "4625", "severity": "HIGH", "desc": "Failed Logon"},
    {"code": "4104", "severity": "CRITICAL", "desc": "PowerShell Script Block Execution"},
    {"code": "8001", "severity": "HIGH", "desc": "Nmap Port Scan Detected"}
]

def generate_batch(count=5):
    logs = []
    for _ in range(count):
        event = random.choice(EVENT_CODES)
        log = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": random.choice(IP_POOL),
            "user": random.choice(USER_POOL),
            "event": f"{event['code']} - {event['desc']}",
            "severity": event["severity"]
        }
        logs.append(log)
    return logs