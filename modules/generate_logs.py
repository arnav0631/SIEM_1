import time
import random
import database

IPS = ["192.168.1.15", "10.0.0.4", "172.16.0.22", "192.168.1.105"]
USERS = ["admin", "root", "vikalp", "guest", "service_acc"]
EVENTS = [
    ("LOGIN_SUCCESS", "INFO"),
    ("LOGIN_FAILED", "WARNING"),
    ("PORT_SCAN", "HIGH"),
    ("POWERSHELL_EXEC", "HIGH"),
    ("UNAUTHORIZED_FILE_ACCESS", "CRITICAL")
]

def generate_batch_logs(count=5):
    for _ in range(count):
        ip = random.choice(IPS)
        user = random.choice(USERS)
        event, severity = random.choice(EVENTS)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        
        # Save log directly to database
        database.add_log(timestamp, ip, user, event, severity)
        
        # Check against detector rules
        from modules.detector import check_rules
        check_rules(timestamp, ip, user, event)