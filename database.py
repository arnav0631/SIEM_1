import sqlite3

DB_NAME = "siem.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Table for raw logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            user TEXT,
            event TEXT,
            severity TEXT
        )
    ''')
    
    # Table for security alerts
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            attack_type TEXT,
            severity TEXT
        )
    ''')
    
    # Table for blocked IPs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            timestamp TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

def add_log(timestamp, ip, user, event, severity):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs (timestamp, ip, user, event, severity) VALUES (?, ?, ?, ?, ?)",
                   (timestamp, ip, user, event, severity))
    conn.commit()
    conn.close()

def add_alert(timestamp, ip, attack_type, severity):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO alerts (timestamp, ip, attack_type, severity) VALUES (?, ?, ?, ?)",
                   (timestamp, ip, attack_type, severity))
    conn.commit()
    conn.close()

def block_ip(ip, timestamp):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO blocked_ips (ip, timestamp) VALUES (?, ?)", (ip, timestamp))
    conn.commit()
    conn.close()

def unblock_ip(ip):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
    conn.commit()
    conn.close()

def get_dashboard_data():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("SELECT timestamp, ip, user, event, severity FROM logs ORDER BY id DESC LIMIT 10")
    logs = cursor.fetchall()
    
    cursor.execute("SELECT timestamp, ip, attack_type, severity FROM alerts ORDER BY id DESC LIMIT 5")
    alerts = cursor.fetchall()
    
    cursor.execute("SELECT ip, timestamp FROM blocked_ips ORDER BY id DESC")
    blocked = cursor.fetchall()
    
    cursor.execute("SELECT COUNT(*) FROM logs")
    total_logs = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cursor.fetchone()[0]
    
    conn.close()
    return logs, alerts, blocked, total_logs, total_alerts