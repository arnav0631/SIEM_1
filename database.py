import sqlite3

DB_NAME = "siem.db"

def get_connection():
    return sqlite3.connect(DB_NAME)

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Wipe old tables so telemetry starts clean at 0 for fresh sessions
    cursor.execute("DROP TABLE IF EXISTS logs")
    cursor.execute("DROP TABLE IF EXISTS alerts")
    cursor.execute("DROP TABLE IF EXISTS blocked_ips")
    
    # Create fresh schema
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            timestamp TEXT,
            ip TEXT,
            user TEXT,
            event TEXT,
            severity TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            timestamp TEXT,
            ip TEXT,
            attack_type TEXT,
            severity TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            timestamp TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

def add_log(timestamp, ip, user, event, severity):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs VALUES (?, ?, ?, ?, ?)", (timestamp, ip, user, event, severity))
    conn.commit()
    conn.close()

def add_alert(timestamp, ip, attack_type, severity):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO alerts VALUES (?, ?, ?, ?)", (timestamp, ip, attack_type, severity))
    conn.commit()
    conn.close()

def block_ip(ip, timestamp):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO blocked_ips VALUES (?, ?)", (ip, timestamp))
    conn.commit()
    conn.close()

def unblock_ip(ip):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
    conn.commit()
    conn.close()

def get_dashboard_data():
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM logs ORDER BY rowid DESC LIMIT 10")
    logs = cursor.fetchall()
    
    cursor.execute("SELECT * FROM alerts ORDER BY rowid DESC LIMIT 5")
    alerts = cursor.fetchall()
    
    cursor.execute("SELECT * FROM blocked_ips")
    blocked = cursor.fetchall()
    
    cursor.execute("SELECT COUNT(*) FROM logs")
    total_logs = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cursor.fetchone()[0]
    
    conn.close()
    return logs, alerts, blocked, total_logs, total_alerts