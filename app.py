from flask import Flask, render_template, redirect, url_for, Response, session
from datetime import datetime, timedelta
import database
from modules import generate_logs, detector

app = Flask(__name__)
app.secret_key = 'siem_secret_session_key'  # Required for Flask session management

# Global state for interactive SOAR detection rules
ACTIVE_RULES = {
    'BRUTE_FORCE': True,
    'POWERSHELL': True,
    'PORT_SCAN': True,
    'ANOMALY_SPIKE': True
}

# Initialize database schema on startup
database.init_db()

@app.route('/')
def index():
    # If opened in a new browser window/tab, reset database to start at 0
    if 'visited' not in session:
        database.init_db()
        session['visited'] = True

    logs, alerts, blocked, total_logs, total_alerts = database.get_dashboard_data()
    
    # Check SOC status (System status reverts to SECURE if no alerts in last 60 seconds)
    recent_threat = False
    now = datetime.now()
    for alert in alerts:
        try:
            alert_time = datetime.strptime(alert[0], "%Y-%m-%d %H:%M:%S")
            if (now - alert_time) <= timedelta(seconds=60):
                recent_threat = True
                break
        except Exception:
            pass

    status = "UNDER ATTACK" if recent_threat else "SYSTEM STATUS: SECURE"
    status_class = "status-danger" if recent_threat else "status-secure"

    return render_template(
        'index.html',
        logs=logs,
        alerts=alerts,
        blocked=blocked,
        total_logs=total_logs,
        total_alerts=total_alerts,
        status=status,
        status_class=status_class,
        active_rules=ACTIVE_RULES
    )

@app.route('/generate')
def generate():
    # Generate batch of 5 synthetic telemetry events
    new_logs = generate_logs.generate_batch(5)
    for log in new_logs:
        database.add_log(log['timestamp'], log['ip'], log['user'], log['event'], log['severity'])
        # Evaluate log through correlation engine
        detector.analyze_log(log, ACTIVE_RULES)
    return redirect(url_for('index'))

@app.route('/toggle_rule/<rule_name>')
def toggle_rule(rule_name):
    if rule_name in ACTIVE_RULES:
        ACTIVE_RULES[rule_name] = not ACTIVE_RULES[rule_name]
    return redirect(url_for('index'))

@app.route('/unblock/<ip>')
def unblock(ip):
    database.unblock_ip(ip)
    return redirect(url_for('index'))

@app.route('/export/logs')
def export_logs():
    logs, _, _, _, _ = database.get_dashboard_data()
    
    # Build CSV text output
    csv_data = "Timestamp,IP Address,User ID,Event Code,Severity\n"
    for log in logs:
        csv_data += f'"{log[0]}","{log[1]}","{log[2]}","{log[3]}","{log[4]}"\n'
        
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=siem_telemetry_export.csv"}
    )

if __name__ == '__main__':
    app.run(debug=True)