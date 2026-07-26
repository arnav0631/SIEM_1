import csv
import io
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, Response
import database
from modules.generate_logs import generate_batch_logs
from modules.detector import ACTIVE_RULES, toggle_rule

app = Flask(__name__)
database.init_db()

@app.route("/")
def dashboard():
    logs, alerts, blocked, total_logs, total_alerts = database.get_dashboard_data()
    
    # --- FIX 1: REALISTIC SYSTEM STATUS LOGIC ---
    # Check if any alert happened in the last 60 seconds
    now = datetime.now()
    recent_critical_alerts = 0
    
    for alert in alerts:
        try:
            alert_time = datetime.strptime(alert[0], "%Y-%m-%d %H:%M:%S")
            if (now - alert_time) <= timedelta(seconds=60):
                recent_critical_alerts += 1
        except ValueError:
            pass

    # Status is UNDER ATTACK only if active threats happened in the last 1 minute
    soc_status = "UNDER ATTACK" if recent_critical_alerts > 0 else "SECURE"
    
    return render_template(
        "index.html", 
        logs=logs, 
        alerts=alerts, 
        blocked=blocked,
        total_logs=total_logs, 
        total_alerts=total_alerts,
        soc_status=soc_status,
        rules=ACTIVE_RULES
    )

@app.route("/generate")
def trigger_logs():
    generate_batch_logs(count=5)
    return redirect(url_for("dashboard"))

@app.route("/unblock/<ip>")
def unblock(ip):
    database.unblock_ip(ip)
    return redirect(url_for("dashboard"))

@app.route("/export/logs")
def export_logs():
    logs, _, _, _, _ = database.get_dashboard_data()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "IP Address", "User", "Event", "Severity"])
    for row in logs:
        writer.writerow(row)
        
    response = Response(output.getvalue(), mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=siem_telemetry_report.csv"
    return response

@app.route("/toggle_rule/<rule_name>")
def toggle_rule_route(rule_name):
    current = ACTIVE_RULES.get(rule_name, True)
    toggle_rule(rule_name, not current)
    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    app.run(debug=True, port=5000)