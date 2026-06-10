import csv
from collections import Counter
failed_logins = Counter()
powershell_usage = Counter()
ip_activity = Counter()

with open("logs/security_logs.csv", "r") as file:
    reader = csv.DictReader(file)
    for row in reader:
        ip = row["source_ip"]
        event = row["event_type"]
        status = row["status"]
        ip_activity[ip] += 1
        if event == "LOGIN" and status == "FAILED":
            failed_logins[ip] += 1
        if event == "POWERSHELL":
            powershell_usage[ip] += 1
report = []

report.append("THREAT HUNTING REPORT")
report.append("=" * 50)
report.append("")
report.append("BRUTE FORCE DETECTION")
report.append("-" * 50)

for ip, count in failed_logins.items():
    if count >= 3:
        report.append(f"[HIGH] Possible Brute Force Attack : {ip} ({count} failed logins)")
report.append("")
report.append("POWERSHELL ACTIVITY ANALYSIS")
report.append("-" * 50)

for ip, count in powershell_usage.items():
    if count >= 3:
        report.append(f"[MEDIUM] Excessive PowerShell Usage : {ip} ({count} executions)")

report.append("")
report.append("TOP ACTIVE IPS")
report.append("-" * 50)

for ip, count in ip_activity.most_common(20):
    report.append(f"{ip} : {count} events")
with open("reports/threat_hunting_report.txt", "w") as file:
    file.write("\n".join(report))

print("Threat hunting completed successfully")
print("Report saved to reports/threat_hunting_report.txt")