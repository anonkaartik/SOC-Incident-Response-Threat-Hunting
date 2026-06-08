import csv
failed_logins = {}
iocs = set()
critical_events = []
total_events = 0

with open("logs/security_logs.csv", "r") as file:
    reader = csv.DictReader(file)

    for row in reader:
        total_events += 1
        ip = row["source_ip"]
        event = row["event_type"]
        status = row["status"]
        user = row["username"]
        iocs.add(ip)

        if event == "LOGIN" and status == "FAILED":
            failed_logins[ip] = failed_logins.get(ip, 0) + 1

        if event == "POWERSHELL":
            critical_events.append(("HIGH", f"PowerShell executed by {user} from {ip}"))

        if event == "FILE_ACCESS":
            critical_events.append(("HIGH", f"Sensitive file accessed by {user}"))

        if event == "NETWORK_CONNECTION":
            critical_events.append(("MEDIUM", f"Suspicious outbound connection to {ip}"))

report = []

report.append("SOC INCIDENT RESPONSE REPORT")
report.append("=" * 50)
report.append("")

report.append(f"Total Events Analyzed : {total_events}")
report.append(f"Total Unique IOCs : {len(iocs)}")
report.append(f"Critical Events Detected : {len(critical_events)}")
report.append("")

report.append("BRUTE FORCE DETECTION")
report.append("-" * 50)

for ip, count in failed_logins.items():
    if count >= 5:
        report.append(f"[HIGH] Brute Force Attack Detected : {ip} ({count} failed attempts)")

report.append("")
report.append("CRITICAL EVENTS")
report.append("-" * 50)

for severity, event in critical_events:
    report.append(f"[{severity}] {event}")

report.append("")
report.append("IOC LIST")
report.append("-" * 50)

for ioc in sorted(iocs):
    report.append(ioc)

report.append("")
report.append("INCIDENT SUMMARY")
report.append("-" * 50)
report.append(f"Failed Login Sources : {len(failed_logins)}")
report.append(f"Critical Events : {len(critical_events)}")
with open("reports/incident_report.txt", "w") as report_file:
    report_file.write("\n".join(report))
print("\nSOC INCIDENT RESPONSE REPORT GENERATED SUCCESSFULLY")
print("Report saved to reports/incident_report.txt")


