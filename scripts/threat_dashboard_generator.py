import csv
from collections import Counter
event_counter = Counter()
ip_counter = Counter()

with open("logs/security_logs.csv", "r") as file:
    reader = csv.DictReader(file)
    for row in reader:
        event_counter[row["event_type"]] += 1
        ip_counter[row["source_ip"]] += 1

with open("dashboards/threat_statistics.csv", "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["Event Type", "Count"])
    for event, count in event_counter.items():
        writer.writerow([event, count])

with open("dashboards/ioc_summary.csv", "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["IP Address", "Occurrences"])
    for ip, count in ip_counter.most_common(20):
        writer.writerow([ip, count])

print("Dashboard files generated successfully")
