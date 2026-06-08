import csv
import random
from datetime import datetime, timedelta

events = ["LOGIN", "POWERSHELL", "FILE_ACCESS", "NETWORK_CONNECTION"]
users = ["admin", "john", "mary", "test", "guest"]
start_time = datetime(2026, 6, 1, 9, 0, 0)

with open("logs/security_logs.csv", "w", newline="") as file:
    writer = csv.writer(file)

    writer.writerow([
        "timestamp",
        "event_type",
        "username",
        "source_ip",
        "status"])

    for i in range(1000):
        timestamp = start_time + timedelta(seconds=i * 30)

        event = random.choice(events)

        user = random.choice(users)

        ip = ".".join(str(random.randint(1, 255)) for _ in range(4))

        if event == "LOGIN":
            status = random.choice(["SUCCESS", "FAILED"])

        elif event == "POWERSHELL":
            status = "EXECUTED"

        elif event == "FILE_ACCESS":
            status = "SENSITIVE_FILE"

        else:
            status = "OUTBOUND"

        writer.writerow([
            timestamp,
            event,
            user,
            ip,
            status])

print("1000 security logs generated successfully")

