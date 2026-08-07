import json
from collections import defaultdict

with open("reports/cloudtrail_logs.json", "r") as file:
    logs = json.load(file)
print("Total Events:", len(logs))

usage = defaultdict(lambda: {
    "total_api_calls": 0,
    "services_used": set(),
    "last_activity": ""
})

for event in logs:
    username = event.get("username", "Unknown")
    usage[username]["total_api_calls"] += 1
    service = event["event_source"].split(".")[0].upper()
    usage[username]["services_used"].add(service)
    current = event["event_time"]
    if current > usage[username]["last_activity"]:
        usage[username]["last_activity"] = current

report = []
for user, info in usage.items():
    report.append({
        "username": user,
        "total_api_calls":
        info["total_api_calls"],
        "services_used":
        sorted(list(info["services_used"])),
        "last_activity":
        info["last_activity"]
    })

with open("reports/usage_report.json", "w") as file:
    json.dump(report, file, indent=4)

print("\n=====================================")
print("CloudTrail Usage Report")
print("=====================================")

for user in report:
    print(f"\nUser : {user['username']}")
    print(f"API Calls : {user['total_api_calls']}")
    print("Services Used:")
    for service in user["services_used"]:
        print(f" - {service}")
    print("Last Activity:")
    print(user["last_activity"])
print("\nReport saved to reports/usage_report.json")