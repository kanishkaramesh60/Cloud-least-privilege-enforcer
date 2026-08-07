import json
from datetime import datetime, timezone

with open("reports/policies.json", "r") as file:
    policies = json.load(file)
with open("reports/usage_report.json", "r") as file:
    usage = json.load(file)

usage_dict = {}
for user in usage:
    usage_dict[user["username"]] = user
orphan_report = []

for user in policies["users"]:
    username = user["username"]
    if username not in usage_dict:
        last_activity = "Never"
        inactive_days = 999
    else:
        last_activity = usage_dict[username]["last_activity"]
        last_date = datetime.fromisoformat(last_activity)
        today = datetime.now(timezone.utc)
        inactive_days = (today - last_date).days

    if inactive_days <= 30:
        status = "Active"
    elif inactive_days <= 90:
        status = "Warning"
    else:
        status = "Orphan"

    attached = user["attached_policies"]
    if "AdministratorAccess" in attached:
        risk = "High"
    elif len(attached) >= 2:
        risk = "Medium"
    else:
        risk = "Low"
    orphan_report.append({
        "username": username,
        "status": status,
        "last_activity": last_activity,
        "inactive_days": inactive_days,
        "attached_policies": attached,
        "risk": risk
    })

with open("reports/orphan_report.json", "w") as file:
    json.dump(orphan_report, file, indent=4)

print("\n======================================")
print("Orphan Identity Detection Report")
print("======================================")

for user in orphan_report:
    print(f"\nUser: {user['username']}")
    print(f"Status: {user['status']}")
    print(f"Inactive Days: {user['inactive_days']}")
    print("Policies:")
    if user["attached_policies"]:
        for policy in user["attached_policies"]:
            print(f" - {policy}")
    else:
        print(" None")
    print(f"Risk: {user['risk']}")
print("\nReport saved to reports/orphan_report.json")