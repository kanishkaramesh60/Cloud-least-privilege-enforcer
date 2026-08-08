import json
from pathlib import Path

POLICY_FILE = Path("reports/policies.json")
USAGE_FILE = Path("reports/usage_report.json")
ORPHAN_FILE = Path("reports/orphan_report.json")
TEMPORAL_FILE = Path("reports/temporal_report.json")
OUTPUT_FILE = Path("reports/risk_report.json")

MAX_PERMISSION_RISK = 50
MAX_USAGE_RISK = 20
MAX_ORPHAN_RISK = 20
MAX_TEMPORAL_RISK = 10

def load_json(file_path):
    if not file_path.exists():
        print(f"ERROR: {file_path} not found.")
        return None
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except json.JSONDecodeError:
        print(f"ERROR: Invalid JSON: {file_path}")
        return None

def get_policy_users(data):
    users = {}
    if not data:
        return users
    if isinstance(data, dict):
        if "users" in data:
            data = data["users"]
        elif "Users" in data:
            data = data["Users"]
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            username = (
                item.get("username")
                or item.get("Username")
                or item.get("user")
                or item.get("User")
            )
            policies = (
                item.get("policies")
                or item.get("Policies")
                or []
            )
            if username:
                users[username] = policies
    elif isinstance(data, dict):
        for username, value in data.items():
            if username in [
                "users",
                "Users",
                "roles",
                "Roles"
            ]:
                continue
            if isinstance(value, dict):
                policies = (
                    value.get("policies")
                    or value.get("Policies")
                    or []
                )
                users[username] = policies
            elif isinstance(value, list):
                users[username] = value
    return users

def get_usage_users(data):
    users = {}
    if not data:
        return users
    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        records = (
            data.get("users")
            or data.get("Users")
            or data.get("usage")
            or data.get("results")
            or []
        )
    else:
        records = []
    if isinstance(records, list):
        for item in records:
            if not isinstance(item, dict):
                continue
            username = (
                item.get("username")
                or item.get("Username")
                or item.get("user")
                or item.get("User")
            )
            if username:
                users[username] = item
    return users

def get_orphan_users(data):
    users = {}
    if not data:
        return users
    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        records = (
            data.get("users")
            or data.get("Users")
            or data.get("results")
            or []
        )
    else:
        records = []
    if isinstance(records, list):
        for item in records:
            if not isinstance(item, dict):
                continue
            username = (
                item.get("username")
                or item.get("Username")
                or item.get("user")
                or item.get("User")
            )
            if username:
                users[username] = item
    return users

def get_temporal_users(data):
    users = {}
    if not data:
        return users
    if isinstance(data, dict):
        records = (
            data.get("events")
            or data.get("Events")
            or []
        )
    elif isinstance(data, list):
        records = data
    else:
        records = []
    if isinstance(records, list):
        for item in records:
            if not isinstance(item, dict):
                continue
            username = (
                item.get("username")
                or item.get("Username")
                or item.get("user")
                or item.get("User")
            )
            if username:
                if username not in users:
                    users[username] = {
                        "total_events": 0,
                        "outside_access_window": 0
                    }
                users[username]["total_events"] += 1
                if item.get("outside_access_window") is True:
                    users[username]["outside_access_window"] += 1
    return users

def calculate_permission_risk(policies):
    if not policies:
        return 0, "Low"
    risk = 0
    policy_names = []
    for policy in policies:
        if isinstance(policy, dict):
            name = (
                policy.get("PolicyName")
                or policy.get("policy_name")
                or policy.get("name")
                or "Unknown"
            )
        else:
            name = str(policy)
        policy_names.append(name)
        if name in [
            "AdministratorAccess",
            "PowerUserAccess"
        ]:
            risk += 40
        elif name.endswith("FullAccess"):
            risk += 15
        elif name == "IAMUserChangePassword":
            risk += 2
        else:
            risk += 5
    risk = min(risk, MAX_PERMISSION_RISK)
    if risk >= 40:
        level = "Critical"
    elif risk >= 25:
        level = "High"
    elif risk >= 10:
        level = "Medium"
    else:
        level = "Low"
    return risk, level

def calculate_usage_risk(usage):
    if not usage:
        return 20, "High"
    api_calls = (
        usage.get("api_calls")
        or usage.get("API Calls")
        or usage.get("apiCalls")
        or 0
    )
    try:
        api_calls = int(api_calls)
    except (ValueError, TypeError):
        api_calls = 0
    if api_calls == 0:
        return 20, "High"
    elif api_calls <= 5:
        return 10, "Medium"
    else:
        return 0, "Low"

def calculate_orphan_risk(orphan):
    if not orphan:
        return 0, "Low"
    status = str(
        orphan.get("status", "")
    ).lower()
    if status == "inactive":
        return 20, "Critical"
    elif status == "active":
        return 0, "Low"
    return 5, "Medium"

def calculate_temporal_risk(temporal):
    if not temporal:
        return 0, "Low"
    total = temporal.get("total_events", 0)
    outside = temporal.get(
        "outside_access_window",
        0
    )
    try:
        total = int(total)
        outside = int(outside)
    except (ValueError, TypeError):
        return 0, "Low"
    if total == 0:
        return 0, "Low"
    percentage = (
        outside / total
    ) * 100
    if percentage >= 50:
        return 10, "High"
    elif percentage >= 25:
        return 5, "Medium"
    else:
        return 0, "Low"

def get_overall_risk(score):
    if score >= 75:
        return "Critical"
    elif score >= 50:
        return "High"
    elif score >= 25:
        return "Medium"
    else:
        return "Low"

def main():
    print("=" * 60)
    print("             RISK SCORING ENGINE")
    print("=" * 60)
    policy_data = load_json(POLICY_FILE)
    usage_data = load_json(USAGE_FILE)
    orphan_data = load_json(ORPHAN_FILE)
    temporal_data = load_json(TEMPORAL_FILE)
    if policy_data is None:
        print("Cannot continue without policies.json.")
        return
    policy_users = get_policy_users(policy_data)
    usage_users = get_usage_users(usage_data)
    orphan_users = get_orphan_users(orphan_data)
    temporal_users = get_temporal_users(
        temporal_data
    )
    usernames = set()
    usernames.update(policy_users.keys())
    usernames.update(usage_users.keys())
    usernames.update(orphan_users.keys())
    usernames.update(temporal_users.keys())
    results = []

    for username in sorted(usernames):
        policies = policy_users.get(
            username,
            []
        )
        usage = usage_users.get(
            username
        )
        orphan = orphan_users.get(
            username
        )
        temporal = temporal_users.get(
            username
        )
        permission_score, permission_level = (
            calculate_permission_risk(policies)
        )
        usage_score, usage_level = (
            calculate_usage_risk(usage)
        )
        orphan_score, orphan_level = (
            calculate_orphan_risk(orphan)
        )
        temporal_score, temporal_level = (
            calculate_temporal_risk(temporal)
        )
        total_score = (
            permission_score
            + usage_score
            + orphan_score
            + temporal_score
        )
        total_score = min(
            total_score,
            100
        )
        overall_level = get_overall_risk(
            total_score
        )
        result = {
            "username": username,
            "risk_score": {
                "permission": permission_score,
                "usage": usage_score,
                "orphan": orphan_score,
                "temporal": temporal_score,
                "total": total_score
            },
            "risk_level": {
                "permission": permission_level,
                "usage": usage_level,
                "orphan": orphan_level,
                "temporal": temporal_level,
                "overall": overall_level
            },
            "policies": policies
        }
        results.append(result)
        print("\nUser:", username)
        print(
            "Permission Risk:",
            permission_score,
            permission_level
        )
        print(
            "Usage Risk:",
            usage_score,
            usage_level
        )
        print(
            "Orphan Risk:",
            orphan_score,
            orphan_level
        )
        print(
            "Temporal Risk:",
            temporal_score,
            temporal_level
        )
        print(
            "Total Risk:",
            total_score,
            overall_level
        )

    report = {
        "scoring_model": {
            "permission_max": MAX_PERMISSION_RISK,
            "usage_max": MAX_USAGE_RISK,
            "orphan_max": MAX_ORPHAN_RISK,
            "temporal_max": MAX_TEMPORAL_RISK,
            "total_max": 100
        },
        "users": results
    }
    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            report,
            file,
            indent=4
        )
    print("\n" + "=" * 60)
    print("Risk Scoring Completed Successfully")
    print(
        f"Report saved to: {OUTPUT_FILE}"
    )
    print("=" * 60)

if __name__ == "__main__":
    main()