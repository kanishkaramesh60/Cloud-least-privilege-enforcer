import json
from pathlib import Path
POLICY_FILE = Path("reports/policies.json")
USAGE_FILE = Path("reports/usage_report.json")
PERMISSION_FILE = Path("reports/permission_analysis.json")
ORPHAN_FILE = Path("reports/orphan_report.json")
TEMPORAL_FILE = Path("reports/temporal_report.json")
OUTPUT_FILE = Path("reports/ml_features.json")
def load_json(path):
    if not path.exists():
        print(f"WARNING: {path} not found.")
        return None
    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)
    except json.JSONDecodeError:
        print(f"ERROR: Invalid JSON: {path}")
        return None
def get_username(item):
    if not isinstance(item, dict):
        return None
    return (
        item.get("username")
        or item.get("Username")
        or item.get("user")
        or item.get("User")
    )
def get_policy_users(data):
    users = {}
    if not isinstance(data, dict):
        return users
    records = data.get("users", [])
    for item in records:
        username = get_username(item)
        if not username:
            continue
        policies = (
            item.get("attached_policies")
            or item.get("policies")
            or item.get("Policies")
            or []
        )
        users[username] = policies
    return users
def get_usage_users(data):
    users = {}
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
    for item in records:
        username = get_username(item)
        if username:
            users[username] = item
    return users
def get_permission_users(data):
    users = {}
    if not isinstance(data, dict):
        return users
    records = data.get("users", [])
    for item in records:
        username = get_username(item)
        if username:
            users[username] = item
    return users
def get_orphan_users(data):
    users = {}
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
    for item in records:
        username = get_username(item)
        if username:
            users[username] = item
    return users
def get_temporal_users(data):
    users = {}
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
    for item in records:
        username = get_username(item)
        if username:
            users[username] = item
    return users
def policy_names(policies):
    names = []
    for policy in policies:
        if isinstance(policy, str):
            names.append(policy)
        elif isinstance(policy, dict):
            name = (
                policy.get("PolicyName")
                or policy.get("policy_name")
                or policy.get("name")
            )
            if name:
                names.append(name)
    return names
def calculate_policy_features(policies):
    names = policy_names(policies)
    broad_count = 0
    admin_access = 0
    full_access = 0
    for policy in names:
        if policy == "AdministratorAccess":
            admin_access = 1
            broad_count += 1
        elif policy.endswith("FullAccess"):
            full_access = 1
            broad_count += 1
    return {
        "policy_count": len(names),
        "broad_policy_count": broad_count,
        "has_admin_access": admin_access,
        "has_full_access": full_access
    }
def calculate_usage_features(usage):
    if not usage:
        return {
            "api_call_count": 0,
            "service_count": 0
        }
    api_calls = (
        usage.get("total_api_calls")
        or usage.get("api_calls")
        or usage.get("API Calls")
        or 0
    )
    services = (
        usage.get("services_used")
        or usage.get("Services Used")
        or usage.get("services")
        or []
    )
    if not isinstance(services, list):
        services = []
    try:
        api_calls = int(api_calls)
    except (ValueError, TypeError):
        api_calls = 0
    return {
        "api_call_count": api_calls,
        "service_count": len(services)
    }
def calculate_permission_features(permission):
    if not permission:
        return {
            "unused_service_count": 0
        }
    analysis = permission.get("analysis", {})
    unused_services = (
        analysis.get("unused_services")
        or []
    )
    if not isinstance(unused_services, list):
        unused_services = []
    return {
        "unused_service_count": len(unused_services)
    }
def calculate_orphan_features(orphan):
    if not orphan:
        return {
            "inactive_days": 0,
            "rare_activity": 0
        }
    inactive_days = (
        orphan.get("inactive_days")
        or orphan.get("Inactive Days")
        or 0
    )
    try:
        inactive_days = int(inactive_days)
    except (ValueError, TypeError):
        inactive_days = 0
    rare_activity = 0
    if inactive_days >= 7:
        rare_activity = 1
    return {
        "inactive_days": inactive_days,
        "rare_activity": rare_activity
    }
def calculate_temporal_features(temporal):
    if not temporal:
        return {
            "odd_hour_activity": 0
        }
    odd_hour = (
        temporal.get("odd_hour_activity")
        or temporal.get("odd_hour")
        or temporal.get("unusual_time")
        or False
    )
    if isinstance(odd_hour, str):
        odd_hour = odd_hour.lower() in [
            "true",
            "yes",
            "1",
            "high"
        ]
    return {
        "odd_hour_activity": int(bool(odd_hour))
    }
def main():
    print("=" * 60)
    print("        ML FEATURE ENGINEERING")
    print("=" * 60)
    policy_data = load_json(POLICY_FILE)
    usage_data = load_json(USAGE_FILE)
    permission_data = load_json(PERMISSION_FILE)
    orphan_data = load_json(ORPHAN_FILE)
    temporal_data = load_json(TEMPORAL_FILE)
    policy_users = get_policy_users(policy_data)
    usage_users = get_usage_users(usage_data)
    permission_users = get_permission_users(permission_data)
    orphan_users = get_orphan_users(orphan_data)
    temporal_users = get_temporal_users(temporal_data)
    all_users = set()
    all_users.update(policy_users.keys())
    all_users.update(usage_users.keys())
    all_users.update(permission_users.keys())
    all_users.update(orphan_users.keys())
    all_users.update(temporal_users.keys())
    results = []
    for username in sorted(all_users):
        policy_features = calculate_policy_features(
            policy_users.get(username, [])
        )
        usage_features = calculate_usage_features(
            usage_users.get(username, {})
        )
        permission_features = calculate_permission_features(
            permission_users.get(username, {})
        )
        orphan_features = calculate_orphan_features(
            orphan_users.get(username, {})
        )
        temporal_features = calculate_temporal_features(
            temporal_users.get(username, {})
        )
        features = {}
        features.update(policy_features)
        features.update(usage_features)
        features.update(permission_features)
        features.update(orphan_features)
        features.update(temporal_features)
        result = {
            "username": username,
            "features": features
        }
        results.append(result)
        print()
        print("User:", username)
        print("Features:")
        for key, value in features.items():
            print(f"  {key}: {value}")
    report = {
        "module": "ML Feature Engineering",
        "description": "Features generated from IAM, CloudTrail, permission, orphan and temporal analysis.",
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
    print()
    print("=" * 60)
    print("Feature Engineering Completed")
    print("Report saved to:", OUTPUT_FILE)
    print("=" * 60)
if __name__ == "__main__":
    main()