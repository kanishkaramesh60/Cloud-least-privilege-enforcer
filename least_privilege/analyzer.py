import json
from pathlib import Path

POLICY_FILE = Path("reports/policies.json")
USAGE_FILE = Path("reports/usage_report.json")
OUTPUT_FILE = Path("reports/permission_analysis.json")

def load_json(path):
    if not path.exists():
        print(f"ERROR: {path} not found.")
        return None
    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)
    except json.JSONDecodeError:
        print(f"ERROR: Invalid JSON file: {path}")
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
    return users

def get_usage_users(data):
    users = {}
    if not data:
        return users
    if isinstance(data, dict):
        records = (
            data.get("users")
            or data.get("Users")
            or data.get("usage")
            or data.get("results")
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
                users[username] = item
    return users

def extract_policy_names(policies):
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

def extract_used_services(usage):
    if not usage:
        return []
    services = (
        usage.get("services_used")
        or usage.get("Services Used")
        or usage.get("services")
        or []
    )
    if isinstance(services, str):
        return [services]
    if isinstance(services, list):
        return services
    return []

def extract_api_calls(usage):
    if not usage:
        return 0
    value = (
        usage.get("api_calls")
        or usage.get("API Calls")
        or usage.get("apiCalls")
        or 0
    )
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0

def analyze_user(username, policies, usage):
    policy_names = extract_policy_names(policies)
    services = extract_used_services(usage)
    api_calls = extract_api_calls(usage)
    analysis = {
        "username": username,
        "assigned_policies": policy_names,
        "observed_api_calls": api_calls,
        "observed_services": services,
        "analysis": {
            "broad_policies": [],
            "potentially_excessive_policies": [],
            "used_services": services,
            "unused_services": [],
            "least_privilege_status": "Needs Analysis"
        }
    }

    for policy in policy_names:
        if policy == "AdministratorAccess":
            analysis["analysis"]["broad_policies"].append(
                policy
            )
            analysis["analysis"][
                "potentially_excessive_policies"
            ].append(policy)
        elif policy.endswith("FullAccess"):
            analysis["analysis"]["broad_policies"].append(
                policy
            )
            analysis["analysis"][
                "potentially_excessive_policies"
            ].append(policy)

    if not policy_names:
        analysis["analysis"][
            "least_privilege_status"
        ] = "No Policies"
    elif not services:
        analysis["analysis"][
            "least_privilege_status"
        ] = "No Observed Usage"
    elif analysis["analysis"][
        "potentially_excessive_policies"
    ]:
        analysis["analysis"][
            "least_privilege_status"
        ] = "Potentially Over-Privileged"
    else:
        analysis["analysis"][
            "least_privilege_status"
        ] = "Requires Detailed Review"
    return analysis

def main():
    print("=" * 60)
    print("        LEAST-PRIVILEGE PERMISSION ANALYZER")
    print("=" * 60)
    policy_data = load_json(POLICY_FILE)
    usage_data = load_json(USAGE_FILE)
    if policy_data is None:
        return
    if usage_data is None:
        return
    policy_users = get_policy_users(policy_data)
    usage_users = get_usage_users(usage_data)
    all_users = set()
    all_users.update(policy_users.keys())
    all_users.update(usage_users.keys())
    results = []
    for username in sorted(all_users):
        policies = policy_users.get(
            username,
            []
        )
        usage = usage_users.get(
            username,
            {}
        )
        result = analyze_user(
            username,
            policies,
            usage
        )
        results.append(result)
        print()
        print("User:", username)
        print(
            "Assigned Policies:",
            result["assigned_policies"]
        )
        print(
            "API Calls:",
            result["observed_api_calls"]
        )
        print(
            "Services Used:",
            result["observed_services"]
        )
        print(
            "Broad Policies:",
            result["analysis"]["broad_policies"]
        )
        print(
            "Status:",
            result["analysis"]["least_privilege_status"]
        )
    report = {
        "module": "Least-Privilege Permission Analysis",
        "description":
            "Compares assigned IAM policies with observed CloudTrail usage.",
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
    print("Least-Privilege Analysis Completed")
    print(
        "Report saved to:",
        OUTPUT_FILE
    )
    print("=" * 60)

if __name__ == "__main__":
    main()