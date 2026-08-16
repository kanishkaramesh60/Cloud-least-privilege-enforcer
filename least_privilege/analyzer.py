import json
from pathlib import Path
POLICY_FILE = Path("reports/policies.json")
USAGE_FILE = Path("reports/usage_report.json")
CLOUDTRAIL_FILE = Path("reports/cloudtrail_logs.json")
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
    records = data.get("users", [])
    for item in records:
        username = item.get("username")
        policies = item.get(
            "attached_policies",
            []
        )
        inline_policies = item.get(
            "inline_policies",
            []
        )
        all_policies = policies + inline_policies
        if username:
            users[username] = all_policies
    return users
def get_usage_users(data):
    users = {}
    if not data:
        return users
    if not isinstance(data, list):
        return users
    for item in data:
        username = item.get("username")
        if username:
            users[username] = item
    return users
def get_cloudtrail_actions(data):
    user_actions = {}
    if not data:
        return user_actions
    if not isinstance(data, list):
        return user_actions
    for event in data:
        username = event.get("username")
        event_name = event.get("event_name")
        event_source = event.get("event_source")
        if not username:
            continue
        if not event_name or not event_source:
            continue
        service = event_source.split(".")[0]
        action = f"{service}:{event_name}"
        if username not in user_actions:
            user_actions[username] = set()
        user_actions[username].add(action)
    return user_actions
def analyze_user(
    username,
    policies,
    usage,
    cloudtrail_actions
):
    api_calls = usage.get(
        "total_api_calls",
        0
    )
    services = usage.get(
        "services_used",
        []
    )
    observed_actions = sorted(
        cloudtrail_actions
    )
    analysis = {
        "username": username,
        "assigned_policies": policies,
        "observed_api_calls": api_calls,
        "observed_services": services,
        "observed_iam_actions": observed_actions,
        "analysis": {
            "broad_policies": [],
            "potentially_excessive_policies": [],
            "used_services": services,
            "unused_services": [],
            "least_privilege_status":
                "Needs Analysis"
        }
    }
    for policy in policies:
        if policy == "AdministratorAccess":
            analysis["analysis"][
                "broad_policies"
            ].append(policy)
            analysis["analysis"][
                "potentially_excessive_policies"
            ].append(policy)
        elif policy.endswith("FullAccess"):
            analysis["analysis"][
                "broad_policies"
            ].append(policy)
            analysis["analysis"][
                "potentially_excessive_policies"
            ].append(policy)
    if not policies:
        status = "No Policies"
    elif not services:
        status = "No Observed Usage"
    elif analysis["analysis"][
        "potentially_excessive_policies"
    ]:
        status = "Potentially Over-Privileged"
    else:
        status = "Requires Detailed Review"
    analysis["analysis"][
        "least_privilege_status"
    ] = status
    return analysis
def main():
    print("=" * 60)
    print(
        "        LEAST-PRIVILEGE PERMISSION ANALYZER"
    )
    print("=" * 60)
    policy_data = load_json(
        POLICY_FILE
    )
    usage_data = load_json(
        USAGE_FILE
    )
    cloudtrail_data = load_json(
        CLOUDTRAIL_FILE
    )
    if policy_data is None:
        return
    if usage_data is None:
        return
    if cloudtrail_data is None:
        return
    policy_users = get_policy_users(
        policy_data
    )
    usage_users = get_usage_users(
        usage_data
    )
    cloudtrail_actions = get_cloudtrail_actions(
        cloudtrail_data
    )
    all_users = set()
    all_users.update(
        policy_users.keys()
    )
    all_users.update(
        usage_users.keys()
    )
    all_users.update(
        cloudtrail_actions.keys()
    )
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
        actions = cloudtrail_actions.get(
            username,
            set()
        )
        result = analyze_user(
            username,
            policies,
            usage,
            actions
        )
        results.append(result)
        print()
        print(
            "User:",
            username
        )
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
            "Observed IAM Actions:",
            result["observed_iam_actions"]
        )
        print(
            "Broad Policies:",
            result["analysis"]["broad_policies"]
        )
        print(
            "Status:",
            result["analysis"][
                "least_privilege_status"
            ]
        )
    report = {
        "module":
            "Least-Privilege Permission Analysis",
        "description":
            "Compares assigned IAM policies with observed CloudTrail usage and extracts observed IAM actions.",
        "users":
            results
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
    print(
        "Least-Privilege Analysis Completed"
    )
    print(
        "Report saved to:",
        OUTPUT_FILE
    )
    print("=" * 60)
if __name__ == "__main__":
    main()