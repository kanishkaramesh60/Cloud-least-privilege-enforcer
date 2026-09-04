import json
from pathlib import Path
INPUT_FILE = Path("reports/observed_actions.json")
PERMISSION_FILE = Path("reports/permission_analysis.json")
OUTPUT_FILE = Path("reports/recommended_policy.json")
def load_json(path):
    if not path.exists():
        print(f"ERROR: {path} not found.")
        return None
    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)
    except json.JSONDecodeError:
        print(f"ERROR: Invalid JSON: {path}")
        return None
def get_actions(data):
    if not data:
        return []
    actions = data.get("observed_actions", [])
    if not isinstance(actions, list):
        return []
    return sorted(set(actions))
def main():
    print("=" * 60)
    print("       LEAST-PRIVILEGE POLICY GENERATOR")
    print("=" * 60)
    observed_data = load_json(INPUT_FILE)
    permission_data = load_json(PERMISSION_FILE)
    if observed_data is None:
        return
    if isinstance(observed_data, dict):
        users = (
            observed_data.get("users")
            or observed_data.get("results")
            or []
        )
    elif isinstance(observed_data, list):
        users = observed_data
    else:
        users = []
    permission_users = {}
    if permission_data:
        for user in permission_data.get("users", []):
            if isinstance(user, dict):
                username = user.get("username")
                if username:
                    permission_users[username] = user
    results = []
    for user in users:
        if not isinstance(user, dict):
            continue
        username = (
            user.get("username")
            or "Unknown"
        )
        actions = get_actions(user)
        permission_info = permission_users.get(
            username,
            {}
        )
        assigned_policies = permission_info.get(
            "assigned_policies",
            []
        )
        broad_policies = (
            permission_info
            .get("analysis", {})
            .get("broad_policies", [])
        )
        statements = []
        if actions:
            statement = {
                "Effect": "Allow",
                "Action": actions,
                "Resource": "*"
            }
            statements.append(statement)
            status = "Policy generated"
        else:
            status = "Manual review required"
        recommended_policy = {
            "Version": "2012-10-17",
            "Statement": statements
        }
        result = {
            "username": username,
            "current_policies":
                assigned_policies,
            "broad_policies":
                broad_policies,
            "observed_actions":
                actions,
            "recommended_policy":
                recommended_policy,
            "status":
                status
        }
        results.append(result)
        print()
        print("User:", username)
        print(
            "Current Policies:",
            assigned_policies
        )
        print(
            "Broad Policies:",
            broad_policies
        )
        print(
            "Observed Actions:",
            actions
        )
        print(
            "Status:",
            status
        )
        if actions:
            print("Recommended IAM Actions:")
            for action in actions:
                print("  ", action)
    report = {
        "module":
            "Least-Privilege Policy Recommendation",
        "description":
            "Generates IAM policies from observed CloudTrail actions.",
        "users":
            results
    }
    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )
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
    print("Policy Recommendation Completed")
    print(
        "Report saved to:",
        OUTPUT_FILE
    )
    print("=" * 60)
if __name__ == "__main__":
    main()