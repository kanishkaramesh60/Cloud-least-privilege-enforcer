import json
from pathlib import Path


ACTIONS_FILE = Path("reports/observed_actions.json")
RISK_FILE = Path("reports/risk_report.json")
PERMISSION_FILE = Path("reports/permission_analysis.json")

OUTPUT_FILE = Path("reports/recommended_policy.json")


def load_json(path):

    if not path.exists():
        print(f"ERROR: {path} not found.")
        return None

    try:

        with open(
            path,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except json.JSONDecodeError:

        print(f"ERROR: Invalid JSON: {path}")

        return None


def get_users(data):

    if not isinstance(data, dict):
        return []

    users = data.get("users", [])

    if isinstance(users, list):
        return users

    return []


def get_username(item):

    return (
        item.get("username")
        or item.get("Username")
        or item.get("user")
        or item.get("User")
    )


def get_actions_map(data):

    actions_map = {}

    for item in get_users(data):

        username = get_username(item)

        if not username:
            continue

        actions = item.get(
            "observed_actions",
            []
        )

        if not isinstance(actions, list):
            actions = []

        actions_map[username] = actions

    return actions_map


def get_risk_map(data):

    risk_map = {}

    for item in get_users(data):

        username = get_username(item)

        if not username:
            continue

        risk_map[username] = {
            "risk_score": item.get(
                "risk_score",
                0
            ),
            "risk_level": item.get(
                "risk_level",
                "UNKNOWN"
            )
        }

    return risk_map


def get_permission_map(data):

    permission_map = {}

    for item in get_users(data):

        username = get_username(item)

        if not username:
            continue

        analysis = item.get(
            "analysis",
            {}
        )

        permission_map[username] = {
            "assigned_policies": item.get(
                "assigned_policies",
                []
            ),
            "broad_policies": analysis.get(
                "broad_policies",
                []
            ),
            "status": analysis.get(
                "least_privilege_status",
                "UNKNOWN"
            )
        }

    return permission_map


def create_policy(actions):

    unique_actions = sorted(
        set(actions)
    )

    if not unique_actions:
        return None

    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": unique_actions,
                "Resource": "*"
            }
        ]
    }


def main():

    print("=" * 60)
    print("       ML-BASED LEAST-PRIVILEGE POLICY GENERATOR")
    print("=" * 60)

    action_data = load_json(
        ACTIONS_FILE
    )

    risk_data = load_json(
        RISK_FILE
    )

    permission_data = load_json(
        PERMISSION_FILE
    )

    if action_data is None:
        return

    if risk_data is None:
        return

    if permission_data is None:
        return

    actions_map = get_actions_map(
        action_data
    )

    risk_map = get_risk_map(
        risk_data
    )

    permission_map = get_permission_map(
        permission_data
    )

    all_users = set()

    all_users.update(
        actions_map.keys()
    )

    all_users.update(
        risk_map.keys()
    )

    all_users.update(
        permission_map.keys()
    )

    results = []

    for username in sorted(all_users):

        observed_actions = actions_map.get(
            username,
            []
        )

        risk = risk_map.get(
            username,
            {}
        )

        permissions = permission_map.get(
            username,
            {}
        )

        risk_score = risk.get(
            "risk_score",
            0
        )

        risk_level = risk.get(
            "risk_level",
            "UNKNOWN"
        )

        assigned_policies = permissions.get(
            "assigned_policies",
            []
        )

        broad_policies = permissions.get(
            "broad_policies",
            []
        )

        recommended_policy = create_policy(
            observed_actions
        )

        if recommended_policy:

            status = (
                "Least-privilege policy generated"
            )

        else:

            status = (
                "Manual review required - "
                "no observed actions"
            )

        result = {
            "username": username,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "current_policies": assigned_policies,
            "current_broad_policies": broad_policies,
            "observed_actions": observed_actions,
            "recommended_actions": observed_actions,
            "recommended_policy": recommended_policy,
            "status": status
        }

        results.append(result)

        print()
        print("User:", username)
        print(
            "Risk Score:",
            risk_score
        )
        print(
            "Risk Level:",
            risk_level
        )
        print(
            "Current Broad Policies:",
            broad_policies
        )
        print(
            "Observed Actions:",
            observed_actions
        )
        print(
            "Recommended Actions:",
            observed_actions
        )
        print(
            "Status:",
            status
        )
    report = {
        "module": (
            "ML-Based Least-Privilege "
            "Policy Recommendation"
        ),
        "description": (
            "Generates IAM policies using "
            "observed CloudTrail actions "
            "and ML-based IAM risk scores."
        ),
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
    print("Policy Recommendation Completed")
    print(
        "Report saved to:",
        OUTPUT_FILE
    )
    print("=" * 60)
if __name__ == "__main__":
    main()