import json
from pathlib import Path
ANALYSIS_FILE = Path(
    "reports/permission_analysis.json"
)
OUTPUT_FILE = Path(
    "reports/recommended_policy.json"
)
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
        print(
            f"ERROR: Invalid JSON file: {path}"
        )
        return None
def create_policy(actions):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": actions,
                "Resource": "*"
            }
        ]
    }
def main():
    print("=" * 60)
    print(
        "       LEAST-PRIVILEGE POLICY GENERATOR"
    )
    print("=" * 60)
    data = load_json(
        ANALYSIS_FILE
    )
    if data is None:
        return
    users = data.get(
        "users",
        []
    )
    recommendations = []
    for user in users:
        username = user.get(
            "username"
        )
        current_policies = user.get(
            "assigned_policies",
            []
        )
        observed_actions = user.get(
            "observed_iam_actions",
            []
        )
        broad_policies = user.get(
            "analysis",
            {}
        ).get(
            "broad_policies",
            []
        )
        print()
        print(
            "User:",
            username
        )
        print(
            "Current Policies:",
            current_policies
        )
        print(
            "Broad Policies:",
            broad_policies
        )
        print(
            "Observed IAM Actions:",
            observed_actions
        )
        if not observed_actions:
            recommended_actions = []
            status = (
                "Manual review required"
            )
        else:
            recommended_actions = sorted(
                set(observed_actions)
            )
            status = (
                "Least-privilege policy generated"
            )
        policy = create_policy(
            recommended_actions
        )
        recommendation = {
            "username":
                username,
            "current_policies":
                current_policies,
            "broad_policies":
                broad_policies,
            "observed_iam_actions":
                observed_actions,
            "recommended_actions":
                recommended_actions,
            "recommended_policy":
                policy,
            "status":
                status
        }
        recommendations.append(
            recommendation
        )
        print(
            "Recommended Actions:",
            recommended_actions
        )
        print(
            "Status:",
            status
        )
    report = {
        "module":
            "Policy Recommendation Engine",
        "description":
            "Generates a least-privilege IAM policy from observed CloudTrail IAM actions.",
        "recommendations":
            recommendations
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
        "Policy Recommendation Completed"
    )
    print(
        "Report saved to:",
        OUTPUT_FILE
    )
    print("=" * 60)
if __name__ == "__main__":
    main()