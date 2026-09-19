import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = (
    BASE_DIR
    / "ci"
    / "policies"
    / "overprivileged_test_policy.json"
)

OUTPUT_FILE = (
    BASE_DIR
    / "reports"
    / "ci_remediation_test_report.json"
)


def load_json(path):

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def build_least_privilege_policy(observed_actions):

    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": observed_actions,
                "Resource": "*"
            }
        ]
    }


def main():

    print()
    print("=" * 65)
    print("        LEAST PRIVILEGE REMEDIATION TEST")
    print("=" * 65)

    data = load_json(INPUT_FILE)

    identity = data["identity"]
    current_policies = data["current_policies"]
    observed_actions = data["observed_actions"]
    excessive_permissions = data["excessive_permissions"]

    print()
    print("Identity :", identity)

    print()
    print("Current Policies:")
    for policy in current_policies:
        print(" -", policy)

    print()
    print("Excessive Permissions:")
    for permission in excessive_permissions:
        print(" -", permission)

    print()
    print("Observed Actions:")
    for action in observed_actions:
        print(" -", action)

    # --------------------------------------------------------
    # BUILD LEAST-PRIVILEGE POLICY
    # --------------------------------------------------------

    recommended_policy = build_least_privilege_policy(
        observed_actions
    )

    print()
    print("=" * 65)
    print("        RECOMMENDED LEAST-PRIVILEGE POLICY")
    print("=" * 65)

    print(
        json.dumps(
            recommended_policy,
            indent=4
        )
    )

    # --------------------------------------------------------
    # SAFETY CHECK
    # --------------------------------------------------------

    actions = recommended_policy["Statement"][0]["Action"]

    wildcard_present = "*" in actions

    if wildcard_present:
        status = "FAILED"
    else:
        status = "PASS"

    # --------------------------------------------------------
    # REPORT
    # --------------------------------------------------------

    report = {
        "module":
            "Synthetic Least Privilege Remediation Test",

        "identity":
            identity,

        "current_policies":
            current_policies,

        "excessive_permissions":
            excessive_permissions,

        "observed_actions":
            observed_actions,

        "recommended_policy":
            recommended_policy,

        "wildcard_action":
            wildcard_present,

        "status":
            status,

        "aws_changes_performed":
            False
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
    print("=" * 65)
    print("REMEDIATION TEST STATUS:", status)
    print("AWS CHANGES PERFORMED   : False")
    print("=" * 65)

    print()
    print("Report saved:")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    main()