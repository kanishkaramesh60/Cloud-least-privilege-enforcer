import json
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
POLICY_DIR = BASE_DIR / "ci" / "policies"


def scan_policy(policy_path):

    print("=" * 60)
    print("       CI/CD LEAST PRIVILEGE POLICY SCANNER")
    print("=" * 60)

    print("\nPolicy:", policy_path)

    try:

        with open(policy_path, "r", encoding="utf-8") as f:
            policy = json.load(f)

    except Exception as error:

        print("ERROR:", error)
        return False

    risk_findings = []

    if policy.get("Version") != "2012-10-17":
        risk_findings.append(
            "Invalid or missing policy version"
        )

    statements = policy.get("Statement", [])

    if not isinstance(statements, list):
        statements = [statements]

    for index, statement in enumerate(statements):

        action = statement.get("Action")
        resource = statement.get("Resource")

        if action == "*":
            risk_findings.append(
                f"Statement {index}: Action '*' grants all actions"
            )

        elif isinstance(action, list) and "*" in action:
            risk_findings.append(
                f"Statement {index}: wildcard Action detected"
            )

        if resource == "*":
            risk_findings.append(
                f"Statement {index}: Resource '*' is unrestricted"
            )

    if risk_findings:

        print("\nHIGH-RISK POLICY DETECTED\n")

        for finding in risk_findings:
            print("[HIGH]", finding)

        print("\nCI/CD STATUS: FAIL")

        return False

    print("\nNo obvious high-risk permissions detected.")
    print("\nCI/CD STATUS: PASS")

    return True


def main():

    if len(sys.argv) < 2:

        print(
            "Usage: python ci\\ci_policy_scanner.py "
            "ci\\policies\\test_policy.json"
        )

        sys.exit(1)

    policy_path = Path(sys.argv[1])

    if not policy_path.exists():

        print("ERROR: Policy file not found.")
        sys.exit(1)

    success = scan_policy(policy_path)

    if success:
        sys.exit(0)

    sys.exit(1)


if __name__ == "__main__":
    main()