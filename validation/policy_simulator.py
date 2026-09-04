import json
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, BotoCoreError


BASE_DIR = Path(__file__).resolve().parent.parent

POLICY_FILE = BASE_DIR / "reports" / "recommended_policy.json"
OUTPUT_FILE = BASE_DIR / "reports" / "policy_simulation_report.json"

PROFILE = "leastprivilege"
REGION = "ap-south-1"


def load_json(path):
    if not path.exists():
        print(f"ERROR: File not found: {path}")
        return None

    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)

    except json.JSONDecodeError as error:
        print(f"ERROR: Invalid JSON in {path}")
        print(error)
        return None


def create_iam_client():
    session = boto3.Session(
        profile_name=PROFILE,
        region_name=REGION
    )

    return session.client("iam")


def simulate_policy(iam_client, policy_document, actions):

    policy_string = json.dumps(
        policy_document,
        separators=(",", ":")
    )

    try:
        response = iam_client.simulate_custom_policy(
            PolicyInputList=[
                policy_string
            ],
            ActionNames=actions,
            ResourceArns=["*"]
        )

        return {
            "success": True,
            "data": response
        }

    except (ClientError, BotoCoreError) as error:

        return {
            "success": False,
            "error": str(error)
        }


def main():

    print("=" * 70)
    print("             IAM POLICY SIMULATION")
    print("=" * 70)

    data = load_json(POLICY_FILE)

    if data is None:
        return

    try:
        iam_client = create_iam_client()

    except Exception as error:
        print("ERROR: Could not create IAM client.")
        print(error)
        return

    report = {
        "module": "IAM Policy Simulation",
        "description": (
            "Simulates recommended IAM policies against observed "
            "actions without attaching the policies."
        ),
        "users": []
    }

    for user in data.get("users", []):

        username = user.get("username", "Unknown")

        policy = user.get("recommended_policy")

        actions = user.get("observed_actions", [])

        print()
        print("-" * 70)
        print("Identity:", username)

        if not policy:
            print("No recommended policy.")
            continue

        if not actions:
            print("No observed actions.")
            continue

        print("Actions being simulated:")

        for action in actions:
            print("   ", action)

        simulation = simulate_policy(
            iam_client,
            policy,
            actions
        )

        if not simulation["success"]:

            print("Simulation FAILED")
            print(simulation["error"])

            report["users"].append({
                "username": username,
                "status": "FAILED",
                "error": simulation["error"]
            })

            continue

        results = simulation["data"].get(
            "EvaluationResults",
            []
        )

        allowed = []
        denied = []
        other = []

        for result in results:

            action = result.get("EvalActionName")

            decision = result.get("EvalDecision")

            print(
                "Action:",
                action,
                "| Decision:",
                decision
            )

            if decision == "allowed":

                allowed.append(action)

            elif decision in [
                "explicitDeny",
                "implicitDeny"
            ]:

                denied.append(action)

            else:

                other.append({
                    "action": action,
                    "decision": decision
                })

        total = len(actions)

        allowed_count = len(allowed)

        denied_count = len(denied)

        if denied_count == 0 and total > 0:

            verification_status = "PASS"

        else:

            verification_status = "FAIL"

        report["users"].append({

            "username": username,

            "status": "SUCCESS",

            "verification_status": verification_status,

            "total_actions": total,

            "allowed_count": allowed_count,

            "denied_count": denied_count,

            "allowed_actions": allowed,

            "denied_actions": denied,

            "other_results": other,

            "evaluation_results": results
        })

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
            indent=4,
            default=str
        )

    print()
    print("=" * 70)
    print("POLICY SIMULATION COMPLETED")
    print("Report saved to:", OUTPUT_FILE)
    print("=" * 70)


if __name__ == "__main__":
    main()