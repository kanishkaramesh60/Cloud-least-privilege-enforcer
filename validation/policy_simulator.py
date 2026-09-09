import json
import boto3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

AI_POLICY_FILE = BASE_DIR / "reports" / "ai_recommended_policies.json"
OUTPUT_FILE = BASE_DIR / "reports" / "ai_policy_simulation_report.json"

PROFILE = "leastprivilege"
REGION = "ap-south-1"


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def simulate_policy(iam_client, username, policy, actions):
    print("\nIAM POLICY SIMULATION")
    print("-" * 60)
    print("Identity:", username)

    if not actions:
        print("No actions to simulate.")
        return {
            "identity": username,
            "results": [],
            "status": "NO_ACTIONS"
        }

    try:
        response = iam_client.simulate_custom_policy(
            PolicyInputList=[
                json.dumps(policy, separators=(",", ":"))
            ],
            ActionNames=actions,
            ResourceArns=["*"]
        )

        results = []

        for result in response.get("EvaluationResults", []):
            action = result.get("EvalActionName")
            decision = result.get("EvalDecision")

            print(f"{action:<45} {decision}")

            results.append({
                "action": action,
                "decision": decision
            })

        all_allowed = all(
            item["decision"] == "allowed"
            for item in results
        )

        return {
            "identity": username,
            "results": results,
            "all_required_actions_allowed": all_allowed,
            "status": "PASS" if all_allowed else "FAIL"
        }

    except Exception as error:
        print("ERROR:", error)

        return {
            "identity": username,
            "results": [],
            "status": "ERROR",
            "error": str(error)
        }


def main():

    print("=" * 60)
    print("        AI POLICY SIMULATION")
    print("=" * 60)

    if not AI_POLICY_FILE.exists():
        print("ERROR: AI recommendation file not found.")
        print(AI_POLICY_FILE)
        return

    data = load_json(AI_POLICY_FILE)

    identity = data.get("identity", {})
    username = identity.get("name", "Unknown")

    policy = data.get("recommended_policy")

    if not policy:
        print("ERROR: recommended_policy not found.")
        return

    actions = []

    for statement in policy.get("Statement", []):
        action = statement.get("Action", [])

        if isinstance(action, str):
            actions.append(action)

        elif isinstance(action, list):
            actions.extend(action)

    actions = sorted(set(actions))

    print("\nTarget Identity :", username)
    print("Risk Level      :", identity.get("risk_level"))
    print("Risk Score      :", identity.get("risk_score"))

    print("\nRecommended Actions:")
    for action in actions:
        print(" -", action)

    session = boto3.Session(
        profile_name=PROFILE,
        region_name=REGION
    )

    iam_client = session.client("iam")

    simulation = simulate_policy(
        iam_client,
        username,
        policy,
        actions
    )

    report = {
        "module": "AI Policy Simulation",
        "identity": identity,
        "policy": policy,
        "simulated_actions": actions,
        "simulation": simulation
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    print("\n" + "=" * 60)
    print("SIMULATION STATUS:", simulation["status"])
    print("=" * 60)

    print("\nReport saved:")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    main()