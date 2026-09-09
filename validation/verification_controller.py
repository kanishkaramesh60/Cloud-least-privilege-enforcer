import json
import subprocess
import boto3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

AI_POLICY_FILE = BASE_DIR / "reports" / "ai_recommended_policies.json"
VALIDATION_FILE = BASE_DIR / "reports" / "policy_validation_report.json"
SIMULATION_FILE = BASE_DIR / "reports" / "ai_policy_simulation_report.json"
OUTPUT_FILE = BASE_DIR / "reports" / "verification_controller_report.json"

PROFILE = "leastprivilege"
REGION = "ap-south-1"

MAX_ATTEMPTS = 3


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_with_access_analyzer(policy):
    temp_file = BASE_DIR / "validation" / "controller_policy.json"

    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(policy, f, indent=4)

    command = [
        "aws",
        "accessanalyzer",
        "validate-policy",
        "--policy-document",
        f"file://{temp_file}",
        "--policy-type",
        "IDENTITY_POLICY",
        "--profile",
        PROFILE,
        "--region",
        REGION,
        "--output",
        "json"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    try:
        temp_file.unlink()
    except Exception:
        pass

    if result.returncode != 0:
        return {
            "status": "ERROR",
            "findings": [],
            "error": result.stderr.strip()
        }

    try:
        response = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {
            "status": "ERROR",
            "findings": [],
            "error": "Unable to parse AWS response"
        }

    findings = response.get("findings", [])

    return {
        "status": "PASS" if not findings else "FAIL",
        "findings": findings
    }


def simulate_policy(policy, actions):

    session = boto3.Session(
        profile_name=PROFILE,
        region_name=REGION
    )

    iam_client = session.client("iam")

    try:

        response = iam_client.simulate_custom_policy(
            PolicyInputList=[
                json.dumps(policy, separators=(",", ":"))
            ],
            ActionNames=actions,
            ResourceArns=["*"]
        )

        results = []

        for item in response.get("EvaluationResults", []):

            results.append({
                "action": item.get("EvalActionName"),
                "decision": item.get("EvalDecision")
            })

        all_allowed = all(
            item["decision"] == "allowed"
            for item in results
        )

        return {
            "status": "PASS" if all_allowed else "FAIL",
            "results": results
        }

    except Exception as error:

        return {
            "status": "ERROR",
            "results": [],
            "error": str(error)
        }


def main():

    print("=" * 65)
    print("        CLOUD LEAST PRIVILEGE VERIFICATION CONTROLLER")
    print("=" * 65)

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

    attempts = []

    print()
    print("Identity   :", username)
    print("Risk Level :", identity.get("risk_level"))
    print("Risk Score :", identity.get("risk_score"))

    print()
    print("Maximum verification attempts:", MAX_ATTEMPTS)

    for attempt in range(1, MAX_ATTEMPTS + 1):

        print()
        print("=" * 65)
        print(f"VERIFICATION ATTEMPT {attempt}")
        print("=" * 65)

        # --------------------------------------------------
        # ACCESS ANALYZER
        # --------------------------------------------------

        print()
        print("1. AWS ACCESS ANALYZER")
        print("-" * 65)

        analyzer = validate_with_access_analyzer(policy)

        print("Status:", analyzer["status"])

        if analyzer["findings"]:

            for finding in analyzer["findings"]:

                print(
                    "Finding:",
                    finding.get("findingType"),
                    finding.get("issueCode")
                )

        # --------------------------------------------------
        # IAM SIMULATOR
        # --------------------------------------------------

        print()
        print("2. IAM POLICY SIMULATOR")
        print("-" * 65)

        simulator = simulate_policy(
            policy,
            actions
        )

        print("Status:", simulator["status"])

        for result in simulator.get("results", []):

            print(
                result["action"],
                "->",
                result["decision"]
            )

        # --------------------------------------------------
        # FINAL DECISION
        # --------------------------------------------------

        if (
            analyzer["status"] == "PASS"
            and
            simulator["status"] == "PASS"
        ):

            print()
            print("=" * 65)
            print("VERIFICATION RESULT: PASS")
            print("=" * 65)

            attempts.append({
                "attempt": attempt,
                "access_analyzer": analyzer,
                "iam_simulator": simulator,
                "result": "PASS"
            })

            final_status = "VERIFIED"

            break

        else:

            print()
            print("VERIFICATION FAILED")

            attempts.append({
                "attempt": attempt,
                "access_analyzer": analyzer,
                "iam_simulator": simulator,
                "result": "FAIL"
            })

            final_status = "FAILED"

            print()
            print(
                "Policy would need AI regeneration before another attempt."
            )

            break

    report = {

        "module":
            "Cloud Least Privilege Verification Controller",

        "identity":
            identity,

        "max_attempts":
            MAX_ATTEMPTS,

        "attempts":
            attempts,

        "final_status":
            final_status,

        "deployment_allowed":
            final_status == "VERIFIED"
    }

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            report,
            f,
            indent=4
        )

    print()
    print("=" * 65)
    print("FINAL STATUS:", final_status)
    print(
        "DEPLOYMENT ALLOWED:",
        final_status == "VERIFIED"
    )
    print("=" * 65)

    print()
    print("Report saved:")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    main()