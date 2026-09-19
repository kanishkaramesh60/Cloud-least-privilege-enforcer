import json
import subprocess
import boto3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

AI_POLICY_FILE = BASE_DIR / "reports" / "ai_recommended_policies.json"
VALIDATION_FILE = BASE_DIR / "reports" / "policy_validation_report.json"
SIMULATION_FILE = BASE_DIR / "reports" / "ai_policy_simulation_report.json"
OBSERVED_ACTIONS_FILE = BASE_DIR / "reports" / "observed_actions.json"
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

        all_allowed = (
            len(results) == len(actions)
            and
            all(
                item["decision"] == "allowed"
                for item in results
            )
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


def get_observed_actions(username):
    observed_data = load_json(OBSERVED_ACTIONS_FILE)

    for user in observed_data.get("users", []):
        if user.get("username") == username:
            return sorted(
                set(user.get("observed_actions", []))
            )

    return []


def compare_observed_with_policy(policy, observed_actions):
    policy_actions = []

    for statement in policy.get("Statement", []):
        action = statement.get("Action", [])

        if isinstance(action, str):
            policy_actions.append(action)

        elif isinstance(action, list):
            policy_actions.extend(action)

    policy_actions = sorted(set(policy_actions))

    missing_actions = [
        action
        for action in observed_actions
        if action not in policy_actions
    ]

    return {
        "observed_actions": observed_actions,
        "policy_actions": policy_actions,
        "missing_actions": missing_actions,
        "status": "PASS" if not missing_actions else "FAIL"
    }


def main():

    print("=" * 65)
    print("        CLOUD LEAST PRIVILEGE VERIFICATION CONTROLLER")
    print("=" * 65)

    # ------------------------------------------------------------
    # CHECK REQUIRED FILES
    # ------------------------------------------------------------

    if not AI_POLICY_FILE.exists():
        print()
        print("ERROR: AI recommendation file not found.")
        print(AI_POLICY_FILE)
        return

    if not OBSERVED_ACTIONS_FILE.exists():
        print()
        print("ERROR: observed actions file not found.")
        print(OBSERVED_ACTIONS_FILE)
        return

    # ------------------------------------------------------------
    # LOAD AI POLICY
    # ------------------------------------------------------------

    data = load_json(AI_POLICY_FILE)

    identity = data.get("identity", {})

    username = identity.get(
        "name",
        "Unknown"
    )

    policy = data.get(
        "recommended_policy"
    )

    if not policy:
        print()
        print("ERROR: recommended_policy not found.")
        return

    # ------------------------------------------------------------
    # LOAD INDEPENDENT CLOUDTRAIL OBSERVED ACTIONS
    # ------------------------------------------------------------

    actions = get_observed_actions(username)

    if not actions:
        print()
        print(
            "ERROR: No observed CloudTrail actions found "
            "for identity:",
            username
        )
        return

    # ------------------------------------------------------------
    # DISPLAY IDENTITY INFORMATION
    # ------------------------------------------------------------

    print()
    print("Identity   :", username)
    print(
        "Risk Level :",
        identity.get("risk_level")
    )
    print(
        "Risk Score :",
        identity.get("risk_score")
    )

    print()
    print("Observed CloudTrail actions:")

    for action in actions:
        print(" -", action)

    print()
    print(
        "Maximum verification attempts:",
        MAX_ATTEMPTS
    )

    attempts = []

    final_status = "FAILED"

    # ------------------------------------------------------------
    # VERIFICATION LOOP
    # ------------------------------------------------------------

    for attempt in range(
        1,
        MAX_ATTEMPTS + 1
    ):

        print()
        print("=" * 65)
        print(
            f"VERIFICATION ATTEMPT {attempt}"
        )
        print("=" * 65)

        # --------------------------------------------------------
        # STEP 1: COMPARE OBSERVED ACTIONS WITH RECOMMENDED POLICY
        # --------------------------------------------------------

        print()
        print(
            "1. OBSERVED ACTION POLICY COVERAGE"
        )
        print("-" * 65)

        coverage = compare_observed_with_policy(
            policy,
            actions
        )

        print(
            "Status:",
            coverage["status"]
        )

        if coverage["missing_actions"]:

            print()
            print(
                "Missing observed actions:"
            )

            for action in coverage[
                "missing_actions"
            ]:
                print(
                    " -",
                    action
                )

        # --------------------------------------------------------
        # STEP 2: AWS ACCESS ANALYZER
        # --------------------------------------------------------

        print()
        print(
            "2. AWS ACCESS ANALYZER"
        )
        print("-" * 65)

        analyzer = validate_with_access_analyzer(
            policy
        )

        print(
            "Status:",
            analyzer["status"]
        )

        if analyzer["findings"]:

            for finding in analyzer["findings"]:

                print(
                    "Finding:",
                    finding.get(
                        "findingType"
                    ),
                    finding.get(
                        "issueCode"
                    )
                )

        # --------------------------------------------------------
        # STEP 3: IAM POLICY SIMULATOR
        # --------------------------------------------------------

        print()
        print(
            "3. IAM POLICY SIMULATOR"
        )
        print("-" * 65)

        simulator = simulate_policy(
            policy,
            actions
        )

        print(
            "Status:",
            simulator["status"]
        )

        for result in simulator.get(
            "results",
            []
        ):

            print(
                result["action"],
                "->",
                result["decision"]
            )

        # --------------------------------------------------------
        # FINAL VERIFICATION DECISION
        # --------------------------------------------------------

        if (
            coverage["status"] == "PASS"
            and
            analyzer["status"] == "PASS"
            and
            simulator["status"] == "PASS"
        ):

            print()
            print("=" * 65)
            print(
                "VERIFICATION RESULT: PASS"
            )
            print("=" * 65)

            attempts.append({

                "attempt": attempt,

                "observed_action_coverage":
                    coverage,

                "access_analyzer":
                    analyzer,

                "iam_simulator":
                    simulator,

                "result": "PASS"
            })

            final_status = "VERIFIED"

            break

        else:

            print()
            print(
                "VERIFICATION FAILED"
            )

            attempts.append({

                "attempt": attempt,

                "observed_action_coverage":
                    coverage,

                "access_analyzer":
                    analyzer,

                "iam_simulator":
                    simulator,

                "result": "FAIL"
            })

            final_status = "FAILED"

            print()
            print(
                "Policy requires review/regeneration "
                "before another verification attempt."
            )

            break

    # ------------------------------------------------------------
    # DEPLOYMENT DECISION
    # ------------------------------------------------------------

    ready_for_deployment_review = (
        final_status == "VERIFIED"
    )

    # ------------------------------------------------------------
    # FINAL REPORT
    # ------------------------------------------------------------

    report = {

        "module":
            "Cloud Least Privilege Verification Controller",

        "identity":
            identity,

        "verification_basis": {

            "source":
                "CloudTrail observed actions",

            "observed_actions":
                actions
        },

        "max_attempts":
            MAX_ATTEMPTS,

        "attempts":
            attempts,

        "final_status":
            final_status,

        "ready_for_deployment_review":
            ready_for_deployment_review,

        "deployment_performed":
            False
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

    # ------------------------------------------------------------
    # FINAL OUTPUT
    # ------------------------------------------------------------

    print()
    print("=" * 65)
    print(
        "FINAL STATUS:",
        final_status
    )

    print(
        "READY FOR DEPLOYMENT REVIEW:",
        ready_for_deployment_review
    )

    print(
        "DEPLOYMENT PERFORMED:",
        False
    )

    print("=" * 65)

    print()
    print(
        "Report saved:"
    )

    print(
        OUTPUT_FILE
    )


if __name__ == "__main__":
    main()