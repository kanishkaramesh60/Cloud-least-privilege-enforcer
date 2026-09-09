import json
import subprocess
import boto3
import ollama
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

AI_POLICY_FILE = BASE_DIR / "reports" / "ai_recommended_policies.json"
OUTPUT_FILE = BASE_DIR / "reports" / "ai_retry_report.json"

PROFILE = "leastprivilege"
REGION = "ap-south-1"

MODEL = "llama3.2:3b"
MAX_ATTEMPTS = 3


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def validate_policy(policy):

    temp_file = BASE_DIR / "validation" / "retry_policy.json"

    save_json(temp_file, policy)

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
            "error": "Invalid AWS response"
        }

    findings = response.get("findings", [])

    return {
        "status": "PASS" if not findings else "FAIL",
        "findings": findings
    }


def get_actions(policy):

    actions = []

    for statement in policy.get("Statement", []):

        action = statement.get("Action", [])

        if isinstance(action, str):
            actions.append(action)

        elif isinstance(action, list):
            actions.extend(action)

    return sorted(set(actions))


def simulate_policy(policy, actions):

    session = boto3.Session(
        profile_name=PROFILE,
        region_name=REGION
    )

    iam = session.client("iam")

    try:

        response = iam.simulate_custom_policy(
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


def regenerate_policy(previous_policy, findings, identity):

    prompt = f"""
You are an AWS IAM least-privilege security engineer.

Correct the following IAM policy.

IDENTITY:
{json.dumps(identity, indent=2)}

CURRENT POLICY:
{json.dumps(previous_policy, indent=2)}

VERIFICATION FINDINGS:
{json.dumps(findings, indent=2)}

Generate a corrected IAM identity policy.

Rules:
1. Return ONLY valid JSON.
2. Use Version 2012-10-17.
3. Include Statement as a list.
4. Every statement must contain Effect and Action.
5. Never use Action "*".
6. Keep permissions as narrow as possible.
7. Do not invent unrelated permissions.
8. Preserve required permissions unless a verification finding requires changing them.

Return exactly:

{{
    "Version": "2012-10-17",
    "Statement": [
        {{
            "Effect": "Allow",
            "Action": [],
            "Resource": "*"
        }}
    ]
}}
"""

    response = ollama.chat(
        model=MODEL,
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ],
        options={
            "temperature": 0,
            "num_predict": 500
        },
        format="json"
    )

    content = response["message"]["content"]

    return json.loads(content)


def main():

    print("=" * 65)
    print("          AI CLOSED-LOOP REMEDIATION")
    print("=" * 65)

    if not AI_POLICY_FILE.exists():

        print("ERROR: AI policy file not found.")
        return

    data = load_json(AI_POLICY_FILE)

    identity = data.get("identity", {})
    policy = data.get("recommended_policy")

    if not policy:

        print("ERROR: recommended_policy missing.")
        return

    attempts = []

    for attempt in range(1, MAX_ATTEMPTS + 1):

        print()
        print("=" * 65)
        print(f"ATTEMPT {attempt} OF {MAX_ATTEMPTS}")
        print("=" * 65)

        print("\n1. ACCESS ANALYZER")

        analyzer = validate_policy(policy)

        print("Status:", analyzer["status"])

        if analyzer["findings"]:

            for finding in analyzer["findings"]:
                print(
                    finding.get("findingType"),
                    finding.get("issueCode")
                )

        print("\n2. IAM POLICY SIMULATOR")

        actions = get_actions(policy)

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

        verification_passed = (
            analyzer["status"] == "PASS"
            and
            simulator["status"] == "PASS"
        )

        attempt_record = {
            "attempt": attempt,
            "policy": policy,
            "access_analyzer": analyzer,
            "iam_simulator": simulator
        }

        if verification_passed:

            print()
            print("VERIFICATION PASSED")

            attempt_record["result"] = "PASS"
            attempts.append(attempt_record)

            final_status = "VERIFIED"

            break

        print()
        print("VERIFICATION FAILED")

        attempt_record["result"] = "FAIL"

        attempts.append(attempt_record)

        if attempt == MAX_ATTEMPTS:

            print("Maximum attempts reached.")
            final_status = "BLOCKED"
            break

        findings = {
            "access_analyzer": analyzer,
            "iam_simulator": simulator
        }

        print()
        print("Sending verification findings to Ollama...")
        print("Generating corrected policy...")

        try:

            policy = regenerate_policy(
                policy,
                findings,
                identity
            )

            print("Corrected policy generated.")

        except Exception as error:

            print("AI regeneration failed:", error)

            final_status = "BLOCKED"
            break

    report = {
        "module": "AI Closed-Loop Remediation",
        "identity": identity,
        "max_attempts": MAX_ATTEMPTS,
        "attempts": attempts,
        "final_status": final_status,
        "deployment_allowed": final_status == "VERIFIED"
    }

    save_json(
        OUTPUT_FILE,
        report
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