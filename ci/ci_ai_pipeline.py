import json
import subprocess
import sys
from pathlib import Path

import boto3


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

POLICY_FILE = BASE_DIR / "ci" / "policies" / "test_policy.json"
REQUIRED_ACTIONS_FILE = BASE_DIR / "ci" / "policies" / "required_actions.json"

AI_POLICY_FILE = BASE_DIR / "validation" / "ai_policy.json"
REPORT_FILE = BASE_DIR / "reports" / "ci_ai_pipeline_report.json"

PROFILE = "leastprivilege"
REGION = "ap-south-1"

OLLAMA_MODEL = "llama3.2:3b"

MAX_ATTEMPTS = 3


# ============================================================
# JSON FUNCTIONS
# ============================================================

def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


# ============================================================
# STEP 1 - CI POLICY SCANNER
# ============================================================

def run_policy_scanner():

    print("\n" + "=" * 60)
    print("STEP 1 - CI/CD POLICY SCANNER")
    print("=" * 60)

    result = subprocess.run(
        [
            sys.executable,
            str(BASE_DIR / "ci" / "ci_policy_scanner.py"),
            str(POLICY_FILE)
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    print(result.stdout)

    if result.stderr:
        print(result.stderr)

    return result.returncode == 0


# ============================================================
# FIND POLICY PROBLEMS
# ============================================================

def analyze_policy(policy):

    findings = []

    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for index, statement in enumerate(statements):

        actions = statement.get("Action", [])

        resources = statement.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]

        if isinstance(resources, str):
            resources = [resources]

        if "*" in actions:

            findings.append({
                "severity": "HIGH",
                "statement": index,
                "issue": "Wildcard Action grants all AWS actions"
            })

        if "*" in resources:

            findings.append({
                "severity": "HIGH",
                "statement": index,
                "issue": "Wildcard Resource is unrestricted"
            })

    return findings


# ============================================================
# STEP 2 - AI REMEDIATION
# ============================================================

def call_ollama(policy, findings, required_actions):

    print("\n" + "=" * 60)
    print("STEP 2 - AI POLICY REMEDIATION")
    print("=" * 60)

    prompt = f"""
You are an AWS IAM least-privilege security remediation engine.

You must transform the supplied IAM policy into a least-privilege
identity policy.

ORIGINAL POLICY:
{json.dumps(policy, indent=2)}

SECURITY FINDINGS:
{json.dumps(findings, indent=2)}

APPLICATION REQUIRED ACTIONS:
{json.dumps(required_actions, indent=2)}

STRICT REQUIREMENTS:

1. Only allow actions from APPLICATION REQUIRED ACTIONS.
2. Remove Action "*".
3. Never generate Action "*".
4. Never add permissions that are not required.
5. Preserve the AWS IAM policy Version.
6. Use Effect "Allow".
7. Use explicit actions.
8. Resource "*" may be used only when resource-level
   restriction is not provided or not possible.
9. Do not invent additional AWS services.
10. Return ONLY valid JSON.
11. Do not use Markdown.
12. Output must contain:
    Version
    Statement
"""

    try:

        result = subprocess.run(
            [
                "ollama",
                "run",
                OLLAMA_MODEL,
                prompt
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120
        )

        if result.returncode != 0:

            print("OLLAMA ERROR:")
            print(result.stderr)

            return None

        output = result.stdout.strip()

        # Remove possible Markdown fences
        if output.startswith("```json"):
            output = output[7:]

        elif output.startswith("```"):
            output = output[3:]

        if output.endswith("```"):
            output = output[:-3]

        output = output.strip()

        # Find JSON boundaries if Ollama adds extra text
        start = output.find("{")
        end = output.rfind("}")

        if start == -1 or end == -1:

            print("ERROR: AI did not return valid JSON.")

            return None

        output = output[start:end + 1]

        ai_policy = json.loads(output)

        print("\nAI GENERATED POLICY:")
        print("-" * 60)
        print(json.dumps(ai_policy, indent=4))

        return ai_policy

    except subprocess.TimeoutExpired:

        print("ERROR: Ollama timed out.")

        return None

    except json.JSONDecodeError as error:

        print("ERROR: AI returned invalid JSON.")
        print(error)

        return None

    except Exception as error:

        print("AI ERROR:", error)

        return None


# ============================================================
# DETERMINISTIC AI GUARDRAILS
# ============================================================

def apply_guardrails(policy, required_actions):

    if not isinstance(policy, dict):
        return None, ["Policy is not a JSON object."]

    findings = []

    if policy.get("Version") != "2012-10-17":

        findings.append(
            "Invalid or missing IAM policy version."
        )

        policy["Version"] = "2012-10-17"

    statements = policy.get("Statement")

    if not statements:

        return None, ["Policy contains no Statement."]

    if isinstance(statements, dict):
        statements = [statements]

    allowed_required = set(required_actions)

    cleaned_statements = []

    for statement in statements:

        actions = statement.get("Action", [])

        if isinstance(actions, str):
            actions = [actions]

        # Remove wildcard Action
        if "*" in actions:

            findings.append(
                "Wildcard Action removed by deterministic guardrail."
            )

            actions = [
                action
                for action in actions
                if action != "*"
            ]

        # Only retain required actions
        filtered_actions = []

        for action in actions:

            if action in allowed_required:

                filtered_actions.append(action)

            else:

                findings.append(
                    f"Unrequired action removed: {action}"
                )

        if not filtered_actions:
            continue

        new_statement = {
            "Effect": "Allow",
            "Action": sorted(set(filtered_actions)),
            "Resource": statement.get("Resource", "*")
        }

        cleaned_statements.append(new_statement)

    if not cleaned_statements:

        return None, findings + [
            "No valid required actions remained."
        ]

    policy["Statement"] = cleaned_statements

    return policy, findings


# ============================================================
# STEP 3 - AWS ACCESS ANALYZER
# ============================================================

def validate_with_access_analyzer(policy):

    print("\n" + "=" * 60)
    print("STEP 3 - AWS ACCESS ANALYZER")
    print("=" * 60)

    save_json(AI_POLICY_FILE, policy)

    command = [
        "aws",
        "accessanalyzer",
        "validate-policy",
        "--policy-document",
        "file://validation/ai_policy.json",
        "--policy-type",
        "IDENTITY_POLICY",
        "--profile",
        PROFILE,
        "--region",
        REGION,
        "--output",
        "json"
    ]

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )

        if result.returncode != 0:

            print("ACCESS ANALYZER ERROR:")
            print(result.stderr)

            return {
                "status": "ERROR",
                "findings": [],
                "error": result.stderr
            }

        data = json.loads(result.stdout)

        findings = data.get("findings", [])

        if not findings:

            print("ACCESS ANALYZER: PASS")

            return {
                "status": "PASS",
                "findings": []
            }

        print("ACCESS ANALYZER: FAIL")

        for finding in findings:

            print(
                "[{}] {}".format(
                    finding.get(
                        "findingType",
                        "UNKNOWN"
                    ),
                    finding.get(
                        "findingDetails",
                        ""
                    )
                )
            )

        return {
            "status": "FAIL",
            "findings": findings
        }

    except Exception as error:

        print("ACCESS ANALYZER ERROR:")
        print(error)

        return {
            "status": "ERROR",
            "findings": [],
            "error": str(error)
        }


# ============================================================
# STEP 4 - IAM POLICY SIMULATOR
# ============================================================

def simulate_policy(policy, required_actions):

    print("\n" + "=" * 60)
    print("STEP 4 - IAM POLICY SIMULATOR")
    print("=" * 60)

    actions = []

    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:

        action = statement.get("Action", [])

        if isinstance(action, str):
            actions.append(action)

        elif isinstance(action, list):
            actions.extend(action)

    actions = sorted(set(actions))

    # --------------------------------------------------------
    # Wildcard protection
    # --------------------------------------------------------

    if "*" in actions:

        print("IAM SIMULATOR: FAIL")
        print("Generated policy still contains Action '*'.")

        return {
            "status": "FAIL",
            "results": [],
            "reason": "Wildcard Action remains."
        }

    # --------------------------------------------------------
    # Verify required actions are present
    # --------------------------------------------------------

    missing_actions = [
        action
        for action in required_actions
        if action not in actions
    ]

    if missing_actions:

        print("IAM SIMULATOR: FAIL")

        print("\nMissing required actions:")

        for action in missing_actions:
            print(" -", action)

        return {
            "status": "FAIL",
            "results": [],
            "missing_required_actions": missing_actions
        }

    if not actions:

        print("IAM SIMULATOR: FAIL")
        print("No explicit actions found.")

        return {
            "status": "FAIL",
            "results": [],
            "reason": "No actions found."
        }

    # --------------------------------------------------------
    # AWS Simulation
    # --------------------------------------------------------

    try:

        session = boto3.Session(
            profile_name=PROFILE,
            region_name=REGION
        )

        iam_client = session.client("iam")

        response = iam_client.simulate_custom_policy(
            PolicyInputList=[
                json.dumps(
                    policy,
                    separators=(",", ":")
                )
            ],
            ActionNames=required_actions,
            ResourceArns=["*"]
        )

        results = []

        all_allowed = True

        for result in response.get(
            "EvaluationResults",
            []
        ):

            action = result.get(
                "EvalActionName"
            )

            decision = result.get(
                "EvalDecision"
            )

            print(
                f"{action:<45} {decision}"
            )

            results.append({
                "action": action,
                "decision": decision
            })

            if decision != "allowed":

                all_allowed = False

        status = (
            "PASS"
            if all_allowed
            else "FAIL"
        )

        print("\nIAM SIMULATOR:", status)

        return {
            "status": status,
            "results": results,
            "required_actions": required_actions
        }

    except Exception as error:

        print("IAM SIMULATOR ERROR:")
        print(error)

        return {
            "status": "ERROR",
            "results": [],
            "error": str(error)
        }


# ============================================================
# MAIN PIPELINE
# ============================================================

def main():

    print("=" * 60)
    print("     AI-ASSISTED CI/CD LEAST PRIVILEGE PIPELINE")
    print("=" * 60)

    # --------------------------------------------------------
    # Check files
    # --------------------------------------------------------

    if not POLICY_FILE.exists():

        print("ERROR: Policy file not found:")
        print(POLICY_FILE)

        sys.exit(1)

    if not REQUIRED_ACTIONS_FILE.exists():

        print("ERROR: Required actions file not found:")
        print(REQUIRED_ACTIONS_FILE)

        sys.exit(1)

    # --------------------------------------------------------
    # Load input
    # --------------------------------------------------------

    original_policy = load_json(
        POLICY_FILE
    )

    required_data = load_json(
        REQUIRED_ACTIONS_FILE
    )

    required_actions = sorted(
        set(
            required_data.get(
                "required_actions",
                []
            )
        )
    )

    if not required_actions:

        print(
            "ERROR: No required actions defined."
        )

        sys.exit(1)

    # --------------------------------------------------------
    # STEP 1
    # --------------------------------------------------------

    safe = run_policy_scanner()

    if safe:

        print("=" * 60)
        print("POLICY PASSED INITIAL CI SCAN")
        print("CI/CD STATUS: PASS")
        print("=" * 60)

        report = {
            "module":
                "AI-Assisted CI/CD Least Privilege Pipeline",

            "original_policy":
                original_policy,

            "required_actions":
                required_actions,

            "final_status":
                "SAFE",

            "ci_cd_allowed":
                True
        }

        save_json(
            REPORT_FILE,
            report
        )

        sys.exit(0)

    # --------------------------------------------------------
    # Analyze original policy
    # --------------------------------------------------------

    findings = analyze_policy(
        original_policy
    )

    print("\nHIGH-RISK POLICY SENT TO AI REMEDIATION")

    # --------------------------------------------------------
    # AI CLOSED LOOP
    # --------------------------------------------------------

    current_policy = original_policy

    attempts = []

    for attempt in range(
        1,
        MAX_ATTEMPTS + 1
    ):

        print("\n" + "=" * 60)
        print(
            f"AI VERIFICATION ATTEMPT "
            f"{attempt} OF {MAX_ATTEMPTS}"
        )
        print("=" * 60)

        # ----------------------------------------------------
        # AI
        # ----------------------------------------------------

        ai_policy = call_ollama(
            current_policy,
            findings,
            required_actions
        )

        if ai_policy is None:

            attempts.append({
                "attempt": attempt,
                "status": "AI_ERROR"
            })

            continue

        # ----------------------------------------------------
        # Deterministic Guardrails
        # ----------------------------------------------------

        print("\n" + "-" * 60)
        print("DETERMINISTIC SECURITY GUARDRAILS")
        print("-" * 60)

        guarded_policy, guardrail_findings = (
            apply_guardrails(
                ai_policy,
                required_actions
            )
        )

        if guarded_policy is None:

            print(
                "GUARDRAILS: FAIL"
            )

            attempts.append({
                "attempt": attempt,
                "policy": ai_policy,
                "guardrails": {
                    "status": "FAIL",
                    "findings":
                        guardrail_findings
                },
                "status": "FAIL"
            })

            current_policy = ai_policy

            continue

        print(
            "GUARDRAILS: PASS"
        )

        if guardrail_findings:

            print(
                "Guardrail adjustments:"
            )

            for finding in guardrail_findings:

                print(
                    " -",
                    finding
                )

        # ----------------------------------------------------
        # ACCESS ANALYZER
        # ----------------------------------------------------

        analyzer_result = (
            validate_with_access_analyzer(
                guarded_policy
            )
        )

        if analyzer_result["status"] != "PASS":

            attempts.append({
                "attempt": attempt,
                "policy": guarded_policy,
                "guardrails": {
                    "status": "PASS",
                    "findings":
                        guardrail_findings
                },
                "access_analyzer":
                    analyzer_result,
                "status": "FAIL"
            })

            current_policy = guarded_policy

            findings = (
                analyzer_result.get(
                    "findings",
                    []
                )
            )

            continue

        # ----------------------------------------------------
        # IAM SIMULATOR
        # ----------------------------------------------------

        simulator_result = simulate_policy(
            guarded_policy,
            required_actions
        )

        if simulator_result["status"] != "PASS":

            attempts.append({
                "attempt": attempt,
                "policy": guarded_policy,
                "guardrails": {
                    "status": "PASS",
                    "findings":
                        guardrail_findings
                },
                "access_analyzer":
                    analyzer_result,
                "iam_simulator":
                    simulator_result,
                "status": "FAIL"
            })

            current_policy = guarded_policy

            findings = [
                {
                    "severity": "HIGH",
                    "issue":
                        "IAM simulation failed.",
                    "details":
                        simulator_result
                }
            ]

            continue

        # ----------------------------------------------------
        # VERIFIED
        # ----------------------------------------------------

        attempts.append({
            "attempt": attempt,
            "policy": guarded_policy,
            "guardrails": {
                "status": "PASS",
                "findings":
                    guardrail_findings
            },
            "access_analyzer":
                analyzer_result,
            "iam_simulator":
                simulator_result,
            "status": "PASS"
        })

        # ----------------------------------------------------
        # FINAL REPORT
        # ----------------------------------------------------

        report = {
            "module":
                "AI-Assisted CI/CD Least Privilege Pipeline",

            "original_policy":
                original_policy,

            "required_actions":
                required_actions,

            "max_attempts":
                MAX_ATTEMPTS,

            "attempts":
                attempts,

            "final_policy":
                guarded_policy,

            "final_status":
                "VERIFIED",

            "ci_cd_allowed":
                True
        }

        save_json(
            REPORT_FILE,
            report
        )

        print("\n" + "=" * 60)
        print("FINAL STATUS: VERIFIED")
        print("CI/CD STATUS: PASS")
        print("MERGE/DEPLOYMENT ALLOWED: TRUE")
        print("=" * 60)

        print("\nFinal least-privilege policy:")
        print(
            json.dumps(
                guarded_policy,
                indent=4
            )
        )

        print("\nReport saved:")
        print(REPORT_FILE)

        sys.exit(0)

    # --------------------------------------------------------
    # ALL ATTEMPTS FAILED
    # --------------------------------------------------------

    report = {
        "module":
            "AI-Assisted CI/CD Least Privilege Pipeline",

        "original_policy":
            original_policy,

        "required_actions":
            required_actions,

        "max_attempts":
            MAX_ATTEMPTS,

        "attempts":
            attempts,

        "final_status":
            "FAILED",

        "ci_cd_allowed":
            False
    }

    save_json(
        REPORT_FILE,
        report
    )

    print("\n" + "=" * 60)
    print("FINAL STATUS: FAILED")
    print("CI/CD STATUS: FAIL")
    print("MERGE/DEPLOYMENT ALLOWED: FALSE")
    print("=" * 60)

    print("\nReport saved:")
    print(REPORT_FILE)

    sys.exit(1)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()