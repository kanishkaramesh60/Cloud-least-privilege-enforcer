import json
import subprocess
import sys
from pathlib import Path

import boto3

BASE_DIR = Path(__file__).resolve().parent.parent

REQUIRED_ACTIONS_FILE = BASE_DIR / "ci" / "policies" / "required_actions.json"

AI_POLICY_FILE = BASE_DIR / "validation" / "ai_policy.json"
REPORT_FILE = BASE_DIR / "reports" / "ci_ai_pipeline_report.json"

PROFILE = "leastprivilege"
REGION = "ap-south-1"

OLLAMA_MODEL = "llama3.2:3b"

MAX_ATTEMPTS = 3


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

def find_policy_file():
    """
    Find IAM policy files changed in Git.

    Checks:
    1. Uncommitted working-tree changes
    2. Staged changes
    3. Changes in the latest commit

    required_actions.json is ignored because it contains
    application-required permissions, not the policy being scanned.
    """

    try:
        changed_files = set()

        # 1. Uncommitted working-tree changes
        result = subprocess.run(
            ["git", "diff", "--name-only","HEAD~1", "HEAD"],
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            check=True
        )

        changed_files.update(result.stdout.splitlines())

        # 2. Staged changes
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            check=True
        )

        changed_files.update(result.stdout.splitlines())

        # 3. Changes in the latest commit
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", "HEAD~1", "HEAD"],
                cwd=BASE_DIR,
                capture_output=True,
                text=True,
                check=True
            )

            changed_files.update(result.stdout.splitlines())

        except subprocess.CalledProcessError:
            print("WARNING: HEAD~1 is not available.")
            print("Falling back to the current HEAD commit.")

            result = subprocess.run(
                ["git", "show", "--pretty=", "--name-only", "HEAD"],
                cwd=BASE_DIR,
                capture_output=True,
                text=True,
                check=True
            )

            changed_files.update(result.stdout.splitlines())

        changed_files.update(result.stdout.splitlines())

    except subprocess.CalledProcessError as e:
        print("ERROR: Unable to determine changed files from Git.")
        print(e)
        return None

    changed_policies = []

    for file in changed_files:
        file_path = Path(file)

        if (
            file_path.suffix.lower() == ".json"
            and file_path.parent.as_posix() == "ci/policies"
            and file_path.name != "required_actions.json"
        ):
            changed_policies.append(BASE_DIR / file_path)

    if not changed_policies:
        print("ERROR: No changed IAM policy file detected.")
        print("Changed files:")

        for file in sorted(changed_files):
            print(" -", file)

        return None

    if len(changed_policies) > 1:
        print("ERROR: Multiple IAM policies were changed.")
        print("Please scan one policy at a time:")

        for file in changed_policies:
            print(" -", file)

        return None

    print("Git changed policy detected:")
    print(changed_policies[0])

    return changed_policies[0]

def extract_json_object(text):
    """
    Extract exactly ONE JSON object from Ollama output.

    Handles:
    - normal JSON
    - Markdown code fences
    - extra text before JSON
    - extra text after JSON
    - multiple JSON objects by taking the first valid object
    """

    if not text:
        raise ValueError("AI returned an empty response.")

    text = text.strip()

    if text.startswith("```"):
        lines = text.splitlines()

        if lines and lines[0].strip().startswith("```"):
            lines = lines[1:]

        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]

        text = "\n".join(lines).strip()

    start = text.find("{")

    if start == -1:
        raise ValueError(
            "No JSON object found in AI response."
        )

    json_text = text[start:]

    decoder = json.JSONDecoder()

    policy, end_index = decoder.raw_decode(json_text)

    if not isinstance(policy, dict):
        raise ValueError(
            "AI response JSON is not an object."
        )

    return policy


def validate_ai_policy_structure(policy):
    """
    Basic structural validation before AWS validation.
    """

    if not isinstance(policy, dict):
        return False, "AI policy is not a JSON object."

    if "Version" not in policy:
        return False, "AI policy is missing Version."

    if "Statement" not in policy:
        return False, "AI policy is missing Statement."

    statements = policy["Statement"]

    if isinstance(statements, dict):
        statements = [statements]

    if not isinstance(statements, list):
        return False, "Statement must be a list or object."

    if len(statements) == 0:
        return False, "Statement is empty."

    for index, statement in enumerate(statements):

        if not isinstance(statement, dict):
            return False, (
                f"Statement {index} is not an object."
            )

        if "Effect" not in statement:
            return False, (
                f"Statement {index} is missing Effect."
            )

        if "Action" not in statement:
            return False, (
                f"Statement {index} is missing Action."
            )

    return True, ""

def run_policy_scanner(policy_file):

    print("\n" + "=" * 60)
    print("STEP 1 - CI/CD POLICY SCANNER")
    print("=" * 60)

    result = subprocess.run(
        [
            sys.executable,
            str(BASE_DIR / "ci" / "ci_policy_scanner.py"),
            str(policy_file)
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

def call_ollama(policy, findings, required_actions):

    print("\n" + "=" * 60)
    print("STEP 2 - AI POLICY REMEDIATION")
    print("=" * 60)

    prompt = f"""
You are an AWS IAM least-privilege security remediation engine.

Your task is to transform the supplied IAM policy into a safer
least-privilege identity policy.

ORIGINAL POLICY:
{json.dumps(policy, indent=2)}

SECURITY FINDINGS:
{json.dumps(findings, indent=2)}

APPLICATION REQUIRED ACTIONS:
{json.dumps(required_actions, indent=2)}

STRICT SECURITY REQUIREMENTS:

1. Only allow actions from APPLICATION REQUIRED ACTIONS.
2. Remove Action "*".
3. Never generate Action "*".
4. Never add permissions that are not in APPLICATION REQUIRED ACTIONS.
5. Preserve Version "2012-10-17".
6. Use Effect "Allow".
7. Use explicit IAM actions.
8. Resource "*" may be used only when a more specific resource
   is not provided or is not possible for the action.
9. Do not invent additional AWS services.
10. Do not add explanations.
11. Do not add comments.
12. Do not use Markdown.
13. Do not use code fences.
14. Return exactly ONE JSON object.
15. The JSON object must contain Version and Statement.
16. Statement must contain at least one statement.
17. Each statement must contain Effect, Action, and Resource.

VERY IMPORTANT:

Return ONLY the JSON object.

Do NOT write:
- explanations
- introductions
- conclusions
- Markdown
- ```json
- ``` 
- multiple JSON objects

Your entire response must be exactly ONE valid JSON object.
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

        if not output:

            print("ERROR: Ollama returned an empty response.")

            return None

        print("\nAI RAW RESPONSE:")
        print("-" * 60)
        print(output)
        print("-" * 60)

        ai_policy = extract_json_object(output)

        valid, error_message = validate_ai_policy_structure(
            ai_policy
        )

        if not valid:

            print(
                "ERROR: AI returned an invalid IAM policy structure."
            )

            print(
                "Reason:",
                error_message
            )

            return None

        print("\nAI GENERATED POLICY:")
        print("-" * 60)
        print(
            json.dumps(
                ai_policy,
                indent=4
            )
        )

        return ai_policy

    except subprocess.TimeoutExpired:

        print("ERROR: Ollama timed out.")

        return None

    except json.JSONDecodeError as error:

        print("ERROR: AI returned invalid JSON.")

        print("Reason:", error)

        return None

    except ValueError as error:

        print("ERROR: AI JSON extraction failed.")

        print("Reason:", error)

        return None

    except Exception as error:

        print("AI ERROR:", error)

        return None

def apply_guardrails(policy, required_actions):

    if not isinstance(policy, dict):

        return None, [
            "Policy is not a JSON object."
        ]

    findings = []

    if policy.get("Version") != "2012-10-17":

        findings.append(
            "Invalid or missing IAM policy version."
        )

        policy["Version"] = "2012-10-17"

    statements = policy.get("Statement")

    if not statements:

        return None, [
            "Policy contains no Statement."
        ]

    if isinstance(statements, dict):
        statements = [statements]

    allowed_required = set(required_actions)

    cleaned_statements = []

    for statement in statements:

        actions = statement.get(
            "Action",
            []
        )

        if isinstance(actions, str):
            actions = [actions]

        if "*" in actions:

            findings.append(
                "Wildcard Action removed by deterministic guardrail."
            )

            actions = [
                action
                for action in actions
                if action != "*"
            ]

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

        resource = statement.get(
            "Resource",
            "*"
        )

        new_statement = {
            "Effect": "Allow",
            "Action": sorted(
                set(filtered_actions)
            ),
            "Resource": resource
        }

        cleaned_statements.append(
            new_statement
        )

    if not cleaned_statements:

        return None, findings + [
            "No valid required actions remained."
        ]

    policy["Statement"] = cleaned_statements

    return policy, findings

def validate_with_access_analyzer(policy):

    print("\n" + "=" * 60)
    print("STEP 3 - AWS ACCESS ANALYZER")
    print("=" * 60)

    save_json(
        AI_POLICY_FILE,
        policy
    )

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

        data = json.loads(
            result.stdout
        )

        findings = data.get(
            "findings",
            []
        )

        if not findings:

            print(
                "ACCESS ANALYZER: PASS"
            )

            return {
                "status": "PASS",
                "findings": []
            }

        print(
            "ACCESS ANALYZER: FAIL"
        )

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

        print(
            "ACCESS ANALYZER ERROR:"
        )

        print(error)

        return {
            "status": "ERROR",
            "findings": [],
            "error": str(error)
        }


def simulate_policy(policy, required_actions):

    print("\n" + "=" * 60)
    print("STEP 4 - IAM POLICY SIMULATOR")
    print("=" * 60)

    actions = []

    statements = policy.get(
        "Statement",
        []
    )

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:

        action = statement.get(
            "Action",
            []
        )

        if isinstance(action, str):

            actions.append(action)

        elif isinstance(action, list):

            actions.extend(action)

    actions = sorted(
        set(actions)
    )

    if "*" in actions:

        print(
            "IAM SIMULATOR: FAIL"
        )

        print(
            "Generated policy still contains Action '*'."
        )

        return {
            "status": "FAIL",
            "results": [],
            "reason": "Wildcard Action remains."
        }

    missing_actions = [
        action
        for action in required_actions
        if action not in actions
    ]

    if missing_actions:

        print(
            "IAM SIMULATOR: FAIL"
        )

        print(
            "\nMissing required actions:"
        )

        for action in missing_actions:

            print(
                " -",
                action
            )

        return {
            "status": "FAIL",
            "results": [],
            "missing_required_actions":
                missing_actions
        }

    if not actions:

        print(
            "IAM SIMULATOR: FAIL"
        )

        print(
            "No explicit actions found."
        )

        return {
            "status": "FAIL",
            "results": [],
            "reason": "No actions found."
        }

    try:

        session = boto3.Session(
            profile_name=PROFILE,
            region_name=REGION
        )

        iam_client = session.client(
            "iam"
        )

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

        print(
            "\nIAM SIMULATOR:",
            status
        )

        return {
            "status": status,
            "results": results,
            "required_actions":
                required_actions
        }

    except Exception as error:

        print(
            "IAM SIMULATOR ERROR:"
        )

        print(error)

        return {
            "status": "ERROR",
            "results": [],
            "error": str(error)
        }

def main():

    print("=" * 60)
    print(
        "     AI-ASSISTED CI/CD LEAST PRIVILEGE PIPELINE"
    )
    print("=" * 60)

    if len(sys.argv) > 1:
        POLICY_FILE = sys.argv[1]
    else:
        POLICY_FILE = find_policy_file()

    if POLICY_FILE is None:
        sys.exit(1)

    print("\nPolicy selected for scanning:")
    print(POLICY_FILE) 

    if not REQUIRED_ACTIONS_FILE.exists():

        print(
            "ERROR: Required actions file not found:"
        )

        print(
            REQUIRED_ACTIONS_FILE
        )

        sys.exit(1)

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

    safe = run_policy_scanner(POLICY_FILE)

    if safe:

        print("=" * 60)
        print(
            "POLICY PASSED INITIAL CI SCAN"
        )
        print(
            "CI/CD STATUS: PASS"
        )
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

    findings = analyze_policy(
        original_policy
    )

    print(
        "\nHIGH-RISK POLICY SENT TO AI REMEDIATION"
    )

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

        ai_policy = call_ollama(
            current_policy,
            findings,
            required_actions
        )

        if ai_policy is None:

            attempts.append({

                "attempt":
                    attempt,

                "status":
                    "AI_ERROR"
            })

            findings = [
                {
                    "severity": "HIGH",
                    "issue":
                        "Previous AI response was invalid or could not be parsed.",
                    "instruction":
                        "Return exactly one valid JSON IAM policy object and nothing else."
                }
            ]

            continue

        print("\n" + "-" * 60)
        print(
            "DETERMINISTIC SECURITY GUARDRAILS"
        )
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

                "attempt":
                    attempt,

                "policy":
                    ai_policy,

                "guardrails": {

                    "status":
                        "FAIL",

                    "findings":
                        guardrail_findings
                },

                "status":
                    "FAIL"
            })

            current_policy = ai_policy

            findings = [
                {
                    "severity": "HIGH",
                    "issue":
                        "AI policy failed deterministic security guardrails.",
                    "details":
                        guardrail_findings
                }
            ]

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

        analyzer_result = (
            validate_with_access_analyzer(
                guarded_policy
            )
        )

        if analyzer_result["status"] != "PASS":

            attempts.append({

                "attempt":
                    attempt,

                "policy":
                    guarded_policy,

                "guardrails": {

                    "status":
                        "PASS",

                    "findings":
                        guardrail_findings
                },

                "access_analyzer":
                    analyzer_result,

                "status":
                    "FAIL"
            })

            current_policy = guarded_policy

            findings = (
                analyzer_result.get(
                    "findings",
                    []
                )
            )

            continue

        simulator_result = simulate_policy(
            guarded_policy,
            required_actions
        )

        if simulator_result["status"] != "PASS":

            attempts.append({

                "attempt":
                    attempt,

                "policy":
                    guarded_policy,

                "guardrails": {

                    "status":
                        "PASS",

                    "findings":
                        guardrail_findings
                },

                "access_analyzer":
                    analyzer_result,

                "iam_simulator":
                    simulator_result,

                "status":
                    "FAIL"
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

        attempts.append({

            "attempt":
                attempt,

            "policy":
                guarded_policy,

            "guardrails": {

                "status":
                    "PASS",

                "findings":
                    guardrail_findings
            },

            "access_analyzer":
                analyzer_result,

            "iam_simulator":
                simulator_result,

            "status":
                "PASS"
        })

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
        print(
            "FINAL STATUS: VERIFIED"
        )
        print(
            "CI/CD STATUS: PASS"
        )
        print(
            "MERGE/DEPLOYMENT ALLOWED: TRUE"
        )
        print("=" * 60)

        print(
            "\nFinal least-privilege policy:"
        )

        print(
            json.dumps(
                guarded_policy,
                indent=4
            )
        )

        print(
            "\nReport saved:"
        )

        print(
            REPORT_FILE
        )

        sys.exit(0)

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
    print(
        "FINAL STATUS: FAILED"
    )
    print(
        "CI/CD STATUS: FAIL"
    )
    print(
        "MERGE/DEPLOYMENT ALLOWED: FALSE"
    )
    print("=" * 60)

    print(
        "\nReport saved:"
    )

    print(
        REPORT_FILE
    )

    sys.exit(1)

if __name__ == "__main__":
    main()