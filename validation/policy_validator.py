import json
import subprocess
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = BASE_DIR / "reports" / "recommended_policy.json"
OUTPUT_FILE = BASE_DIR / "reports" / "policy_validation_report.json"

PROFILE = "leastprivilege"
REGION = "ap-south-1"


def load_json(path):
    """Load JSON file safely."""
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


def validate_policy_structure(policy):
    """Perform basic local IAM policy structure checks."""

    findings = []

    if not isinstance(policy, dict):
        findings.append({
            "type": "ERROR",
            "message": "Policy must be a JSON object."
        })
        return findings

    if "Version" not in policy:
        findings.append({
            "type": "ERROR",
            "message": "Policy is missing Version."
        })

    if "Statement" not in policy:
        findings.append({
            "type": "ERROR",
            "message": "Policy is missing Statement."
        })
        return findings

    statements = policy["Statement"]

    if not isinstance(statements, list):
        statements = [statements]

    for index, statement in enumerate(statements):

        if not isinstance(statement, dict):
            findings.append({
                "type": "ERROR",
                "message": f"Statement {index} is not an object."
            })
            continue

        if "Effect" not in statement:
            findings.append({
                "type": "ERROR",
                "message": f"Statement {index} is missing Effect."
            })

        if "Action" not in statement:
            findings.append({
                "type": "ERROR",
                "message": f"Statement {index} is missing Action."
            })

        if statement.get("Effect") not in ["Allow", "Deny"]:
            findings.append({
                "type": "ERROR",
                "message": f"Statement {index} has invalid Effect."
            })

        if statement.get("Resource") == "*":
            findings.append({
                "type": "WARNING",
                "message": (
                    f"Statement {index} uses Resource '*'. "
                    "Resource-level restriction should be reviewed."
                )
            })

    return findings


def run_access_analyzer(policy_file):
    """Run AWS IAM Access Analyzer policy validation."""

    command = [
        "aws",
        "accessanalyzer",
        "validate-policy",
        "--policy-document",
        f"file://{policy_file}",
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
            encoding="utf-8"
        )
    except FileNotFoundError:
        return {
            "success": False,
            "error": "AWS CLI was not found."
        }

    if result.returncode != 0:
        return {
            "success": False,
            "error": result.stderr.strip()
        }

    try:
        return {
            "success": True,
            "data": json.loads(result.stdout)
        }
    except json.JSONDecodeError:
        return {
            "success": False,
            "error": "AWS CLI returned invalid JSON.",
            "raw_output": result.stdout
        }


def main():

    print("=" * 70)
    print("             IAM POLICY VALIDATION")
    print("=" * 70)

    data = load_json(INPUT_FILE)

    if data is None:
        return

    users = data.get("users", [])

    validation_report = {
        "module": "IAM Policy Validation",
        "description": (
            "Validates recommended IAM policies using local checks "
            "and AWS IAM Access Analyzer."
        ),
        "users": []
    }

    for user in users:

        username = user.get("username", "Unknown")
        policy = user.get("recommended_policy")

        print()
        print("-" * 70)
        print("Identity:", username)

        if not policy:
            print("No recommended policy.")
            continue

        print("Performing local validation...")

        local_findings = validate_policy_structure(policy)

        policy_file = (
            BASE_DIR
            / "reports"
            / f"temp_policy_{username}.json"
        )

        try:
            with open(policy_file, "w", encoding="utf-8") as file:
                json.dump(policy, file, indent=4)

            print("Running AWS IAM Access Analyzer...")

            aws_result = run_access_analyzer(policy_file)

        finally:
            if policy_file.exists():
                policy_file.unlink()

        if aws_result["success"]:
            print("AWS Access Analyzer: SUCCESS")

            aws_findings = aws_result["data"].get("findings", [])

            for finding in aws_findings:
                print(
                    "  ",
                    finding.get("findingType"),
                    "-",
                    finding.get("issueCode"),
                    "-",
                    finding.get("findingDetails")
                )

        else:
            print("AWS Access Analyzer: FAILED")
            print(aws_result.get("error"))

            aws_findings = []

        result = {
            "username": username,
            "local_validation": {
                "status": (
                    "PASS"
                    if not any(
                        f["type"] == "ERROR"
                        for f in local_findings
                    )
                    else "FAIL"
                ),
                "findings": local_findings
            },
            "access_analyzer": {
                "status": (
                    "SUCCESS"
                    if aws_result["success"]
                    else "FAILED"
                ),
                "findings": aws_findings
            }
        }

        validation_report["users"].append(result)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(validation_report, file, indent=4)

    print()
    print("=" * 70)
    print("POLICY VALIDATION COMPLETED")
    print("Report saved to:", OUTPUT_FILE)
    print("=" * 70)


if __name__ == "__main__":
    main()