import json
import subprocess
import tempfile
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

AI_POLICY_FILE = BASE_DIR / "reports" / "ai_recommended_policies.json"
OUTPUT_FILE = BASE_DIR / "reports" / "policy_validation_report.json"

PROFILE = "leastprivilege"
REGION = "ap-south-1"


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def local_validate_policy(policy):
    findings = []

    if policy.get("Version") != "2012-10-17":
        findings.append("Invalid or missing policy Version")

    statements = policy.get("Statement")

    if not isinstance(statements, list):
        findings.append("Statement must be a list")
        return findings

    if len(statements) == 0:
        findings.append("Statement list is empty")
        return findings

    for index, statement in enumerate(statements):

        if statement.get("Effect") not in ["Allow", "Deny"]:
            findings.append(
                f"Statement {index}: invalid Effect"
            )

        if "Action" not in statement:
            findings.append(
                f"Statement {index}: missing Action"
            )

        action = statement.get("Action")

        if isinstance(action, list) and len(action) == 0:
            findings.append(
                f"Statement {index}: Action list is empty"
            )

        if action == "*":
            findings.append(
                f"Statement {index}: wildcard Action detected"
            )

        if statement.get("Resource") == "*":
            # Resource "*" is not automatically an error.
            # Some AWS services/actions require it.
            pass

    return findings


def run_access_analyzer(policy):

    temp_file = None

    try:

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=False,
            encoding="utf-8"
        ) as f:

            json.dump(policy, f, indent=2)
            temp_file = f.name

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

        if result.returncode != 0:

            return {
                "status": "ERROR",
                "findings": [],
                "error": result.stderr.strip()
            }

        response = json.loads(result.stdout)

        findings = response.get("findings", [])

        return {
            "status": "SUCCESS",
            "findings": findings
        }

    except Exception as error:

        return {
            "status": "ERROR",
            "findings": [],
            "error": str(error)
        }

    finally:

        if temp_file:

            try:
                Path(temp_file).unlink()
            except Exception:
                pass


def main():

    print("=" * 60)
    print("       AI POLICY VALIDATION")
    print("=" * 60)

    if not AI_POLICY_FILE.exists():

        print()
        print("ERROR:")
        print("AI policy file not found:")
        print(AI_POLICY_FILE)

        return

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
        print("ERROR: recommended_policy missing.")

        return

    print()
    print(f"Identity       : {username}")
    print(
        f"Risk Level     : "
        f"{identity.get('risk_level')}"
    )
    print(
        f"Risk Score     : "
        f"{identity.get('risk_score')}"
    )

    print()
    print("LOCAL POLICY CHECK")
    print("-" * 60)

    local_findings = local_validate_policy(
        policy
    )

    if local_findings:

        local_status = "FAIL"

        for finding in local_findings:
            print(f"[FAIL] {finding}")

    else:

        local_status = "PASS"
        print("[PASS] Local policy structure is valid")

    print()
    print("AWS ACCESS ANALYZER")
    print("-" * 60)

    analyzer_result = run_access_analyzer(
        policy
    )

    print(
        f"Status: "
        f"{analyzer_result['status']}"
    )

    findings = analyzer_result.get(
        "findings",
        []
    )

    if findings:

        for finding in findings:

            print(
                f"[{finding.get('findingType', 'UNKNOWN')}] "
                f"{finding.get('issueCode', '')}"
            )

    else:

        print("[PASS] No Access Analyzer findings")

    if analyzer_result["status"] == "SUCCESS" and not findings:

        analyzer_status = "PASS"

    else:

        analyzer_status = "FAIL"

    overall_status = (
        "PASS"
        if local_status == "PASS"
        and analyzer_status == "PASS"
        else "FAIL"
    )

    report = {
        "module": "AI Policy Validation",
        "identity": username,
        "risk_level": identity.get("risk_level"),
        "risk_score": identity.get("risk_score"),
        "policy_source": "ai_recommended_policies.json",
        "local_validation": {
            "status": local_status,
            "findings": local_findings
        },
        "access_analyzer": {
            "status": analyzer_status,
            "findings": findings,
            "raw_status": analyzer_result["status"]
        },
        "overall_status": overall_status
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
    print("=" * 60)
    print(f"OVERALL VALIDATION: {overall_status}")
    print("=" * 60)

    print()
    print("Report saved:")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    main()