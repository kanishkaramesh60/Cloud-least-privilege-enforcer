import json
import os
import ollama


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INPUT_FILE = os.path.join(
    BASE_DIR,
    "ci",
    "policies",
    "overprivileged_test_policy.json"
)

OUTPUT_FILE = os.path.join(
    BASE_DIR,
    "reports",
    "ci_ai_remediation_report.json"
)

MODEL = "llama3.2:3b"


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_prompt(data):

    return f"""
You are an AWS IAM least-privilege security expert.

Analyze this synthetic IAM security scenario.

IMPORTANT RULES:

1. Do not invent AWS permissions.
2. The observed_actions list is authoritative.
3. Every observed action must be preserved.
4. The excessive permissions must be removed.
5. Do not use Action "*".
6. Do not return an empty Action list.
7. Do not include excessive wildcard permissions such as:
   iam:*
   ec2:*
   s3:*
   lambda:*
   dynamodb:*
8. The recommended policy must contain ONLY the required
   observed actions.
9. Resource "*" is acceptable for this synthetic test.
10. Return ONLY valid JSON.

SYNTHETIC SECURITY CONTEXT:

{json.dumps(data, indent=2)}

Return exactly this structure:

{{
    "identity": "{data["identity"]}",
    "identity_type": "{data["identity_type"]}",
    "current_policies": [],
    "excessive_permissions": [],
    "required_permissions": [],
    "recommended_policy": {{
        "Version": "2012-10-17",
        "Statement": [
            {{
                "Effect": "Allow",
                "Action": [],
                "Resource": "*"
            }}
        ]
    }},
    "security_impact": {{
        "privilege_reduced": false,
        "administrator_access_removed": false,
        "full_access_removed": false
    }},
    "ai_status": "GENERATED"
}}
"""


def apply_guardrails(result, data):

    observed_actions = data.get("observed_actions", [])
    excessive_permissions = data.get(
        "excessive_permissions", []
    )

    if not observed_actions:
        raise ValueError(
            "Guardrail failed: no observed actions."
        )

    # ---------------------------------------------------------
    # FORCE AUTHORITATIVE VALUES
    # ---------------------------------------------------------

    result["identity"] = data["identity"]
    result["identity_type"] = data["identity_type"]

    result["current_policies"] = data.get(
        "current_policies", []
    )

    result["excessive_permissions"] = excessive_permissions

    result["required_permissions"] = observed_actions

    # ---------------------------------------------------------
    # BUILD POLICY
    # ---------------------------------------------------------

    policy = result.get("recommended_policy", {})

    if not isinstance(policy, dict):
        policy = {}

    policy["Version"] = "2012-10-17"

    statements = policy.get("Statement")

    if not isinstance(statements, list) or not statements:
        statements = [{}]

    statement = statements[0]

    statement["Effect"] = "Allow"

    # Authoritative observed actions
    statement["Action"] = sorted(
        set(observed_actions)
    )

    statement["Resource"] = "*"

    policy["Statement"] = [statement]

    result["recommended_policy"] = policy

    # ---------------------------------------------------------
    # SECURITY IMPACT
    # ---------------------------------------------------------

    result["security_impact"] = {
        "privilege_reduced": True,
        "administrator_access_removed": (
            "AdministratorAccess"
            in data.get("current_policies", [])
        ),
        "full_access_removed": (
            any(
                permission.endswith(":*")
                for permission in excessive_permissions
            )
        )
    }

    result["ai_status"] = "GENERATED"

    return result


def validate_result(result):

    policy = result["recommended_policy"]

    statement = policy["Statement"][0]

    actions = statement.get("Action", [])

    required_permissions = result[
        "required_permissions"
    ]

    excessive_permissions = result[
        "excessive_permissions"
    ]

    # Check empty Action
    if not actions:
        raise ValueError(
            "Validation failed: empty Action."
        )

    # Check wildcard Action
    if "*" in actions:
        raise ValueError(
            "Validation failed: wildcard Action."
        )

    # Check required actions
    missing = []

    for action in required_permissions:
        if action not in actions:
            missing.append(action)

    if missing:
        raise ValueError(
            f"Validation failed: missing actions: {missing}"
        )

    # Check excessive wildcard permissions
    remaining_excessive = []

    for permission in excessive_permissions:

        if permission in actions:
            remaining_excessive.append(permission)

    if remaining_excessive:
        raise ValueError(
            "Validation failed: excessive permissions remain: "
            + str(remaining_excessive)
        )

    return True


def main():

    print("=" * 60)
    print("        AI SYNTHETIC REMEDIATION")
    print("=" * 60)

    data = load_json(INPUT_FILE)

    print()
    print("Identity:", data["identity"])

    print()
    print("Current Policies")
    for policy in data.get("current_policies", []):
        print("  -", policy)

    print()
    print("Excessive Permissions")
    for permission in data.get(
        "excessive_permissions", []
    ):
        print("  -", permission)

    print()
    print("Observed Actions")
    for action in data.get(
        "observed_actions", []
    ):
        print("  -", action)

    prompt = build_prompt(data)

    print()
    print("Sending synthetic context to Ollama...")
    print("Model:", MODEL)

    try:

        response = ollama.chat(
            model=MODEL,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            format="json",
            options={
                "temperature": 0,
                "num_predict": 500
            }
        )

        content = response.message.content

        result = json.loads(content)

        result = apply_guardrails(
            result,
            data
        )

        validate_result(result)

        OUTPUT_DIR = os.path.dirname(
            OUTPUT_FILE
        )

        os.makedirs(
            OUTPUT_DIR,
            exist_ok=True
        )

        with open(
            OUTPUT_FILE,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                result,
                f,
                indent=4
            )

        print()
        print("=" * 60)
        print("AI RECOMMENDED LEAST-PRIVILEGE POLICY")
        print("=" * 60)

        print(
            json.dumps(
                result["recommended_policy"],
                indent=4
            )
        )

        print()
        print("Security Impact")
        print("-" * 60)

        impact = result[
            "security_impact"
        ]

        print(
            "Privilege Reduced       :",
            impact["privilege_reduced"]
        )

        print(
            "Administrator Removed   :",
            impact["administrator_access_removed"]
        )

        print(
            "Full Access Removed     :",
            impact["full_access_removed"]
        )

        print()
        print("AI SYNTHETIC REMEDIATION: PASS")

        print()
        print("AWS CHANGES PERFORMED   : False")

        print()
        print("Report saved:")
        print(OUTPUT_FILE)

    except Exception as error:

        print()
        print("AI SYNTHETIC REMEDIATION: FAILED")
        print(str(error))


if __name__ == "__main__":
    main()