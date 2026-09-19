import json
from pathlib import Path
import ollama


BASE_DIR = Path(__file__).resolve().parent.parent

PERMISSION_FILE = BASE_DIR / "reports" / "permission_analysis.json"
IDENTITY_FILE = BASE_DIR / "reports" / "identity_report.json"
RISK_FILE = BASE_DIR / "reports" / "risk_report.json"
ACTIONS_FILE = BASE_DIR / "reports" / "observed_actions.json"

OUTPUT_FILE = BASE_DIR / "reports" / "ai_recommended_policies.json"

MODEL = "llama3.2:3b"
TARGET_IDENTITY = "Least_privilege"


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def find_identity(identity_report, username):
    for item in identity_report.get("identities", []):
        if item.get("identity") == username:
            return item

    return {
        "identity": username,
        "identity_type": "Unknown",
        "confidence": "Low"
    }


def find_user(report, username):
    for item in report.get("users", []):
        if item.get("username") == username:
            return item

    return None


def find_observed_actions(action_report, username):
    for item in action_report.get("users", []):
        if item.get("username") == username:
            return item.get("observed_actions", [])

    return []


def build_context(
    permission_report,
    identity_report,
    risk_report,
    action_report,
    username
):
    permission_user = find_user(permission_report, username)
    risk_user = find_user(risk_report, username)
    identity = find_identity(identity_report, username)

    observed_actions = find_observed_actions(
        action_report,
        username
    )

    if permission_user is None:
        raise ValueError(
            f"Identity '{username}' not found in permission_analysis.json"
        )

    if risk_user is None:
        raise ValueError(
            f"Identity '{username}' not found in risk_report.json"
        )

    analysis = permission_user.get("analysis", {})

    context = {
        "identity": {
            "name": username,
            "type": identity.get("identity_type"),
            "confidence": identity.get("confidence"),
            "risk_level": risk_user.get("risk_level"),
            "risk_score": risk_user.get("total_risk")
        },

        "current_policies": permission_user.get(
            "assigned_policies", []
        ),

        "broad_policies": analysis.get(
            "broad_policies", []
        ),

        "potentially_excessive_policies": analysis.get(
            "potentially_excessive_policies", []
        ),

        "least_privilege_status": analysis.get(
            "least_privilege_status"
        ),

        "observed_api_calls": permission_user.get(
            "observed_api_calls", 0
        ),

        "observed_services": permission_user.get(
            "observed_services", []
        ),

        "observed_actions": observed_actions
    }

    return context


def build_prompt(context):

    return f"""
You are an AWS IAM least-privilege security expert.

Analyze the supplied security context and produce a least-privilege
remediation recommendation.

IMPORTANT RULES:

1. Do NOT invent AWS permissions.
2. The observed_actions list is authoritative.
3. Every observed action must appear in required_permissions.
4. Every required permission must appear in the recommended policy Action.
5. Never return an empty Action list.
6. Do not use Action "*".
7. Remove broad permissions such as AdministratorAccess and
   AmazonEC2FullAccess when they are identified as excessive.
8. Resource "*" is acceptable for actions where AWS does not support
   resource-level permissions.
9. Return ONLY valid JSON.
10. Do not include markdown.
11. Do not include explanations outside JSON.

SECURITY CONTEXT:

{json.dumps(context, indent=2)}

Return exactly this structure:

{{
  "identity": {{
    "name": "{context["identity"]["name"]}",
    "type": "{context["identity"]["type"]}",
    "risk_level": "{context["identity"]["risk_level"]}",
    "risk_score": {context["identity"]["risk_score"]}
  }},
  "excessive_permissions": [],
  "required_permissions": [],
  "recommendation": {{
    "action": "",
    "reason": ""
  }},
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


def extract_content(response):

    # Ollama Python SDK response object
    try:
        content = response.message.content

        if content:
            return content
    except Exception:
        pass

    # Fallback if response behaves like a dictionary
    try:
        content = response["message"]["content"]

        if content:
            return content
    except Exception:
        pass

    raise ValueError(
        "Could not extract message.content from Ollama response."
    )


def parse_ai_response(response):

    content = extract_content(response)

    print("\nRAW AI CONTENT")
    print("-" * 60)
    print(content)
    print("-" * 60)

    content = content.strip()

    # Remove accidental markdown fences
    if content.startswith("```"):
        content = content.replace("```json", "")
        content = content.replace("```", "")
        content = content.strip()

    try:
        return json.loads(content)

    except json.JSONDecodeError:

        start = content.find("{")
        end = content.rfind("}")

        if start != -1 and end != -1:
            extracted = content[start:end + 1]

            try:
                return json.loads(extracted)
            except json.JSONDecodeError:
                pass

    raise ValueError("Ollama returned invalid JSON.")


def apply_guardrails(result, context):

    observed_actions = context["observed_actions"]

    excessive_permissions = context[
        "potentially_excessive_policies"
    ]

    if not observed_actions:
        raise ValueError(
            "Guardrail failed: no observed actions available."
        )

    # ---------------------------------------------------------
    # FORCE AUTHORITATIVE EXCESSIVE PERMISSIONS
    # ---------------------------------------------------------

    result["excessive_permissions"] = excessive_permissions

    # ---------------------------------------------------------
    # FORCE AUTHORITATIVE REQUIRED PERMISSIONS
    # ---------------------------------------------------------

    result["required_permissions"] = observed_actions

    # ---------------------------------------------------------
    # ENSURE POLICY STRUCTURE EXISTS
    # ---------------------------------------------------------

    policy = result.get("recommended_policy")

    if not isinstance(policy, dict):
        policy = {}

    policy["Version"] = "2012-10-17"

    statements = policy.get("Statement")

    if not isinstance(statements, list) or not statements:
        statements = [
            {
                "Effect": "Allow",
                "Action": observed_actions,
                "Resource": "*"
            }
        ]

    statement = statements[0]

    statement["Effect"] = "Allow"

    # ---------------------------------------------------------
    # NEVER ALLOW EMPTY ACTIONS
    # ---------------------------------------------------------

    ai_actions = statement.get("Action", [])

    if not ai_actions:
        ai_actions = observed_actions

    # ---------------------------------------------------------
    # REMOVE WILDCARD ACTION
    # ---------------------------------------------------------

    if "*" in ai_actions:
        ai_actions = [
            action for action in ai_actions
            if action != "*"
        ]

    # ---------------------------------------------------------
    # GUARANTEE ALL OBSERVED ACTIONS
    # ---------------------------------------------------------

    for action in observed_actions:

        if action not in ai_actions:
            ai_actions.append(action)

    statement["Action"] = sorted(set(ai_actions))

    if "Resource" not in statement:
        statement["Resource"] = "*"

    policy["Statement"] = [statement]

    result["recommended_policy"] = policy

    # ---------------------------------------------------------
    # SECURITY IMPACT
    # ---------------------------------------------------------

    result["security_impact"] = {
        "privilege_reduced": bool(excessive_permissions),
        "administrator_access_removed": (
            "AdministratorAccess" in excessive_permissions
        ),
        "full_access_removed": (
            "AmazonEC2FullAccess" in excessive_permissions
        )
    }

    result["ai_status"] = "GENERATED"

    return result


def main():

    print("=" * 60)
    print("        FAST AI POLICY RECOMMENDER")
    print("=" * 60)

    print()
    print(f"Target identity: {TARGET_IDENTITY}")

    permission_report = load_json(PERMISSION_FILE)
    identity_report = load_json(IDENTITY_FILE)
    risk_report = load_json(RISK_FILE)
    action_report = load_json(ACTIONS_FILE)

    context = build_context(
        permission_report,
        identity_report,
        risk_report,
        action_report,
        TARGET_IDENTITY
    )

    print()
    print("COMPACT AI INPUT")
    print("-" * 60)
    print(json.dumps(context, indent=2))

    prompt = build_prompt(context)

    print()
    print("Sending compact context to Ollama...")
    print(f"Model: {MODEL}")

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

        result = parse_ai_response(response)

        # -----------------------------------------------------
        # SECURITY GUARDRAILS
        # -----------------------------------------------------

        result = apply_guardrails(
            result,
            context
        )

        # -----------------------------------------------------
        # SAVE RESULT
        # -----------------------------------------------------

        OUTPUT_FILE.parent.mkdir(
            parents=True,
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
        print("AI POLICY RECOMMENDATION")
        print("=" * 60)

        print()
        print(f"Identity       : {TARGET_IDENTITY}")
        print(
            f"Risk Level     : "
            f"{result['identity']['risk_level']}"
        )
        print(
            f"Risk Score     : "
            f"{result['identity']['risk_score']}"
        )

        print()
        print("Excessive Permissions")
        for permission in result["excessive_permissions"]:
            print(f"  - {permission}")

        print()
        print("Required Permissions")
        for action in result["required_permissions"]:
            print(f"  - {action}")

        print()
        print("Recommended Policy")
        print("-" * 60)

        print(
            json.dumps(
                result["recommended_policy"],
                indent=4
            )
        )

        print()
        print("Security Impact")
        print("-" * 60)

        impact = result["security_impact"]

        print(
            f"Privilege Reduced       : "
            f"{impact['privilege_reduced']}"
        )

        print(
            f"Administrator Removed   : "
            f"{impact['administrator_access_removed']}"
        )

        print(
            f"Full Access Removed     : "
            f"{impact['full_access_removed']}"
        )

        print()
        print(f"Output saved to:")
        print(OUTPUT_FILE)

        print()
        print("=" * 60)
        print("AI STATUS: GENERATED")
        print("=" * 60)

    except Exception as error:

        print()
        print("ERROR: Ollama recommendation failed.")
        print(str(error))


if __name__ == "__main__":
    main()