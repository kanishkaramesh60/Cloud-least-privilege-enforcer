import json
from pathlib import Path
import ollama

from ai.iam_action_mapper import (
    map_actions,
    get_unmapped_actions
)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

PERMISSION_FILE = BASE_DIR / "reports" / "permission_analysis.json"
IDENTITY_FILE = BASE_DIR / "reports" / "identity_report.json"
RISK_FILE = BASE_DIR / "reports" / "risk_report.json"
ACTIONS_FILE = BASE_DIR / "reports" / "observed_actions.json"

OUTPUT_FILE = BASE_DIR / "reports" / "ai_recommended_policies.json"


# ============================================================
# CONFIGURATION
# ============================================================

MODEL = "llama3.2:3b"

TARGET_IDENTITY = "LeastPrivilegeDemoUser"


# ============================================================
# JSON LOADER
# ============================================================

def load_json(path):

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:

        return json.load(f)


# ============================================================
# FIND IDENTITY
# ============================================================

def find_identity(
    identity_report,
    username
):

    for item in identity_report.get(
        "identities",
        []
    ):

        if item.get("identity") == username:

            return item

    return {

        "identity": username,

        "identity_type": "Unknown",

        "confidence": "Low"

    }


# ============================================================
# FIND USER
# ============================================================

def find_user(
    report,
    username
):

    for item in report.get(
        "users",
        []
    ):

        if item.get("username") == username:

            return item

    return None


# ============================================================
# FIND OBSERVED ACTIONS
# ============================================================

def find_observed_actions(
    action_report,
    username
):

    for item in action_report.get(
        "users",
        []
    ):

        if item.get("username") == username:

            return item.get(
                "observed_actions",
                []
            )

    return []


# ============================================================
# BUILD SECURITY CONTEXT
# ============================================================

def build_context(
    permission_report,
    identity_report,
    risk_report,
    action_report,
    username
):

    permission_user = find_user(
        permission_report,
        username
    )

    risk_user = find_user(
        risk_report,
        username
    )

    identity = find_identity(
        identity_report,
        username
    )

    observed_actions = find_observed_actions(
        action_report,
        username
    )

    if permission_user is None:

        raise ValueError(
            f"Identity '{username}' not found "
            f"in permission_analysis.json"
        )

    if risk_user is None:

        raise ValueError(
            f"Identity '{username}' not found "
            f"in risk_report.json"
        )

    # ========================================================
    # MAP CLOUDTRAIL OPERATIONS
    # ========================================================

    iam_actions = map_actions(
        observed_actions
    )

    unmapped_actions = get_unmapped_actions(
        observed_actions
    )

    # ========================================================
    # PERMISSION ANALYSIS
    # ========================================================

    analysis = permission_user.get(
        "analysis",
        {}
    )

    excessive_policies = analysis.get(
        "potentially_excessive_policies",
        []
    )

    if not isinstance(
        excessive_policies,
        list
    ):

        excessive_policies = []

    # ========================================================
    # CONTEXT
    # ========================================================

    context = {

        "identity": {

            "name": username,

            "type": identity.get(
                "identity_type",
                "Unknown"
            ),

            "confidence": identity.get(
                "confidence",
                "Low"
            ),

            "risk_level": risk_user.get(
                "risk_level",
                "Unknown"
            ),

            "risk_score": risk_user.get(
                "total_risk",
                0
            )

        },

        "current_policies":
            permission_user.get(
                "assigned_policies",
                []
            ),

        "broad_policies":
            analysis.get(
                "broad_policies",
                []
            ),

        # AUTHORITATIVE FINDINGS
        "potentially_excessive_policies":
            excessive_policies,

        "least_privilege_status":
            analysis.get(
                "least_privilege_status",
                "Unknown"
            ),

        "observed_api_calls":
            permission_user.get(
                "observed_api_calls",
                0
            ),

        "observed_services":
            permission_user.get(
                "observed_services",
                []
            ),

        # Raw CloudTrail activity
        "observed_actions":
            observed_actions,

        # Confirmed IAM mappings
        "mapped_iam_actions":
            iam_actions,

        # Context only
        "unmapped_context_actions":
            unmapped_actions

    }

    return context


# ============================================================
# BUILD AI PROMPT
# ============================================================

def build_prompt(context):

    return f"""
You are an AWS IAM least-privilege security assistant.

Your job is to explain the supplied security analysis and
produce a conservative IAM policy recommendation.

You MUST obey these security rules.

============================================================
AUTHORITATIVE SECURITY RULES
============================================================

1. The deterministic security analysis is authoritative.

2. You MUST NOT invent an excessive permission.

3. You MUST NOT invent an excessive policy.

4. The ONLY policies that may be considered excessive are
   those already present in:

   potentially_excessive_policies

5. If potentially_excessive_policies is empty:

   excessive_permissions MUST be [].

6. If potentially_excessive_policies is empty:

   privilege_reduced MUST be false.

7. observed_actions are raw CloudTrail API operations.

8. observed_actions are NOT automatically IAM permissions.

9. Only mapped_iam_actions are confirmed IAM policy actions.

10. unmapped_context_actions MUST NOT be added to the
    recommended IAM policy.

11. Every required permission MUST come from
    mapped_iam_actions.

12. Do NOT invent permissions.

13. Do NOT invent AWS policy names.

14. Do NOT use Action "*".

15. Do NOT add sts:GetCallerIdentity merely because it
    appears in CloudTrail.

16. Do NOT claim that an AWS managed policy is excessive
    unless it appears in potentially_excessive_policies.

17. If there is no confirmed excessive permission/policy,
    describe the recommendation as a policy review candidate,
    NOT as confirmed remediation.

18. Resource "*" may be used when appropriate.

19. Return valid JSON only.

20. Do not return markdown.

============================================================
SECURITY CONTEXT
============================================================

{json.dumps(context, indent=2)}

============================================================
OUTPUT FORMAT
============================================================

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


# ============================================================
# EXTRACT OLLAMA CONTENT
# ============================================================

def extract_content(response):

    try:

        content = response.message.content

        if content:

            return content

    except Exception:

        pass

    try:

        content = response[
            "message"
        ][
            "content"
        ]

        if content:

            return content

    except Exception:

        pass

    raise ValueError(
        "Could not extract message.content "
        "from Ollama response."
    )


# ============================================================
# PARSE AI RESPONSE
# ============================================================

def parse_ai_response(response):

    content = extract_content(
        response
    )

    print()
    print("RAW AI CONTENT")
    print("-" * 60)
    print(content)
    print("-" * 60)

    content = content.strip()

    # Remove markdown fences
    if content.startswith("```"):

        content = content.replace(
            "```json",
            ""
        )

        content = content.replace(
            "```",
            ""
        )

        content = content.strip()

    try:

        return json.loads(
            content
        )

    except json.JSONDecodeError:

        start = content.find("{")

        end = content.rfind("}")

        if start != -1 and end != -1:

            extracted = content[
                start:end + 1
            ]

            try:

                return json.loads(
                    extracted
                )

            except json.JSONDecodeError:

                pass

    raise ValueError(
        "Ollama returned invalid JSON."
    )


# ============================================================
# SAFE RECOMMENDATION TEXT
# ============================================================

def build_safe_recommendation(
    context,
    excessive_policies,
    iam_actions
):

    if excessive_policies:

        return {

            "action":
                "Review the identified excessive "
                "policy permissions before remediation.",

            "reason":
                "The deterministic permission analysis "
                "identified potentially excessive policies: "
                + ", ".join(
                    excessive_policies
                )

        }

    if iam_actions:

        return {

            "action":
                "No confirmed excessive permission was "
                "identified. Keep the recommendation as "
                "a review candidate.",

            "reason":
                "Observed CloudTrail activity produced "
                "confirmed IAM mappings, but the deterministic "
                "analysis did not identify a confirmed "
                "excessive policy."

        }

    return {

        "action":
            "No IAM remediation is recommended.",

        "reason":
            "No confirmed excessive permission or policy "
            "was identified by the deterministic analysis."

    }


# ============================================================
# APPLY SECURITY GUARDRAILS
# ============================================================

def apply_guardrails(
    result,
    context
):

    # ========================================================
    # AUTHORITATIVE DATA
    # ========================================================

    iam_actions = context.get(
        "mapped_iam_actions",
        []
    )

    if not isinstance(
        iam_actions,
        list
    ):

        iam_actions = []

    excessive_policies = context.get(
        "potentially_excessive_policies",
        []
    )

    if not isinstance(
        excessive_policies,
        list
    ):

        excessive_policies = []

    # ========================================================
    # OBSERVED ACTION CHECK
    # ========================================================

    observed_actions = context.get(
        "observed_actions",
        []
    )

    if not observed_actions:

        raise ValueError(
            "Guardrail failed: no observed actions available."
        )

    # ========================================================
    # FORCE AUTHORITATIVE EXCESSIVE FINDINGS
    # ========================================================

    result[
        "excessive_permissions"
    ] = list(
        excessive_policies
    )

    # ========================================================
    # FORCE CONFIRMED REQUIRED PERMISSIONS
    # ========================================================

    result[
        "required_permissions"
    ] = list(
        iam_actions
    )

    # ========================================================
    # SAFE POLICY
    # ========================================================

    policy = {

        "Version":
            "2012-10-17",

        "Statement": [

            {

                "Effect":
                    "Allow",

                "Action":
                    sorted(
                        set(
                            iam_actions
                        )
                    ),

                "Resource":
                    "*"

            }

        ]

    }

    result[
        "recommended_policy"
    ] = policy

    # ========================================================
    # SAFE RECOMMENDATION
    # ========================================================

    result[
        "recommendation"
    ] = build_safe_recommendation(

        context,

        excessive_policies,

        iam_actions

    )

    # ========================================================
    # SECURITY IMPACT
    # ========================================================

    administrator_removed = (
        "AdministratorAccess"
        in excessive_policies
    )

    full_access_removed = (
        "AmazonEC2FullAccess"
        in excessive_policies
    )

    result[
        "security_impact"
    ] = {

        "privilege_reduced":
            bool(
                excessive_policies
            ),

        "administrator_access_removed":
            administrator_removed,

        "full_access_removed":
            full_access_removed

    }

    # ========================================================
    # FORCE IDENTITY INFORMATION
    # ========================================================

    result[
        "identity"
    ] = {

        "name":
            context["identity"]["name"],

        "type":
            context["identity"]["type"],

        "risk_level":
            context["identity"]["risk_level"],

        "risk_score":
            context["identity"]["risk_score"]

    }

    # ========================================================
    # FINAL STATUS
    # ========================================================

    result[
        "ai_status"
    ] = "GENERATED"

    return result


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)

    print(
        "        SAFE AI POLICY RECOMMENDER"
    )

    print("=" * 60)

    print()

    print(
        f"Target identity: {TARGET_IDENTITY}"
    )

    # ========================================================
    # LOAD REPORTS
    # ========================================================

    permission_report = load_json(
        PERMISSION_FILE
    )

    identity_report = load_json(
        IDENTITY_FILE
    )

    risk_report = load_json(
        RISK_FILE
    )

    action_report = load_json(
        ACTIONS_FILE
    )

    # ========================================================
    # BUILD CONTEXT
    # ========================================================

    context = build_context(

        permission_report,

        identity_report,

        risk_report,

        action_report,

        TARGET_IDENTITY

    )

    print()

    print(
        "COMPACT AI INPUT"
    )

    print(
        "-" * 60
    )

    print(
        json.dumps(
            context,
            indent=2
        )
    )

    # ========================================================
    # BUILD PROMPT
    # ========================================================

    prompt = build_prompt(
        context
    )

    print()

    print(
        "Sending compact context to Ollama..."
    )

    print(
        f"Model: {MODEL}"
    )

    try:

        response = ollama.chat(

            model=MODEL,

            messages=[

                {

                    "role":
                        "user",

                    "content":
                        prompt

                }

            ],

            format="json",

            options={

                "temperature":
                    0,

                "num_predict":
                    500

            }

        )

        # ====================================================
        # PARSE AI RESULT
        # ====================================================

        result = parse_ai_response(
            response
        )

        # ====================================================
        # APPLY SECURITY GUARDRAILS
        # ====================================================

        result = apply_guardrails(

            result,

            context

        )

        # ====================================================
        # SAVE
        # ====================================================

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

        # ====================================================
        # DISPLAY
        # ====================================================

        print()

        print("=" * 60)

        print(
            "AI POLICY RECOMMENDATION"
        )

        print("=" * 60)

        print()

        print(
            f"Identity       : "
            f"{TARGET_IDENTITY}"
        )

        print(

            f"Risk Level     : "
            f"{result['identity']['risk_level']}"

        )

        print(

            f"Risk Score     : "
            f"{result['identity']['risk_score']}"

        )

        print()

        print(
            "Excessive Permissions"
        )

        if result[
            "excessive_permissions"
        ]:

            for permission in result[
                "excessive_permissions"
            ]:

                print(
                    f"  - {permission}"
                )

        else:

            print(
                "  None confirmed"
            )

        print()

        print(
            "Required Permissions"
        )

        if result[
            "required_permissions"
        ]:

            for action in result[
                "required_permissions"
            ]:

                print(
                    f"  - {action}"
                )

        else:

            print(
                "  None"
            )

        print()

        print(
            "Recommendation"
        )

        print(
            "-" * 60
        )

        print(
            result[
                "recommendation"
            ][
                "action"
            ]
        )

        print(
            result[
                "recommendation"
            ][
                "reason"
            ]
        )

        print()

        print(
            "Recommended Policy"
        )

        print(
            "-" * 60
        )

        print(

            json.dumps(

                result[
                    "recommended_policy"
                ],

                indent=4

            )

        )

        print()

        print(
            "Security Impact"
        )

        print(
            "-" * 60
        )

        impact = result[
            "security_impact"
        ]

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

        print(
            "Output saved to:"
        )

        print(
            OUTPUT_FILE
        )

        print()

        print("=" * 60)

        print(
            "AI STATUS: GENERATED"
        )

        print("=" * 60)

    except Exception as error:

        print()

        print(
            "ERROR: Ollama recommendation failed."
        )

        print(
            str(error)
        )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()