import json
import os


BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)


# ============================================================
# INPUT REPORTS
# ============================================================

AI_REMEDIATION_REPORT = os.path.join(
    BASE_DIR,
    "reports",
    "ci_ai_remediation_report.json"
)

VALIDATION_REPORT = os.path.join(
    BASE_DIR,
    "reports",
    "ci_remediation_validation_report.json"
)

OUTPUT_REPORT = os.path.join(
    BASE_DIR,
    "reports",
    "ci_post_remediation_verification_report.json"
)


# ============================================================
# LOAD JSON
# ============================================================

def load_json(path):

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:

        return json.load(f)


# ============================================================
# LOAD REPORTS
# ============================================================

try:

    remediation = load_json(
        AI_REMEDIATION_REPORT
    )

    validation = load_json(
        VALIDATION_REPORT
    )

except Exception as error:

    print("=" * 60)
    print("POST-REMEDIATION VERIFICATION")
    print("=" * 60)

    print()
    print("ERROR: Unable to load required reports.")
    print(error)

    exit()


# ============================================================
# BASIC DATA
# ============================================================

identity = remediation.get(
    "identity",
    "Unknown"
)

identity_type = remediation.get(
    "identity_type",
    "Unknown"
)

excessive_permissions = remediation.get(
    "excessive_permissions",
    []
)

required_permissions = remediation.get(
    "required_permissions",
    []
)

recommended_policy = remediation.get(
    "recommended_policy",
    {}
)


# ============================================================
# GET RECOMMENDED ACTIONS
# ============================================================

statements = recommended_policy.get(
    "Statement",
    []
)

if not isinstance(
    statements,
    list
):

    statements = []


recommended_actions = []

if statements:

    recommended_actions = statements[0].get(
        "Action",
        []
    )

    if isinstance(
        recommended_actions,
        str
    ):

        recommended_actions = [
            recommended_actions
        ]


# ============================================================
# DISPLAY HEADER
# ============================================================

print("=" * 60)
print("POST-REMEDIATION VERIFICATION")
print("=" * 60)

print()
print("Identity:", identity)
print("Identity Type:", identity_type)


# ============================================================
# 1. EXCESSIVE PERMISSION REMOVAL
# ============================================================

print()
print("1. EXCESSIVE PERMISSION REMOVAL")
print("-" * 60)


remaining_excessive = []

for permission in excessive_permissions:

    if permission in recommended_actions:

        remaining_excessive.append(
            permission
        )


if not remaining_excessive:

    excessive_status = "PASS"

    print(
        "Status: PASS"
    )

    print(
        "No excessive permissions remain."
    )

else:

    excessive_status = "FAIL"

    print(
        "Status: FAIL"
    )

    for permission in remaining_excessive:

        print(
            "Still present:",
            permission
        )


# ============================================================
# 2. REQUIRED ACTION PRESERVATION
# ============================================================

print()
print("2. REQUIRED ACTION PRESERVATION")
print("-" * 60)


missing_actions = []

for action in required_permissions:

    if action not in recommended_actions:

        missing_actions.append(
            action
        )


if not missing_actions:

    action_status = "PASS"

    print(
        "Status: PASS"
    )

    for action in required_permissions:

        print(
            "Preserved:",
            action
        )

else:

    action_status = "FAIL"

    print(
        "Status: FAIL"
    )

    for action in missing_actions:

        print(
            "Missing:",
            action
        )


# ============================================================
# 3. WILDCARD ACTION CHECK
# ============================================================

print()
print("3. WILDCARD ACTION CHECK")
print("-" * 60)


wildcard_action = (
    "*" in recommended_actions
)


if wildcard_action:

    wildcard_status = "FAIL"

    print(
        "Status: FAIL"
    )

    print(
        "Wildcard Action detected."
    )

else:

    wildcard_status = "PASS"

    print(
        "Status: PASS"
    )

    print(
        "No wildcard Action detected."
    )


# ============================================================
# 4. PREVIOUS VALIDATION
# ============================================================

print()
print("4. PREVIOUS VALIDATION")
print("-" * 60)


previous_validation = validation.get(
    "validation_status",
    "UNKNOWN"
)


print(
    "Previous validation:",
    previous_validation
)


if previous_validation == "VERIFIED":

    validation_status = "PASS"

    print(
        "Status: PASS"
    )

else:

    validation_status = "FAIL"

    print(
        "Status: FAIL"
    )


# ============================================================
# 5. AWS CHANGE CHECK
# ============================================================

print()
print("5. AWS CHANGE CHECK")
print("-" * 60)


aws_policy_attached = validation.get(
    "aws_policy_attached",
    False
)

aws_changes_performed = validation.get(
    "aws_changes_performed",
    False
)


if (
    aws_policy_attached is False
    and aws_changes_performed is False
):

    aws_status = "PASS"

    print(
        "Status: PASS"
    )

    print(
        "No AWS policy was attached."
    )

    print(
        "No AWS changes were performed."
    )

else:

    aws_status = "FAIL"

    print(
        "Status: FAIL"
    )

    print(
        "AWS policy attached:",
        aws_policy_attached
    )

    print(
        "AWS changes performed:",
        aws_changes_performed
    )


# ============================================================
# 6. AI REMEDIATION REPORT CHECK
# ============================================================

print()
print("6. AI REMEDIATION REPORT CHECK")
print("-" * 60)


ai_status = remediation.get(
    "ai_status",
    "UNKNOWN"
)


if ai_status == "GENERATED":

    ai_report_status = "PASS"

    print(
        "Status: PASS"
    )

    print(
        "AI remediation report is valid."
    )

else:

    ai_report_status = "FAIL"

    print(
        "Status: FAIL"
    )

    print(
        "AI status:",
        ai_status
    )


# ============================================================
# FINAL VERIFICATION
# ============================================================

print()
print("7. FINAL VERIFICATION")
print("-" * 60)


all_checks_passed = (

    excessive_status == "PASS"

    and action_status == "PASS"

    and wildcard_status == "PASS"

    and validation_status == "PASS"

    and aws_status == "PASS"

    and ai_report_status == "PASS"

)


if all_checks_passed:

    final_status = (
        "POST_REMEDIATION_VERIFIED"
    )

    print(
        "Status: POST-REMEDIATION VERIFIED"
    )

else:

    final_status = (
        "POST_REMEDIATION_FAILED"
    )

    print(
        "Status: POST-REMEDIATION FAILED"
    )


# ============================================================
# BUILD REPORT
# ============================================================

report = {

    "module":
        "Cloud Least Privilege Post-Remediation Verification",

    "identity":
        identity,

    "identity_type":
        identity_type,

    "verification_type":
        "SYNTHETIC",

    "source_reports": {

        "ai_remediation_report":
            AI_REMEDIATION_REPORT,

        "validation_report":
            VALIDATION_REPORT

    },

    "before_remediation": {

        "excessive_permissions":
            excessive_permissions,

        "required_permissions":
            required_permissions

    },

    "after_remediation": {

        "recommended_actions":
            recommended_actions,

        "remaining_excessive_permissions":
            remaining_excessive,

        "missing_required_actions":
            missing_actions

    },

    "checks": {

        "excessive_permission_removal":
            excessive_status,

        "required_action_preservation":
            action_status,

        "wildcard_action_check":
            wildcard_status,

        "previous_validation":
            validation_status,

        "aws_change_check":
            aws_status,

        "ai_remediation_report":
            ai_report_status

    },

    "aws_policy_attached":
        False,

    "aws_changes_performed":
        False,

    "final_status":
        final_status

}


# ============================================================
# SAVE REPORT
# ============================================================

with open(
    OUTPUT_REPORT,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        report,
        f,
        indent=4
    )


# ============================================================
# FINAL OUTPUT
# ============================================================

print()
print("=" * 60)

if all_checks_passed:

    print(
        "POST-REMEDIATION VERIFICATION: VERIFIED"
    )

else:

    print(
        "POST-REMEDIATION VERIFICATION: FAILED"
    )

print("=" * 60)

print()
print(
    "AWS POLICY ATTACHED     :",
    False
)

print(
    "AWS CHANGES PERFORMED  :",
    False
)

print()
print(
    "Report saved:"
)

print(
    OUTPUT_REPORT
)