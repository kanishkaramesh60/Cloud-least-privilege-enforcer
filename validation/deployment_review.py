import json
from pathlib import Path

from ai.iam_action_mapper import (
    map_actions,
    get_unmapped_actions
)


# ============================================================
# BASE CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

AI_POLICY_FILE = (
    BASE_DIR
    / "reports"
    / "ai_recommended_policies.json"
)

VERIFICATION_FILE = (
    BASE_DIR
    / "reports"
    / "verification_controller_report.json"
)

OUTPUT_FILE = (
    BASE_DIR
    / "reports"
    / "deployment_review_report.json"
)


# ============================================================
# DEPLOYMENT SAFETY CONFIGURATION
# ============================================================

# IMPORTANT:
# This is the identity that may be considered for remediation.
#
# Least_privilege is the scanner identity and must NEVER be
# automatically modified by this deployment pipeline.

TARGET_IDENTITY = "LeastPrivilegeDemoUser"

ALLOWED_IDENTITY_TYPE = "IAM User"


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
# EXTRACT POLICY ACTIONS
# ============================================================

def extract_policy_actions(policy):

    actions = []

    for statement in policy.get(
        "Statement",
        []
    ):

        action = statement.get(
            "Action",
            []
        )

        if isinstance(
            action,
            str
        ):

            actions.append(
                action
            )

        elif isinstance(
            action,
            list
        ):

            actions.extend(
                action
            )

    return sorted(
        set(actions)
    )


# ============================================================
# WILDCARD ACTION CHECK
# ============================================================

def contains_wildcard_action(
    actions
):

    return "*" in actions


# ============================================================
# REVIEW POLICY
# ============================================================

def review_policy(
    ai_data,
    verification_data
):

    identity = ai_data.get(
        "identity",
        {}
    )

    policy = ai_data.get(
        "recommended_policy"
    )

    checks = []

    # --------------------------------------------------------
    # 1. TARGET IDENTITY CHECK
    # --------------------------------------------------------

    identity_name = identity.get(
        "name"
    )

    identity_type = identity.get(
        "type"
    )

    identity_check = (
        identity_name == TARGET_IDENTITY
        and
        identity_type == ALLOWED_IDENTITY_TYPE
    )

    checks.append({

        "check":
            "Target identity",

        "expected":
            TARGET_IDENTITY,

        "actual":
            identity_name,

        "status":
            "PASS"
            if identity_check
            else "FAIL"
    })

    # --------------------------------------------------------
    # 2. IDENTITY TYPE CHECK
    # --------------------------------------------------------

    identity_type_check = (
        identity_type
        == ALLOWED_IDENTITY_TYPE
    )

    checks.append({

        "check":
            "Identity type",

        "expected":
            ALLOWED_IDENTITY_TYPE,

        "actual":
            identity_type,

        "status":
            "PASS"
            if identity_type_check
            else "FAIL"
    })

    # --------------------------------------------------------
    # 3. VERIFICATION STATUS
    # --------------------------------------------------------

    final_status = verification_data.get(
        "final_status"
    )

    verification_check = (
        final_status
        == "VERIFIED"
    )

    checks.append({

        "check":
            "Verification status",

        "expected":
            "VERIFIED",

        "actual":
            final_status,

        "status":
            "PASS"
            if verification_check
            else "FAIL"
    })

    # --------------------------------------------------------
    # 4. DEPLOYMENT REVIEW FLAG
    # --------------------------------------------------------

    review_ready = verification_data.get(
        "ready_for_deployment_review",
        False
    )

    review_ready_check = (
        review_ready is True
    )

    checks.append({

        "check":
            "Ready for deployment review",

        "expected":
            True,

        "actual":
            review_ready,

        "status":
            "PASS"
            if review_ready_check
            else "FAIL"
    })

    # --------------------------------------------------------
    # 5. ACCESS ANALYZER
    # --------------------------------------------------------

    analyzer_pass = False

    attempts = verification_data.get(
        "attempts",
        []
    )

    latest_attempt = {}

    if attempts:

        latest_attempt = attempts[-1]

        analyzer = latest_attempt.get(
            "access_analyzer",
            {}
        )

        analyzer_pass = (
            analyzer.get(
                "status"
            )
            == "PASS"
        )

    checks.append({

        "check":
            "AWS Access Analyzer",

        "expected":
            "PASS",

        "actual":
            "PASS"
            if analyzer_pass
            else "FAIL",

        "status":
            "PASS"
            if analyzer_pass
            else "FAIL"
    })

    # --------------------------------------------------------
    # 6. IAM POLICY SIMULATOR
    # --------------------------------------------------------

    simulator_pass = False

    if attempts:

        simulator = latest_attempt.get(
            "iam_simulator",
            {}
        )

        simulator_pass = (
            simulator.get(
                "status"
            )
            == "PASS"
        )

    checks.append({

        "check":
            "IAM Policy Simulator",

        "expected":
            "PASS",

        "actual":
            "PASS"
            if simulator_pass
            else "FAIL",

        "status":
            "PASS"
            if simulator_pass
            else "FAIL"
    })

    # --------------------------------------------------------
    # 7. POLICY EXISTS
    # --------------------------------------------------------

    policy_exists = (
        isinstance(
            policy,
            dict
        )
        and
        bool(policy)
    )

    checks.append({

        "check":
            "Recommended policy exists",

        "expected":
            True,

        "actual":
            policy_exists,

        "status":
            "PASS"
            if policy_exists
            else "FAIL"
    })

    # --------------------------------------------------------
    # 8. WILDCARD ACTION CHECK
    # --------------------------------------------------------

    policy_actions = []

    if policy_exists:

        policy_actions = (
            extract_policy_actions(
                policy
            )
        )

    wildcard_action = (
        contains_wildcard_action(
            policy_actions
        )
    )

    checks.append({

        "check":
            "Wildcard Action",

        "expected":
            "Not present",

        "actual":
            "*"
            if wildcard_action
            else "Not present",

        "status":
            "FAIL"
            if wildcard_action
            else "PASS"
    })

    # --------------------------------------------------------
    # 9. IAM ACTION COVERAGE
    # --------------------------------------------------------
    #
    # IMPORTANT:
    #
    # CloudTrail API operations are not always identical to
    # IAM policy action names.
    #
    # Example:
    #
    # CloudTrail:
    #     s3:ListBuckets
    #
    # Confirmed IAM mapping:
    #     s3:ListAllMyBuckets
    #
    # Therefore we compare the recommended policy against
    # CONFIRMED IAM ACTIONS, not raw CloudTrail operations.
    #
    # Unmapped actions such as:
    #
    #     sts:GetCallerIdentity
    #
    # remain contextual evidence and are NOT automatically
    # treated as required permissions.
    # --------------------------------------------------------

    observed_actions = (
        verification_data.get(
            "verification_basis",
            {}
        ).get(
            "observed_actions",
            []
        )
    )

    mapped_actions = map_actions(
        observed_actions
    )

    unmapped_actions = get_unmapped_actions(
        observed_actions
    )

    missing_iam_actions = [

        action

        for action in mapped_actions

        if action not in policy_actions
    ]

    coverage_pass = (
        len(
            missing_iam_actions
        ) == 0
    )

    checks.append({

        "check":
            "IAM action coverage",

        "expected":
            "All confirmed IAM actions included",

        "actual":
            "All covered"
            if coverage_pass
            else missing_iam_actions,

        "status":
            "PASS"
            if coverage_pass
            else "FAIL"
    })

    # --------------------------------------------------------
    # 10. AI STATUS
    # --------------------------------------------------------

    ai_status = ai_data.get(
        "ai_status"
    )

    ai_status_check = (
        ai_status
        == "GENERATED"
    )

    checks.append({

        "check":
            "AI recommendation status",

        "expected":
            "GENERATED",

        "actual":
            ai_status,

        "status":
            "PASS"
            if ai_status_check
            else "FAIL"
    })

    # --------------------------------------------------------
    # FINAL REVIEW DECISION
    # --------------------------------------------------------

    all_passed = all(
        check["status"] == "PASS"
        for check in checks
    )

    return {

        "checks":
            checks,

        "policy_actions":
            policy_actions,

        "observed_actions":
            observed_actions,

        "mapped_iam_actions":
            mapped_actions,

        "unmapped_context_actions":
            unmapped_actions,

        "missing_iam_actions":
            missing_iam_actions,

        "review_status":

            "APPROVED_FOR_HUMAN_REVIEW"

            if all_passed

            else "REVIEW_BLOCKED"
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "=" * 65
    )

    print(
        "          CLOUD LEAST PRIVILEGE DEPLOYMENT REVIEW"
    )

    print(
        "=" * 65
    )

    # --------------------------------------------------------
    # FILE CHECKS
    # --------------------------------------------------------

    if not AI_POLICY_FILE.exists():

        print()

        print(
            "ERROR: AI recommendation file not found."
        )

        print(
            AI_POLICY_FILE
        )

        return

    if not VERIFICATION_FILE.exists():

        print()

        print(
            "ERROR: Verification report not found."
        )

        print(
            VERIFICATION_FILE
        )

        return

    # --------------------------------------------------------
    # LOAD FILES
    # --------------------------------------------------------

    ai_data = load_json(
        AI_POLICY_FILE
    )

    verification_data = load_json(
        VERIFICATION_FILE
    )

    # --------------------------------------------------------
    # RUN REVIEW
    # --------------------------------------------------------

    result = review_policy(
        ai_data,
        verification_data
    )

    identity = ai_data.get(
        "identity",
        {}
    )

    # --------------------------------------------------------
    # DISPLAY IDENTITY
    # --------------------------------------------------------

    print()

    print(
        "Identity   :",
        identity.get(
            "name"
        )
    )

    print(
        "Type       :",
        identity.get(
            "type"
        )
    )

    print(
        "Risk Level :",
        identity.get(
            "risk_level"
        )
    )

    print(
        "Risk Score :",
        identity.get(
            "risk_score"
        )
    )

    print()

    print(
        "TARGET IDENTITY ALLOWED FOR REMEDIATION:"
    )

    print(
        " -",
        TARGET_IDENTITY
    )

    print()

    # --------------------------------------------------------
    # DISPLAY REVIEW CHECKS
    # --------------------------------------------------------

    print(
        "DEPLOYMENT REVIEW CHECKS"
    )

    print(
        "-" * 65
    )

    for check in result[
        "checks"
    ]:

        print(

            f"[{check['status']}] "
            f"{check['check']}"
        )

        print(
            "    Expected:",
            check["expected"]
        )

        print(
            "    Actual  :",
            check["actual"]
        )

    # --------------------------------------------------------
    # DISPLAY ACTION INFORMATION
    # --------------------------------------------------------

    print()

    print(
        "OBSERVED CLOUDTRAIL ACTIONS"
    )

    print(
        "-" * 65
    )

    for action in result[
        "observed_actions"
    ]:

        print(
            " -",
            action
        )

    print()

    print(
        "CONFIRMED IAM ACTIONS"
    )

    print(
        "-" * 65
    )

    for action in result[
        "mapped_iam_actions"
    ]:

        print(
            " -",
            action
        )

    print()

    print(
        "UNMAPPED / CONTEXT ACTIONS"
    )

    print(
        "-" * 65
    )

    for action in result[
        "unmapped_context_actions"
    ]:

        print(
            " -",
            action
        )

    # --------------------------------------------------------
    # FINAL STATUS
    # --------------------------------------------------------

    print()

    print(
        "=" * 65
    )

    print(
        "REVIEW STATUS:",
        result[
            "review_status"
        ]
    )

    print(
        "AWS CHANGES PERFORMED: False"
    )

    print(
        "=" * 65
    )

    # --------------------------------------------------------
    # SAVE REPORT
    # --------------------------------------------------------

    report = {

        "module":
            "Cloud Least Privilege Deployment Review",

        "target_identity":
            TARGET_IDENTITY,

        "allowed_identity_type":
            ALLOWED_IDENTITY_TYPE,

        "identity":
            identity,

        "policy_actions":
            result[
                "policy_actions"
            ],

        "observed_actions":
            result[
                "observed_actions"
            ],

        "mapped_iam_actions":
            result[
                "mapped_iam_actions"
            ],

        "unmapped_context_actions":
            result[
                "unmapped_context_actions"
            ],

        "missing_iam_actions":
            result[
                "missing_iam_actions"
            ],

        "checks":
            result[
                "checks"
            ],

        "review_status":
            result[
                "review_status"
            ],

        "human_approval_required":
            True,

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

    print()

    print(
        "Report saved:"
    )

    print(
        OUTPUT_FILE
    )


# ============================================================
# PROGRAM ENTRY
# ============================================================

if __name__ == "__main__":

    main()