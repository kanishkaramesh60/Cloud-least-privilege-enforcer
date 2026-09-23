import json
from pathlib import Path
from datetime import datetime, timezone

import boto3


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

AI_POLICY_FILE = (
    BASE_DIR
    / "reports"
    / "ai_recommended_policies.json"
)

REVIEW_FILE = (
    BASE_DIR
    / "reports"
    / "deployment_review_report.json"
)

OUTPUT_FILE = (
    BASE_DIR
    / "reports"
    / "deployment_controller_report.json"
)


# ============================================================
# SAFETY CONFIGURATION
# ============================================================

# IMPORTANT:
# This is the identity that may be remediated.
#
# The scanner identity "Least_privilege" must NEVER be
# modified by this controller.

TARGET_IDENTITY = "LeastPrivilegeDemoUser"

TARGET_TYPE = "IAM User"


# ------------------------------------------------------------
# Separate deployment identity
# ------------------------------------------------------------

DEPLOYER_PROFILE = "leastprivilege-deployer"

REGION = "ap-south-1"


# ------------------------------------------------------------
# Safety switch
#
# True  = inspect and simulate deployment only
# False = allow real AWS changes
#
# KEEP THIS TRUE until the dry run has been reviewed.
# ------------------------------------------------------------

DRY_RUN = True


# ============================================================
# LOAD JSON
# ============================================================

def load_json(path):

    if not path.exists():

        raise FileNotFoundError(
            f"File not found: {path}"
        )

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


# ============================================================
# SAVE JSON
# ============================================================

def save_json(
    path,
    data
):

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            data,
            file,
            indent=4
        )


# ============================================================
# EXTRACT POLICY ACTIONS
# ============================================================

def extract_actions(policy):

    actions = []

    statements = policy.get(
        "Statement",
        []
    )

    if isinstance(
        statements,
        dict
    ):

        statements = [
            statements
        ]

    for statement in statements:

        action = statement.get(
            "Action",
            []
        )

        if isinstance(
            action,
            str
        ):

            action = [
                action
            ]

        actions.extend(
            action
        )

    return sorted(
        set(actions)
    )


# ============================================================
# EXTRACT CURRENT ATTACHED POLICIES
# ============================================================

def get_attached_policies(
    iam_client,
    username
):

    response = (
        iam_client.list_attached_user_policies(
            UserName=username
        )
    )

    policies = []

    for policy in response.get(
        "AttachedPolicies",
        []
    ):

        policies.append({

            "policy_name":
                policy.get(
                    "PolicyName"
                ),

            "policy_arn":
                policy.get(
                    "PolicyArn"
                )
        })

    return policies


# ============================================================
# GET USER
# ============================================================

def get_target_user(
    iam_client,
    username
):

    response = iam_client.get_user(
        UserName=username
    )

    return response.get(
        "User",
        {}
    )


# ============================================================
# SAFETY CHECKS
# ============================================================

def run_safety_checks(
    ai_data,
    review_data
):

    checks = []

    identity = ai_data.get(
        "identity",
        {}
    )

    # --------------------------------------------------------
    # 1. TARGET IDENTITY
    # --------------------------------------------------------

    identity_name = identity.get(
        "name"
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
            if identity_name == TARGET_IDENTITY
            else "FAIL"
    })

    # --------------------------------------------------------
    # 2. IDENTITY TYPE
    # --------------------------------------------------------

    identity_type = identity.get(
        "type"
    )

    checks.append({

        "check":
            "Identity type",

        "expected":
            TARGET_TYPE,

        "actual":
            identity_type,

        "status":
            "PASS"
            if identity_type == TARGET_TYPE
            else "FAIL"
    })

    # --------------------------------------------------------
    # 3. DEPLOYMENT REVIEW
    # --------------------------------------------------------

    review_status = review_data.get(
        "review_status"
    )

    checks.append({

        "check":
            "Deployment review",

        "expected":
            "APPROVED_FOR_HUMAN_REVIEW",

        "actual":
            review_status,

        "status":
            "PASS"
            if review_status
            == "APPROVED_FOR_HUMAN_REVIEW"
            else "FAIL"
    })

    # --------------------------------------------------------
    # 4. RECOMMENDED POLICY
    # --------------------------------------------------------

    policy = ai_data.get(
        "recommended_policy"
    )

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
    # 5. POLICY ACTIONS
    # --------------------------------------------------------

    actions = extract_actions(
        policy
    ) if policy_exists else []

    checks.append({

        "check":
            "Policy contains actions",

        "expected":
            "At least one action",

        "actual":
            actions,

        "status":
            "PASS"
            if actions
            else "FAIL"
    })

    # --------------------------------------------------------
    # 6. WILDCARD ACTION
    # --------------------------------------------------------

    wildcard_present = (
        "*" in actions
    )

    checks.append({

        "check":
            "Wildcard Action",

        "expected":
            "Not present",

        "actual":
            "*"
            if wildcard_present
            else "Not present",

        "status":
            "FAIL"
            if wildcard_present
            else "PASS"
    })

    # --------------------------------------------------------
    # 7. VERIFICATION REPORT
    # --------------------------------------------------------

    verification_status = (
        review_data.get(
            "review_status"
        )
        == "APPROVED_FOR_HUMAN_REVIEW"
    )

    checks.append({

        "check":
            "Verification/deployment review",

        "expected":
            True,

        "actual":
            verification_status,

        "status":
            "PASS"
            if verification_status
            else "FAIL"
    })

    return (
        checks,
        actions
    )


# ============================================================
# HUMAN APPROVAL
# ============================================================

def request_approval(
    identity,
    actions
):

    print()

    print(
        "=" * 65
    )

    print(
        "                 HUMAN DEPLOYMENT APPROVAL"
    )

    print(
        "=" * 65
    )

    print()

    print(
        "Target Identity :",
        identity
    )

    print(
        "Deployment Mode :",
        "DRY RUN"
        if DRY_RUN
        else "LIVE"
    )

    print()

    print(
        "Policy Actions:"
    )

    print(
        "-" * 65
    )

    for action in actions:

        print(
            " -",
            action
        )

    print()

    if DRY_RUN:

        print(
            "No AWS changes will be made during DRY RUN."
        )

    else:

        print(
            "WARNING: LIVE AWS changes are enabled."
        )

        print(
            "The target IAM user's policies may be modified."
        )

    print()

    response = input(
        "Type APPROVE to continue or anything else to cancel: "
    ).strip()

    return response == "APPROVE"


# ============================================================
# CREATE DEPLOYMENT POLICY NAME
# ============================================================

def generate_policy_name():

    timestamp = datetime.now(
        timezone.utc
    ).strftime(
        "%Y%m%d%H%M%S"
    )

    return (
        "LeastPrivilegeRemediation-"
        + TARGET_IDENTITY
        + "-"
        + timestamp
    )


# ============================================================
# CREATE CUSTOMER-MANAGED POLICY
# ============================================================

def create_customer_managed_policy(
    iam_client,
    policy_document
):

    policy_name = generate_policy_name()

    response = (
        iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(
                policy_document,
                separators=(
                    ",",
                    ":"
                )
            ),
            Description=(
                "Least privilege remediation "
                "policy generated by Cloud "
                "Least Privilege Enforcer"
            )
        )
    )

    policy = response.get(
        "Policy",
        {}
    )

    return {

        "policy_name":
            policy.get(
                "PolicyName"
            ),

        "policy_arn":
            policy.get(
                "Arn"
            ),

        "policy_id":
            policy.get(
                "PolicyId"
            )
    }


# ============================================================
# ATTACH POLICY
# ============================================================

def attach_policy(
    iam_client,
    username,
    policy_arn
):

    iam_client.attach_user_policy(

        UserName=username,

        PolicyArn=policy_arn
    )


# ============================================================
# DETACH POLICY
# ============================================================

def detach_policy(
    iam_client,
    username,
    policy_arn
):

    iam_client.detach_user_policy(

        UserName=username,

        PolicyArn=policy_arn
    )


# ============================================================
# VERIFY DEPLOYMENT
# ============================================================

def verify_deployment(
    iam_client,
    username,
    new_policy_arn,
    old_policy_arn
):

    attached_policies = (
        get_attached_policies(
            iam_client,
            username
        )
    )

    attached_arns = {

        policy[
            "policy_arn"
        ]

        for policy in attached_policies
    }

    new_policy_attached = (
        new_policy_arn
        in attached_arns
    )

    old_policy_detached = (
        old_policy_arn
        not in attached_arns
    )

    return {

        "new_policy_attached":
            new_policy_attached,

        "old_policy_detached":
            old_policy_detached,

        "verified":
            (
                new_policy_attached
                and
                old_policy_detached
            ),

        "attached_policies":
            attached_policies
    }


# ============================================================
# ROLLBACK
# ============================================================

def rollback_deployment(
    iam_client,
    username,
    new_policy_arn,
    old_policy_arn
):

    rollback_actions = []

    # --------------------------------------------------------
    # Detach new policy if attached
    # --------------------------------------------------------

    try:

        detach_policy(
            iam_client,
            username,
            new_policy_arn
        )

        rollback_actions.append({

            "action":
                "Detach replacement policy",

            "status":
                "PASS"
        })

    except Exception as error:

        rollback_actions.append({

            "action":
                "Detach replacement policy",

            "status":
                "FAIL",

            "error":
                str(error)
        })

    # --------------------------------------------------------
    # Restore old policy
    # --------------------------------------------------------

    try:

        attach_policy(
            iam_client,
            username,
            old_policy_arn
        )

        rollback_actions.append({

            "action":
                "Reattach original policy",

            "status":
                "PASS"
        })

    except Exception as error:

        rollback_actions.append({

            "action":
                "Reattach original policy",

            "status":
                "FAIL",

            "error":
                str(error)
        })

    rollback_success = all(

        item["status"]
        == "PASS"

        for item in rollback_actions
    )

    return {

        "status":
            "ROLLBACK_SUCCESS"
            if rollback_success
            else "ROLLBACK_FAILED",

        "actions":
            rollback_actions
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print()

    print(
        "=" * 65
    )

    print(
        "        CLOUD LEAST PRIVILEGE DEPLOYMENT CONTROLLER"
    )

    print(
        "=" * 65
    )

    try:

        # ----------------------------------------------------
        # LOAD REPORTS
        # ----------------------------------------------------

        ai_data = load_json(
            AI_POLICY_FILE
        )

        review_data = load_json(
            REVIEW_FILE
        )

        identity = ai_data.get(
            "identity",
            {}
        )

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
            "Deployment Mode :",
            "DRY RUN"
            if DRY_RUN
            else "LIVE"
        )

        print(
            "Target Identity :",
            TARGET_IDENTITY
        )

        print(
            "Deployer Profile:",
            DEPLOYER_PROFILE
        )

        # ----------------------------------------------------
        # SAFETY CHECKS
        # ----------------------------------------------------

        print()

        print(
            "DEPLOYMENT SAFETY CHECKS"
        )

        print(
            "-" * 65
        )

        checks, actions = (
            run_safety_checks(
                ai_data,
                review_data
            )
        )

        all_passed = all(

            check["status"]
            == "PASS"

            for check in checks
        )

        for check in checks:

            print(

                f"[{check['status']}] "
                f"{check['check']}"
            )

        # ----------------------------------------------------
        # BLOCK IF SAFETY CHECK FAILS
        # ----------------------------------------------------

        if not all_passed:

            print()

            print(
                "=" * 65
            )

            print(
                "DEPLOYMENT STATUS: BLOCKED"
            )

            print(
                "=" * 65
            )

            report = {

                "module":
                    "Cloud Least Privilege "
                    "Deployment Controller",

                "target_identity":
                    TARGET_IDENTITY,

                "identity":
                    identity,

                "deployment_mode":
                    "DRY_RUN"
                    if DRY_RUN
                    else "LIVE",

                "human_approval":
                    False,

                "deployment_performed":
                    False,

                "status":
                    "BLOCKED",

                "safety_checks":
                    checks
            }

            save_json(
                OUTPUT_FILE,
                report
            )

            print()

            print(
                "Report saved:"
            )

            print(
                OUTPUT_FILE
            )

            return

        # ----------------------------------------------------
        # REMEDIATION SAFETY GATE
        # ----------------------------------------------------

        excessive_permissions = (
            ai_data.get(
                "excessive_permissions",
                []
            )
        )

        # IMPORTANT:
        #
        # A generated narrower policy is NOT enough by itself
        # to justify modifying the user's access.
        #
        # The current evidence contains no confirmed excessive
        # permissions, so automatic remediation remains blocked.
        #

        if not excessive_permissions:

            print()

            print(
                "=" * 65
            )

            print(
                "              NO REMEDIATION REQUIRED"
            )

            print(
                "=" * 65
            )

            print()

            print(
                "Identity :",
                identity.get(
                    "name"
                )
            )

            print(
                "Risk     :",
                identity.get(
                    "risk_level"
                )
            )

            print(
                "Score    :",
                identity.get(
                    "risk_score"
                )
            )

            print()

            print(
                "No confirmed excessive permissions were detected."
            )

            print(
                "No IAM changes will be performed."
            )

            print(
                "The recommended policy remains a candidate"
            )

            print(
                "until excessive permissions are established."
            )

            report = {

                "module":
                    "Cloud Least Privilege "
                    "Deployment Controller",

                "target_identity":
                    TARGET_IDENTITY,

                "identity":
                    identity,

                "deployment_mode":
                    "NO_REMEDIATION",

                "human_approval":
                    False,

                "excessive_permissions":
                    [],

                "policy_actions":
                    actions,

                "deployment_performed":
                    False,

                "status":
                    "NO_REMEDIATION_REQUIRED",

                "reason":
                    (
                        "No confirmed excessive "
                        "permissions detected."
                    ),

                "aws_changes":
                    []
            }

            save_json(
                OUTPUT_FILE,
                report
            )

            print()

            print(
                "Report saved:"
            )

            print(
                OUTPUT_FILE
            )

            return

        # ----------------------------------------------------
        # HUMAN APPROVAL
        # ----------------------------------------------------

        approved = request_approval(
            TARGET_IDENTITY,
            actions
        )

        # ----------------------------------------------------
        # CANCELLED
        # ----------------------------------------------------

        if not approved:

            print()

            print(
                "=" * 65
            )

            print(
                "DEPLOYMENT CANCELLED"
            )

            print(
                "=" * 65
            )

            report = {

                "module":
                    "Cloud Least Privilege "
                    "Deployment Controller",

                "target_identity":
                    TARGET_IDENTITY,

                "identity":
                    identity,

                "deployment_mode":
                    "DRY_RUN"
                    if DRY_RUN
                    else "LIVE",

                "human_approval":
                    False,

                "deployment_performed":
                    False,

                "status":
                    "CANCELLED",

                "safety_checks":
                    checks
            }

            save_json(
                OUTPUT_FILE,
                report
            )

            return

        # ----------------------------------------------------
        # DRY RUN
        # ----------------------------------------------------

        if DRY_RUN:

            policy = ai_data[
                "recommended_policy"
            ]

            print()

            print(
                "=" * 65
            )

            print(
                "                 DRY RUN DEPLOYMENT"
            )

            print(
                "=" * 65
            )

            print()

            print(
                "Human approval : APPROVED"
            )

            print(
                "AWS changes    : NONE"
            )

            print(
                "IAM user       :",
                TARGET_IDENTITY
            )

            print()

            print(
                "Policy that WOULD be deployed:"
            )

            print(
                "-" * 65
            )

            print(
                json.dumps(
                    policy,
                    indent=4
                )
            )

            print()

            print(
                "=" * 65
            )

            print(
                "DRY RUN STATUS: SUCCESS"
            )

            print(
                "DEPLOYMENT PERFORMED: False"
            )

            print(
                "=" * 65
            )

            report = {

                "module":
                    "Cloud Least Privilege "
                    "Deployment Controller",

                "target_identity":
                    TARGET_IDENTITY,

                "identity":
                    identity,

                "deployment_mode":
                    "DRY_RUN",

                "human_approval":
                    True,

                "safety_checks":
                    checks,

                "policy_actions":
                    actions,

                "deployment_performed":
                    False,

                "status":
                    "DRY_RUN_SUCCESS",

                "aws_changes":
                    []
            }

            save_json(
                OUTPUT_FILE,
                report
            )

            print()

            print(
                "Report saved:"
            )

            print(
                OUTPUT_FILE
            )

            return

        # ====================================================
        # LIVE DEPLOYMENT
        # ====================================================

        print()

        print(
            "=" * 65
        )

        print(
            "                 LIVE AWS DEPLOYMENT"
        )

        print(
            "=" * 65
        )

        print()

        print(
            "WARNING: REAL AWS IAM CHANGES ARE ENABLED."
        )

        print(
            "Target:",
            TARGET_IDENTITY
        )

        # ----------------------------------------------------
        # CREATE DEPLOYER SESSION
        # ----------------------------------------------------

        session = boto3.Session(

            profile_name=DEPLOYER_PROFILE,

            region_name=REGION
        )

        iam_client = session.client(
            "iam"
        )

        # ----------------------------------------------------
        # VERIFY TARGET USER
        # ----------------------------------------------------

        target_user = get_target_user(
            iam_client,
            TARGET_IDENTITY
        )

        actual_username = target_user.get(
            "UserName"
        )

        if actual_username != TARGET_IDENTITY:

            raise RuntimeError(
                "Target identity verification failed."
            )

        # ----------------------------------------------------
        # GET CURRENT POLICIES
        # ----------------------------------------------------

        current_policies = (
            get_attached_policies(
                iam_client,
                TARGET_IDENTITY
            )
        )

        print()

        print(
            "Current attached policies:"
        )

        for policy in current_policies:

            print(
                " -",
                policy[
                    "policy_name"
                ]
            )

        # ----------------------------------------------------
        # SELECT ORIGINAL POLICY
        # ----------------------------------------------------

        old_policy = None

        for policy in current_policies:

            if policy[
                "policy_name"
            ] == "AmazonS3ReadOnlyAccess":

                old_policy = policy

                break

        if not old_policy:

            raise RuntimeError(
                "Expected original "
                "AmazonS3ReadOnlyAccess policy "
                "was not found. Deployment blocked."
            )

        old_policy_arn = old_policy[
            "policy_arn"
        ]

        # ----------------------------------------------------
        # LOAD RECOMMENDED POLICY
        # ----------------------------------------------------

        recommended_policy = ai_data[
            "recommended_policy"
        ]

        # ----------------------------------------------------
        # CREATE REPLACEMENT POLICY
        # ----------------------------------------------------

        print()

        print(
            "Creating customer-managed replacement policy..."
        )

        new_policy = (
            create_customer_managed_policy(
                iam_client,
                recommended_policy
            )
        )

        new_policy_arn = new_policy[
            "policy_arn"
        ]

        print(
            "Created:",
            new_policy[
                "policy_name"
            ]
        )

        print(
            "ARN:",
            new_policy_arn
        )

        aws_changes = []

        try:

            # ------------------------------------------------
            # ATTACH NEW POLICY FIRST
            # ------------------------------------------------

            print()

            print(
                "Attaching replacement policy..."
            )

            attach_policy(

                iam_client,

                TARGET_IDENTITY,

                new_policy_arn
            )

            aws_changes.append({

                "action":
                    "Attach replacement policy",

                "policy":
                    new_policy_arn,

                "status":
                    "PASS"
            })

            # ------------------------------------------------
            # VERIFY NEW POLICY BEFORE REMOVING OLD POLICY
            # ------------------------------------------------

            attached_after_new = (
                get_attached_policies(
                    iam_client,
                    TARGET_IDENTITY
                )
            )

            new_attached = any(

                policy[
                    "policy_arn"
                ]
                == new_policy_arn

                for policy
                in attached_after_new
            )

            if not new_attached:

                raise RuntimeError(
                    "Replacement policy attachment "
                    "could not be verified."
                )

            # ------------------------------------------------
            # DETACH OLD POLICY
            # ------------------------------------------------

            print()

            print(
                "Detaching original policy..."
            )

            detach_policy(

                iam_client,

                TARGET_IDENTITY,

                old_policy_arn
            )

            aws_changes.append({

                "action":
                    "Detach original policy",

                "policy":
                    old_policy_arn,

                "status":
                    "PASS"
            })

            # ------------------------------------------------
            # FINAL VERIFICATION
            # ------------------------------------------------

            print()

            print(
                "Verifying final IAM state..."
            )

            verification = (
                verify_deployment(

                    iam_client,

                    TARGET_IDENTITY,

                    new_policy_arn,

                    old_policy_arn
                )
            )

            print()

            print(
                "New policy attached:",
                verification[
                    "new_policy_attached"
                ]
            )

            print(
                "Old policy detached:",
                verification[
                    "old_policy_detached"
                ]
            )

            if not verification[
                "verified"
            ]:

                raise RuntimeError(
                    "Post-deployment verification failed."
                )

            # ------------------------------------------------
            # SUCCESS
            # ------------------------------------------------

            print()

            print(
                "=" * 65
            )

            print(
                "DEPLOYMENT STATUS: SUCCESS"
            )

            print(
                "=" * 65
            )

            report = {

                "module":
                    "Cloud Least Privilege "
                    "Deployment Controller",

                "target_identity":
                    TARGET_IDENTITY,

                "identity":
                    identity,

                "deployment_mode":
                    "LIVE",

                "human_approval":
                    True,

                "safety_checks":
                    checks,

                "policy_actions":
                    actions,

                "original_policy":
                    old_policy,

                "replacement_policy":
                    new_policy,

                "aws_changes":
                    aws_changes,

                "post_deployment_verification":
                    verification,

                "deployment_performed":
                    True,

                "status":
                    "DEPLOYMENT_SUCCESS",

                "rollback_performed":
                    False
            }

            save_json(
                OUTPUT_FILE,
                report
            )

            print()

            print(
                "Report saved:"
            )

            print(
                OUTPUT_FILE
            )

            return

        except Exception as deployment_error:

            # ------------------------------------------------
            # ROLLBACK
            # ------------------------------------------------

            print()

            print(
                "=" * 65
            )

            print(
                "DEPLOYMENT FAILED"
            )

            print(
                "=" * 65
            )

            print()

            print(
                "Error:",
                str(deployment_error)
            )

            print()

            print(
                "Attempting rollback..."
            )

            rollback = (
                rollback_deployment(

                    iam_client,

                    TARGET_IDENTITY,

                    new_policy_arn,

                    old_policy_arn
                )
            )

            print()

            print(
                "Rollback status:",
                rollback[
                    "status"
                ]
            )

            report = {

                "module":
                    "Cloud Least Privilege "
                    "Deployment Controller",

                "target_identity":
                    TARGET_IDENTITY,

                "identity":
                    identity,

                "deployment_mode":
                    "LIVE",

                "human_approval":
                    True,

                "safety_checks":
                    checks,

                "policy_actions":
                    actions,

                "original_policy":
                    old_policy,

                "replacement_policy":
                    new_policy,

                "aws_changes":
                    aws_changes,

                "deployment_performed":
                    False,

                "status":
                    "DEPLOYMENT_FAILED",

                "error":
                    str(deployment_error),

                "rollback":
                    rollback,

                "rollback_performed":
                    True
            }

            save_json(
                OUTPUT_FILE,
                report
            )

            print()

            print(
                "Report saved:"
            )

            print(
                OUTPUT_FILE
            )

            return

    except Exception as error:

        print()

        print(
            "=" * 65
        )

        print(
            "DEPLOYMENT CONTROLLER ERROR"
        )

        print(
            "=" * 65
        )

        print()

        print(
            str(error)
        )

        report = {

            "module":
                "Cloud Least Privilege "
                "Deployment Controller",

            "target_identity":
                TARGET_IDENTITY,

            "deployment_mode":
                "DRY_RUN"
                if DRY_RUN
                else "LIVE",

            "human_approval":
                False,

            "deployment_performed":
                False,

            "status":
                "ERROR",

            "error":
                str(error)
        }

        save_json(
            OUTPUT_FILE,
            report
        )

        print()

        print(
            "Report saved:"
        )

        print(
            OUTPUT_FILE
        )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()