import json
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

AI_POLICY_FILE = BASE_DIR / "reports" / "ai_recommended_policies.json"
REVIEW_FILE = BASE_DIR / "reports" / "deployment_review_report.json"
OUTPUT_FILE = BASE_DIR / "reports" / "deployment_controller_report.json"

TARGET_IDENTITY = "Least_privilege"
TARGET_TYPE = "IAM User"

# Safety switch
# True  = no AWS changes
# False = real deployment (DO NOT change yet)
DRY_RUN = True


# ============================================================
# LOAD JSON
# ============================================================

def load_json(path):

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


# ============================================================
# EXTRACT ACTIONS
# ============================================================

def extract_actions(policy):

    actions = []

    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:

        action = statement.get("Action", [])

        if isinstance(action, str):
            action = [action]

        actions.extend(action)

    return actions


# ============================================================
# SAFETY CHECKS
# ============================================================

def run_safety_checks(ai_data, review_data):

    checks = []

    identity = ai_data.get("identity", {})

    # Target identity
    if identity.get("name") == TARGET_IDENTITY:
        checks.append({
            "check": "Target identity",
            "status": "PASS"
        })
    else:
        checks.append({
            "check": "Target identity",
            "status": "FAIL"
        })

    # Identity type
    if identity.get("type") == TARGET_TYPE:
        checks.append({
            "check": "Identity type",
            "status": "PASS"
        })
    else:
        checks.append({
            "check": "Identity type",
            "status": "FAIL"
        })

    # Deployment review
    if review_data.get("review_status") == "APPROVED_FOR_HUMAN_REVIEW":
        checks.append({
            "check": "Deployment review",
            "status": "PASS"
        })
    else:
        checks.append({
            "check": "Deployment review",
            "status": "FAIL"
        })

    # Recommended policy
    policy = ai_data.get("recommended_policy")

    if isinstance(policy, dict):
        checks.append({
            "check": "Recommended policy exists",
            "status": "PASS"
        })
    else:
        checks.append({
            "check": "Recommended policy exists",
            "status": "FAIL"
        })
        policy = {}

    # Actions
    actions = extract_actions(policy)

    if len(actions) > 0:
        checks.append({
            "check": "Policy contains actions",
            "status": "PASS"
        })
    else:
        checks.append({
            "check": "Policy contains actions",
            "status": "FAIL"
        })

    # Wildcard Action
    if "*" not in actions:
        checks.append({
            "check": "Wildcard Action",
            "status": "PASS"
        })
    else:
        checks.append({
            "check": "Wildcard Action",
            "status": "FAIL"
        })

    return checks, actions


# ============================================================
# HUMAN APPROVAL
# ============================================================

def request_approval(identity, actions):

    print()
    print("=" * 65)
    print("                 HUMAN DEPLOYMENT APPROVAL")
    print("=" * 65)

    print()
    print("Target Identity :", identity)
    print("Deployment Mode :", "DRY RUN" if DRY_RUN else "LIVE")

    print()
    print("Policy Actions:")
    print("-" * 65)

    for action in actions:
        print(" -", action)

    print()
    print("No AWS changes will be made during DRY RUN.")
    print()

    response = input(
        "Type APPROVE to continue or anything else to cancel: "
    ).strip()

    return response == "APPROVE"


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 65)
    print("        CLOUD LEAST PRIVILEGE DEPLOYMENT CONTROLLER")
    print("=" * 65)

    try:

        # ----------------------------------------------------
        # LOAD REPORTS
        # ----------------------------------------------------

        ai_data = load_json(AI_POLICY_FILE)
        review_data = load_json(REVIEW_FILE)

        identity = ai_data.get("identity", {})

        print()
        print("Identity   :", identity.get("name"))
        print("Type       :", identity.get("type"))
        print("Risk Level :", identity.get("risk_level"))
        print("Risk Score :", identity.get("risk_score"))

        print()
        print("Deployment Mode :", "DRY RUN" if DRY_RUN else "LIVE")

        # ----------------------------------------------------
        # SAFETY CHECKS
        # ----------------------------------------------------

        print()
        print("DEPLOYMENT SAFETY CHECKS")
        print("-" * 65)

        checks, actions = run_safety_checks(
            ai_data,
            review_data
        )

        all_passed = True

        for check in checks:

            print(
                f"[{check['status']}] "
                f"{check['check']}"
            )

            if check["status"] == "FAIL":
                all_passed = False

        # ----------------------------------------------------
        # BLOCK IF SAFETY CHECK FAILS
        # ----------------------------------------------------

        if not all_passed:

            print()
            print("=" * 65)
            print("DEPLOYMENT STATUS: BLOCKED")
            print("=" * 65)

            report = {
                "module":
                    "Cloud Least Privilege Deployment Controller",

                "identity": identity,

                "deployment_mode":
                    "DRY_RUN",

                "human_approval":
                    False,

                "deployment_performed":
                    False,

                "status":
                    "BLOCKED",

                "safety_checks":
                    checks
            }

            with open(
                OUTPUT_FILE,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    report,
                    file,
                    indent=4
                )

            return

        # ----------------------------------------------------
        # REMEDIATION SAFETY GATE
        # ----------------------------------------------------

        excessive_permissions = ai_data.get(
            "excessive_permissions",
            []
        )

        if not excessive_permissions:

            print()
            print("=" * 65)
            print("              NO REMEDIATION REQUIRED")
            print("=" * 65)

            print()
            print("Identity :", identity.get("name"))
            print("Risk     :", identity.get("risk_level"))
            print("Score    :", identity.get("risk_score"))

            print()
            print("No excessive permissions were detected.")
            print("No IAM changes will be performed.")

            report = {
                "module":
                    "Cloud Least Privilege Deployment Controller",

                "identity":
                    identity,

                "deployment_mode":
                    "NO_REMEDIATION",

                "human_approval":
                    False,

                "excessive_permissions":
                    [],

                "deployment_performed":
                    False,

                "status":
                    "NO_REMEDIATION_REQUIRED",

                "reason":
                    "No excessive permissions detected.",

                "aws_changes":
                    []
            }

            with open(
                OUTPUT_FILE,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    report,
                    file,
                    indent=4
                )

            print()
            print("Report saved:")
            print(OUTPUT_FILE)

            return       
 # ----------------------------------------------------
        # HUMAN APPROVAL
        # ----------------------------------------------------

        approved = request_approval(
            identity.get("name"),
            actions
        )

        # ----------------------------------------------------
        # CANCELLED
        # ----------------------------------------------------

        if not approved:

            print()
            print("=" * 65)
            print("DEPLOYMENT CANCELLED")
            print("=" * 65)

            report = {
                "module":
                    "Cloud Least Privilege Deployment Controller",

                "identity": identity,

                "deployment_mode":
                    "DRY_RUN",

                "human_approval":
                    False,

                "deployment_performed":
                    False,

                "status":
                    "CANCELLED",

                "safety_checks":
                    checks
            }

            with open(
                OUTPUT_FILE,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    report,
                    file,
                    indent=4
                )

            return

        # ----------------------------------------------------
        # DRY RUN
        # ----------------------------------------------------

        if DRY_RUN:

            policy = ai_data["recommended_policy"]

            print()
            print("=" * 65)
            print("                 DRY RUN DEPLOYMENT")
            print("=" * 65)

            print()
            print("Human approval : APPROVED")
            print("AWS changes    : NONE")
            print("IAM user       :", identity.get("name"))

            print()
            print("Policy that WOULD be deployed:")
            print("-" * 65)

            print(
                json.dumps(
                    policy,
                    indent=4
                )
            )

            print()
            print("=" * 65)
            print("DRY RUN STATUS: SUCCESS")
            print("DEPLOYMENT PERFORMED: False")
            print("=" * 65)

            report = {
                "module":
                    "Cloud Least Privilege Deployment Controller",

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

            with open(
                OUTPUT_FILE,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    report,
                    file,
                    indent=4
                )

            print()
            print("Report saved:")
            print(OUTPUT_FILE)

            return

    except Exception as e:

        print()
        print("=" * 65)
        print("DEPLOYMENT CONTROLLER ERROR")
        print("=" * 65)

        print()
        print(str(e))


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()