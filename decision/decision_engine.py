
import json
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

REPORTS_DIR = BASE_DIR / "reports"

RISK_FILE = REPORTS_DIR / "risk_report.json"
ML_RISK_FILE = REPORTS_DIR / "ml_risk_predictions.json"
PERMISSION_FILE = REPORTS_DIR / "permission_analysis.json"
AI_POLICY_FILE = REPORTS_DIR / "ai_recommended_policies.json"
VALIDATION_FILE = REPORTS_DIR / "policy_validation_report.json"
SIMULATION_FILE = REPORTS_DIR / "ai_policy_simulation_report.json"
VERIFICATION_FILE = REPORTS_DIR / "verification_controller_report.json"

OUTPUT_FILE = REPORTS_DIR / "decision_engine_report.json"


# ============================================================
# LOAD JSON
# ============================================================

def load_json(path):

    if not path.exists():

        raise FileNotFoundError(
            f"Required report not found: {path}"
        )

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


# ============================================================
# FIND USER
# ============================================================

def find_user(records, username):

    for record in records:

        if record.get("username") == username:

            return record

    return {}


# ============================================================
# FIND PERMISSION USER
# ============================================================

def find_permission_user(permission_data, username):

    for user in permission_data.get(
        "users",
        []
    ):

        if user.get("username") == username:

            return user

    return {}


# ============================================================
# DECISION LOGIC
# ============================================================

def make_decision(
    risk_user,
    ml_user,
    permission_user,
    ai_data,
    validation_data,
    simulation_data,
    verification_data
):

    reasons = []
    blockers = []

    # --------------------------------------------------------
    # BASIC IDENTITY
    # --------------------------------------------------------

    identity = ai_data.get(
        "identity",
        {}
    )

    username = identity.get(
        "name"
    )

    identity_type = identity.get(
        "type"
    )

    # --------------------------------------------------------
    # RULE-BASED RISK
    # --------------------------------------------------------

    rule_score = risk_user.get(
        "total_risk",
        0
    )

    rule_level = risk_user.get(
        "risk_level",
        "Unknown"
    )

    # --------------------------------------------------------
    # ML RISK
    # --------------------------------------------------------

    ml_score = ml_user.get(
        "ml_risk_score",
        0
    )

    ml_level = ml_user.get(
        "risk_level",
        "Unknown"
    )

    # --------------------------------------------------------
    # PERMISSION FINDINGS
    # --------------------------------------------------------

    potentially_unused = permission_user.get(
        "potentially_unused_actions",
        []
    )

    potentially_excessive = permission_user.get(
        "potentially_excessive_policies",
        []
    )

    least_privilege_status = permission_user.get(
        "least_privilege_status",
        "Unknown"
    )

    # --------------------------------------------------------
    # CONFIRMED EXCESSIVE PERMISSIONS
    # --------------------------------------------------------

    confirmed_excessive = ai_data.get(
        "excessive_permissions",
        []
    )

    # --------------------------------------------------------
    # VALIDATION
    # --------------------------------------------------------

    validation_status = validation_data.get(
        "overall_status",
        validation_data.get(
            "status",
            "UNKNOWN"
        )
    )

    # --------------------------------------------------------
    # SIMULATION
    # --------------------------------------------------------

    simulation_status = simulation_data.get(
        "simulation",
        {}
    ).get(
        "status",
        "UNKNOWN"
    )

    # --------------------------------------------------------
    # VERIFICATION
    # --------------------------------------------------------

    verification_status = verification_data.get(
        "final_status",
        "UNKNOWN"
    )

    # ========================================================
    # SAFETY CONDITIONS
    # ========================================================

    # --------------------------------------------------------
    # 1. TARGET MUST BE IAM USER
    # --------------------------------------------------------

    if identity_type != "IAM User":

        blockers.append(
            "Target identity is not an IAM User."
        )

    # --------------------------------------------------------
    # 2. CONFIRMED EXCESSIVE PERMISSIONS
    # --------------------------------------------------------

    if confirmed_excessive:

        reasons.append(
            "Confirmed excessive permissions were detected."
        )

    else:

        reasons.append(
            "No confirmed excessive permissions were detected."
        )

    # --------------------------------------------------------
    # 3. POTENTIALLY UNUSED PERMISSIONS
    # --------------------------------------------------------

    if potentially_unused:

        reasons.append(
            "Potentially unused permissions require review "
            "but are not treated as confirmed excessive permissions."
        )

    # --------------------------------------------------------
    # 4. POTENTIALLY EXCESSIVE POLICIES
    # --------------------------------------------------------

    if potentially_excessive:

        reasons.append(
            "Potentially excessive policies were identified "
            "by deterministic permission analysis."
        )

    # --------------------------------------------------------
    # 5. POLICY VALIDATION
    # --------------------------------------------------------

    if validation_status not in (
        "PASS",
        "SUCCESS",
        "VALID"
    ):

        blockers.append(
            "Recommended policy validation did not pass."
        )

    # --------------------------------------------------------
    # 6. IAM SIMULATION
    # --------------------------------------------------------

    if simulation_status not in (
        "PASS",
        "SUCCESS",
        "VERIFIED"
    ):

        blockers.append(
            "IAM policy simulation did not pass."
        )

    # --------------------------------------------------------
    # 7. VERIFICATION
    # --------------------------------------------------------

    if verification_status != "VERIFIED":

        blockers.append(
            "Policy verification did not reach VERIFIED status."
        )

    # ========================================================
    # FINAL DECISION
    # ========================================================

    if blockers:

        decision = "BLOCKED"

    elif not confirmed_excessive:

        decision = "NO_REMEDIATION_REQUIRED"

    else:

        decision = "REMEDIATION_CANDIDATE"

    # ========================================================
    # HUMAN REVIEW
    # ========================================================

    human_approval_required = (
        decision == "REMEDIATION_CANDIDATE"
    )

    # ========================================================
    # DECISION EXPLANATION
    # ========================================================

    if decision == "NO_REMEDIATION_REQUIRED":

        explanation = (
            "No confirmed excessive permissions exist. "
            "The current evidence does not justify modifying "
            "the target identity's IAM permissions."
        )

    elif decision == "REMEDIATION_CANDIDATE":

        explanation = (
            "Confirmed excessive permissions exist and the "
            "required validation, simulation and verification "
            "checks passed. The identity is eligible for "
            "human-reviewed remediation."
        )

    else:

        explanation = (
            "Remediation is blocked because one or more "
            "mandatory safety checks failed."
        )

    return {

        "decision": decision,

        "explanation": explanation,

        "identity": {
            "name": username,
            "type": identity_type
        },

        "risk": {
            "rule_based_score": rule_score,
            "rule_based_level": rule_level,
            "ml_score": ml_score,
            "ml_level": ml_level
        },

        "permission_findings": {

            "confirmed_excessive_permissions":
                confirmed_excessive,

            "potentially_excessive_policies":
                potentially_excessive,

            "potentially_unused_permissions":
                potentially_unused,

            "least_privilege_status":
                least_privilege_status
        },

        "validation": {

            "policy_validation":
                validation_status,

            "iam_simulation":
                simulation_status,

            "verification":
                verification_status
        },

        "reasons":
            reasons,

        "blockers":
            blockers,

        "human_approval_required":
            human_approval_required,

        "remediation_allowed":
            decision == "REMEDIATION_CANDIDATE"
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 70)
    print("              LEAST PRIVILEGE DECISION ENGINE")
    print("=" * 70)

    # --------------------------------------------------------
    # LOAD REPORTS
    # --------------------------------------------------------

    risk_data = load_json(
        RISK_FILE
    )

    ml_data = load_json(
        ML_RISK_FILE
    )

    permission_data = load_json(
        PERMISSION_FILE
    )

    ai_data = load_json(
        AI_POLICY_FILE
    )

    validation_data = load_json(
        VALIDATION_FILE
    )

    simulation_data = load_json(
        SIMULATION_FILE
    )

    verification_data = load_json(
        VERIFICATION_FILE
    )

    # --------------------------------------------------------
    # TARGET IDENTITY
    # --------------------------------------------------------

    identity = ai_data.get(
        "identity",
        {}
    )

    username = identity.get(
        "name"
    )

    if not username:

        raise RuntimeError(
            "Target identity could not be determined."
        )

    # --------------------------------------------------------
    # FIND USER DATA
    # --------------------------------------------------------

    risk_user = find_user(
        risk_data.get(
            "users",
            []
        ),
        username
    )

    ml_user = find_user(
        ml_data.get(
            "predictions",
            []
        ),
        username
    )

    permission_user = find_permission_user(
        permission_data,
        username
    )

    # --------------------------------------------------------
    # MAKE DECISION
    # --------------------------------------------------------

    decision_report = make_decision(

        risk_user,

        ml_user,

        permission_user,

        ai_data,

        validation_data,

        simulation_data,

        verification_data
    )

    # --------------------------------------------------------
    # ADD MODULE INFORMATION
    # --------------------------------------------------------

    report = {

        "module":
            "Cloud Least Privilege Decision Engine",

        "description":
            (
                "Determines whether IAM remediation is "
                "justified using deterministic findings, "
                "rule-based risk, XGBoost risk, policy "
                "validation, IAM simulation and verification."
            ),

        **decision_report
    }

    # --------------------------------------------------------
    # SAVE REPORT
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # DISPLAY RESULT
    # --------------------------------------------------------

    print()

    print(
        "Identity       :",
        report["identity"]["name"]
    )

    print(
        "Rule Risk      :",
        report["risk"]["rule_based_score"],
        "(",
        report["risk"]["rule_based_level"],
        ")"
    )

    print(
        "XGBoost Risk   :",
        report["risk"]["ml_score"],
        "(",
        report["risk"]["ml_level"],
        ")"
    )

    print()

    print(
        "Confirmed Excessive Permissions:",
        len(
            report[
                "permission_findings"
            ][
                "confirmed_excessive_permissions"
            ]
        )
    )

    print(
        "Potentially Unused Permissions:",
        len(
            report[
                "permission_findings"
            ][
                "potentially_unused_permissions"
            ]
        )
    )

    print()

    print(
        "Policy Validation:",
        report[
            "validation"
        ][
            "policy_validation"
        ]
    )

    print(
        "IAM Simulation:",
        report[
            "validation"
        ][
            "iam_simulation"
        ]
    )

    print(
        "Verification:",
        report[
            "validation"
        ][
            "verification"
        ]
    )

    print()

    print("=" * 70)

    print(
        "DECISION:",
        report["decision"]
    )

    print("=" * 70)

    print()

    print(
        report["explanation"]
    )

    print()

    print(
        "Human Approval Required:",
        report[
            "human_approval_required"
        ]
    )

    print(
        "Remediation Allowed:",
        report[
            "remediation_allowed"
        ]
    )

    if report["blockers"]:

        print()

        print(
            "BLOCKERS:"
        )

        for blocker in report["blockers"]:

            print(
                " -",
                blocker
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
