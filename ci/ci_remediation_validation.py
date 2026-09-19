import json
import os
import boto3


BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

# AI remediation report
INPUT_FILE = os.path.join(
    BASE_DIR,
    "reports",
    "ci_ai_remediation_report.json"
)

# Validation report
OUTPUT_FILE = os.path.join(
    BASE_DIR,
    "reports",
    "ci_remediation_validation_report.json"
)

PROFILE = "leastprivilege"
REGION = "ap-south-1"


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
# SAVE JSON
# ============================================================

def save_json(path, data):

    output_dir = os.path.dirname(path)

    os.makedirs(
        output_dir,
        exist_ok=True
    )

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            data,
            f,
            indent=4
        )


# ============================================================
# LOCAL POLICY VALIDATION
# ============================================================

def validate_local_policy(policy):

    errors = []

    if not isinstance(policy, dict):

        errors.append(
            "Recommended policy is not a JSON object."
        )

        return errors

    if policy.get("Version") != "2012-10-17":

        errors.append(
            "Invalid or missing policy Version."
        )

    statements = policy.get("Statement")

    if not isinstance(
        statements,
        list
    ) or not statements:

        errors.append(
            "Policy Statement is missing or invalid."
        )

        return errors

    statement = statements[0]

    if statement.get("Effect") != "Allow":

        errors.append(
            "Policy Effect must be Allow."
        )

    actions = statement.get(
        "Action",
        []
    )

    if not actions:

        errors.append(
            "Policy Action is empty."
        )

    if "*" in actions:

        errors.append(
            "Wildcard Action '*' is not allowed."
        )

    return errors


# ============================================================
# GET POLICY ACTIONS
# ============================================================

def get_policy_actions(policy):

    statements = policy.get(
        "Statement",
        []
    )

    if not statements:

        return []

    actions = statements[0].get(
        "Action",
        []
    )

    if isinstance(
        actions,
        str
    ):

        actions = [actions]

    return actions


# ============================================================
# ACTION COVERAGE
# ============================================================

def check_action_coverage(
    observed_actions,
    policy_actions
):

    missing = []

    covered = []

    for action in observed_actions:

        if action in policy_actions:

            covered.append(action)

        else:

            missing.append(action)

    return covered, missing


# ============================================================
# REQUIRED PERMISSION COVERAGE
# ============================================================

def check_required_permission_coverage(
    required_permissions,
    policy_actions
):

    missing = []

    covered = []

    for permission in required_permissions:

        if permission in policy_actions:

            covered.append(permission)

        else:

            missing.append(permission)

    return covered, missing


# ============================================================
# ACCESS ANALYZER
# ============================================================

def validate_with_access_analyzer(policy):

    try:

        session = boto3.Session(
            profile_name=PROFILE
        )

        access_analyzer = session.client(
            "accessanalyzer",
            region_name=REGION
        )

        response = access_analyzer.validate_policy(
            policyDocument=json.dumps(policy),
            policyType="IDENTITY_POLICY"
        )

        findings = response.get(
            "findings",
            []
        )

        errors = []

        for finding in findings:

            finding_type = finding.get(
                "findingType"
            )

            if finding_type == "ERROR":

                errors.append(finding)

        return errors

    except Exception as error:

        return [
            {
                "error": str(error)
            }
        ]


# ============================================================
# IAM POLICY SIMULATION
# ============================================================

def simulate_policy(
    policy,
    actions
):

    results = []

    try:

        session = boto3.Session(
            profile_name=PROFILE
        )

        iam = session.client(
            "iam",
            region_name=REGION
        )

        policy_document = json.dumps(
            policy
        )

        response = iam.simulate_custom_policy(
            PolicyInputList=[
                policy_document
            ],
            ActionNames=actions,
            ResourceArns=[
                "*"
            ]
        )

        evaluation_results = response.get(
            "EvaluationResults",
            []
        )

        for result in evaluation_results:

            action = result.get(
                "EvalActionName"
            )

            decision = result.get(
                "EvalDecision"
            )

            results.append(
                {
                    "action": action,
                    "decision": decision
                }
            )

        return results

    except Exception as error:

        return [
            {
                "error": str(error)
            }
        ]


# ============================================================
# CHECK SIMULATION RESULTS
# ============================================================

def validate_simulation(
    simulation_results,
    required_actions
):

    errors = []

    result_map = {}

    for result in simulation_results:

        if "error" in result:

            errors.append(
                result["error"]
            )

            continue

        action = result.get(
            "action"
        )

        decision = result.get(
            "decision"
        )

        result_map[action] = decision

    for action in required_actions:

        decision = result_map.get(
            action
        )

        if decision != "allowed":

            errors.append(
                f"{action} was not allowed. "
                f"Decision: {decision}"
            )

    return errors


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 65)

    print(
        "       AI SYNTHETIC REMEDIATION POLICY VALIDATION"
    )

    print("=" * 65)


    # --------------------------------------------------------
    # LOAD AI REPORT
    # --------------------------------------------------------

    try:

        data = load_json(
            INPUT_FILE
        )

    except Exception as error:

        print()
        print(
            "ERROR: Could not load AI remediation report."
        )

        print(
            str(error)
        )

        return


    identity = data.get(
        "identity"
    )

    ai_status = data.get(
        "ai_status"
    )

    # IMPORTANT:
    # The AI report does NOT contain observed_actions.
    # It contains required_permissions.
    #
    # required_permissions is copied from the authoritative
    # observed_actions list by ci_ai_remediation.py.
    #
    # Therefore we use required_permissions as the
    # authoritative observed-action list.

    required_permissions = data.get(
        "required_permissions",
        []
    )

    observed_actions = required_permissions


    print()
    print(
        "AI REMEDIATION REPORT"
    )

    print("-" * 65)

    print(
        "Identity:",
        identity
    )

    print(
        "Status:",
        "PASS"
        if ai_status == "GENERATED"
        else "FAIL"
    )


    # --------------------------------------------------------
    # CHECK AI REPORT
    # --------------------------------------------------------

    if not identity:

        print(
            " - Identity is missing."
        )

        return


    if not required_permissions:

        print(
            " - Required permissions are empty."
        )

        print()
        print(
            "Validation stopped because the AI report is incomplete."
        )

        return


    # --------------------------------------------------------
    # DISPLAY OBSERVED ACTIONS
    # --------------------------------------------------------

    print()
    print(
        "Observed Actions:"
    )

    for action in observed_actions:

        print(
            " -",
            action
        )


    # --------------------------------------------------------
    # DISPLAY REQUIRED PERMISSIONS
    # --------------------------------------------------------

    print()
    print(
        "Required Permissions:"
    )

    for permission in required_permissions:

        print(
            " -",
            permission
        )


    # --------------------------------------------------------
    # RECOMMENDED POLICY
    # --------------------------------------------------------

    policy = data.get(
        "recommended_policy"
    )

    if not policy:

        print()
        print(
            " - Recommended policy is missing."
        )

        print()
        print(
            "Validation stopped because the AI report is incomplete."
        )

        return


    # ========================================================
    # 1. LOCAL POLICY VALIDATION
    # ========================================================

    print()
    print(
        "1. LOCAL POLICY VALIDATION"
    )

    print("-" * 65)

    local_errors = validate_local_policy(
        policy
    )

    if local_errors:

        print(
            "Status: FAIL"
        )

        for error in local_errors:

            print(
                " -",
                error
            )

        print()
        print(
            "Validation stopped because the policy is invalid."
        )

        return

    else:

        print(
            "Status: PASS"
        )

        print(
            "No structural policy errors."
        )


    # --------------------------------------------------------
    # POLICY ACTIONS
    # --------------------------------------------------------

    policy_actions = get_policy_actions(
        policy
    )

    print()
    print(
        "Policy Actions:"
    )

    for action in policy_actions:

        print(
            " -",
            action
        )


    # ========================================================
    # 2. OBSERVED ACTION COVERAGE
    # ========================================================

    print()
    print(
        "2. OBSERVED-ACTION COVERAGE"
    )

    print("-" * 65)

    covered_actions, missing_actions = (
        check_action_coverage(
            observed_actions,
            policy_actions
        )
    )

    if missing_actions:

        print(
            "Status: FAIL"
        )

        for action in missing_actions:

            print(
                "Missing:",
                action
            )

    else:

        print(
            "Status: PASS"
        )

        for action in covered_actions:

            print(
                "Covered:",
                action
            )


    # ========================================================
    # 3. REQUIRED PERMISSION COVERAGE
    # ========================================================

    print()
    print(
        "3. REQUIRED-PERMISSION COVERAGE"
    )

    print("-" * 65)

    covered_permissions, missing_permissions = (
        check_required_permission_coverage(
            required_permissions,
            policy_actions
        )
    )

    if missing_permissions:

        print(
            "Status: FAIL"
        )

        for permission in missing_permissions:

            print(
                "Missing:",
                permission
            )

    else:

        print(
            "Status: PASS"
        )

        for permission in covered_permissions:

            print(
                "Covered:",
                permission
            )


    # ========================================================
    # 4. AWS ACCESS ANALYZER
    # ========================================================

    print()
    print(
        "4. AWS ACCESS ANALYZER"
    )

    print("-" * 65)

    analyzer_errors = (
        validate_with_access_analyzer(
            policy
        )
    )

    if analyzer_errors:

        print(
            "Status: FAIL"
        )

        for error in analyzer_errors:

            print(
                " -",
                error
            )

    else:

        print(
            "Status: PASS"
        )

        print(
            "No Access Analyzer errors."
        )


    # ========================================================
    # 5. IAM POLICY SIMULATOR
    # ========================================================

    print()
    print(
        "5. IAM POLICY SIMULATOR"
    )

    print("-" * 65)

    simulation_results = simulate_policy(
        policy,
        required_permissions
    )


    for result in simulation_results:

        if "error" in result:

            print(
                "ERROR:",
                result["error"]
            )

            continue

        action = result.get(
            "action"
        )

        decision = result.get(
            "decision"
        )

        print(
            f"{action:<45} {decision}"
        )


    simulation_errors = (
        validate_simulation(
            simulation_results,
            required_permissions
        )
    )


    if simulation_errors:

        print()
        print(
            "Status: FAIL"
        )

        for error in simulation_errors:

            print(
                " -",
                error
            )

    else:

        print()
        print(
            "Status: PASS"
        )


    # ========================================================
    # FINAL VALIDATION
    # ========================================================

    validation_passed = (

        not local_errors

        and not missing_actions

        and not missing_permissions

        and not analyzer_errors

        and not simulation_errors

    )


    # ========================================================
    # VALIDATION REPORT
    # ========================================================

    validation_report = {

        "identity": identity,

        "identity_type": data.get(
            "identity_type"
        ),

        "ai_status": ai_status,

        "observed_actions": observed_actions,

        "required_permissions": required_permissions,

        "policy_actions": policy_actions,

        "recommended_policy": policy,

        "validation": {

            "local_policy": (
                "PASS"
                if not local_errors
                else "FAIL"
            ),

            "observed_action_coverage": (
                "PASS"
                if not missing_actions
                else "FAIL"
            ),

            "required_permission_coverage": (
                "PASS"
                if not missing_permissions
                else "FAIL"
            ),

            "access_analyzer": (
                "PASS"
                if not analyzer_errors
                else "FAIL"
            ),

            "iam_policy_simulator": (
                "PASS"
                if not simulation_errors
                else "FAIL"
            )

        },

        "simulation_results": simulation_results,

        "errors": {

            "local_policy": local_errors,

            "missing_observed_actions": missing_actions,

            "missing_required_permissions": missing_permissions,

            "access_analyzer": analyzer_errors,

            "iam_policy_simulator": simulation_errors

        },

        "validation_status": (
            "VERIFIED"
            if validation_passed
            else "FAILED"
        ),

        "aws_policy_attached": False,

        "aws_changes_performed": False

    }


    save_json(
        OUTPUT_FILE,
        validation_report
    )


    # ========================================================
    # FINAL RESULT
    # ========================================================

    print()
    print("=" * 65)

    if validation_passed:

        print(
            "AI REMEDIATION VALIDATION: VERIFIED"
        )

    else:

        print(
            "AI REMEDIATION VALIDATION: FAILED"
        )

    print(
        "AWS POLICY ATTACHED     : False"
    )

    print("=" * 65)

    print()
    print(
        "Report saved:"
    )

    print(
        OUTPUT_FILE
    )


# ============================================================
# PROGRAM START
# ============================================================

if __name__ == "__main__":

    main()