
import json
from pathlib import Path

import joblib
import pandas as pd


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_PATH = BASE_DIR / "ml" / "xgboost_risk_model.pkl"
PREPROCESSOR_PATH = BASE_DIR / "ml" / "risk_preprocessor.pkl"

RISK_REPORT_PATH = BASE_DIR / "reports" / "risk_report.json"
IDENTITY_REPORT_PATH = BASE_DIR / "reports" / "identity_report.json"
PERMISSION_REPORT_PATH = BASE_DIR / "reports" / "permission_analysis.json"
CLOUDTRAIL_REPORT_PATH = BASE_DIR / "reports" / "cloudtrail_analysis.json"

OUTPUT_PATH = BASE_DIR / "reports" / "ml_risk_predictions.json"


# ============================================================
# LOAD JSON
# ============================================================

def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)

    except Exception as e:
        print(f"ERROR loading {path}: {e}")
        return {}


# ============================================================
# FIND USER
# ============================================================

def find_user(data, username):

    if not isinstance(data, dict):
        return {}

    users = data.get("users", [])

    if isinstance(users, list):

        for user in users:

            if not isinstance(user, dict):
                continue

            if user.get("username") == username:
                return user

    return {}


# ============================================================
# IDENTITY TYPE
# ============================================================

def get_identity_type(
    identity_report,
    risk_report,
    username
):

    # Try identity report first
    identity = find_user(
        identity_report,
        username
    )

    if identity:

        identity_type = (
            identity.get("identity_type")
            or identity.get("type")
        )

        if identity_type:
            return identity_type

    # Fall back to risk report
    risk_user = find_user(
        risk_report,
        username
    )

    if risk_user:

        identity_type = risk_user.get(
            "identity_type"
        )

        if identity_type:
            return identity_type

    return "Unresolved"


# ============================================================
# CLOUDTRAIL BEHAVIOR
# ============================================================


def get_cloudtrail_behavior(
    cloudtrail_report,
    username
):

    # cloudtrail_analysis.json stores identities
    # under the "identities" key, not "users".

    identities = cloudtrail_report.get(
        "identities",
        []
    )

    if not isinstance(identities, list):

        return {
            "api_calls": 0,
            "services_used": 0,
            "unusual_hour_access": 0,
            "sensitive_actions": 0,
            "cross_service_access": 0
        }

    # Find the matching identity
    user = None

    for identity in identities:

        if not isinstance(identity, dict):
            continue

        if identity.get("username") == username:

            user = identity
            break

    if user is None:

        return {
            "api_calls": 0,
            "services_used": 0,
            "unusual_hour_access": 0,
            "sensitive_actions": 0,
            "cross_service_access": 0
        }

    # --------------------------------------------------------
    # Exact fields from cloudtrail_analysis.json
    # --------------------------------------------------------

    api_calls = user.get(
        "total_api_calls",
        0
    )

    services_used = user.get(
        "service_count",
        0
    )

    unusual_hour_access = user.get(
        "unusual_hour_access",
        False
    )

    sensitive_actions = user.get(
        "sensitive_action_count",
        0
    )

    cross_service_access = user.get(
        "cross_service_access",
        False
    )

    return {
        "api_calls": int(
            api_calls or 0
        ),

        "services_used": int(
            services_used or 0
        ),

        "unusual_hour_access": int(
            bool(unusual_hour_access)
        ),

        "sensitive_actions": int(
            sensitive_actions or 0
        ),

        "cross_service_access": int(
            bool(cross_service_access)
        )
    }


    user = find_user(
        cloudtrail_report,
        username
    )

    if not user:

        return {
            "api_calls": 0,
            "services_used": 0,
            "unusual_hour_access": 0,
            "sensitive_actions": 0,
            "cross_service_access": 0
        }

    # --------------------------------------------------------
    # API calls
    # --------------------------------------------------------

    api_calls = user.get(
        "api_calls",
        user.get(
            "observed_api_calls",
            0
        )
    )

    # --------------------------------------------------------
    # Services
    # --------------------------------------------------------

    services = user.get(
        "services",
        []
    )

    if isinstance(services, list):

        services_used = len(services)

    elif isinstance(services, int):

        services_used = services

    else:

        services_used = 0

    # --------------------------------------------------------
    # Unusual hour access
    # --------------------------------------------------------

    unusual_hour_access = user.get(
        "outside_access_window",
        user.get(
            "unusual_hour_access",
            0
        )
    )

    # --------------------------------------------------------
    # Sensitive actions
    # --------------------------------------------------------

    sensitive_actions = user.get(
        "sensitive_actions",
        []
    )

    if isinstance(sensitive_actions, list):

        sensitive_action_count = len(
            sensitive_actions
        )

    elif isinstance(sensitive_actions, int):

        sensitive_action_count = sensitive_actions

    else:

        sensitive_action_count = 0

    # --------------------------------------------------------
    # Cross-service access
    # --------------------------------------------------------

    cross_service = user.get(
        "cross_service",
        False
    )

    if isinstance(cross_service, bool):

        cross_service_access = int(
            cross_service
        )

    else:

        cross_service_access = int(
            user.get(
                "cross_service_access",
                0
            ) or 0
        )

    return {
        "api_calls": int(api_calls or 0),

        "services_used": int(
            services_used or 0
        ),

        "unusual_hour_access": int(
            unusual_hour_access or 0
        ),

        "sensitive_actions": int(
            sensitive_action_count or 0
        ),

        "cross_service_access": int(
            cross_service_access
        )
    }


# ============================================================
# PERMISSION FEATURES
# ============================================================

def get_permission_features(
    permission_report,
    username
):

    user = find_user(
        permission_report,
        username
    )

    if not user:

        return {
            "admin_access": 0,
            "full_access_policies": 0,
            "policy_count": 0,
            "unused_permissions_pct": 0.0
        }

    # --------------------------------------------------------
    # Assigned policies
    # --------------------------------------------------------

    assigned_policies = user.get(
        "assigned_policies",
        []
    )

    if not isinstance(
        assigned_policies,
        list
    ):
        assigned_policies = []

    policy_count = len(
        assigned_policies
    )

    # --------------------------------------------------------
    # Granted actions
    # --------------------------------------------------------

    granted_actions = user.get(
        "granted_actions",
        []
    )

    if not isinstance(
        granted_actions,
        list
    ):
        granted_actions = []

    # --------------------------------------------------------
    # Potentially unused actions
    # --------------------------------------------------------

    unused_actions = user.get(
        "potentially_unused_actions",
        []
    )

    if not isinstance(
        unused_actions,
        list
    ):
        unused_actions = []

    granted_count = len(
        granted_actions
    )

    unused_count = len(
        unused_actions
    )

    # --------------------------------------------------------
    # Unused percentage
    # --------------------------------------------------------

    if granted_count > 0:

        unused_permissions_pct = (
            unused_count /
            granted_count
        ) * 100

    else:

        unused_permissions_pct = 0.0

    # --------------------------------------------------------
    # Admin / full access detection
    # --------------------------------------------------------

    admin_access = 0
    full_access_policies = 0

    for policy in assigned_policies:

        policy_name = str(
            policy
        ).lower()

        if (
            "administratoraccess"
            in policy_name
            or "administrator"
            in policy_name
        ):

            admin_access = 1

        if (
            "fullaccess"
            in policy_name
            or "full-access"
            in policy_name
        ):

            full_access_policies += 1

    return {
        "admin_access": int(
            admin_access
        ),

        "full_access_policies": int(
            full_access_policies
        ),

        "policy_count": int(
            policy_count
        ),

        "unused_permissions_pct": float(
            unused_permissions_pct
        )
    }


# ============================================================
# RISK FEATURES
# ============================================================

def get_risk_features(
    risk_report,
    username
):

    user = find_user(
        risk_report,
        username
    )

    if not user:

        return {
            "permission_risk": 0,
            "usage_risk": 0,
            "temporal_risk": 0,
            "orphan_risk": 0
        }

    return {
        "permission_risk": int(
            user.get(
                "permission_risk",
                0
            ) or 0
        ),

        "usage_risk": int(
            user.get(
                "usage_risk",
                0
            ) or 0
        ),

        "temporal_risk": int(
            user.get(
                "temporal_risk",
                0
            ) or 0
        ),

        "orphan_risk": int(
            user.get(
                "orphan_risk",
                0
            ) or 0
        )
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("          XGBOOST RISK PREDICTION")
    print("=" * 60)

    # --------------------------------------------------------
    # Load model
    # --------------------------------------------------------

    try:

        model = joblib.load(
            MODEL_PATH
        )

        preprocessor = joblib.load(
            PREPROCESSOR_PATH
        )

    except Exception as e:

        print(
            f"ERROR loading model/preprocessor: {e}"
        )

        return

    # --------------------------------------------------------
    # Load reports
    # --------------------------------------------------------

    risk_report = load_json(
        RISK_REPORT_PATH
    )

    identity_report = load_json(
        IDENTITY_REPORT_PATH
    )

    permission_report = load_json(
        PERMISSION_REPORT_PATH
    )

    cloudtrail_report = load_json(
        CLOUDTRAIL_REPORT_PATH
    )

    # --------------------------------------------------------
    # Get identities
    # --------------------------------------------------------

    users = permission_report.get(
        "users",
        []
    )

    if not isinstance(users, list):

        print(
            "ERROR: users list not found "
            "in permission_analysis.json"
        )

        return

    predictions = []

    # ========================================================
    # PROCESS EACH USER
    # ========================================================

    for user in users:

        username = user.get(
            "username"
        )

        if not username:
            continue

        # ----------------------------------------------------
        # Identity
        # ----------------------------------------------------

        identity_type = get_identity_type(
            identity_report,
            risk_report,
            username
        )

        # ----------------------------------------------------
        # Risk features
        # ----------------------------------------------------

        risk_features = get_risk_features(
            risk_report,
            username
        )

        # ----------------------------------------------------
        # Permission features
        # ----------------------------------------------------

        permission_features = (
            get_permission_features(
                permission_report,
                username
            )
        )

        # ----------------------------------------------------
        # CloudTrail features
        # ----------------------------------------------------

        cloudtrail_features = (
            get_cloudtrail_behavior(
                cloudtrail_report,
                username
            )
        )

        # ----------------------------------------------------
        # Features not currently available
        #
        # We keep them at 0 rather than
        # inventing values.
        # ----------------------------------------------------

        api_calls_7d = 0
        inactive_days = 0
        new_source_ip = 0
        failed_auth_attempts = 0

        # ====================================================
        # BUILD EXACT TRAINING SCHEMA
        # ====================================================

        features = {

            # Risk engine features
            "permission_risk":
                risk_features[
                    "permission_risk"
                ],

            "usage_risk":
                risk_features[
                    "usage_risk"
                ],

            "temporal_risk":
                risk_features[
                    "temporal_risk"
                ],

            "orphan_risk":
                risk_features[
                    "orphan_risk"
                ],

            # CloudTrail features
            "services_used":
                cloudtrail_features[
                    "services_used"
                ],

            "unusual_hour_access":
                cloudtrail_features[
                    "unusual_hour_access"
                ],

            "sensitive_actions":
                cloudtrail_features[
                    "sensitive_actions"
                ],

            "cross_service_access":
                cloudtrail_features[
                    "cross_service_access"
                ],

            # Permission features
            "admin_access":
                permission_features[
                    "admin_access"
                ],

            "full_access_policies":
                permission_features[
                    "full_access_policies"
                ],

            "policy_count":
                permission_features[
                    "policy_count"
                ],

            "unused_permissions_pct":
                permission_features[
                    "unused_permissions_pct"
                ],

            # Currently unavailable features
            "api_calls_7d":
                api_calls_7d,

            "inactive_days":
                inactive_days,

            "new_source_ip":
                new_source_ip,

            "failed_auth_attempts":
                failed_auth_attempts,

            # Categorical feature
            "identity_type":
                identity_type
        }

        # ----------------------------------------------------
        # Create DataFrame
        # ----------------------------------------------------

        df = pd.DataFrame(
            [features]
        )

        # ====================================================
        # PREDICT
        # ====================================================

        try:

            transformed = (
                preprocessor.transform(df)
            )

            prediction = model.predict(
                transformed
            )

            risk_score = float(
                prediction[0]
            )

        except Exception as e:

            print(
                f"ERROR predicting "
                f"{username}: {e}"
            )

            continue

        # ----------------------------------------------------
        # Clamp score
        # ----------------------------------------------------

        risk_score = max(
            0.0,
            min(
                100.0,
                risk_score
            )
        )

        # ----------------------------------------------------
        # Risk level
        # ----------------------------------------------------

        if risk_score < 25:

            risk_level = "Low"

        elif risk_score < 50:

            risk_level = "Medium"

        elif risk_score < 75:

            risk_level = "High"

        else:

            risk_level = "Critical"

        # ====================================================
        # DISPLAY
        # ====================================================

        print()

        print(
            f"Identity: {username}"
        )

        print(
            f"Identity Type: "
            f"{identity_type}"
        )

        print(
            f"Permission Risk: "
            f"{risk_features['permission_risk']}"
        )

        print(
            f"Usage Risk: "
            f"{risk_features['usage_risk']}"
        )

        print(
            f"Services Used: "
            f"{cloudtrail_features['services_used']}"
        )

        print(
            f"Unusual Hour Access: "
            f"{cloudtrail_features['unusual_hour_access']}"
        )

        print(
            f"Sensitive Actions: "
            f"{cloudtrail_features['sensitive_actions']}"
        )

        print(
            f"Cross-Service Access: "
            f"{cloudtrail_features['cross_service_access']}"
        )

        print(
            f"Temporal Risk: "
            f"{risk_features['temporal_risk']}"
        )

        print(
            f"Orphan Risk: "
            f"{risk_features['orphan_risk']}"
        )

        print(
            f"Admin Access: "
            f"{permission_features['admin_access']}"
        )

        print(
            f"Full Access Policies: "
            f"{permission_features['full_access_policies']}"
        )

        print(
            f"Policy Count: "
            f"{permission_features['policy_count']}"
        )

        print(
            f"Unused Permissions %: "
            f"{permission_features['unused_permissions_pct']:.2f}"
        )

        print(
            f"ML Risk Score: "
            f"{risk_score:.2f}"
        )

        print(
            f"Risk Level: "
            f"{risk_level}"
        )

        # ====================================================
        # SAVE RESULT
        # ====================================================

        predictions.append({

            "username":
                username,

            "identity_type":
                identity_type,

            "features": features,

            "ml_risk_score":
                round(
                    risk_score,
                    2
                ),

            "risk_level":
                risk_level
        })

    # ========================================================
    # SAVE REPORT
    # ========================================================

    output = {

        "module":
            "XGBoost Risk Prediction",

        "description":
            "ML-based risk prediction using "
            "behavioral, identity, permission "
            "and rule-based risk features.",

        "model":
            "XGBoost",

        "predictions":
            predictions
    }

    try:

        with open(
            OUTPUT_PATH,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                output,
                file,
                indent=4
            )

    except Exception as e:

        print(
            f"ERROR saving report: {e}"
        )

        return

    # ========================================================
    # COMPLETED
    # ========================================================

    print()

    print("=" * 60)
    print(
        "ML RISK PREDICTION COMPLETED"
    )

    print(
        "Report saved to: "
        "reports\\ml_risk_predictions.json"
    )

    print("=" * 60)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()