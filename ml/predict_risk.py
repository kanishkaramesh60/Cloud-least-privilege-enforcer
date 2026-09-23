
import json
from pathlib import Path

import joblib
import pandas as pd


# ============================================================
# FILE PATHS
# ============================================================

MODEL_FILE = Path(
    "ml/xgboost_risk_model.pkl"
)

PREPROCESSOR_FILE = Path(
    "ml/risk_preprocessor.pkl"
)

RISK_FILE = Path(
    "reports/risk_report.json"
)

IDENTITY_FILE = Path(
    "reports/identity_report.json"
)

PERMISSION_FILE = Path(
    "reports/permission_analysis.json"
)

CLOUDTRAIL_ANALYSIS_FILE = Path(
    "reports/cloudtrail_analysis.json"
)

OUTPUT_FILE = Path(
    "reports/ml_risk_predictions.json"
)


# ============================================================
# LOAD JSON
# ============================================================

def load_json(path):

    if not path.exists():

        print(
            f"ERROR: {path} not found."
        )

        return None

    try:

        with open(
            path,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except json.JSONDecodeError:

        print(
            f"ERROR: Invalid JSON: {path}"
        )

        return None


# ============================================================
# FIND USER IN REPORT
# ============================================================

def find_user(
    report,
    username
):

    if not isinstance(
        report,
        dict
    ):

        return None

    users = report.get(
        "users",
        []
    )

    if not isinstance(
        users,
        list
    ):

        return None

    for user in users:

        if not isinstance(
            user,
            dict
        ):

            continue

        name = (
            user.get("username")
            or user.get("user")
            or user.get("identity")
        )

        if name == username:

            return user

    return None


# ============================================================
# IDENTITY TYPE
# ============================================================

def get_identity_type(
    identity_report,
    username
):

    if not identity_report:

        return "Unknown"

    identities = identity_report.get(
        "identities",
        []
    )

    for identity in identities:

        if not isinstance(
            identity,
            dict
        ):

            continue

        name = (
            identity.get("identity")
            or identity.get("username")
            or identity.get("name")
        )

        if name == username:

            return (
                identity.get("type")
                or identity.get("identity_type")
                or "Unknown"
            )

    return "Unknown"


# ============================================================
# CLOUDTRAIL BEHAVIOR
# ============================================================

def get_cloudtrail_behavior(
    cloudtrail_report,
    username
):

    default_behavior = {

        "total_api_calls": 0,

        "service_count": 0,

        "unusual_hour_access": 0,

        "sensitive_action_count": 0,

        "cross_service_access": 0

    }

    if not cloudtrail_report:

        return default_behavior

    identities = cloudtrail_report.get(
        "identities",
        []
    )

    if not isinstance(
        identities,
        list
    ):

        return default_behavior

    for identity in identities:

        if not isinstance(
            identity,
            dict
        ):

            continue

        name = (
            identity.get("username")
            or identity.get("identity")
            or identity.get("name")
        )

        if name != username:

            continue

        return {

            "total_api_calls":
                identity.get(
                    "total_api_calls",
                    0
                ),

            "service_count":
                identity.get(
                    "service_count",
                    0
                ),

            "unusual_hour_access":
                int(
                    identity.get(
                        "unusual_hour_access",
                        False
                    )
                ),

            "sensitive_action_count":
                identity.get(
                    "sensitive_action_count",
                    0
                ),

            "cross_service_access":
                int(
                    identity.get(
                        "cross_service_access",
                        False
                    )
                )

        }

    return default_behavior


# ============================================================
# GET PERMISSION ANALYSIS
# ============================================================

def get_permission_features(
    permission_report,
    username
):

    default_features = {

        "admin_access": 0,

        "full_access_policies": 0,

        "policy_count": 0,

        "unused_permissions_pct": 0,

        "assigned_policies": [],

        "potentially_unused_permissions": [],

        "potentially_excessive_policies": []

    }

    user = find_user(
        permission_report,
        username
    )

    if user is None:

        return default_features

    assigned_policies = user.get(
        "assigned_policies",
        []
    )

    if not isinstance(
        assigned_policies,
        list
    ):

        assigned_policies = []

    analysis = user.get(
        "analysis",
        {}
    )

    if not isinstance(
        analysis,
        dict
    ):

        analysis = {}

    potentially_unused = analysis.get(
        "potentially_unused_permissions",
        []
    )

    if not isinstance(
        potentially_unused,
        list
    ):

        potentially_unused = []

    potentially_excessive = analysis.get(
        "potentially_excessive_policies",
        []
    )

    if not isinstance(
        potentially_excessive,
        list
    ):

        potentially_excessive = []

    # --------------------------------------------------------
    # ADMIN ACCESS
    # --------------------------------------------------------

    admin_access = 0

    for policy in assigned_policies:

        if not isinstance(
            policy,
            str
        ):

            continue

        if policy == "AdministratorAccess":

            admin_access = 1

    # --------------------------------------------------------
    # FULL ACCESS POLICIES
    # --------------------------------------------------------

    full_access_policies = 0

    for policy in assigned_policies:

        if not isinstance(
            policy,
            str
        ):

            continue

        if policy in [

            "AmazonEC2FullAccess",

            "AdministratorAccess"

        ]:

            full_access_policies = 1

    # --------------------------------------------------------
    # POLICY COUNT
    # --------------------------------------------------------

    policy_count = len(
        assigned_policies
    )

    # --------------------------------------------------------
    # UNUSED PERMISSION PERCENTAGE
    # --------------------------------------------------------
    #
    # The analyzer may provide a total granted-permission
    # count. We only calculate the percentage when reliable
    # counts are available.
    #
    # Otherwise it remains 0 rather than inventing a value.
    # --------------------------------------------------------

    total_permissions = (
        analysis.get(
            "total_granted_permissions"
        )
    )

    if total_permissions is None:

        total_permissions = (
            analysis.get(
                "granted_permission_count"
            )
        )

    try:

        total_permissions = int(
            total_permissions
        )

    except (
        TypeError,
        ValueError
    ):

        total_permissions = 0

    if total_permissions > 0:

        unused_permissions_pct = (
            len(potentially_unused)
            / total_permissions
        ) * 100

    else:

        unused_permissions_pct = 0

    return {

        "admin_access":
            admin_access,

        "full_access_policies":
            full_access_policies,

        "policy_count":
            policy_count,

        "unused_permissions_pct":
            round(
                unused_permissions_pct,
                2
            ),

        "assigned_policies":
            assigned_policies,

        "potentially_unused_permissions":
            potentially_unused,

        "potentially_excessive_policies":
            potentially_excessive

    }


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)

    print(
        "          XGBOOST RISK PREDICTION"
    )

    print("=" * 60)

    # ========================================================
    # CHECK MODEL
    # ========================================================

    if not MODEL_FILE.exists():

        print(
            f"ERROR: Model not found: {MODEL_FILE}"
        )

        print(
            "Run: python ml\\train_model.py"
        )

        return

    if not PREPROCESSOR_FILE.exists():

        print(
            f"ERROR: Preprocessor not found: "
            f"{PREPROCESSOR_FILE}"
        )

        return

    # ========================================================
    # LOAD MODEL
    # ========================================================

    model = joblib.load(
        MODEL_FILE
    )

    preprocessor = joblib.load(
        PREPROCESSOR_FILE
    )

    # ========================================================
    # LOAD REPORTS
    # ========================================================

    risk_data = load_json(
        RISK_FILE
    )

    identity_data = load_json(
        IDENTITY_FILE
    )

    permission_data = load_json(
        PERMISSION_FILE
    )

    cloudtrail_data = load_json(
        CLOUDTRAIL_ANALYSIS_FILE
    )

    if risk_data is None:

        return

    if cloudtrail_data is None:

        print(
            "WARNING: CloudTrail analysis unavailable."
        )

        print(
            "CloudTrail behavioral features "
            "will use 0."
        )

    if permission_data is None:

        print(
            "WARNING: Permission analysis unavailable."
        )

        print(
            "IAM permission features will use 0."
        )

    # ========================================================
    # GET USERS
    # ========================================================

    if isinstance(
        risk_data,
        dict
    ):

        users = (
            risk_data.get("users")
            or risk_data.get("results")
            or []
        )

    elif isinstance(
        risk_data,
        list
    ):

        users = risk_data

    else:

        users = []

    predictions = []

    # ========================================================
    # PROCESS EACH IDENTITY
    # ========================================================

    for user in users:

        if not isinstance(
            user,
            dict
        ):

            continue

        username = (
            user.get("username")
            or user.get("user")
            or user.get("identity")
            or "Unknown"
        )

        # ----------------------------------------------------
        # RULE-BASED RISK FEATURES
        # ----------------------------------------------------

        permission_risk = float(
            user.get(
                "permission_risk",
                0
            )
        )

        usage_risk = float(
            user.get(
                "usage_risk",
                0
            )
        )

        orphan_risk = float(
            user.get(
                "orphan_risk",
                0
            )
        )

        temporal_risk = float(
            user.get(
                "temporal_risk",
                0
            )
        )

        # ----------------------------------------------------
        # IDENTITY
        # ----------------------------------------------------

        identity_type = get_identity_type(
            identity_data,
            username
        )

        # ----------------------------------------------------
        # CLOUDTRAIL
        # ----------------------------------------------------

        cloudtrail_behavior = (
            get_cloudtrail_behavior(
                cloudtrail_data,
                username
            )
        )

        # ----------------------------------------------------
        # IAM PERMISSION FEATURES
        # ----------------------------------------------------

        permission_features = (
            get_permission_features(
                permission_data,
                username
            )
        )

        # ====================================================
        # XGBOOST FEATURES
        # ====================================================

        features = {

            "permission_risk":
                permission_risk,

            "usage_risk":
                usage_risk,

            "orphan_risk":
                orphan_risk,

            "temporal_risk":
                temporal_risk,

            # Real IAM analysis
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

            # Current CloudTrail collection is not
            # guaranteed to represent seven days.
            "api_calls_7d":
                0,

            # Real CloudTrail value
            "services_used":
                cloudtrail_behavior[
                    "service_count"
                ],

            # Not currently available
            "inactive_days":
                0,

            # Real CloudTrail value
            "unusual_hour_access":
                cloudtrail_behavior[
                    "unusual_hour_access"
                ],

            # Not currently available
            "new_source_ip":
                0,

            # Not currently available
            "failed_auth_attempts":
                0,

            # Real CloudTrail value
            "sensitive_actions":
                cloudtrail_behavior[
                    "sensitive_action_count"
                ],

            # Real CloudTrail value
            "cross_service_access":
                cloudtrail_behavior[
                    "cross_service_access"
                ],

            "identity_type":
                identity_type

        }

        # ====================================================
        # CREATE MODEL INPUT
        # ====================================================

        X = pd.DataFrame(
            [features]
        )

        X_processed = (
            preprocessor.transform(X)
        )

        predicted_score = model.predict(
            X_processed
        )[0]

        predicted_score = max(
            0,
            min(
                100,
                float(
                    predicted_score
                )
            )
        )

        # ====================================================
        # RISK LEVEL
        # ====================================================

        if predicted_score >= 70:

            risk_level = "High"

        elif predicted_score >= 40:

            risk_level = "Medium"

        else:

            risk_level = "Low"

        # ====================================================
        # RESULT
        # ====================================================

        result = {

            "username":
                username,

            "identity_type":
                identity_type,

            "ml_risk_score":
                round(
                    predicted_score,
                    2
                ),

            "risk_level":
                risk_level,

            "model_features":
                features,

            "cloudtrail_features": {

                "total_api_calls":
                    cloudtrail_behavior[
                        "total_api_calls"
                    ],

                "service_count":
                    cloudtrail_behavior[
                        "service_count"
                    ],

                "unusual_hour_access":
                    cloudtrail_behavior[
                        "unusual_hour_access"
                    ],

                "sensitive_action_count":
                    cloudtrail_behavior[
                        "sensitive_action_count"
                    ],

                "cross_service_access":
                    cloudtrail_behavior[
                        "cross_service_access"
                    ]

            },

            "permission_features": {

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

                "assigned_policies":
                    permission_features[
                        "assigned_policies"
                    ],

                "potentially_unused_permissions":
                    permission_features[
                        "potentially_unused_permissions"
                    ],

                "potentially_excessive_policies":
                    permission_features[
                        "potentially_excessive_policies"
                    ]

            }

        }

        predictions.append(
            result
        )

        # ====================================================
        # DISPLAY
        # ====================================================

        print()

        print(
            "Identity:",
            username
        )

        print(
            "Identity Type:",
            identity_type
        )

        print(
            "CloudTrail API Calls:",
            cloudtrail_behavior[
                "total_api_calls"
            ]
        )

        print(
            "CloudTrail Services:",
            cloudtrail_behavior[
                "service_count"
            ]
        )

        print(
            "Admin Access:",
            permission_features[
                "admin_access"
            ]
        )

        print(
            "Full Access Policies:",
            permission_features[
                "full_access_policies"
            ]
        )

        print(
            "Policy Count:",
            permission_features[
                "policy_count"
            ]
        )

        print(
            "Unused Permissions %:",
            permission_features[
                "unused_permissions_pct"
            ]
        )

        print(
            "Unusual Hour Access:",
            cloudtrail_behavior[
                "unusual_hour_access"
            ]
        )

        print(
            "Sensitive Actions:",
            cloudtrail_behavior[
                "sensitive_action_count"
            ]
        )

        print(
            "Cross-Service Access:",
            cloudtrail_behavior[
                "cross_service_access"
            ]
        )

        print(
            "ML Risk Score:",
            round(
                predicted_score,
                2
            )
        )

        print(
            "Risk Level:",
            risk_level
        )

    # ========================================================
    # BUILD OUTPUT REPORT
    # ========================================================

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    report = {

        "module":
            "XGBoost ML Risk Prediction",

        "model":
            "XGBoost Regressor",

        "description":
            "Predicts IAM identity risk using the trained XGBoost model and available IAM and CloudTrail behavioral features.",

        "feature_sources": {

            "risk_report":
                str(RISK_FILE),

            "identity_report":
                str(IDENTITY_FILE),

            "permission_analysis":
                str(PERMISSION_FILE),

            "cloudtrail_analysis":
                str(CLOUDTRAIL_ANALYSIS_FILE)

        },

        "connected_features": [

            "permission_risk",

            "usage_risk",

            "orphan_risk",

            "temporal_risk",

            "admin_access",

            "full_access_policies",

            "policy_count",

            "unused_permissions_pct",

            "services_used",

            "unusual_hour_access",

            "sensitive_actions",

            "cross_service_access",

            "identity_type"

        ],

        "unavailable_features": [

            "api_calls_7d",

            "inactive_days",

            "new_source_ip",

            "failed_auth_attempts"

        ],

        "limitations": [

            "The current CloudTrail collection window is not necessarily seven days.",

            "Inactive days are not available from the current dataset.",

            "Source IP history is not available in the current collected log format.",

            "Failed authentication attempts are not available in the current collected log format.",

            "Unused permission percentage is calculated only when a reliable total granted-permission count is available in permission_analysis.json.",

            "The XGBoost model was trained on synthetic data, so the resulting score is an ML risk signal rather than a validated real-world probability."

        ],

        "predictions":
            predictions

    }

    # ========================================================
    # SAVE REPORT
    # ========================================================

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

    print("=" * 60)

    print(
        "ML RISK PREDICTION COMPLETED"
    )

    print(
        "Report saved to:",
        OUTPUT_FILE
    )

    print("=" * 60)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()