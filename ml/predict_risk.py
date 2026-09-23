import json
from pathlib import Path
import joblib
import pandas as pd


MODEL_FILE = Path("ml/xgboost_risk_model.pkl")
PREPROCESSOR_FILE = Path("ml/risk_preprocessor.pkl")
RISK_FILE = Path("reports/risk_report.json")
IDENTITY_FILE = Path("reports/identity_report.json")
CLOUDTRAIL_ANALYSIS_FILE = Path(
    "reports/cloudtrail_analysis.json"
)
OUTPUT_FILE = Path("reports/ml_risk_predictions.json")


def load_json(path):
    if not path.exists():
        print(f"ERROR: {path} not found.")
        return None

    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)

    except json.JSONDecodeError:
        print(f"ERROR: Invalid JSON: {path}")
        return None


def get_identity_type(identity_report, username):
    if not identity_report:
        return "Unknown"

    identities = identity_report.get("identities", [])

    for identity in identities:
        if not isinstance(identity, dict):
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


def get_cloudtrail_behavior(cloudtrail_report, username):
    default_behavior = {
        "total_api_calls": 0,
        "service_count": 0,
        "unusual_hour_access": 0,
        "sensitive_action_count": 0,
        "cross_service_access": 0
    }

    if not cloudtrail_report:
        return default_behavior

    identities = cloudtrail_report.get("identities", [])

    for identity in identities:
        if not isinstance(identity, dict):
            continue

        if identity.get("username") == username:
            return {
                "total_api_calls": identity.get(
                    "total_api_calls", 0
                ),
                "service_count": identity.get(
                    "service_count", 0
                ),
                "unusual_hour_access": int(
                    identity.get(
                        "unusual_hour_access", False
                    )
                ),
                "sensitive_action_count": identity.get(
                    "sensitive_action_count", 0
                ),
                "cross_service_access": int(
                    identity.get(
                        "cross_service_access", False
                    )
                )
            }

    return default_behavior


def main():
    print("=" * 60)
    print("          XGBOOST RISK PREDICTION")
    print("=" * 60)

    if not MODEL_FILE.exists():
        print(f"ERROR: Model not found: {MODEL_FILE}")
        print("Run: python ml\\train_model.py")
        return

    if not PREPROCESSOR_FILE.exists():
        print(
            f"ERROR: Preprocessor not found: "
            f"{PREPROCESSOR_FILE}"
        )
        return

    model = joblib.load(MODEL_FILE)

    preprocessor = joblib.load(
        PREPROCESSOR_FILE
    )

    risk_data = load_json(RISK_FILE)
    identity_data = load_json(IDENTITY_FILE)
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
            "CloudTrail behavioral features will use 0."
        )

    if isinstance(risk_data, dict):
        users = (
            risk_data.get("users")
            or risk_data.get("results")
            or []
        )

    elif isinstance(risk_data, list):
        users = risk_data

    else:
        users = []

    predictions = []

    for user in users:

        if not isinstance(user, dict):
            continue

        username = (
            user.get("username")
            or user.get("user")
            or user.get("identity")
            or "Unknown"
        )

        permission_risk = float(
            user.get("permission_risk", 0)
        )

        usage_risk = float(
            user.get("usage_risk", 0)
        )

        orphan_risk = float(
            user.get("orphan_risk", 0)
        )

        temporal_risk = float(
            user.get("temporal_risk", 0)
        )

        identity_type = get_identity_type(
            identity_data,
            username
        )

        cloudtrail_behavior = get_cloudtrail_behavior(
            cloudtrail_data,
            username
        )

        features = {
            "permission_risk":
                permission_risk,

            "usage_risk":
                usage_risk,

            "orphan_risk":
                orphan_risk,

            "temporal_risk":
                temporal_risk,

            # These can be derived from IAM/risk reports
            # in a future enhancement.
            "admin_access": 0,

            "full_access_policies": 0,

            "policy_count": 0,

            "unused_permissions_pct": 0,

            # Current CloudTrail collection is NOT
            # necessarily a 7-day window.
            # Therefore we do not use total_api_calls
            # as api_calls_7d.
            "api_calls_7d": 0,

            # Real CloudTrail analysis value
            "services_used":
                cloudtrail_behavior["service_count"],

            # Not available from current dataset
            "inactive_days": 0,

            # Real CloudTrail analysis value
            "unusual_hour_access":
                cloudtrail_behavior[
                    "unusual_hour_access"
                ],

            # Not available from current dataset
            "new_source_ip": 0,

            # Not available from current dataset
            "failed_auth_attempts": 0,

            # Real CloudTrail analysis value
            "sensitive_actions":
                cloudtrail_behavior[
                    "sensitive_action_count"
                ],

            # Real CloudTrail analysis value
            "cross_service_access":
                cloudtrail_behavior[
                    "cross_service_access"
                ],

            "identity_type":
                identity_type
        }

        X = pd.DataFrame([features])

        X_processed = preprocessor.transform(X)

        predicted_score = model.predict(
            X_processed
        )[0]

        predicted_score = max(
            0,
            min(100, float(predicted_score))
        )

        if predicted_score >= 70:
            risk_level = "High"

        elif predicted_score >= 40:
            risk_level = "Medium"

        else:
            risk_level = "Low"

        result = {
            "username":
                username,

            "identity_type":
                identity_type,

            "ml_risk_score":
                round(predicted_score, 2),

            "risk_level":
                risk_level,

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
            }
        }

        predictions.append(result)

        print()
        print("Identity:", username)
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
            round(predicted_score, 2)
        )

        print(
            "Risk Level:",
            risk_level
        )

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
            "Predicts IAM identity risk using the trained XGBoost model and available CloudTrail behavioral features.",

        "feature_sources": {
            "risk_report":
                str(RISK_FILE),

            "identity_report":
                str(IDENTITY_FILE),

            "cloudtrail_analysis":
                str(CLOUDTRAIL_ANALYSIS_FILE)
        },

        "limitations": [
            "The current CloudTrail collection window is not necessarily seven days.",
            "Inactive days are not available from the current dataset.",
            "Source IP history is not available in the current collected log format.",
            "Failed authentication attempts are not available in the current collected log format.",
            "Admin access, full access policies, policy count and unused permission percentage are not yet derived here."
        ],

        "predictions":
            predictions
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
    print("=" * 60)
    print("ML RISK PREDICTION COMPLETED")
    print(
        "Report saved to:",
        OUTPUT_FILE
    )
    print("=" * 60)


if __name__ == "__main__":
    main()
