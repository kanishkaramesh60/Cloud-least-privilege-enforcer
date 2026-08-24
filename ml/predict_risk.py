import json
from pathlib import Path
import joblib
import numpy as np
MODEL_FILE = Path("ml/model/risk_model.pkl")
FEATURE_FILE = Path("reports/ml_features.json")
OUTPUT_FILE = Path("reports/risk_report.json")
FEATURE_NAMES = [
    "policy_count",
    "broad_policy_count",
    "has_admin_access",
    "has_full_access",
    "api_call_count",
    "service_count",
    "inactive_days",
    "odd_hour_activity",
    "rare_activity",
    "unused_service_count"
]
LABELS = {
    0: "LOW",
    1: "MEDIUM",
    2: "HIGH"
}
def main():
    print("=" * 60)
    print("          ML RISK PREDICTION")
    print("=" * 60)
    if not MODEL_FILE.exists():
        print("ERROR: XGBoost model not found:")
        print(MODEL_FILE)
        return
    if not FEATURE_FILE.exists():
        print("ERROR: ML feature file not found:")
        print(FEATURE_FILE)
        return
    model = joblib.load(MODEL_FILE)
    with open(
        FEATURE_FILE,
        "r",
        encoding="utf-8"
    ) as file:
        data = json.load(file)
    users = data.get("users", [])
    if not users:
        print("ERROR: No users found in ml_features.json")
        return
    results = []
    for user in users:
        username = user.get("username")
        features = user.get("features", {})
        values = []
        for feature in FEATURE_NAMES:
            value = features.get(feature, 0)
            try:
                value = float(value)
            except (ValueError, TypeError):
                value = 0
            values.append(value)
        X = np.array([values])
        probabilities = model.predict_proba(X)[0]
        predicted_class = int(
            model.predict(X)[0]
        )
        risk_level = LABELS.get(
            predicted_class,
            "UNKNOWN"
        )
        low_probability = float(probabilities[0])
        medium_probability = float(probabilities[1])
        high_probability = float(probabilities[2])
        risk_score = round(
            (
                low_probability * 0
                + medium_probability * 50
                + high_probability * 100
            ),
            2
        )
        result = {
            "username": username,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "probabilities": {
                "LOW": round(low_probability, 4),
                "MEDIUM": round(medium_probability, 4),
                "HIGH": round(high_probability, 4)
            },
            "features": features
        }
        results.append(result)
        print()
        print("User:", username)
        print("Risk Score:", risk_score)
        print("Risk Level:", risk_level)
        print(
            "LOW:",
            round(low_probability * 100, 2),
            "%"
        )
        print(
            "MEDIUM:",
            round(medium_probability * 100, 2),
            "%"
        )
        print(
            "HIGH:",
            round(high_probability * 100, 2),
            "%"
        )
    report = {
        "module": "XGBoost ML Risk Scoring",
        "description": (
            "Predicts IAM risk using features generated "
            "from IAM policies, CloudTrail usage, "
            "permission analysis, orphan detection "
            "and temporal analysis."
        ),
        "users": results
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
    print("ML Risk Prediction Completed")
    print("Report saved to:", OUTPUT_FILE)
    print("=" * 60)
if __name__ == "__main__":
    main()