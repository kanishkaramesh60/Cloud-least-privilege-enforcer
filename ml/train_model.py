import json
from pathlib import Path
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.metrics import mean_absolute_error, r2_score
from xgboost import XGBRegressor
DATASET = Path("ml/risk_dataset.csv")
MODEL_FILE = Path("ml/xgboost_risk_model.pkl")
PREPROCESSOR_FILE = Path("ml/risk_preprocessor.pkl")
METRICS_FILE = Path("reports/ml_model_metrics.json")
def main():
    print("=" * 60)
    print("       XGBOOST RISK MODEL TRAINING")
    print("=" * 60)
    if not DATASET.exists():
        print(f"ERROR: Dataset not found: {DATASET}")
        return
    df = pd.read_csv(DATASET)
    print("Dataset size:", len(df))
    TARGET = "risk_score"
    if TARGET not in df.columns:
        print(
            f"ERROR: Target column '{TARGET}' "
            "not found in dataset."
        )
        print("Available columns:")
        print(list(df.columns))
        return
    X = df.drop(TARGET, axis=1)
    y = df[TARGET]
    print("Features:", X.shape[1])
    print("Target:", TARGET)
    categorical_columns = [
        "identity_type"
    ]
    categorical_columns = [
        column
        for column in categorical_columns
        if column in X.columns
    ]
    numerical_columns = [
        column
        for column in X.columns
        if column not in categorical_columns
    ]
    print("Numerical features:", len(numerical_columns))
    print("Categorical features:", len(categorical_columns))
    preprocessor = ColumnTransformer(
        transformers=[
            (
                "categorical",
                OneHotEncoder(
                    handle_unknown="ignore"
                ),
                categorical_columns
            )
        ],
        remainder="passthrough"
    )
    X_processed = preprocessor.fit_transform(X)
    X_train, X_test, y_train, y_test = train_test_split(
        X_processed,
        y,
        test_size=0.20,
        random_state=42
    )
    print("Training samples:", X_train.shape[0])
    print("Testing samples:", X_test.shape[0])
    model = XGBRegressor(
        n_estimators=300,
        max_depth=5,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="reg:squarederror",
        random_state=42
    )
    print()
    print("Training XGBoost model...")
    model.fit(
        X_train,
        y_train
    )
    predictions = model.predict(X_test)
    predictions = predictions.clip(0, 100)
    mae = mean_absolute_error(
        y_test,
        predictions
    )
    r2 = r2_score(
        y_test,
        predictions
    )
    print()
    print("=" * 60)
    print("MODEL EVALUATION")
    print("=" * 60)
    print(
        f"Mean Absolute Error: {mae:.2f}"
    )
    print(
        f"R2 Score: {r2:.4f}"
    )
    MODEL_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )
    joblib.dump(
        model,
        MODEL_FILE
    )
    joblib.dump(
        preprocessor,
        PREPROCESSOR_FILE
    )
    METRICS_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )
    metrics = {
        "model": "XGBoost Regressor",
        "dataset": str(DATASET),
        "samples": len(df),
        "features": X.shape[1],
        "training_samples": len(X_train),
        "testing_samples": len(X_test),
        "target": TARGET,
        "mean_absolute_error": round(
            float(mae),
            4
        ),
        "r2_score": round(
            float(r2),
            4
        )
    }
    with open(
        METRICS_FILE,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            metrics,
            file,
            indent=4
        )
    print()
    print("=" * 60)
    print("XGBOOST MODEL TRAINING COMPLETED")
    print("=" * 60)
    print(
        "Model saved to:",
        MODEL_FILE
    )
    print(
        "Preprocessor saved to:",
        PREPROCESSOR_FILE
    )
    print(
        "Metrics saved to:",
        METRICS_FILE
    )
    print("=" * 60)
if __name__ == "__main__":
    main()