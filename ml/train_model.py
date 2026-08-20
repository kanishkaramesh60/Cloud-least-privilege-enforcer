import pandas as pd
import joblib
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
DATASET = "ml/risk_dataset.csv"
MODEL_FILE = "ml/model/risk_model.pkl"
def main():
    print("=" * 60)
    print("       XGBOOST RISK MODEL TRAINING")
    print("=" * 60)
    df = pd.read_csv(DATASET)
    print("Dataset size:", len(df))
    X = df.drop("risk", axis=1)
    y = df["risk"]
    label_map = {
        "LOW": 0,
        "MEDIUM": 1,
        "HIGH": 2
    }
    y = y.map(label_map)
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )
    model = XGBClassifier(
        n_estimators=150,
        max_depth=4,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="multi:softprob",
        num_class=3,
        eval_metric="mlogloss",
        random_state=42
    )
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)
    accuracy = accuracy_score(
        y_test,
        predictions
    )
    print()
    print("Model Accuracy:", round(accuracy * 100, 2), "%")
    print()
    print("Classification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "LOW",
                "MEDIUM",
                "HIGH"
            ]
        )
    )
    joblib.dump(model, MODEL_FILE)
    print()
    print("Model saved to:", MODEL_FILE)
    print("=" * 60)

if __name__ == "__main__":
    main()