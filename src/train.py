"""Train, evaluate, and save a reproducible threat classification pipeline."""
from pathlib import Path
import json
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, ConfusionMatrixDisplay, roc_auc_score
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression

from src.data import ROOT, FEATURES, TARGET, load_dataset, clean_dataset

MODELS = ROOT / "models"
REPORTS = ROOT / "outputs" / "reports"
FIGURES = ROOT / "outputs" / "figures"

def train(dataset_path: str | None = None, model_name: str = "random_forest") -> dict:
    MODELS.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    FIGURES.mkdir(parents=True, exist_ok=True)

    df = clean_dataset(load_dataset(dataset_path))
    df.to_csv(ROOT / "data" / "processed" / "cleaned_traffic.csv", index=False)
    X, y = df[FEATURES], df[TARGET]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    if model_name == "logistic_regression":
        estimator = LogisticRegression(max_iter=1500, class_weight="balanced")
        pipeline = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            ("model", estimator),
        ])
    else:
        pipeline = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("model", RandomForestClassifier(
                n_estimators=180, max_depth=None, min_samples_leaf=2,
                class_weight="balanced_subsample", random_state=42, n_jobs=-1
            )),
        ])

    pipeline.fit(X_train, y_train)
    pred = pipeline.predict(X_test)
    probability = pipeline.predict_proba(X_test)[:, 1]
    metrics = {
        "model": model_name,
        "dataset_rows": int(len(df)),
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "accuracy": round(float(accuracy_score(y_test, pred)), 4),
        "precision": round(float(precision_score(y_test, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, pred, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_test, pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, probability)), 4),
        "classification_report": classification_report(
            y_test, pred, target_names=["benign", "threat"], zero_division=0, output_dict=True
        ),
        "note": "Synthetic demo data unless an external CSV was supplied. Metrics are not real-world performance claims."
    }
    joblib.dump({"pipeline": pipeline, "features": FEATURES, "model_name": model_name},
                MODELS / "threat_detector.joblib")
    (REPORTS / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    disp = ConfusionMatrixDisplay.from_predictions(
        y_test, pred, display_labels=["Benign", "Threat"], cmap="Blues", values_format="d"
    )
    disp.ax_.set_title("Threat Detection — Confusion Matrix")
    plt.tight_layout()
    plt.savefig(FIGURES / "confusion_matrix.png", dpi=160)
    plt.close()

    fig, ax = plt.subplots(figsize=(7, 4))
    pd.Series(metrics | {}).drop(labels=["classification_report", "note", "model"], errors="ignore").drop(
        labels=["dataset_rows", "train_rows", "test_rows"], errors="ignore"
    ).plot(kind="bar", ax=ax, ylim=(0, 1), title="Evaluation Metrics")
    ax.set_ylabel("Score")
    ax.tick_params(axis="x", rotation=0)
    plt.tight_layout()
    plt.savefig(FIGURES / "evaluation_metrics.png", dpi=160)
    plt.close()

    # Feature importance is available for the Random Forest pipeline.
    model = pipeline.named_steps["model"]
    if hasattr(model, "feature_importances_"):
        importance = pd.Series(model.feature_importances_, index=FEATURES).sort_values()
        ax = importance.plot(kind="barh", figsize=(8, 5), title="Random Forest Feature Importance")
        ax.set_xlabel("Importance")
        plt.tight_layout()
        plt.savefig(FIGURES / "feature_importance.png", dpi=160)
        plt.close()

    print("\n=== THREAT DETECTOR TRAINING REPORT ===")
    print(f"Model: {model_name}")
    print(f"Rows: {len(df)} | Train: {len(X_train)} | Test: {len(X_test)}")
    for key in ["accuracy", "precision", "recall", "f1_score", "roc_auc"]:
        print(f"{key.replace('_', ' ').title():<12}: {metrics[key]:.3f}")
    print(f"Saved model: {MODELS / 'threat_detector.joblib'}")
    print(f"Saved reports: {REPORTS / 'metrics.json'}")
    print(f"Saved graphs: {FIGURES}")
    return metrics

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Train the threat detection model.")
    parser.add_argument("--data", default=None, help="Optional CSV path matching the project schema.")
    parser.add_argument("--model", choices=["random_forest", "logistic_regression"],
                        default="random_forest")
    args = parser.parse_args()
    train(args.data, args.model)
