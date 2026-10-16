"""Score telemetry rows and generate explainable demo alerts."""
from pathlib import Path
import json
import joblib
import pandas as pd
from src.data import ROOT, FEATURES

MODEL_PATH = ROOT / "models" / "threat_detector.joblib"
OUT_DIR = ROOT / "outputs" / "reports"

def rule_reasons(row: pd.Series) -> str:
    reasons = []
    if row["failed_logins"] >= 5:
        reasons.append("repeated failed logins")
    if row["connection_count"] >= 100:
        reasons.append("high connection volume")
    if row["unique_dst_ports"] >= 20:
        reasons.append("many destination ports")
    if row["packet_rate"] >= 75:
        reasons.append("high packet rate")
    return "; ".join(reasons) if reasons else "no simple heuristic triggered"

def detect(input_path: str | None = None) -> pd.DataFrame:
    if not MODEL_PATH.exists():
        raise FileNotFoundError("Model not found. Run `python -m src.train` first.")
    bundle = joblib.load(MODEL_PATH)
    if input_path:
        path = Path(input_path)
        if not path.is_absolute():
            path = ROOT / path
        df = pd.read_csv(path)
        missing = set(FEATURES) - set(df.columns)
        if missing:
            raise ValueError("Input CSV missing feature columns: " + ", ".join(sorted(missing)))
        df = df[FEATURES].copy()
    else:
        # Deliberately constructed examples to demonstrate alert generation.
        df = pd.DataFrame([
            [0.4, 800, 1200, 0, 8, 2, 12.0, 1200, 0, 1],
            [1.2, 1200, 400, 9, 180, 35, 110.0, 800, 1, 2],
            [0.1, 80, 10, 14, 260, 50, 160.0, 900, 1, 3],
            [3.4, 3200, 6500, 0, 14, 4, 18.0, 2400, 0, 1],
            [0.2, 200, 100, 6, 95, 22, 82.0, 300, 1, 2],
        ], columns=FEATURES)

    for col in FEATURES:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    if df[FEATURES].isna().all(axis=1).any():
        raise ValueError("At least one input row has no usable feature values.")

    predictions = bundle["pipeline"].predict(df[FEATURES])
    probabilities = bundle["pipeline"].predict_proba(df[FEATURES])[:, 1]
    result = df.copy()
    result["threat_probability"] = probabilities.round(4)
    result["model_prediction"] = ["THREAT" if p == 1 else "BENIGN" for p in predictions]
    result["severity"] = [
        "HIGH" if (p == 1 and prob >= 0.80) else "MEDIUM" if p == 1 else "LOW"
        for p, prob in zip(predictions, probabilities)
    ]
    result["rule_reasons"] = result.apply(rule_reasons, axis=1)
    result["alert"] = result.apply(
        lambda r: f"[{r['severity']}] {r['model_prediction']} | probability={r['threat_probability']:.2f} | {r['rule_reasons']}",
        axis=1
    )

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "detection_results.csv"
    result.to_csv(out_path, index=False)
    print("\n=== DETECTION RESULTS ===")
    print(result[["model_prediction", "threat_probability", "severity", "rule_reasons"]].to_string(index=False))
    print(f"\nRows flagged as threats: {(result['model_prediction'] == 'THREAT').sum()} / {len(result)}")
    print(f"Saved results: {out_path}")
    return result

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run detection on sample or supplied telemetry.")
    parser.add_argument("--input", default=None, help="Optional CSV containing the required features.")
    args = parser.parse_args()
    detect(args.input)
