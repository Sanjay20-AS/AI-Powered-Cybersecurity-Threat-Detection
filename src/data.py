"""Dataset loading and safe preprocessing for the demo threat detector."""
from pathlib import Path
import pandas as pd
from sklearn.datasets import make_classification

ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "data" / "raw"
PROCESSED_DIR = ROOT / "data" / "processed"

FEATURES = [
    "duration", "src_bytes", "dst_bytes", "failed_logins",
    "connection_count", "unique_dst_ports", "packet_rate",
    "bytes_per_second", "is_external", "protocol_code"
]
TARGET = "label"

def create_demo_dataset(n_samples: int = 6000, random_state: int = 42) -> pd.DataFrame:
    """Create a clearly synthetic dataset when no external dataset is supplied.

    This is for validating the pipeline only, not a substitute for measured network traffic.
    """
    X, y = make_classification(
        n_samples=n_samples, n_features=8, n_informative=6, n_redundant=1,
        n_repeated=0, n_classes=2, weights=[0.78, 0.22],
        class_sep=1.0, flip_y=0.025, random_state=random_state
    )
    # Transform generic numeric signals into plausible-looking toy telemetry.
    df = pd.DataFrame(X, columns=[
        "duration", "src_bytes", "dst_bytes", "failed_logins",
        "connection_count", "unique_dst_ports", "packet_rate", "bytes_per_second"
    ])
    df["duration"] = (abs(df["duration"]) * 25).round(3)
    df["src_bytes"] = (abs(df["src_bytes"]) * 1800).round().astype(int)
    df["dst_bytes"] = (abs(df["dst_bytes"]) * 2400).round().astype(int)
    df["failed_logins"] = (abs(df["failed_logins"]) * 2).round().clip(0, 20).astype(int)
    df["connection_count"] = (abs(df["connection_count"]) * 35).round().clip(0, 500).astype(int)
    df["unique_dst_ports"] = (abs(df["unique_dst_ports"]) * 8).round().clip(1, 100).astype(int)
    df["packet_rate"] = (abs(df["packet_rate"]) * 50).round(3)
    df["bytes_per_second"] = (abs(df["bytes_per_second"]) * 5000).round(3)
    df["is_external"] = ((df["connection_count"] > df["connection_count"].median()).astype(int))
    df["protocol_code"] = ((df["unique_dst_ports"] % 3) + 1).astype(int)
    df[TARGET] = y.astype(int)
    # Inject a few understandable high-signal simulated patterns into the positive class.
    positive = df[TARGET].eq(1)
    df.loc[positive, "failed_logins"] = df.loc[positive, "failed_logins"].clip(lower=3)
    df.loc[positive, "connection_count"] = df.loc[positive, "connection_count"].clip(lower=80)
    df.loc[positive, "unique_dst_ports"] = df.loc[positive, "unique_dst_ports"].clip(lower=15)
    return df[FEATURES + [TARGET]]

def load_dataset(path: str | None = None) -> pd.DataFrame:
    """Load a CSV with the expected features and label; otherwise make demo data."""
    if path:
        csv_path = Path(path)
        if not csv_path.is_absolute():
            csv_path = ROOT / csv_path
        if not csv_path.exists():
            raise FileNotFoundError(f"Dataset not found: {csv_path}")
        df = pd.read_csv(csv_path)
        missing = set(FEATURES + [TARGET]) - set(df.columns)
        if missing:
            raise ValueError(
                "CSV is missing required columns: " + ", ".join(sorted(missing)) +
                ". Map/rename your dataset columns to the project schema first."
            )
        df = df[FEATURES + [TARGET]].copy()
    else:
        df = create_demo_dataset()
        RAW_DIR.mkdir(parents=True, exist_ok=True)
        df.to_csv(RAW_DIR / "synthetic_demo_traffic.csv", index=False)
    return df

def clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize missing/infinite values and enforce numeric model inputs."""
    out = df.copy()
    out = out.replace([float("inf"), float("-inf")], pd.NA)
    for col in FEATURES + [TARGET]:
        out[col] = pd.to_numeric(out[col], errors="coerce")
    out = out.dropna(subset=[TARGET])
    out[FEATURES] = out[FEATURES].fillna(out[FEATURES].median(numeric_only=True))
    out[TARGET] = out[TARGET].astype(int)
    out = out[out[TARGET].isin([0, 1])]
    if out.empty:
        raise ValueError("No valid rows remain after cleaning.")
    if out[TARGET].nunique() < 2:
        raise ValueError("Training requires both label classes: 0=benign, 1=threat.")
    return out.reset_index(drop=True)
