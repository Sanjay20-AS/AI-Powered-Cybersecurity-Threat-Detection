"""Streamlit UI for the AI-Powered Cybersecurity Threat Detection demo."""
from pathlib import Path
import json
import pandas as pd
import streamlit as st

from src.train import train
from src.detect import detect
from src.data import FEATURES, TARGET, create_demo_dataset

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "outputs" / "reports"
FIGURES = ROOT / "outputs" / "figures"
MODEL = ROOT / "models" / "threat_detector.joblib"

st.set_page_config(
    page_title="Cyber Threat Detection | AI SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .stApp { background: #0b1220; color: #e5edf8; }
    [data-testid="stSidebar"] { background: #111b2e; }
    div[data-testid="stMetric"] {
        background: #111b2e; border: 1px solid #263754;
        padding: 16px; border-radius: 12px;
    }
    .hero {
        padding: 24px 26px; border-radius: 16px;
        background: linear-gradient(120deg, #132b4f, #123d42);
        border: 1px solid #2b526b; margin-bottom: 18px;
    }
    .hero h1 { margin: 0; color: #f5f8ff; font-size: 2rem; }
    .hero p { color: #bfd0e7; margin-bottom: 0; }
    .small-note { color: #9db0ca; font-size: .9rem; }
</style>
""", unsafe_allow_html=True)

def load_metrics():
    path = REPORTS / "metrics.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))

def run_detection(df):
    MODEL.parent.mkdir(parents=True, exist_ok=True)
    temp_path = ROOT / "data" / "processed" / "ui_input.csv"
    temp_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(temp_path, index=False)
    return detect("data/processed/ui_input.csv")

with st.sidebar:
    st.title("🛡️ AI SOC Console")
    page = st.radio("Navigation", ["Overview", "Train & Evaluate", "Threat Simulator", "Analyze CSV", "Project Guide"])
    st.divider()
    st.caption("Offline student project")
    st.caption("Synthetic demo • No live network access")

if page == "Overview":
    st.markdown("""
    <div class="hero">
      <h1>AI-Powered Cybersecurity Threat Detection</h1>
      <p>Machine-learning triage for simulated network telemetry</p>
    </div>
    """, unsafe_allow_html=True)
    metrics = load_metrics()
    if metrics:
        cols = st.columns(4)
        for col, label, key in zip(cols, ["Accuracy", "Precision", "Recall", "F1 Score"],
                                   ["accuracy", "precision", "recall", "f1_score"]):
            col.metric(label, f"{metrics[key]*100:.1f}%")
    else:
        st.info("The model has not been trained yet. Open **Train & Evaluate** and train the demo model.")
    a, b, c = st.columns(3)
    a.metric("Detection mode", "Offline")
    b.metric("Telemetry", "Tabular CSV")
    c.metric("Alert review", "Human-in-the-loop")
    st.subheader("System status")
    st.write("Use the left navigation to train a model, simulate sample telemetry, or analyze a CSV.")
    if (FIGURES / "confusion_matrix.png").exists():
        st.image(str(FIGURES / "confusion_matrix.png"), caption="Latest model evaluation — demo data")
    if (REPORTS / "detection_results.csv").exists():
        st.subheader("Latest detection alerts")
        results = pd.read_csv(REPORTS / "detection_results.csv")
        st.dataframe(results, use_container_width=True, hide_index=True)
    st.warning("This is an educational prototype. The default data is synthetic and does not represent measured enterprise traffic.")

elif page == "Train & Evaluate":
    st.title("Model Training & Evaluation")
    st.write("Train the baseline classifier on the generated demo data, or supply a CSV that matches the documented project schema.")
    model_choice = st.selectbox("Model", ["random_forest", "logistic_regression"])
    uploaded = st.file_uploader("Optional labeled training CSV", type=["csv"], help="Required columns: ten features plus label (0=benign, 1=threat).")
    if st.button("Train model", type="primary"):
        data_arg = None
        if uploaded is not None:
            upload_path = ROOT / "data" / "raw" / "uploaded_training.csv"
            upload_path.parent.mkdir(parents=True, exist_ok=True)
            upload_path.write_bytes(uploaded.getvalue())
            data_arg = "data/raw/uploaded_training.csv"
        with st.spinner("Training and evaluating model..."):
            try:
                metrics = train(data_arg, model_choice)
                st.success("Training complete. Model and evaluation outputs were saved.")
                st.json({k: v for k, v in metrics.items() if k != "classification_report"})
                st.rerun()
            except Exception as exc:
                st.error(f"Training failed: {exc}")
    metrics = load_metrics()
    if metrics:
        cols = st.columns(5)
        for col, label, key in zip(cols, ["Accuracy", "Precision", "Recall", "F1", "ROC-AUC"],
                                   ["accuracy", "precision", "recall", "f1_score", "roc_auc"]):
            col.metric(label, f"{metrics[key]*100:.1f}%")
        left, right = st.columns(2)
        if (FIGURES / "confusion_matrix.png").exists():
            left.image(str(FIGURES / "confusion_matrix.png"), caption="Confusion matrix")
        if (FIGURES / "evaluation_metrics.png").exists():
            right.image(str(FIGURES / "evaluation_metrics.png"), caption="Evaluation metrics")
        if (FIGURES / "feature_importance.png").exists():
            st.image(str(FIGURES / "feature_importance.png"), caption="Random Forest feature importance")

elif page == "Threat Simulator":
    st.title("Threat Simulation Lab")
    st.write("Generate illustrative telemetry rows and score them with the trained model. This does not send traffic or execute attacks.")
    scenario = st.selectbox("Choose a scenario", [
        "Mixed benign and suspicious activity",
        "Repeated login failures",
        "High connection / port scan-like volume",
        "Normal low-volume activity"
    ])
    if st.button("Run simulation", type="primary"):
        if not MODEL.exists():
            with st.spinner("No model found — training the default demo model first..."):
                train()
        scenarios = {
            "Mixed benign and suspicious activity": [
                [0.4, 800, 1200, 0, 8, 2, 12.0, 1200, 0, 1],
                [1.2, 1200, 400, 9, 180, 35, 110.0, 800, 1, 2],
                [0.1, 80, 10, 14, 260, 50, 160.0, 900, 1, 3],
                [3.4, 3200, 6500, 0, 14, 4, 18.0, 2400, 0, 1],
                [0.2, 200, 100, 6, 95, 22, 82.0, 300, 1, 2],
            ],
            "Repeated login failures": [
                [0.2, 100, 50, 12, 40, 2, 18.0, 100, 1, 2],
                [0.3, 130, 40, 16, 55, 3, 20.0, 110, 1, 2],
                [0.4, 140, 60, 10, 45, 2, 19.0, 105, 1, 2],
            ],
            "High connection / port scan-like volume": [
                [0.1, 500, 100, 0, 220, 60, 145.0, 500, 1, 3],
                [0.2, 400, 120, 1, 180, 45, 120.0, 450, 1, 3],
                [0.3, 700, 200, 0, 150, 32, 95.0, 650, 1, 2],
            ],
            "Normal low-volume activity": [
                [2.4, 1600, 2500, 0, 7, 2, 8.0, 900, 0, 1],
                [1.7, 900, 1200, 0, 10, 3, 11.0, 700, 0, 1],
                [3.1, 2200, 4000, 0, 12, 4, 13.0, 1400, 0, 1],
            ],
        }
        df = pd.DataFrame(scenarios[scenario], columns=FEATURES)
        result = run_detection(df)
        st.subheader("Detection output")
        st.dataframe(result[["model_prediction", "threat_probability", "severity", "rule_reasons", "alert"]],
                     use_container_width=True, hide_index=True)
        flagged = int((result["model_prediction"] == "THREAT").sum())
        st.metric("Rows flagged as threats", f"{flagged} / {len(result)}")
        st.download_button("Download detection CSV", result.to_csv(index=False).encode("utf-8"),
                           file_name="detection_results.csv", mime="text/csv")

elif page == "Analyze CSV":
    st.title("Analyze Telemetry CSV")
    st.write("Upload a CSV with the ten feature columns. The app will score each row using the saved model.")
    st.caption("Columns: " + ", ".join(FEATURES))
    uploaded = st.file_uploader("Upload unlabeled telemetry CSV", type=["csv"])
    if uploaded is not None:
        try:
            df = pd.read_csv(uploaded)
            st.subheader("Input preview")
            st.dataframe(df.head(20), use_container_width=True, hide_index=True)
            if st.button("Analyze uploaded rows", type="primary"):
                if not MODEL.exists():
                    st.error("Train a model first in Train & Evaluate.")
                else:
                    result = run_detection(df)
                    st.subheader("Predictions and alerts")
                    st.dataframe(result, use_container_width=True, hide_index=True)
                    st.download_button("Download results", result.to_csv(index=False).encode("utf-8"),
                                       file_name="analyzed_telemetry.csv", mime="text/csv")
        except Exception as exc:
            st.error(f"Could not read CSV: {exc}")

else:
    st.title("Project Guide")
    st.subheader("What this demo does")
    st.markdown("""
    1. **Train:** fits a classifier to labeled tabular data.
    2. **Evaluate:** reports accuracy, precision, recall, F1 and ROC-AUC.
    3. **Detect:** scores telemetry rows and labels them benign or threat.
    4. **Triage:** attaches illustrative severity and transparent rule-based reasons.
    5. **Export:** lets you download prediction results as CSV.

    **Expected feature columns**
    """)
    st.code(", ".join(FEATURES) + ", label (training only)")
    st.subheader("Run locally")
    st.code("pip install -r requirements.txt\nstreamlit run app.py", language="bash")
    st.subheader("Safety and limitations")
    st.warning("No live packet capture, attack execution, blocking, or production SIEM integration. The default data is synthetic; benchmark performance must be measured separately on a documented public dataset.")
