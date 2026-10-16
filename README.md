# AI-Powered Cybersecurity Threat Detection System

A student-built, reproducible machine-learning project that classifies network-telemetry-like rows as **benign** or **potential threat**, generates severity-tagged alerts, and saves evaluation charts and CSV reports.

> **Honest scope:** The default dataset is synthetic and is intended to verify the full workflow locally. It is not live monitoring, a production SOC tool, or proof of performance on real enterprise traffic. Use a properly licensed public dataset and validate the column mapping before making real-data claims.

## Project highlights

- Modular Python pipeline for loading, cleaning, training, evaluating, and scoring data
- Random Forest baseline and optional Logistic Regression baseline
- Accuracy, precision, recall, F1 and ROC-AUC metrics
- Confusion matrix, evaluation metrics and feature-importance plots
- Detection output with probability, severity and human-readable heuristic reasons
- Reproducible synthetic demo; no GPU or corporate network access required

## Architecture

```text
Synthetic demo CSV / mapped public dataset
                  |
                  v
       Validate columns and clean rows
                  |
                  v
       Train/test split (stratified)
                  |
                  v
       Scikit-learn model pipeline
                  |
         +--------+---------+
         |                  |
         v                  v
  Evaluation metrics    Saved model bundle
  + diagnostic plots          |
                              v
                    Sample / input telemetry
                              |
                              v
                    Predictions + rule reasons
                              |
                              v
                    CSV alert report
```

## Tech stack

Python 3.10–3.12, pandas, NumPy, scikit-learn, Matplotlib and joblib.

## Folder layout

```text
AI-Powered-Cybersecurity-Threat-Detection/
├── data/
│   ├── raw/                 # Generated or user-downloaded source CSVs
│   └── processed/           # Cleaned data (generated)
├── docs/                    # Add design notes and dataset card
├── images/                  # Optional README screenshots
├── models/                  # Saved model (generated; ignored by Git)
├── notebooks/               # Optional exploratory notebooks
├── outputs/
│   ├── figures/             # Generated plots (ignored by Git by default)
│   └── reports/              # Metrics and detection CSVs (ignored by Git by default)
├── screenshots/             # Evidence captures (optional)
├── src/
│   ├── data.py
│   ├── train.py
│   └── detect.py
├── tests/
├── main.py
├── requirements.txt
├── .gitignore
└── README.md
```

## Web UI (Streamlit)

This repository includes a local dashboard with Overview, Train & Evaluate, Threat Simulator, Analyze CSV, and Project Guide pages.

```bash
pip install -r requirements.txt
streamlit run app.py
```

Streamlit prints a local URL (usually `http://localhost:8501`). Open it in your browser. The UI is local-only by default and uses the synthetic demo unless you upload a correctly mapped dataset. It does not capture live network traffic.

## Installation

### Windows PowerShell

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that terminal, then activate again.

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Run the project

From the repository root, with the virtual environment active:

```bash
# Train and evaluate on reproducible synthetic demo data
python -m src.train

# Score a small built-in simulated scenario
python -m src.detect

# Run both in sequence
python main.py
```

Generated files:

- `data/raw/synthetic_demo_traffic.csv`
- `data/processed/cleaned_traffic.csv`
- `models/threat_detector.joblib`
- `outputs/reports/metrics.json`
- `outputs/reports/detection_results.csv`
- `outputs/figures/confusion_matrix.png`
- `outputs/figures/evaluation_metrics.png`
- `outputs/figures/feature_importance.png` (Random Forest only)

The demo values and metrics are generated locally; exact metrics may change with code/library versions.

## Use a public dataset

This project expects the following canonical schema:

`duration, src_bytes, dst_bytes, failed_logins, connection_count, unique_dst_ports, packet_rate, bytes_per_second, is_external, protocol_code, label`

`label` must be `0` for benign and `1` for threat. Most public datasets use different names and attack categories. Create a separate mapping/preprocessing step for your chosen dataset; do not simply rename unrelated columns or assume labels mean the same thing. Check dataset licensing, citation requirements, label definitions, and class balance. A model trained on the synthetic demo data should **not** be evaluated on an unrelated public dataset without retraining.

Train on a mapped CSV:

```bash
python -m src.train --data data/raw/your_mapped_dataset.csv --model random_forest
python -m src.detect --input data/raw/your_unlabelled_mapped_telemetry.csv
```

Input prediction CSV must contain the ten feature columns; it does not need `label`. Training CSV must contain those features plus `label`.

## Model choices

```bash
python -m src.train --model random_forest
python -m src.train --model logistic_regression
```

Random Forest is the default baseline because it can learn non-linear patterns and provides feature importances. Logistic Regression offers a simpler linear baseline. Compare precision and recall, not accuracy alone, especially if attack records are rare.

## Interpreting alerts

- `BENIGN`: model predicts label 0.
- `THREAT`: model predicts label 1.
- `threat_probability`: estimated class probability from the trained classifier; it is not a calibrated real-world risk score.
- `HIGH` / `MEDIUM` / `LOW`: demo severity rule based on prediction and probability, not a formal SOC severity standard.
- `rule_reasons`: transparent threshold checks on selected features. These are illustrative heuristics, not proof of a particular attack.

## Dataset and simulation notes

The default generator creates synthetic tabular data and injects a few high-signal patterns into positive rows to make pipeline behavior demonstrable. It does not generate packets, execute attacks, or interact with a network. For a stronger portfolio version, repeat the experiment on a documented public intrusion-detection dataset such as UNSW-NB15 or CICIDS2017, after verifying its current access and license terms, and record the exact preprocessing decisions.

## Evaluation

Report all metrics from `outputs/reports/metrics.json`. Include confusion matrix and class-level precision/recall/F1. Avoid claiming “industry-grade accuracy” from synthetic data. Keep a separate results table for each dataset and split.

## Tests

```bash
python -m pip install pytest
python -m pytest -q
```

## GitHub publishing

```bash
git init
git add README.md requirements.txt .gitignore LICENSE main.py src tests docs
git commit -m "Build modular threat detection baseline"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/AI-Powered-Cybersecurity-Threat-Detection.git
git push -u origin main
```

Recommended topics: `cybersecurity`, `machine-learning`, `intrusion-detection`, `scikit-learn`, `python`, `threat-detection`, `SOC`.

Before publishing, add your own screenshots to `images/` and link them below. Do not commit large raw datasets or model artifacts without checking licensing and repository size.

## Screenshots

Add screenshots such as:

- `images/dataset-preview.png`
- `images/training-report.png`
- `images/confusion-matrix.png`
- `images/detection-results.png`
- `images/github-repository.png`

Then embed them, for example:

```markdown
![Confusion matrix](images/confusion-matrix.png)
```

## Limitations and responsible use

This is an educational offline prototype. It does not capture live traffic, block connections, identify specific malware, or replace a SIEM/EDR. Predictions can be wrong. Do not use it to make production security decisions without representative data, validation, monitoring, and human review.

## Learning outcomes

- Data cleaning and tabular feature engineering
- Supervised binary classification
- Train/test separation and evaluation metrics
- Model serialization and repeatable inference
- Alert formatting and basic rule-based triage
- Git, documentation and evidence-driven project presentation
