# Dataset card: synthetic demo traffic

- **Purpose:** Test that the project can load tabular records, train a model, evaluate it, and generate predictions.
- **Origin:** Generated locally by `sklearn.datasets.make_classification`; then transformed into illustrative feature ranges and selected positive-class thresholds.
- **Real network capture:** No.
- **Labels:** 0 = benign, 1 = simulated threat.
- **Privacy:** No personal data; no packet payloads.
- **Known limitation:** The data generator deliberately introduces learnable patterns. Results do not estimate performance on real networks.
- **Recommended next step:** Select a public intrusion-detection dataset, read its license and label documentation, create a documented mapping to the project schema, and evaluate on a split that avoids leakage.
