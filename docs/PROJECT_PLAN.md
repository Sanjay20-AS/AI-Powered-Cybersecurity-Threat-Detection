# Project plan and portfolio evidence

## Objective
Build a local, offline demonstration of a threat-detection workflow using labeled tabular telemetry. The initial generator is synthetic; a public-dataset experiment is the next milestone.

## Module flow
1. `src/data.py`: creates or loads records, checks schema, cleans missing/infinite values.
2. `src/train.py`: stratified split, fits a model pipeline, calculates metrics, exports diagnostic charts and a serialized model.
3. `src/detect.py`: loads the model, scores example or supplied telemetry, attaches severity and heuristic reasons, exports a CSV.
4. `main.py`: convenience command that runs training then demo detection.

## Ten-feature schema
- `duration`: simulated connection duration
- `src_bytes`, `dst_bytes`: simulated bytes in each direction
- `failed_logins`: simulated failed-login count
- `connection_count`: simulated connection count in a window
- `unique_dst_ports`: number of distinct destination ports in a window
- `packet_rate`: simulated packets per second
- `bytes_per_second`: simulated byte rate
- `is_external`: illustrative binary external-connection flag
- `protocol_code`: illustrative numeric protocol category
- `label`: 0 benign, 1 threat

These names make the demo understandable; they are not asserted to be fields from a particular benchmark dataset.

## Seven-day commit and evidence plan
| Day | Work | Suggested commit | Evidence |
|---|---|---|---|
| 1 | Environment, folder structure, README | `chore: initialize project structure` | terminal showing Python and dependency install |
| 2 | Data generator and schema | `feat: add reproducible demo telemetry dataset` | CSV head and label counts |
| 3 | Cleaning and validation | `feat: add data validation and cleaning` | before/after row counts |
| 4 | Training pipeline | `feat: train baseline threat classifier` | training report and saved model |
| 5 | Metrics and evaluation plots | `feat: add evaluation metrics and plots` | confusion matrix and metrics JSON |
| 6 | Detection output and alert logic | `feat: generate severity-tagged demo alerts` | detection CSV and terminal |
| 7 | Documentation, screenshots, GitHub | `docs: add runbook and portfolio evidence` | repository page and README rendered |

## Evidence checklist
- [ ] dataset preview and label distribution
- [ ] training terminal output
- [ ] metrics JSON
- [ ] confusion matrix
- [ ] feature importance chart
- [ ] detection results CSV
- [ ] README displayed on GitHub
- [ ] repository page with meaningful commits

Never present synthetic-data metrics as real-world performance. Record Python/package versions and the exact dataset/source when using public data.
