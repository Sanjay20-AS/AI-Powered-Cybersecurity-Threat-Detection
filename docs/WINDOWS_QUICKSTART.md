# Windows quick start

1. Extract the ZIP.
2. Open the extracted `AI-Powered-Cybersecurity-Threat-Detection` folder in VS Code.
3. Open Terminal > New Terminal.
4. Run:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m src.train
python -m src.detect
```

If `py -3.11` is unavailable, install Python 3.11 or use `python` if it points to Python 3.10–3.12. Start with the generated synthetic demo; it does not require a separate dataset download.
