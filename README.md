# SQLbase – Security Scanning Toolkit

Cross-platform (Linux, Windows, macOS) security scanning: SQL injection scanning, dynamic testing, code fixing, and remediation. Uses `pathlib` and portable paths throughout.

## Install

```bash
python -m venv .venv
# Linux/macOS:
.venv/bin/activate
# Windows:
.venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

Or run without install (from repo root):

```bash
# Linux/macOS/Windows (same commands)
PYTHONPATH=. python -m sqlbase scan .
PYTHONPATH=. python -m sqlbase predict .
PYTHONPATH=. python -m sqlbase remediate SQL_INJECTION python
```

## Usage

```bash
# Scan path for SQL injection patterns (file or directory)
python -m sqlbase scan [path] [-o report.json] [--fail-on-findings]

# Predict vulnerability likelihood (heuristic/ML-ready)
python -m sqlbase predict [path]

# Get remediation for a vulnerability type and language
python -m sqlbase remediate SQL_INJECTION python
```

Programmatic use:

```python
from pathlib import Path
from sqlbase.scanner import SQLInjectionScanner
from sqlbase.tester import DynamicSQLiTester
from sqlbase.fixer import SqliCodeFixer
from sqlbase.remediation import RemediationKnowledgeBase
from sqlbase.injector import SecurityPatternInjector
from sqlbase.predictor import VulnerabilityPredictor

scanner = SQLInjectionScanner()
for v in scanner.scan_path(Path("src")):
    print(v["file"], v["line"], v["type"])
```

## CI

GitHub Actions: `.github/workflows/security-scan.yml` runs on **ubuntu-latest**, **windows-latest**, and **macos-latest** on push/PR.
