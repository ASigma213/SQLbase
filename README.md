# SQLbase – Security Scanning Toolkit

Cross-platform (Linux, Windows, macOS) security scanning: SQL injection scanning, dynamic testing, code fixing, and remediation. Uses `pathlib` and portable paths throughout.

<img src="https://capsule-render.vercel.app/api?type=waving&height=200&color=gradient&customColorList=6,11,20,29&text=DocIotaAegis&fontSize=48&fontColor=fff&animation=twinkling&fontAlignY=35&textBg=false"/>

<p align="center">
  <a href="https://komarev.com/ghpvc/?username=ASigma213">
    <img src="https://komarev.com/ghpvc/?username=ASigma213&label=Profile%20views&color=00FFFF&style=flat-square" alt="ASigma213's profile views" />
  </a>
</p>

## 📊 GitHub Stats & Trophies
<p align="center">
  <img src="https://streak-stats.demolab.com/?user=ASigma213&theme=gruvbox&hide_border=true&cache_seconds=86400" alt="ASigma213's GitHub Streak" width="49%" />
</p>
<p align="center">
  <img height="280em" src="https://github-readme-activity-graph.vercel.app/graph?username=ASigma213&theme=gruvbox&radius=10" alt="ASigma213's Activity Graph" />
</p>


## 🛠️ Languages & Tools

> ## Programming Languages
<p align="center"><img src="https://raw.githubusercontent.com/devicons/devicon/master/icons/javascript/javascript-original.svg" alt="JavaScript" width="48" height="48" style="margin: 4px;" /> <img src="https://raw.githubusercontent.com/devicons/devicon/master/icons/python/python-original.svg" alt="Python" width="48" height="48" style="margin: 4px;" /> <img src="https://raw.githubusercontent.com/devicons/devicon/master/icons/java/java-original.svg" alt="Java" width="48" height="48" style="margin: 4px;" /> <img src="https://raw.githubusercontent.com/devicons/devicon/master/icons/cplusplus/cplusplus-original.svg" alt="C++" width="48" height="48" style="margin: 4px;" /></p>

> ## Frontend
<p align="center"><img src="https://raw.githubusercontent.com/devicons/devicon/master/icons/vuejs/vuejs-original.svg" alt="Vue.js" width="48" height="48" style="margin: 4px;" /> <img src="https://cdn.worldvectorlogo.com/logos/nextjs-2.svg" alt="Next.js" width="48" height="48" style="margin: 4px;" /> <img src="https://raw.githubusercontent.com/devicons/devicon/master/icons/html5/html5-original.svg" alt="HTML5" width="48" height="48" style="margin: 4px;" /> <img src="https://www.vectorlogo.zone/logos/tailwindcss/tailwindcss-icon.svg" alt="Tailwind CSS" width="48" height="48" style="margin: 4px;" /></p>

<p align="center">
  <img src="https://github-readme-stats.vercel.app/api/top-langs/?username=ASigma213&layout=compact&theme=gruvbox&hide_border=true&langs_count=10&cache_seconds=86400" alt="Top Languages" />
</p>




<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/abozanona/abozanona/output/pacman-contribution-graph-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/abozanona/abozanona/output/pacman-contribution-graph.svg">
  <img alt="pacman contribution graph" src="https://raw.githubusercontent.com/abozanona/abozanona/output/pacman-contribution-graph.svg">
</picture>


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


https://github.com/user-attachments/assets/a8ab7268-9412-4fc8-94be-53298351aeef
