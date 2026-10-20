# 🛡️ LogGuard AI

**Static analysis + AI recommendations for Python security and logging hygiene.**

LogGuard AI scans Python code — a single file, a pasted snippet, a ZIP project, a
local folder or a GitHub repository — reports risky patterns and credential leaks
with severity, confidence and evidence, and uses an LLM (Groq, Google Gemini or
xAI Grok) to explain the real-world impact and suggest concrete fixes.

```
files=34  lines=6394  findings=8   risk=15.4 (Low)
Medium EX002  src/requests/utils.py:178  Swallowed exception
Low    LG001  src/requests/help.py:128   print() used instead of a logger
```

---

## Table of contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the app](#running-the-app)
- [Command-line interface](#command-line-interface)
- [Detection rules](#detection-rules)
- [Scoring model](#scoring-model)
- [Suppressing a finding](#suppressing-a-finding)
- [Testing](#testing)
- [Project layout](#project-layout)
- [Limitations](#limitations)

---

## Features

- **One-page tabbed UI** — Dashboard, Scan, Findings and Reports live side by side
  in a single-page tab layout, with the AI provider status in the sidebar.
- **Multiple inputs** — pasted code, `.py` file, `.zip` project, local folder, GitHub repo.
- **Static analysis engine** — Python `ast` + custom rule engine, 5 detectors, 28 rules.
- **5 detector families** — Logging, Exception handling, Secrets, Code quality, Web security.
- **Risk & findings engine** — severity, confidence, deduplication and a 0–100 risk score.
- **AI recommendations** — impact + fix per finding via Groq / Gemini / xAI.
- **Reports** — interactive tables and one-click **JSON** / **HTML** export.
- **Safe by design** — input validation, path-traversal guards, size/line limits, binary skip.
- **Low noise** — test/example/vendor dirs skipped, `# noqa` honored, re-raise and
  `usedforsecurity=False` aware.
- **CI ready** — `--fail-on` gate and a JSON/HTML report for automation.

## Architecture

```
                    ┌──────────────────────────────┐
                    │  Streamlit UI (single page)  │
                    │ Dashboard·Scan·Findings·     │
                    │ Reports  (tab navigation)    │
                    └───────────────┬──────────────┘
                                    │
                    ┌───────────────▼──────────────┐
                    │         Input Manager        │
                    │ paste · .py · ZIP · folder · │
                    │ GitHub repo                   │
                    └───────────────┬──────────────┘
                                    │
                    ┌───────────────▼──────────────┐
                    │   Secure Processing Layer    │
                    │ input validation · discovery │
                    └───────────────┬──────────────┘
                                    │
                    ┌───────────────▼──────────────┐
                    │    Static Analysis Engine    │
                    │      Python AST + rules      │
                    └───┬───────┬───────┬───────┬──┘
                        │       │       │       │
         ┌─────────▼─┐ ┌───▼────┐ ┌▼─────┐ ┌▼──────────┐ ┌▼───────────┐
         │ Logging   │ │Exception│ │Secret│ │Code Quality│ │Web Security│
         │ Detector  │ │Analyzer │ │Scan. │ │  Rules     │ │  Rules     │
         └─────────┬─┘ └───┬────┘ └┬─────┘ └┬──────────┘ └┬───────────┘
                   └───────┴───────┴────────┴─────────────┘
                                    │
                    ┌───────────────▼──────────────┐
                    │  Risk & Findings Engine      │
                    │ severity·confidence·dedup·   │
                    │ evidence·risk score          │
                    └───────┬───────────────┬──────┘
                            │               │
          ┌─────────────────▼──┐      ┌─────▼──────────────┐
          │ AI Recommendation  │      │ Results & Reports   │
          │ Groq/Gemini/xAI    │      │ tables · JSON · HTML│
          └────────────────────┘      └─────────────────────┘
```

## Requirements

- Python **3.10+**
- Runtime dependencies: `streamlit`, `python-dotenv`, `requests`, `pandas`
  (see [`requirements.txt`](requirements.txt))

## Installation

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

To install the `logguard` console script as an editable package:

```powershell
pip install -e .
```

## Configuration

Copy `.env.example` to `.env` and add at least one LLM key. **AI features are
optional** — scanning, scoring and reporting all work without any key.

| Variable         | Default                              | Purpose                                                    |
|------------------|--------------------------------------|------------------------------------------------------------|
| `GROQ_API_KEY`   | —                                    | Groq Cloud key (starts with `gsk_`) — OpenAI-compatible      |
| `GROQ_API_BASE`  | `https://api.groq.com/openai/v1`     | Groq API base URL                                          |
| `GROQ_MODEL`     | `openai/gpt-oss-120b`                | Groq model ID                                              |
| `GEMINI_API_KEY` | —                                    | Google Gemini API key                                      |
| `GEMINI_MODEL`   | `gemini-flash-latest`                | Gemini model ID                                            |
| `GEMINI_API_BASE`| `.../v1beta`                         | Gemini API base URL                                        |
| `XAI_API_KEY`    | —                                    | xAI Grok key (starts with `xai-`) — optional               |
| `XAI_API_BASE`   | `https://api.x.ai/v1`                | xAI API base URL                                           |
| `XAI_MODEL`      | `grok-2-latest`                      | xAI model ID                                               |
| `LLM_PROVIDER`   | `groq`                               | Default provider: `groq`, `gemini` or `xai`                |
| `GITHUB_TOKEN`   | —                                    | Optional — scan private repos / raise GitHub rate limits   |

Any key left as a placeholder (`your_...`, `changeme`, empty) is treated as
unset. Run `python -m logguard providers` to see which providers are configured.

## Running the app

```powershell
streamlit run app.py
```

Then open the URL Streamlit prints (default http://localhost:8501).

1. **Dashboard → Scan → Findings → Reports render as tabs on a single page** —
   switch tabs instead of navigating (the sidebar shows AI provider status and
   a findings count after a scan).
2. **Scan** → pick an input source (paste, `.py`, ZIP, GitHub repo, or local folder) and run.
3. **Dashboard** → risk score, severity breakdown, top findings.
4. **Findings** → filter by severity/category, inspect code + recommendation + AI fix.
5. **Reports** → download JSON or HTML.

### Scan a GitHub repository

Choose **GitHub repository** and enter any of:

- `owner/repo`
- `https://github.com/owner/repo`
- `https://github.com/owner/repo/tree/<branch>`

The repo is fetched as a ZIP archive via the GitHub API — **no `git` binary
required**. Set `GITHUB_TOKEN` for private repositories or to raise rate limits.

## Command-line interface

```powershell
python -m logguard scan <path | owner/repo | url> [options]
```

Examples:

```powershell
python -m logguard scan ./myproject
python -m logguard scan psf/requests --json report.json --html report.html
python -m logguard scan app.py --ai --provider groq --min-severity Medium -v
python -m logguard scan ./src --fail-on High     # non-zero exit for CI
python -m logguard rules
python -m logguard providers
```

| Option | Description |
|--------|-------------|
| `--json PATH` / `--html PATH` | write machine-readable / standalone HTML reports |
| `--ai` | add AI explanations and fixes |
| `--provider {groq,gemini,xai}` | choose the LLM provider |
| `--ai-limit N` | max findings to enrich with AI (default `20`) |
| `--min-severity {Critical..Info}` | only display findings at/above this level |
| `--fail-on {Critical..Info}` | exit `1` if any finding is at/above this level (CI gate) |
| `-v` / `-q` | verbose (show recommendations) / quiet |
| `--version` | print the version and exit |

After `pip install -e .` the shorter `logguard scan ...` command is available.

## Detection rules

28 rules across 5 detector families. See [`docs/RULES.md`](docs/RULES.md) for
triggers and confidence details.

| ID    | Detector          | Severity | Description                                    |
|-------|-------------------|----------|------------------------------------------------|
| LG001 | Logging           | Low      | `print()` used instead of a logger             |
| LG002 | Logging           | Low      | Eager f-string log formatting                  |
| LG003 | Logging           | Medium   | Broad/bare exception handled without logging   |
| LG004 | Logging           | High     | Possible sensitive data in a log message       |
| EX001 | Exception         | High     | Bare `except:` clause                          |
| EX002 | Exception         | High/Med | Swallowed exception (`pass`)                   |
| EX003 | Exception         | Medium   | Overly broad `except Exception`                |
| EX004 | Exception         | Low      | `raise <caught>` loses the original traceback  |
| EX005 | Exception         | Low      | Raising a generic `Exception`                  |
| SC001 | Secret Scanner    | Crit/High| Known secret pattern (AWS, Google, GH, …)      |
| SC002 | Secret Scanner    | High     | Generic hard-coded credential assignment       |
| CQ001 | Code Quality      | High     | `eval()` / `exec()`                            |
| CQ002 | Code Quality      | High     | `subprocess` with `shell=True`                 |
| CQ003 | Code Quality      | Medium   | `os.system` / `os.popen`                       |
| CQ004 | Code Quality      | High     | Unsafe deserialization (`pickle`, …)           |
| CQ005 | Code Quality      | High     | `yaml.load` without `SafeLoader`               |
| CQ007 | Code Quality      | Low      | Mutable default argument                       |
| CQ008 | Code Quality      | Low      | `== None` / `== True` comparison               |
| CQ009 | Code Quality      | Medium   | HTTP request without timeout                   |
| CQ010 | Code Quality      | Low      | Binding to `0.0.0.0`                           |
| CQ011 | Code Quality      | Low      | Weak hash (`md5` / `sha1`)                     |
| CQ013 | Code Quality      | Low      | Race-prone `tempfile.mktemp()`                 |
| WS001 | Web Security      | High     | Possible SQL injection                         |
| WS002 | Web Security      | High/Med | TLS verification disabled                      |
| WS003 | Web Security      | Medium   | Debug mode enabled                             |
| WS004 | Web Security      | Medium   | Insecure random for a security value           |
| WS005 | Web Security      | Medium   | Weak cipher / ECB mode                         |
| WS006 | Web Security      | Medium   | `assert` guarding an authorization check       |

## Scoring model

- **Severity** — `Critical`, `High`, `Medium`, `Low`, `Info` (weights 10 / 6 / 3 / 1 / 0.2).
- **Confidence** — `High` (×1.0), `Medium` (×0.7), `Low` (×0.4).
- **Risk score** — `100 × (1 − e^(−Σ/60))`, where each rule contributes its worst
  instance plus a logarithmic bonus for repeats, so one noisy rule cannot
  saturate the score.

| Risk score | Rating   |
|------------|----------|
| ≥ 75       | Critical |
| ≥ 50       | High     |
| ≥ 25       | Medium   |
| > 0        | Low      |
| 0          | Clean    |

Processing limits: `MAX_FILE_BYTES` 1.5 MB per file, `MAX_TOTAL_BYTES` 25 MB per
scan, `MAX_FILES` 500 and `MAX_FILE_LINES` 20,000 (see `logguard/config.py`).

## Suppressing a finding

Add `# noqa` to the offending line and LogGuard AI will skip findings on it:

```python
import chardet
try:
    import charset_normalizer as chardet
except ImportError:  # noqa
    pass
```

## Testing

```powershell
pip install -r requirements-dev.txt
python -m pytest
```

The suite covers every detector rule, the risk engine (dedup/ranking/score),
input handling (paste, ZIP traversal guards, folder discovery), reporting, the
GitHub URL parser and the CLI. CI runs it on Python 3.10–3.13 and self-scans the
package with `--fail-on High`.

## Project layout

```
app.py                    Streamlit UI
pyproject.toml            packaging + `logguard` console script
logguard/
  cli.py                  command-line interface
  config.py               env + processing limits
  models.py               Finding / ScanResult / Severity / Category
  secure_processing.py    validation, discovery, path-traversal guards
  input_manager.py        paste / .py / ZIP / folder -> SourceBundle
  github_scanner.py       repo -> zipball -> SourceBundle
  engine.py               AST orchestration + noqa suppression
  risk_engine.py          dedup, ranking, 0-100 risk score
  ai_module.py            Groq / Gemini / xAI clients
  reporting.py            JSON + HTML export
  detectors/              logging, exception, secret, code-quality, web-security rules
tests/                    pytest suite
docs/                     rule & architecture references
```

## Limitations

- Deep semantic/data-flow analysis (taint tracking) is not performed — rules are
  heuristic and can produce false positives/negatives.
- Non-Python files are only secret-scanned; they are not parsed.
- Very large repositories are bounded by `MAX_FILES` / `MAX_TOTAL_BYTES`.

See [`docs/RULES.md`](docs/RULES.md) for the full rule reference and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for module-level details.
