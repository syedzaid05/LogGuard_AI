# 🛡️ LogGuard AI

Static analysis + AI recommendations for **Python security and logging hygiene**.

LogGuard AI scans Python code (single files, pasted snippets, ZIP projects, local
folders or GitHub repositories), reports risky patterns and credential leaks with
severity/confidence/evidence, and uses an LLM (Groq, Google Gemini or xAI Grok) to
explain the impact and suggest concrete fixes.

## Features

- **Multiple inputs** — pasted code, `.py` file, `.zip` project, local folder, GitHub repo.
- **Static analysis engine** — Python `ast` + custom rule engine, 4 detectors, 18 rules.
- **4 detector families** — Logging, Exception handling, Secrets, Code quality.
- **Risk & findings engine** — severity, confidence, deduplication and a 0–100 risk score.
- **AI recommendations** — impact + fix per finding via Groq / Gemini / xAI.
- **Reports** — interactive tables and one-click **JSON** / **HTML** export.
- **Safe by design** — input validation, path-traversal guards, size/line limits, binary skip.
- **Low noise** — test/example/vendor dirs skipped, `# noqa` honored, re-raise and
  `usedforsecurity=False` aware.

## Architecture

```
                    ┌──────────────────────────────┐
                    │          Streamlit UI         │
                    │ Dashboard·Upload·Scan·       │
                    │ Findings·Reports             │
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
              ┌─────────▼─┐ ┌───▼────┐ ┌▼─────┐ ┌▼──────────┐
              │ Logging   │ │Exception│ │Secret│ │Code Quality│
              │ Detector  │ │Analyzer │ │Scan. │ │  Rules     │
              └─────────┬─┘ └───┬────┘ └┬─────┘ └┬──────────┘
                        └───────┴───────┴────────┘
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

## Installation

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Configuration

Copy `.env.example` to `.env` and add at least one LLM key (AI features are
optional — scanning works without any key).

| Variable          | Purpose                                              |
|-------------------|------------------------------------------------------|
| `GROQ_API_KEY`    | Groq Cloud key (starts with `gsk_`) — OpenAI-compatible |
| `XAI_API_KEY`     | xAI Grok key (starts with `xai-`) — optional         |
| `GEMINI_API_KEY`  | Google Gemini API key                                 |
| `LLM_PROVIDER`    | Default provider: `groq`, `gemini` or `xai`           |
| `GITHUB_TOKEN`    | Optional — scan private repos / raise rate limits     |

Model IDs live in the same file (`GROQ_MODEL`, `GEMINI_MODEL`, `XAI_MODEL`).

## Running

```powershell
streamlit run app.py
```

Then open the URL Streamlit prints (default http://localhost:8501).

1. **Scan** → pick an input source and run.
2. **Dashboard** → risk score, severity breakdown, top findings.
3. **Findings** → filter by severity/category, inspect code + recommendation + AI fix.
4. **Reports** → download JSON or HTML.

### Scan a GitHub repository

Choose **GitHub repository** and enter either `owner/repo` or a full URL
(`https://github.com/owner/repo/tree/branch`). The repo is fetched as a ZIP
archive via the GitHub API — no `git` binary required. Set `GITHUB_TOKEN` for
private repos.

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
| `--min-severity {Critical..Info}` | only display findings at/above this level |
| `--fail-on {Critical..Info}` | exit `1` if any finding is at/above this level (CI gate) |
| `-v` / `-q` | verbose (show recommendations) / quiet |

After `pip install -e .` the shorter `logguard scan ...` command is available.

## Testing

```powershell
pip install -r requirements-dev.txt
python -m pytest
```

The suite covers every detector rule, the risk engine (dedup/ranking/score),
input handling (paste, ZIP traversal guards, folder discovery), reporting, the
GitHub URL parser and the CLI.

## Detection rules

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

## Suppressing a finding

Add `# noqa` to the offending line and LogGuard AI will skip findings on it:

```python
import chardet
try:
    import charset_normalizer as chardet
except ImportError:  # noqa
    pass
```

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
  detectors/              logging, exception, secret, code-quality rules
tests/                    pytest suite
docs/                     rule & architecture references
```

## Example: scanning `psf/requests`

```
files=34  lines=6394  findings=8   risk=15.4 (Low)
Medium EX002  src/requests/utils.py:178  Swallowed exception
Low    LG001  src/requests/help.py:128   print() used instead of a logger
...
```

## Limitations

- Deep semantic/data-flow analysis (taint tracking) is not performed — rules are
  heuristic and can produce false positives/negatives.
- Non-Python files are only secret-scanned; they are not parsed.
- Very large repositories are bounded by `MAX_FILES` / `MAX_TOTAL_BYTES`.

See [`docs/RULES.md`](docs/RULES.md) for the full rule reference and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for module-level details.
