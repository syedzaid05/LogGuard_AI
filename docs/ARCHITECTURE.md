# Architecture

LogGuard AI is a layered pipeline. Each layer has a single responsibility and a
small, explicit interface, so detectors, inputs and AI providers can evolve
independently.

## Layers

### 1. Streamlit UI (`app.py`)
Four pages — Dashboard, Scan, Findings, Reports. Keeps the latest `ScanResult` in
`st.session_state`. Responsible only for presentation and wiring; all logic lives
in the `logguard` package.

### 2. Input Manager (`logguard/input_manager.py`)
Normalises every input source into a `SourceBundle` (`relative path -> text`):

- `from_text` — pasted code
- `from_uploaded_file` — `.py` or `.zip`
- `from_directory` — local folder tree
- `github_scanner.fetch_repo` — GitHub repo via the API zipball

ZIP extraction strips a single common top-level folder (GitHub archives) and
rejects traversal paths.

### 3. Secure Processing Layer (`logguard/secure_processing.py`)
- `validate_upload` — extension/size checks.
- `is_safe_relative_path` — blocks `..` traversal and absolute paths.
- `discover_files` / `should_skip_path` — bounded traversal; skips VCS, caches,
  virtualenvs, `node_modules`, build output, and test/example/vendor folders.
- `read_source` — size/line limits and binary detection.

Limits live in `logguard/config.py` (`MAX_FILE_BYTES`, `MAX_TOTAL_BYTES`,
`MAX_FILES`, `MAX_FILE_LINES`).

### 4. Static Analysis Engine (`logguard/engine.py`)
Parses each `.py` file with `ast` and runs every registered detector
(`logguard/detectors/__init__.py:DETECTORS`). A failing detector is isolated and
recorded in `ScanResult.errors` without aborting the scan. `# noqa` lines are
suppressed before results are merged. Non-Python files are secret-scanned only.
Unparseable Python is still secret-scanned and the `SyntaxError` is reported.

### 5. Detectors (`logguard/detectors/`)
- `base.py` — `Detector` interface, `DetectorResult`, and `Context` with
  `make(...)` (builds a `Finding`) plus source-line helpers.
- `logging_detector.py`, `exception_analyzer.py`, `secret_scanner.py`,
  `code_quality.py`, `web_security.py` — the rule families documented in
  `docs/RULES.md`. Shared AST helpers (`dotted_name`, `keyword_value`,
  `is_true`, `is_false`) live in `base.py`.

### 6. Risk & Findings Engine (`logguard/risk_engine.py`)
Deduplicates by fingerprint, ranks by severity/score/location, and computes the
aggregate 0–100 risk score and rating.

### 7. AI Recommendation Module (`logguard/ai_module.py`)
Thin REST clients for Groq and xAI (both OpenAI-compatible) and Gemini. `chat()`
and `enrich_findings()` return an `AIMessage`; failures degrade gracefully so the
scan always completes with static results.

### 8. Results & Reports (`logguard/reporting.py`)
Serialises a `ScanResult` to JSON or a self-contained HTML report.

## Data flow

```
input source
  └─> Input Manager ──> SourceBundle
        └─> Secure Processing (validate + discover)
              └─> Static Analysis Engine (ast + detectors)
                    └─> Risk & Findings Engine (dedup + score)
                          ├─> AI Recommendation Module (enrich, in place)
                          └─> Results & Reports (JSON / HTML)
```

## Key types (`logguard/models.py`)

- `Severity` — `Critical|High|Medium|Low|Info` (with `rank`).
- `Category` — `Logging|Exception Handling|Secrets|Code Quality`.
- `Finding` — rule id, detector, category, severity, confidence, title, message,
  file/line/column, code, evidence, recommendation, CWE and optional AI fields.
- `ScanResult` — target, findings, file/line counts, errors and a severity summary.
