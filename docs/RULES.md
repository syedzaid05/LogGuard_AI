# Rule reference

Every rule has an ID, a category, a default severity and a confidence level.
Severity is the potential impact; confidence is how sure the analyzer is that the
pattern is a real problem. Rules marked *context-aware* reduce false positives by
inspecting surrounding code (e.g. `shell=False`, re-raise, `usedforsecurity=False`).

## Logging Detector (`LG`)

| ID    | Severity | Confidence | Trigger |
|-------|----------|------------|---------|
| LG001 | Low      | High       | Call to `print(...)` instead of a logger *(skipped in modules with a `__main__` guard)* |
| LG002 | Low      | High       | Log call whose message is an f-string (defeats lazy formatting) |
| LG003 | Medium   | Medium     | Bare/`Exception` handler that acts but never logs (silent handlers are EX002) |
| LG004 | High     | Medium     | Log statement references a sensitive word (`password`, `token`, …) |

## Exception Analyzer (`EX`)

| ID    | Severity | Confidence | Trigger |
|-------|----------|------------|---------|
| EX001 | High     | High       | Bare `except:` |
| EX002 | High/Med | High       | Handler body is only `pass` / empty. High when bare or `Exception`, Medium otherwise |
| EX003 | Medium   | Medium     | `except Exception` / `BaseException` that does not re-raise *(context-aware)* |
| EX004 | Low      | Medium     | `raise <caught-name>` instead of a bare `raise` |
| EX005 | Low      | High       | `raise Exception(...)` / `raise BaseException(...)` |

## Secret Scanner (`SC`)

| ID    | Severity | Confidence | Trigger |
|-------|----------|------------|---------|
| SC001 | Critical/High | High | Known token/key patterns (AWS, Google, GitHub, Slack, Stripe, JWT, PEM private keys) |
| SC002 | High     | Medium     | Generic `password = "..."` / `token = "..."` with a high-entropy literal |

Values sourced from `os.getenv`, `os.environ`, config objects or secret managers are
ignored, as are obvious placeholders (`your_`, `changeme`, `example`, `<...>`). Evidence
is redacted before it is stored or displayed.

## Code Quality Rules (`CQ`)

| ID    | Severity | Confidence | Trigger |
|-------|----------|------------|---------|
| CQ001 | High     | High       | `eval()` / `exec()` |
| CQ002 | High     | High       | `subprocess.*(..., shell=True)` *(context-aware)* |
| CQ003 | Medium   | High       | `os.system()` / `os.popen()` |
| CQ004 | High     | Medium     | `pickle.load(s)`, `dill.loads`, `marshal.loads` |
| CQ005 | High     | Medium     | `yaml.load` / `yaml.full_load` without `Loader=` |
| CQ007 | Low      | High       | Mutable default argument (list/dict/set or `list()`/`dict()`/`set()`) |
| CQ008 | Low      | High       | `== None`, `!= None`, `== True`, … |
| CQ009 | Medium   | Medium     | `requests`/`httpx`/`aiohttp` call without `timeout=` |
| CQ010 | Low      | Low        | `"0.0.0.0"` passed to a `run`/`serve`/`bind`/`listen` call |
| CQ011 | Low      | Low        | `hashlib.md5` / `sha1` without `usedforsecurity=False` *(context-aware)* |
| CQ013 | Low      | High       | `tempfile.mktemp()` |

## Web Security Detector (`WS`)

| ID    | Severity | Confidence | Trigger |
|-------|----------|------------|---------|
| WS001 | High     | High       | SQL passed to `execute`/`executemany` built with f-string, `%`/`+`, or `.format` |
| WS002 | High/Med | High       | TLS verification off: `verify=False`, `_create_unverified_context`, `check_hostname=False`, `verify_mode=CERT_NONE`, `disable_warnings` |
| WS003 | Medium   | High/Med   | `run(debug=True)` or `DEBUG = True` |
| WS004 | Medium   | Medium     | Security-named value generated with the `random` module |
| WS005 | Medium   | High/Med   | `DES`/`ARC4`/`Blowfish` cipher or `MODE_ECB` |
| WS006 | Medium   | Medium     | `assert` guarding an authorization/authentication check *(removed under `python -O`)* |

## Severity and confidence model

- **Severity** — `Critical`, `High`, `Medium`, `Low`, `Info` (weights 10/6/3/1/0.2).
- **Confidence** — `High` (×1.0), `Medium` (×0.7), `Low` (×0.4).
- **Risk score** — `100 × (1 − e^(−Σ/60))`, where each rule contributes its worst
  instance plus a logarithmic bonus for repeats, so one noisy rule cannot saturate
  the score. Ratings: `≥75` Critical, `≥50` High, `≥25` Medium, `>0` Low, else Clean.

## Adding a rule

1. Implement the check in the relevant `logguard/detectors/*.py` detector.
2. Emit via `ctx.make(rule_id=..., severity=..., confidence=..., title=..., message=..., recommendation=..., cwe=...)`.
3. Add a row to this table and, if useful, a fixture under `tests/`.
