"""LogGuard AI - Streamlit UI entry point.

Dashboard | Scan | Findings | Reports
"""
from __future__ import annotations

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from logguard import (
    __version__,
    ai_module,
    github_scanner,
    input_manager,
    reporting,
    risk_engine,
)
from logguard.engine import scan
from logguard.models import ScanResult
from logguard.secure_processing import ValidationError

st.set_page_config(page_title="LogGuard AI", page_icon="🛡️", layout="wide")

_CSS = """
<style>
:root {
  --lg-green: #2ECC71;
  --lg-dark: #08110C;
  --lg-card: #0F1C15;
  --lg-border: #1E3A28;
}
.stApp { background: radial-gradient(1200px 600px at 15% -10%, rgba(46,204,113,0.14), transparent 60%),
                    radial-gradient(900px 500px at 110% 20%, rgba(39,174,96,0.10), transparent 55%),
                    var(--lg-dark); }
section[data-testid="stSidebar"] { background: linear-gradient(180deg, #0B1710 0%, #0E1F14 100%); }
section[data-testid="stSidebar"] .stRadio label { color: #CDE8D6; }

#lg-hero {
  background: linear-gradient(135deg, #0E3B22 0%, #14532D 45%, #1E7A46 100%);
  border: 1px solid var(--lg-border);
  border-radius: 18px;
  padding: 22px 28px;
  margin-bottom: 18px;
  color: #ECFdf5;
}
#lg-hero h1 { margin: 0; font-size: 1.9rem; color: #FFFFFF; }
#lg-hero p { margin: 6px 0 0; color: #CFF3DE; font-size: 0.95rem; }

div[data-testid="stMetric"] {
  background: var(--lg-card);
  border: 1px solid var(--lg-border);
  border-radius: 14px;
  padding: 14px 16px;
  box-shadow: 0 4px 14px rgba(0,0,0,0.35);
}
div[data-testid="stMetric"] label { color: #8FD9AE !important; }
div[data-testid="stMetric"] [data-testid="stMetricValue"] { color: #EAFBF1; }

.stButton > button[kind="primary"] {
  background: linear-gradient(135deg, #27AE60, #2ECC71);
  border: none; color: #06130B; font-weight: 600;
}
.stButton > button[kind="primary"]:hover { filter: brightness(1.08); }

div[role="radiogroup"] label, div[data-testid="stToggle"] { color: #D9EFE3; }

div[data-testid="st.expander"], div[data-testid="stExpander"] {
  border: 1px solid var(--lg-border) !important;
  border-radius: 12px !important;
  background: var(--lg-card) !important;
}
h1, h2, h3 { color: #BFF0D4; }
div[data-testid="stInfo"], div[data-testid="stSuccess"], div[data-testid="stWarning"] { border-radius: 12px; }
</style>
"""


def _hero(title: str, subtitle: str) -> None:
    st.markdown(
        f"<div id='lg-hero'><h1>{title}</h1><p>{subtitle}</p></div>",
        unsafe_allow_html=True,
    )
    st.markdown(_CSS, unsafe_allow_html=True)


SEVERITY_BADGE = {
    "Critical": "🟥",
    "High": "🟧",
    "Medium": "🟨",
    "Low": "🟦",
    "Info": "⬜",
}


def _init_state() -> None:
    st.session_state.setdefault("result", None)


def _sidebar() -> None:
    st.sidebar.title("🛡️ LogGuard AI")
    st.sidebar.caption(f"v{__version__} - Python security & logging review")

    st.sidebar.divider()
    status = ai_module.providers_status()
    st.sidebar.markdown("**AI providers**")
    for name, ok in status.items():
        st.sidebar.write(("✅ " if ok else "⚪ ") + name.capitalize())
    if not any(status.values()):
        st.sidebar.caption("Add GROK_API_KEY or GEMINI_API_KEY to `.env` to enable AI.")  # noqa: E501

    result: ScanResult | None = st.session_state.get("result")
    if result is not None:
        st.sidebar.divider()
        st.sidebar.metric("Findings", len(result.findings))


def _run_scan(bundle, use_ai: bool, provider: str) -> None:
    progress_bar = st.progress(0.0, text="Analysing...")

    def progress(index: int, total: int, path: str) -> None:
        progress_bar.progress(
            min((index + 1) / max(total, 1), 1.0), text=f"Analysing {path}"
        )

    result = scan(bundle, progress=progress)
    progress_bar.empty()

    if use_ai and result.findings:
        with st.spinner("Generating AI recommendations..."):
            message = ai_module.enrich_findings(result.findings, provider=provider or None)
        if not message.ok:
            st.warning(f"AI step skipped: {message.error}")
        else:
            st.success(f"AI recommendations added via {message.provider}.")

    st.session_state["result"] = result
    st.success(
        f"Scan complete: {len(result.findings)} finding(s) across "
        f"{result.files_scanned} file(s)."
    )


def page_dashboard() -> None:
    _hero("Dashboard", "LogGuard AI - Python security &amp; logging review")
    result: ScanResult | None = st.session_state.get("result")

    if result is None:
        st.info("No scan yet. Head to the **Scan** page to analyse a file, project, or repository.")
        c1, c2, c3 = st.columns(3)
        c1.metric("Detectors", "4", help="Logging, Exceptions, Secrets, Code Quality")
        c2.metric("Inputs", "5", help="Paste, .py, ZIP, folder, GitHub repo")
        c3.metric("Exports", "2", help="JSON and HTML")
        return

    score = risk_engine.risk_score(result.findings)
    rating = risk_engine.risk_rating(score)
    summary = result.summary

    top = st.columns([2, 1, 1, 1, 1])
    top[0].metric("Target", result.target or "input")
    top[1].metric("Risk score", f"{score}/100", rating)
    top[2].metric("Files", result.files_scanned)
    top[3].metric("Lines", f"{result.lines_scanned:,}")
    top[4].metric("Findings", summary["Total"])

    st.subheader("Severity breakdown")
    cols = st.columns(len(summary))
    for col, (label, count) in zip(cols, summary.items()):
        col.metric(label, count)

    st.subheader("Top findings")
    for f in result.findings[:8]:
        with st.container(border=True):
            st.markdown(
                f"**{SEVERITY_BADGE.get(f.severity,'•')} {f.title}**  "
                f"`{f.file}:{f.line}`"
            )
            st.caption(f"{f.category} · {f.severity} · confidence {f.confidence}")

    if result.errors:
        with st.expander(f"Scanner notes ({len(result.errors)})"):
            for err in result.errors:
                st.write(f"- {err}")


def page_scan() -> None:
    _hero("Scan", "LogGuard AI - Python security &amp; logging review")
    mode = st.radio(
        "Input source",
        ["Paste code", "Upload .py file", "Upload ZIP project", "GitHub repository", "Local folder"],
        horizontal=True,
    )

    use_ai = st.toggle("Add AI recommendations", value=True)
    provider = ""
    if use_ai:
        status = ai_module.providers_status()
        options = [p for p, ok in status.items() if ok]
        if options:
            provider = st.selectbox("Provider", options, index=0)
        else:
            st.caption("No API keys found - AI step will be skipped.")

    st.divider()
    bundle = None

    if mode == "Paste code":
        code = st.text_area("Paste Python code", height=280, placeholder="def login(...):\n    ...")
        name = st.text_input("Filename", value="pasted_code.py")
        if st.button("Run scan", type="primary"):
            try:
                bundle = input_manager.from_text(code, name or "pasted_code.py")
            except ValidationError as exc:
                st.error(str(exc))

    elif mode == "Upload .py file":
        uploaded = st.file_uploader("Select a Python file", type=["py"])
        if st.button("Run scan", type="primary"):
            if not uploaded:
                st.error("Please choose a file.")
            else:
                try:
                    bundle = input_manager.from_uploaded_file(uploaded.name, uploaded.getvalue())
                except ValidationError as exc:
                    st.error(str(exc))

    elif mode == "Upload ZIP project":
        uploaded = st.file_uploader("Select a ZIP archive", type=["zip"])
        if st.button("Run scan", type="primary"):
            if not uploaded:
                st.error("Please choose a ZIP archive.")
            else:
                try:
                    bundle = input_manager.from_uploaded_file(uploaded.name, uploaded.getvalue())
                except ValidationError as exc:
                    st.error(str(exc))

    elif mode == "GitHub repository":
        url = st.text_input("Repository", placeholder="owner/repo or https://github.com/owner/repo")
        if st.button("Run scan", type="primary"):
            if not url.strip():
                st.error("Enter a repository.")
            else:
                try:
                    with st.spinner("Fetching repository..."):
                        bundle = github_scanner.fetch_repo(url)
                except ValidationError as exc:
                    st.error(str(exc))

    else:  # Local folder
        folder = st.text_input("Folder path", placeholder=r"C:\path\to\project")
        if st.button("Run scan", type="primary"):
            try:
                bundle = input_manager.from_directory(folder)
            except ValidationError as exc:
                st.error(str(exc))

    if bundle is not None:
        if bundle.file_count == 0:
            st.warning("No analysable files were found in the input.")
        else:
            _run_scan(bundle, use_ai, provider)


def page_findings() -> None:
    _hero("Findings", "LogGuard AI - Python security &amp; logging review")
    result: ScanResult | None = st.session_state.get("result")
    if result is None or not result.findings:
        st.info("No findings to show. Run a scan first.")
        return

    severities = sorted({f.severity for f in result.findings}, key=lambda s: -_rank(s))
    categories = sorted({f.category for f in result.findings})

    c1, c2, c3 = st.columns(3)
    sev_filter = c1.multiselect("Severity", severities, default=severities)
    cat_filter = c2.multiselect("Category", categories, default=categories)
    query = c3.text_input("Search")

    rows = []
    for f in result.findings:
        if f.severity not in sev_filter or f.category not in cat_filter:
            continue
        if query and query.lower() not in (f.title + f.message + f.file + f.code).lower():
            continue
        rows.append(
            {
                "Severity": f"{SEVERITY_BADGE.get(f.severity,'')} {f.severity}",
                "Rule": f.rule_id,
                "Title": f.title,
                "Category": f.category,
                "File": f.file,
                "Line": f.line,
                "Confidence": f.confidence,
            }
        )

    st.caption(f"{len(rows)} finding(s) match the filters.")
    if rows:
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    st.divider()
    for f in result.findings:
        if f.severity not in sev_filter or f.category not in cat_filter:
            continue
        with st.expander(f"{SEVERITY_BADGE.get(f.severity,'')} {f.title} - {f.file}:{f.line}"):
            st.markdown(f"**Rule:** `{f.rule_id}` · **Category:** {f.category} · "
                        f"**Severity:** {f.severity} · **Confidence:** {f.confidence}"
                        + (f" · **CWE:** {f.cwe}" if f.cwe else ""))
            st.write(f.message)
            if f.code:
                st.code(f.code, language="python")
            if f.recommendation:
                st.markdown(f"**Recommendation:** {f.recommendation}")
            if f.ai_explanation:
                st.info(f"**AI impact:** {f.ai_explanation}")
            if f.ai_fix:
                st.success(f"**AI fix:** {f.ai_fix}")


def page_reports() -> None:
    _hero("Reports", "LogGuard AI - Python security &amp; logging review")
    result: ScanResult | None = st.session_state.get("result")
    if result is None:
        st.info("Run a scan to generate reports.")
        return

    score = risk_engine.risk_score(result.findings)
    st.write(
        f"Target **{result.target}** · risk **{score}/100 "
        f"({risk_engine.risk_rating(score)})** · {len(result.findings)} finding(s)"
    )

    json_data = reporting.to_json(result)
    html_data = reporting.to_html(result)
    stem = (result.target or "scan").replace("/", "_").replace("@", "_").replace(" ", "_")

    c1, c2 = st.columns(2)
    c1.download_button(
        "⬇️ Download JSON",
        data=json_data,
        file_name=f"logguard_{stem}.json",
        mime="application/json",
        use_container_width=True,
    )
    c2.download_button(
        "⬇️ Download HTML",
        data=html_data,
        file_name=f"logguard_{stem}.html",
        mime="text/html",
        use_container_width=True,
    )

    with st.expander("Preview JSON"):
        st.code(json_data[:4000], language="json")
    with st.expander("Preview HTML report"):
        components.html(html_data, height=500, scrolling=True)

    if result.errors:
        st.subheader("Scanner notes")
        for err in result.errors:
            st.write(f"- {err}")


def _rank(sev: str) -> int:
    return {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}.get(sev, 0)


def main() -> None:
    _init_state()
    _sidebar()

    st.sidebar.divider()
    st.sidebar.caption("Static analysis is heuristic - always review findings in context.")

    tabs = st.tabs(["Dashboard", "Scan", "Findings", "Reports"])
    with tabs[0]:
        page_dashboard()
    with tabs[1]:
        page_scan()
    with tabs[2]:
        page_findings()
    with tabs[3]:
        page_reports()

    with st.sidebar.expander("Advanced settings"):
        st.caption("Placeholder - these options will be wired to the scanner once supported.")
        st.multiselect(
            "Detectors",
            ["logging", "exceptions", "secrets", "code_quality"],
            disabled=True,
            help="Enable/disable individual detectors.",
        )
        st.text_input(
            "Exclude patterns",
            value="tests/, venv/, __pycache__/",
            disabled=True,
            help="Glob patterns for files to skip during scans.",
        )
        st.slider("Minimum severity", 0, 4, 0, disabled=True, help="Filter findings below this level.")
        st.selectbox(
            "Report format", ["JSON + HTML", "JSON only", "HTML only"], disabled=True
        )
        st.toggle("Strict mode", disabled=True, help="Treat warnings as failures.")


if __name__ == "__main__":
    main()



