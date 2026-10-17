"""Results & Reports: JSON and HTML export."""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from . import __version__, risk_engine
from .models import ScanResult

SEVERITY_COLORS = {
    "Critical": "#b71c1c",
    "High": "#e53935",
    "Medium": "#fb8c00",
    "Low": "#fdd835",
    "Info": "#90a4ae",
}


def to_json(result: ScanResult) -> str:
    payload = {
        "tool": "LogGuard AI",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": result.target,
        "summary": result.summary,
        "risk_score": risk_engine.risk_score(result.findings),
        "risk_rating": risk_engine.risk_rating(risk_engine.risk_score(result.findings)),
        "stats": {
            "files_scanned": result.files_scanned,
            "lines_scanned": result.lines_scanned,
        },
        "errors": result.errors,
        "findings": [f.to_dict() for f in result.findings],
    }
    return json.dumps(payload, indent=2)


def to_html(result: ScanResult) -> str:
    score = risk_engine.risk_score(result.findings)
    rating = risk_engine.risk_rating(score)
    summary = result.summary

    rows = []
    for f in result.findings:
        color = SEVERITY_COLORS.get(f.severity, "#607d8b")
        ai = ""
        if f.ai_explanation or f.ai_fix:
            ai = (
                f"<div class='ai'><strong>AI impact:</strong> "
                f"{html.escape(f.ai_explanation) or '&mdash;'}<br>"
                f"<strong>AI fix:</strong> "
                f"{html.escape(f.ai_fix) or '&mdash;'}</div>"
            )
        rows.append(
            f"""
            <tr>
              <td><span class="sev" style="background:{color}">{html.escape(f.severity)}</span></td>
              <td>{html.escape(f.category)}</td>
              <td><strong>{html.escape(f.title)}</strong><br>
                  <span class="msg">{html.escape(f.message)}</span>
                  {ai}
                  <pre>{html.escape(f.code)}</pre></td>
              <td class="loc">{html.escape(f.file)}:{f.line}</td>
              <td>{html.escape(f.confidence)}</td>
            </tr>"""
        )

    cards = "".join(
        f"<div class='card'><span style='background:{SEVERITY_COLORS.get(k,'#607d8b')}'>"
        f"{v}</span><small>{html.escape(k)}</small></div>"
        for k, v in summary.items()
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>LogGuard AI Report - {html.escape(result.target)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; background:#f5f6f8; color:#1c2530; }}
  header {{ background:#0f172a; color:#fff; padding:24px 32px; }}
  header h1 {{ margin:0; font-size:22px; }}
  header p {{ margin:6px 0 0; opacity:.75; font-size:13px; }}
  .wrap {{ padding:24px 32px; }}
  .cards {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:20px; }}
  .card {{ background:#fff; border-radius:10px; padding:12px 16px; min-width:96px; box-shadow:0 1px 3px rgba(0,0,0,.08); text-align:center; }}
  .card span {{ display:block; font-size:26px; font-weight:700; color:#0f172a; }}
  .card small {{ color:#607d8b; }}
  .risk {{ font-size:15px; margin-bottom:20px; }}
  table {{ width:100%; border-collapse:collapse; background:#fff; border-radius:10px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,.08); }}
  th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid #eceff1; vertical-align:top; font-size:13px; }}
  th {{ background:#eceff1; font-size:12px; text-transform:uppercase; letter-spacing:.04em; color:#455a64; }}
  .sev {{ color:#fff; padding:2px 8px; border-radius:20px; font-size:11px; font-weight:600; }}
  .msg {{ color:#546e7a; }}
  .ai {{ margin-top:6px; padding:8px; background:#e8f5e9; border-left:3px solid #43a047; border-radius:4px; font-size:12px; }}
  pre {{ background:#0f172a; color:#e0e0e0; padding:8px 10px; border-radius:6px; overflow-x:auto; margin:8px 0 0; font-size:12px; }}
  .loc {{ color:#455a64; white-space:nowrap; }}
</style>
</head>
<body>
<header>
  <h1>LogGuard AI - Security & Logging Report</h1>
  <p>Target: {html.escape(result.target)} &middot; Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} &middot; v{__version__}</p>
</header>
<div class="wrap">
  <div class="cards">{cards}</div>
  <div class="risk"><strong>Overall risk:</strong> {score}/100 ({html.escape(rating)}) &middot;
    {result.files_scanned} files, {result.lines_scanned} lines scanned.</div>
  <table>
    <thead><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Location</th><th>Confidence</th></tr></thead>
    <tbody>{''.join(rows) or '<tr><td colspan="5">No findings. 🎉</td></tr>'}</tbody>
  </table>
</div>
</body>
</html>"""
