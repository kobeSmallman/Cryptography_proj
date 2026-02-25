from __future__ import annotations

"""
HTML report export (exports report.html)

HTML:
easy to open and readable. Collapsible sections with details and it looks nice
"""

from pathlib import Path
from html import escape
from cryptolab.ui.trace import TraceLevel

CSS= """
body { front-family: system-ui, -apple-system, Segoe UI, Roboto, Arial;
background: #0b1020; color: #eef1ff; margin: 24px;}
.card { background: #121a33; border: 1px solid #26305a; border-radius: 14px;
padding: 16px; margin-bottom: 14px 0;}
.muted {color: #b9c2ff;}
.badge { display: inline-block; padding: 4px 10px; border-radius: 999px;
background: #22306a; margin-right: 10px; }
details { background: #0f1530; border: 1px solid #26305a; border-radius: 12px;
padding: 10px; margin-top: 10px 0;}
summary { cursor: pointer; font-weight: 800; }
pre { white-space: pre-wrap; word-break: break-word; background: #0f1530; 
border: 1px solid #26305a; border-radius: 12px; padding: 12px; }
.kv div { margin: 3px 0;}
"""

def _kv_dict(d: dict) -> str:
    out = ["<div class ='kv'>"]
    for k, v in d.items():
        out.append(f"<div><span class='muted'>{escape(str(k))}:</span> {escape(str(v))}</div>")
    out.append("</div>")
    return "\n".join(out)

def export_html(path: Path, state) -> None:
    steps = state.trace.steps()

    html: list[str] = []
    html.append("<!DOCTYPE html><html><head><meta charset='utf-8'/>")
    html.append(f"<title>Cryptolab Report</title><style>{CSS}</style></head><body>")

    html.append("<h1>Cryptolab Report</h1>")
    html.append("<div class='muted'>Self-contained report: Explanation + Trace + Code refs</div>")

    html.append("<div class='card'>")
    html.append("<h2>Session Status</h2>")
    html.append(_kv_dict(state.session.summary_for_menu()))
    html.append("</div>")

    html.append("<div class='card'>")
    html.append("<h2>Run Configuration</h2>")
    html.append(_kv_dict({
        "Trace level": state.config.trace_level.value,
        "Code view": state.config.code_view,
        "Notation mode": state.config.notation_mode,
    }))
    html.append("</div>")

    html.append("<div class='card'>")
    html.append("<h2>Trace Steps</h2>")

    if not steps:
        html.append("<div class='muted'>No trace steps recorded yet.</div>")
    else:
        for step in steps:
            html.append("<div class='card'>")
            html.append(f"<div class='badge'>{escape(step.module)}</div><b>{escape(step.title)}</b>")
            html.append(f"<div class='muted' style='margin-top: 8px;'><b>Goal:</b> {escape(step.goal)}</div>")

            html.append("<details open><summary>Explanation</summary>")
            html.append("<h3>Inputs</h3>")
            html.append(_kv_dict(step.inputs))
            html.append("<h3>Algorithm Steps</h3><ol>")
            for s in step.algorithm_steps:
                html.append(f"<li>{escape(s)}</li>")
            html.append("</ol>")
            html.append("<h3>Outputs</h3>")
            html.append(_kv_dict(step.outputs))
            html.append("</details>")

            if state.config.trace_level == TraceLevel.SUMMARY:
                html.append("<details><summary>Trace (Summary)</summary><ul>")
                for t in step.trace_sumamry:
                    html.append(f"<li>{escape(t)}</li>")
                html.append("</ul></details>")
            
            if state.config.trace_level == TraceLevel.FULL:
                html.append("<details><summary>Trace (Full)</summary><ul>")
                for t in step.trace_full:
                    html.append(f"<li>{escape(t)}</li>")
                html.append("</ul></details>")
            
            if state.config.trace_level != TraceLevel.OFF:
                html.append("<details><summary>Pros/Cons/Pitfalls</summary>")
                html.append("<h3>Pros</h3><ul>" + "".join(f"<li>{escape(x)}</li>" for x in step.pros) + "</ul>")
                html.append("<h3>Cons</h3><ul>" + "".join(f"<li>{escape(x)}</li>" for x in step.cons) + "</ul>")
                html.append("<h3>Pitfalls</h3><ul>" + "".join(f"<li>{escape(x)}</li>" for x in step.pitfalls) + "</ul>")
                html.append("</details>")
            
            if state.config.code_view:
                html.append("<details><summary>Code References</summary><pre>")
                html.append(escape("\n".join(step.code_refs)))
                html.append("</pre></details>")

            html.append("</div>")
    html.append("</div>") # trace steps card

    html.append("</body></html>")
    path.write_text("\n".join(html), encoding="utf-8")

