from __future__ import annotations

"""
HTML report export (exports report.html)

HTML:
easy to open and readable. Collapsible sections with details and it looks nice
"""
from pathlib import Path
from html import escape
from cryptolab.ui.trace import TraceLevel
import re
CSS= """
body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial;
background: #0b1020; color: #eef1ff; margin: 24px;}
.card { background: #121a33; border: 1px solid #26305a; border-radius: 14px;
padding: 16px; margin: 14px 0;}
.muted {color: #b9c2ff;}
.badge { display: inline-block; padding: 4px 10px; border-radius: 999px;
background: #22306a; margin-right: 10px; }
details { background: #0f1530; border: 1px solid #26305a; border-radius: 12px;
padding: 10px; margin: 10px 0;}
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

def _legend_dict() -> dict[str, str]:
    return{
        "RSA": " Rivest-Shamir-Adleman (Public-key cryptosystem).",
        "DH": "Diffie-Hellman key exchange.",
        "KDF": "Key Derivation Function.",
        "DES": "Data Encryption Standard.",
        "CBC": "Cipher Block Chaining.",
        "IV": "Initialization Vector.",
        "PRNG": "Pseudo Random Number Generator.",
        "GCD": "Greatest Common Divisor.",
        "Modexp": "Modular Exponentiation.",
        "Shared secret": "Same secret both sides derive.",
        "False-prime probability": "Chance Miller-Rabin accepts a composite as probably prime.",
    }
def _read_text_try_paths(rel_path: str) -> str:
    """
    Read a file:
    Path given and cwd/path as given 
    if it fails we return error string instead of crashing the export
    """
    project_root = Path(__file__).resolve().parents[3]
    candidates = [Path(rel_path), Path.cwd() / rel_path, project_root / rel_path]

    last_err: Exception | None = None
    for p in candidates:
        try: 
            if p.exists():
                return p.read_text(encoding="utf-8")
        except Exception as ex:
            last_err = ex
    return f"Could not read {rel_path}. Tried: {', '.join([str(c) for c in candidates])}. Error: {last_err}"

def _extract_top_level_blocks(source: str, names: list[str]) -> str:
    """
    Extract the top-level def/class blocks for the given names and if a name isn't found we note it

    """
    if not names:
        return source
    out: list[str] = []
    for name in names:
        # match: def name or class name
        pat = re.compile(rf"^(def|class)\s+{re.escape(name)}\b.*$", re.MULTILINE)
        m = pat.search(source)
        if not m:
            out.append(f"# [NOT FOUND] {name}")
            continue
        start = m.start()

        #find the next top level def/class after this block
        nxt = re.compile(r"^(def|class)\s+\w+\b", re.MULTILINE).search(source, m.end())
        end = nxt.start() if nxt else len(source)

        out.append(source[start:end].rstrip())
    return "\n\n".join(out).rstrip()
def export_html(path: Path, state) -> None:
    steps = state.trace.steps()

    html: list[str] = []
    html.append("<!DOCTYPE html><html><head><meta charset='utf-8'/>")
    html.append(f"<title>Cryptolab Report</title><style>{CSS}</style></head><body>")

    html.append("<h1>Cryptolab Report</h1>")
    html.append("<div class='muted'>Self-contained report: explanation, trace, and code references</div>")
    html.append("<div class='card'>")
    html.append("<h2>Quick Dictionary / Legend</h2>")
    html.append(_kv_dict(_legend_dict()))
    html.append("</div>")

    html.append("<div class='card'>")
    html.append("<h2>Session Status</h2>")
    html.append(_kv_dict(state.session.summary_for_menu()))
    html.append("</div>")

    html.append("<div class='card'>")
    html.append("<h2>Run Configuration</h2>")
    html.append(_kv_dict({
        "Trace level": state.config.trace_level.value,
        "Code view": state.config.code_view,
        "Notation mode": "Expanded",
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
                for t in step.trace_summary:
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
                refs = getattr(step, "code_ref", [])
                html.append("<details><summary>Code (refs + snippets)</summary>")
                html.append("<div class='muted'>Toggle open to view the source used for this module.</div>")

                #show reference list
                html.append("<h3>References</h3><ul>")
                for r in refs:
                    html.append(f"<li>{escape(str(r))}</li>")
                html.append("</ul>")

                #show snippets
                html.append("<h3>Snippets</h3><ul>")
                for r in refs:
                    ref = str(r)


                    # Split "Path::{...}" into file path + symbols
                    file_part, _, sym_part = ref.partition("::")
                    
                    file_part = file_part.strip()

                    #parse names inside { ... }
                    names: list[str] = []
                    m = re.search(r"\{(.+?)\}", sym_part)
                    if m:
                        names = [x.strip() for x in m.group(1).split(",") if x.strip()]
                    
                    source = _read_text_try_paths(file_part)
                    snippet = _extract_top_level_blocks(source, names)
                    
                    html.append("<details>")
                    html.append(f"<summary>{escape(file_part)} - {escape(', '.join(names) if names else 'full file')}</summary>")
                    html.append("<pre>")
                    html.append(escape(snippet))
                    html.append("</pre>")
                    html.append("</details>")

                html.append("</ul>")

                html.append("</details>")
                               

            html.append("</div>")
    html.append("</div>") # trace steps card

    html.append("</body></html>")
    path.write_text("\n".join(html), encoding="utf-8")

