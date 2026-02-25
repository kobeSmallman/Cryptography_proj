from __future__ import annotations

"""
Markdown transcript export (exports/transcript.md)
Explain like a lab writeup
What it does: 
- Session status
- Trace
- Code
- Pros/Cons
- Pitfalls
how: 
- Iterate through the trace steps and format them into markdown sections
"""

from pathlib import Path
from cryptolab.ui.trace import TraceLevel

def export_markdown(path: Path, state) -> None:
    lines: list[str] = []
    lines.append(f"# Cryptolab Session Transcript\n")

    lines.append("## Session Status\n")
    for k, v in state.session.summary_for_menu().items():
        lines.append(f"- **{k}**: {v}")
    lines.append("\n---\n")

    if state.trace.is_empty():
        lines.append("No trace steps recorded yet. Run the Demo module first \n")
        path.write_text("\n".join(lines), encoding="utf-8")
        return
    
    lines.append("## Trace Steps\n")
    for idx, step in enumerate(state.trace.steps(), 1):
        lines.append(f"### Step {idx}: {step.module} ({step.title})\n")
        lines.append(f"**Goal**: {step.goal}\n")
        
        lines.append("**Inputs**:")
        for k, v in step.inputs.items():
            lines.append(f"- {k}: {v}")
        lines.append("\n**Algorithm Steps**:\n")
        for i, s in enumerate(step.algorithm_steps, 1):
            lines.append(f"{i}. {s}")
        
        lines.append("\n**Outputs**:\n")
        for k, v in step.outputs.items():
            lines.append(f"- {k}: {v}")
        
        if state.config.trace_level == TraceLevel.SUMMARY:
            lines.append("\n**Trace Summary**:")
            for t in step.trace_sumamry:
                lines.append(f"- {t}")
        if state.config.trace_level == TraceLevel.FULL:
            lines.append("\n**Trace (Full):**")
            for t in step.trace_full:
                lines.append(f"- {t}")
        if state.config.trace_level != TraceLevel.OFF:
            lines.append("\n**Pros:**")
            for x in step.pros:
                lines.append(f"- {x}")
            
            lines.append("\n**Cons:**")
            for x in step.cons:
                lines.append(f"- {x}")
            
            lines.append("\n**Pitfalls:**")
            for x in step.pitfalls:
                lines.append(f"- {x}")

        if state.config.code_view:
            lines.append("\n**Code References:**")
            for x in step.code_ref:
                lines.append(f"- {x}")
        
        lines.append("\n---\n")
    path.write_text("\n".join(lines), encoding="utf-8")