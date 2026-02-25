from __future__ import annotations

"""
Menu system 
DEMO module proves UI/trace/export works and RSA keygen for now will say coming soon

"""

from cryptolab.ui.trace import TraceLevel, TraceStep
from cryptolab.ui.render import hr, big_title, print_kv_block, print_numbered_steps
from cryptolab.io.export_html import export_html
from cryptolab.io.export_md import export_markdown

def _prompt_choice(prompt: str, valid: set[str]) -> str:
    while True:
        choice = input(prompt).strip().lower()
        if choice in valid:
            return choice
        print(f"Invalid choice. Try again.")

def _back_to_menu(state) -> None:
    print("\nBack to menu:")
    print(" c) Continue (keep session + trace)")
    print(" r) Reset session (clear trace and reset state)")
    choice = _prompt_choice("Choose an option: ", {"c", "r"})
    if choice == "r":
        state.session.wipe()
        state.trace.clear()
        print("\nSession wiped and starting fresh.\n")

def _render_step_to_terminal(state, step: TraceStep) -> None:
    print("\n" + hr())
    print(big_title(f"MODULE: {step.module}"))
    print_kv_block("Title", step.title)
    print_kv_block("Goal", step.goal)
    print_kv_block("Inputs", step.inputs)
    print_numbered_steps("Algorithm Steps", step.algorithm_steps)
    print_kv_block("Outputs", step.outputs)

    if state.config.trace_level == TraceLevel.SUMMARY:
        print_numbered_steps("Trace (Summary)", step.trace_sumamry)
    elif state.config.trace_level == TraceLevel.FULL:
        print_numbered_steps("Trace (Full)", step.trace_full)
    
    if state.config.trace_level != TraceLevel.OFF:
        print_kv_block("Pros", step.pros)
        print_kv_block("Cons", step.cons)
        print_kv_block("Pitfalls", step.pitfalls)
    
    if state.config.code_view:
        print_kv_block("Code References", step.code_ref)
    print(hr())

def _demo_module(state) -> None:
    state.trace.clear()

    step = TraceStep(
        module="DEMO",
        title="UI / Trace / Export Demo",
        goal="Demonstrate the UI rendering, trace recording, and export functionality with a sample step.",
        inputs={
            "Trace Level": state.config.trace_level.value,
            "Code View": state.config.code_view,
            "Notation Mode": state.config.notation_mode,
        },
        algorithm_steps=[
            "Show current session status in the menu.",
            "Record a TraceStep object - this step",
            "Allow export to HTML + Markdown transcript.",
        ],
        outputs={
            "Session has RSA keys?": (state.session.rsa_n is not None),
        },
        trace_sumamry=[
            "Show current session status in the menu.",
            "Record a TraceStep object - this step",
            "Allow export to HTML + Markdown transcript.",
        ],
        trace_full=[
            "Show current session status in the menu.",
            "Record a TraceStep object - this step",
            "Allow export to HTML + Markdown transcript.",
        ],
        pros=[
            "Demonstrates the full flow of recording a trace step and rendering it in the terminal.",
            "Shows how to export the trace to both HTML and Markdown formats.",
        ],
        cons=[
            "This is a demo module, so it doesn't perform any real cryptographic operations.",
            "The trace content is static and meant for demonstration purposes only.",
        ],
        pitfalls=[
            "None.",
        ],
        code_ref=[
            "src/cryptolab/ui/menu.py::_demo_module",
            "src/cryptolab/ui/trace.py::{TraceCollector, TraceStep}",
            "src/cryptolab/io/export_html.py::export_html",
            "src/cryptolab/io/export_md.py::export_markdown",
        ],
    )

    state.trace.add(step)
    _render_step_to_terminal(state, step)
    _back_to_menu(state)

def _export(state) -> None:
    export_html(state.exports_dir / "report.html", state)
    export_markdown(state.exports_dir / "transcript.md", state)
    print("\nExported:")
    print(f" - HTML report: {state.exports_dir / 'report.html'}")
    print(f" - Markdown transcript: {state.exports_dir / 'transcript.md'}\n")

def run_menu_loop(state) -> None:
    while True:
        print("\n" + hr())
        print(big_title("CRYPTOLAB MAIN MENU"))

        print_kv_block("Session status", state.session.summary_for_menu())

        print("\nToggles:")
        print(f" t) Trace level: {state.config.trace_level.value}")
        print(f" c) Code view: {state.config.code_view}")
        print(f" n) Notation mode: {state.config.notation_mode}")

        print("\nModules:")
        print(" 1) Demo (UI + Trace + Export demo)")
        print(" 2) RSA Key Generation (coming soon)")

        print("\nOther:")
        print(" e) Export report (HTML + Markdown)")
        print(" x) Exit")

        choice = input("\nSelect: ").strip().lower()

        if choice == "t":
            state.config.trace_level = state.config.trace_level.next()
            continue
        if choice == "c":
            state.config.code_view = not state.config.code_view
            continue
        if choice == "n":
            state.config.notation_mode = "EXPANDED" if state.config.notation_mode == "SYMBOLS" else "SYMBOLS"
            continue
        if choice == "1":
            _demo_module(state)
            continue
        if choice == "2":
            print("\nRSA Key Generation module coming soon. Stay tuned!\n")
            continue
        if choice == "e":
            _export(state)
            continue
        if choice == "x":
            print("\nExiting Cryptolab. Goodbye!\n")
            return
        
        print("Invalid choice. Please try again.")