from __future__ import annotations

"""
Menu system 
DEMO module proves UI/trace/export works and RSA keygen for now will say coming soon

"""
import os
from cryptolab.ui.trace import TraceLevel, TraceStep
from cryptolab.ui.render import hr, big_title, print_kv_block, print_numbered_steps
from cryptolab.io.export_html import export_html
from cryptolab.io.export_md import export_markdown
from cryptolab.crypto.rsa import rsa_generate_keypair

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
    print(" e) Export now (HTML + Markdown) and open them")
    choice = _prompt_choice("Choose an option: ", {"c", "r", "e"})
    if choice == "e":
        _export(state)
        return
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
        print_numbered_steps("Trace (Summary)", step.trace_summary)
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
        trace_summary=[
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
def _rsa_keygen_module(state) -> None:
    state.trace.clear()

    print("\nRSA Key Generation Settings:")
    bits_str = input("Prime size in bits with the default at 128: ").strip()
    rounds_str = input("Miller-Rabin rounds (default 24): ").strip()
    seed_str = input("Optional integer seed (blank = auto): ").strip()

    bits = int(bits_str) if bits_str else 128
    rounds = int(rounds_str) if rounds_str else 24
    seed = int(seed_str) if seed_str else None


    print("\nGenerating RSA keypair now... (generating primes p and q)")
    print("If this takes a bit, try a smaller prime_bits (like 64) for a quick demo")
    result = rsa_generate_keypair(bits=bits, mr_rounds=rounds, seed=seed) # type: ignore # TODO: fix type hint

    #Save results into the session so status becomes yes and persists
    state.session.rsa_p = result["p"]
    state.session.rsa_q = result["q"]
    state.session.rsa_n = result["n"]
    state.session.rsa_phi_n = result["phi_n"]
    state.session.rsa_e = result["e"]
    state.session.rsa_d = result["d"]

    #Inputs shown depend on notation mode (referring to no greek letters)
    if state.config.notation_mode == "EXPANDED":
        inputs = {
            "Prime bit length": bits,
            "Miller-Rabin rounds": rounds,
            "PRNG seed": ("auto" if seed is None else seed),
            "public exponent": result["e"], 
        }
    else: 
        inputs = {
            "prime_bits": bits,
            "mr_rounds": rounds,
            "seed": ("auto" if seed is None else seed),
            "e": result["e"],
        }
    step = TraceStep(
        module="RSA",
        title="RSA Key Generation (Requirement 1)",
        goal="Generate RSA keypair manually: p, q, n, phi_n, e, d",
        inputs=inputs,
        algorithm_steps=[
            "Generate probable primes p and q using the Miller Rabin primality test.",
            "Compute n = p*q",
            "Compute phi_n = (p-1)*(q-1)",
            "Choose e with gcd(e, phi_n)=1 and try the default first (e=65537)",
            "Compute d = modinv(e, phi_n) using Extended Euclidean Algorithm (modular inverse)",
            "Output public key (n,e) and private key (n,d)",
        ],
        outputs={
            "p_bits": result["p_bits"],
            "q_bits": result["q_bits"],
            "n_bits": result["n_bits"],
            "n": result["n"],
            "e": result["e"],
            "d": result["d"],
        },
        trace_summary=result["trace_summary"],
        trace_full=result["trace_full"],
        pros=[
            "Anyone can ecnrypt and verify with (n, e) but only those with d can decrypt and sign.",
            "Securrity is tied to the difficulty of factoring n = p*q",
            "Trace supports understanding and full mode shows the two ideas: Miller_rabin prime justification and extended Euclid Modular Inverse reasoning",

        ],
        cons=[
            "Keygen cost scales fast and prime generation + modular arithemtic becomes super slow as bit sizes increases.",
            "It isn't safe without padding/encoding becuase raw textbook style RSA is more vulnerable to predicable attakcs. Real worrld RSA uses OAEP for ecnryption and PSS for singatures (Or other methods like CTR or CFB).",
            "It isn't good for bulk data. RSA operations are expensive and message size is limited (< n). In real world RSA protects keys while symmetric cipphers encrypt the actual bulk.",

        ],
        pitfalls=[
            "If gcd(e, phi_n) != 1, d does not exist and keygen fails. So we must choose a different e",
            "If p == q, factoring gets easier and the key is broken so we must regenerate q.",
            "If primes are too small or rounds too low then keys become factorable, the demo is for speed not optimal security.",
        ],
        code_ref=[
            "src/cryptolab/crypto/math.py::{gcd, egcd, modinv, modexp}",
            "src/cryptolab/crypto/primes.py::{is_probable_prime, generate_prime}",
            "src/cryptolab/crypto/rsa.py::{rsa_generate_keypair}",
            "src/cryptolab/crypto/prng.py::{XorShift64Star}",
        ],
    )

    state.trace.add(step)
    _render_step_to_terminal(state, step)
    _back_to_menu(state)





def _export(state) -> None:
    report_path = (state.exports_dir / "report.html").resolve()
    md_path = (state.exports_dir / "transcript.md").resolve()

    print("\nExported options:")
    print(f" 1)HTML report")
    print(f" 2)Markdown transcript")
    print("  3)Both")
    choice = input("Choose [1/2/3]: ").strip()
    if choice == "1":
        export_html(report_path, state)
        print(f"\nExported HTML: {report_path}")
    elif choice == "2":
        export_markdown(md_path, state)
        print(f"\nExported Markdown: {md_path}")
    else:
        export_html(report_path, state)
        export_markdown(md_path, state)
        print(f"\nExported:\n - HTML: {report_path}\n - Markdown: {md_path}")
    
    open_choice = input("\nOpen exported file(s) now? [y/n]: ").strip().lower()
    if open_choice == "y" and os.name == "nt":
        if choice == "1":
            os.startfile(str(report_path))
        elif choice == "2":
            os.startfile(str(md_path))
        else:
            os.startfile(str(report_path))
            os.startfile(str(md_path))

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
        print(" 2) RSA Key Generation (Requirement 1)")

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
            _rsa_keygen_module(state)
            continue
        if choice == "e":
            _export(state)
            continue
        if choice == "x":
            print("\nExiting Cryptolab. Goodbye!\n")
            return
        
        print("Invalid choice. Please try again.")