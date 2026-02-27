from __future__ import annotations

"""
Menu system 
DEMO module proves UI/trace/export works and RSA key generation, DH key exchange works

"""
import os

from cryptolab.ui.trace import TraceLevel, TraceStep
from cryptolab.ui.render import hr, big_title, print_kv_block, print_numbered_steps
from cryptolab.io.export_html import export_html
from cryptolab.io.export_md import export_markdown
from cryptolab.crypto.rsa import rsa_generate_keypair
from cryptolab.crypto.dh import dh_key_exchange
from cryptolab.io.storage import save_trace

def _label(state, symbol: str, expanded: str) -> str:
    """
    Notation mode: 
    EXPANDED: Use plain-language labels for readbility and understanding
    SYMBOLS: Use p, q, n, phi_n, e, d, g, A, B, s...
    """
    return expanded if state.config.notation_mode == "EXPANDED" else symbol
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
    k = lambda sym, exp: _label(state, sym, exp)

    inputs = {
        k("prime_bits", "prime_bit_length"): bits,
        k("mr_rounds", "miller_rabin_rounds"): rounds,
        k("seed", "prng_seed"): ("auto" if seed is None else seed),
        k("e", "public_exponent_e"): result["e"],
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
            k("p_bits", "prime_p_bits"): result["p_bits"],
            k("q_bits", "prime_q_bits"): result["q_bits"],
            k("n_bits", "modulus_n_bits"): result["n_bits"],
            k("n", "modulus_n"): str(result["n"]),
            k("phi_n", "totient_phi_n"): str(result["phi_n"]),
            k("e", "public_exponent_e"): str(result["e"]),
            k("d", "private_exponent_d"): str(result["d"]),
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
            "It isn't safe without padding/encoding becuase raw textbook style RSA is more vulnerable to predicable attakcs. Real worrld RSA uses OAEP for ecnryption and PSS for singatures.",
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
    save_trace(state.exports_dir / "trace.json", [s.to_json_obj() for s in state.trace.steps()])
    _render_step_to_terminal(state, step)
    _back_to_menu(state)

def _dh_key_exchange_module(state) -> None:
    state.trace.clear()

    print("\nDiffie-Hellman key exchange settings:")
    bits_str = input("Prime size in bits (default 128): ").strip()
    rounds_str = input("Miller-Rabin rounds (default 24): ").strip()
    seed_str = input("Optional integer seed (blank = auto): ").strip()

    bits = int(bits_str) if bits_str else 128
    rounds = int(rounds_str) if rounds_str else 24
    seed = int(seed_str) if seed_str else None

    print("\nRunning Diffie-Hellman exchange right now... Please wait. (generating p and computing A, B, s)")

    result = dh_key_exchange(bits=bits, mr_rounds=rounds, seed=seed)

    # Save DH results into session
    state.session.dh_p = result["p"]
    state.session.dh_g = result["g"]
    state.session.dh_a = result["a"]
    state.session.dh_b = result["b"]
    state.session.dh_A = result["A"]
    state.session.dh_B = result["B"]
    state.session.dh_s = result["s"]

    #inputs shown depend on notation mode (no greek letters)
    k = lambda sym, exp: _label(state, sym, exp)

    inputs = {
        k("prime_bits", "prime_bit_length"): bits,
        k("mr_rounds", "miller_rabin_rounds"): rounds,
        k("seed", "prng_seed"): ("auto" if seed is None else seed),
    }
    
    step = TraceStep(
        module="DH",
        title="Diffie-Hellman Key Exchange",
        goal="Establish a shared secret s over an insecure channel using public p, g and secret exponent a, b",
        inputs=inputs,
        algorithm_steps=[
            "Generate a prime p (public parameter)",
            "Choose base g (public parameter)",
            "Choose secret exponents a and b (private)",
            "Compute public values A = g^a mod p and B = g^b mod p",
            "Compute shared secret s_alice = B^a mod p and s_bob = A^b mod p",
            "verify s_alice == s_bob and if yes shared secret established",

        ],
        outputs={
            k("p_bits", "prime_p_bits"): result["p_bits"],
            k("p", "prime_p"): str(result["p"]),
            k("g", "base_g"): str(result["g"]),
            k("A", "public_A"): str(result["A"]),
            k("B", "public_B"): str(result["B"]),
            k("s", "shared_secret_s"): str(result["s"]),
        },
        trace_summary=result["trace_summary"],
        trace_full=result["trace_full"],
        pros=[
            "Establishes a shared secret without sending the secret directly",
            "Relies on discrete log hardness and given p, g and A it is hard to recover a",
            "Trace shows A, B and verifies both sides compute the same secret s",
        ],
        cons=[
            "Unauthenticated DH is vulnerable to man in the middle unless authenticated (signatures and certificates)",
            "DH makes a shared secret but still requires a KDF(key derivation function) to derive the symmetric keys safely",

        ],
        pitfalls=[
            "If p is not a prime or g is not chosen with proper precautions the exchange may land on a small subgroup which is weak",
            "Secrets a,b must be random and kept private if we reuse them they can weaken the secruity",
            "Shared secret s shouldn't be used as a key-derive key/IV using KDF",
        ],
        code_ref=[
            "src/cryptolab/crypto/math.py::{modexp, gcd}",
            "src/cryptolab/crypto/primes.py::{is_probable_prime, generate_prime}",
            "src/cryptolab/crypto/prng.py::{XorShift64Star}",
            "src/cryptolab/crypto/dh.py::{dh_key_exchange}",
        ],
    )
    state.trace.add(step)
    save_trace(state.exports_dir / "trace.json", [s.to_json_obj() for s in state.trace.steps()])
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
        print("\nWorkflow (recommended for running this):")
        print("\nRun in the following order:")
        print(" 1) Set Trace level (t) and Code view (c) as needed (before running anything)")
        print(" 2) Run modules")
        print(" 3) Continue (c) or Reset session (r) or Export now (e)-> Report captures the latest trace + current session")

        print_kv_block("Session status", state.session.summary_for_menu())

        print("\nToggles:")
        print(f" t) Trace level: {state.config.trace_level.value}")
        print(f" c) Code view: {state.config.code_view}")
        print(f" n) Notation mode: {state.config.notation_mode}")

        print("\nModules:")
        print(" 1) Demo (UI + Trace + Export demo)")
        print(" 2) RSA Key Generation (Requirement 1)")
        print(" 3) Diffie-Hellman Key Exchange (Requirement 2)")

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
        if choice == "3":
            _dh_key_exchange_module(state)
            continue
        if choice == "e":
            _export(state)
            continue
        if choice == "x":
            print("\nExiting Cryptolab. Goodbye!\n")
            return
        
        print("Invalid choice. Please try again.")