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
from cryptolab.crypto.rsa import rsa_generate_keypair, rsa_encrypt, rsa_decrypt, rsa_sign, rsa_verify
from cryptolab.crypto.dh import dh_key_exchange
from cryptolab.crypto.kdf import derive_des_key_iv
from cryptolab.crypto.des.modes import encrypt_cbc_trace, decrypt_cbc_trace
from cryptolab.io.storage import save_trace

def _label(state, symbol: str, expanded: str) -> str:
    """
    Notation mode: 
    EXPANDED: Use plain-language labels for readbility and understanding
    SYMBOLS: Use p, q, n, phi_n, e, d, g, A, B, s...
    """
    return expanded #if state.config.notation_mode == "EXPANDED" else symbol - I decided I didn't want this and instead of dealing with it Ima just comment it out
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



def _rsa_encrypt_decrypt_module(state) -> None:
    """Module 4 — RSA textbook encrypt then decrypt (uses session RSA keys)."""
    

    if state.session.rsa_n is None:
        print("\nNo RSA keys in session. Run RSA Key Generation (option 2) first.")
        return

    n = state.session.rsa_n
    e = state.session.rsa_e
    d = state.session.rsa_d

    print(f"\nRSA modulus n has {n.bit_length()} bits.")
    print("Enter a message as a positive integer m satisfying 1 < m < n.")
    m_str = input("m = ").strip()
    try:
        m = int(m_str)
    except ValueError:
        print("Invalid integer — aborting.")
        return
    if not (1 < m < n):
        print(f"m must satisfy 1 < m < n={n}. Aborting.")
        return

    enc_result = rsa_encrypt(m, e, n)
    dec_result = rsa_decrypt(enc_result["c"], d, n)

    state.session.rsa_last_m = m
    state.session.rsa_last_c = enc_result["c"]

    k = lambda sym, exp: _label(state, sym, exp)

    step = TraceStep(
        module="RSA-ENC",
        title="RSA Message Encryption & Decryption (Requirement 3)",
        goal="Encrypt a plaintext integer m with the public key (n, e), then decrypt with (n, d) to verify round-trip.",
        inputs={
            k("m", "message_m"):             str(m),
            k("e", "public_exponent_e"):      str(e),
            k("n", "modulus_n"):              str(n),
        },
        algorithm_steps=[
            "Verify 0 < m < n (message must fit in the modulus).",
            "Encrypt:  c = m^e mod n  (square-and-multiply modular exponentiation).",
            "Decrypt:  m = c^d mod n  (same algorithm, private exponent d).",
            "Verify recovered m equals original m.",
        ],
        outputs={
            k("c", "ciphertext_c"):           str(enc_result["c"]),
            k("m_recovered", "message_recovered"): str(dec_result["m"]),
            "Round-trip OK":                  str(dec_result["m"] == m),
        },
        trace_summary=enc_result["trace_summary"] + ["---"] + dec_result["trace_summary"],
        trace_full=enc_result["trace_full"]    + ["---"] + dec_result["trace_full"],
        pros=[
            "Only the holder of d can decrypt; anyone with (n, e) can encrypt.",
            "Trace exposes every square-and-multiply step of modular exponentiation.",
        ],
        cons=[
            "Textbook RSA with no padding is vulnerable to chosen-plaintext attacks.",
            "Message m must be smaller than n — unsuitable for long messages.",
            "Real-world RSA encryption uses OAEP padding.",
        ],
        pitfalls=[
            "If m >= n the operation is meaningless — the code enforces m < n.",
            "Small messages (m << n) leak information without padding.",
        ],
        code_ref=[
            "src/cryptolab/crypto/rsa.py::{rsa_encrypt, rsa_decrypt}",
            "src/cryptolab/crypto/math.py::{modexp, modexp_trace}",
        ],
    )

    state.trace.add(step)
    save_trace(state.exports_dir / "trace.json", [s.to_json_obj() for s in state.trace.steps()])
    _render_step_to_terminal(state, step)
    _back_to_menu(state)


def _kdf_module(state) -> None:
    """Module 5 — KDF: derive DES key and IV from the DH shared secret."""
    

    if state.session.dh_s is None:
        print("\nNo DH shared secret in session. Run Diffie-Hellman Key Exchange (option 3) first.")
        return

    s = state.session.dh_s
    result = derive_des_key_iv(s)

    state.session.kdf_key_hex = result["key"].hex()
    state.session.kdf_iv_hex  = result["iv"].hex()

    k = lambda sym, exp: _label(state, sym, exp)

    step = TraceStep(
        module="KDF",
        title="Key Derivation Function (KDF) — DH Secret → DES Key + IV",
        goal="Derive a deterministic 8-byte DES key and 8-byte IV from the DH shared secret s using manual XOR-folding.",
        inputs={
            k("s", "shared_secret_s"): str(s),
            "s bit_length":            s.bit_length(),
        },
        algorithm_steps=[
            "Encode s as big-endian bytes.",
            "Zero-pad to the nearest multiple of 8 bytes.",
            "Split into 8-byte blocks and XOR all blocks together → base material (8 bytes).",
            "key = base with byte[0] XOR 0x01   (counter = 1).",
            "iv  = base with byte[0] XOR 0x02   (counter = 2).",
        ],
        outputs={
            k("key", "des_key_hex"):  result["key"].hex(),
            k("iv",  "des_iv_hex"):   result["iv"].hex(),
        },
        trace_summary=result["trace_summary"],
        trace_full=result["trace_full"],
        pros=[
            "Fully manual — no external crypto libraries.",
            "Deterministic: the same shared secret always produces the same key/IV.",
            "Counter differentiation (XOR 0x01 vs 0x02) ensures key ≠ IV.",
        ],
        cons=[
            "XOR-folding is not a cryptographically secure KDF (use HKDF in production).",
            "Security inherits entirely from the DH shared secret entropy.",
        ],
        pitfalls=[
            "Reusing the same DH secret reuses the same key/IV — always run a fresh DH exchange.",
            "The derived key is only as strong as the DH prime size.",
        ],
        code_ref=[
            "src/cryptolab/crypto/kdf.py::derive_des_key_iv",
            "src/cryptolab/crypto/dh.py::dh_key_exchange",
        ],
    )

    state.trace.add(step)
    save_trace(state.exports_dir / "trace.json", [s.to_json_obj() for s in state.trace.steps()])
    _render_step_to_terminal(state, step)
    _back_to_menu(state)


def _des_cbc_module(state) -> None:
    """Module 6 — DES-CBC encrypt a message, then decrypt it to verify."""
    

    if state.session.kdf_key_hex is None:
        print("\nNo DES key in session. Run KDF (option 5) first.")
        return

    key = bytes.fromhex(state.session.kdf_key_hex)
    iv  = bytes.fromhex(state.session.kdf_iv_hex)

    print(f"\nDES key (hex): {key.hex()}")
    print(f"IV      (hex): {iv.hex()}")
    plaintext_str = input("\nEnter plaintext message to encrypt: ").strip()
    if not plaintext_str:
        print("Empty message — aborting.")
        return

    plaintext_bytes = plaintext_str.encode("utf-8")

    enc_result = encrypt_cbc_trace(plaintext_bytes, key, iv)
    dec_result = decrypt_cbc_trace(enc_result["ciphertext"], key, iv)

    state.session.des_ciphertext_hex = enc_result["ciphertext"].hex()
    state.session.des_last_plaintext = dec_result["plaintext"].decode("utf-8", errors="replace")

    k = lambda sym, exp: _label(state, sym, exp)

    step = TraceStep(
        module="DES-CBC",
        title="DES-CBC Message Encryption & Decryption (Requirement 3)",
        goal=(
            "Encrypt the plaintext with DES in CBC mode using the KDF-derived key and IV, "
            "then decrypt to verify the round-trip."
        ),
        inputs={
            k("plaintext", "plaintext_message"): plaintext_str,
            k("key",       "des_key_hex"):        key.hex(),
            k("iv",        "des_iv_hex"):          iv.hex(),
            "plaintext length (bytes)":            len(plaintext_bytes),
        },
        algorithm_steps=[
            "PKCS#7-pad plaintext to a multiple of 8 bytes.",
            "Encrypt — CBC mode: C_i = DES_K(P_i XOR C_{i-1}),  C_0 = IV.",
            "Each DES block: IP → 16 Feistel rounds (expand, XOR key, S-boxes, P-perm) → FP.",
            "Decrypt — CBC mode: P_i = DES_K^{-1}(C_i) XOR C_{i-1},  C_0 = IV.",
            "Remove PKCS#7 padding and verify recovered plaintext equals original.",
        ],
        outputs={
            k("ciphertext_hex", "ciphertext_hex"):     enc_result["ciphertext"].hex(),
            k("ciphertext_len", "ciphertext_bytes"):   len(enc_result["ciphertext"]),
            k("plaintext_recovered", "plaintext_recovered"): state.session.des_last_plaintext,
            "Round-trip OK": str(state.session.des_last_plaintext == plaintext_str),
        },
        trace_summary=enc_result["trace_summary"] + ["---"] + dec_result["trace_summary"],
        trace_full=enc_result["trace_full"]    + ["---"] + dec_result["trace_full"],
        pros=[
            "CBC chaining makes identical plaintext blocks produce different ciphertext blocks.",
            "DES is a fully manual Feistel cipher — every S-box and permutation is explicit.",
            "PKCS#7 padding handles messages of any length, not just multiples of 8 bytes.",
        ],
        cons=[
            "DES uses a 56-bit effective key — brute-forceable with modern hardware.",
            "Textbook CBC with a static IV (no fresh IV per session) is not IND-CPA secure.",
            "Production systems use AES-256-GCM or ChaCha20-Poly1305.",
        ],
        pitfalls=[
            "IV must be random and unique per encryption in real usage.",
            "CBC decryption is parallelisable; encryption is not.",
            "A padding oracle attack can break CBC-PKCS#7 without the key.",
        ],
        code_ref=[
            "src/cryptolab/crypto/des/core.py::{des_block, des_block_trace}",
            "src/cryptolab/crypto/des/key_schedule.py::generate_round_keys",
            "src/cryptolab/crypto/des/modes.py::{encrypt_cbc_trace, decrypt_cbc_trace}",
            "src/cryptolab/crypto/kdf.py::derive_des_key_iv",
        ],
    )

    state.trace.add(step)
    save_trace(state.exports_dir / "trace.json", [s.to_json_obj() for s in state.trace.steps()])
    _render_step_to_terminal(state, step)
    _back_to_menu(state)


def _rsa_signature_module(state) -> None:
    """ RSA digital signature: sign a message then verify it"""
    

    if state.session.rsa_n is None:
        print("\nNo RSA keys in session. Run RSA Key Generation (option 2) first.")
        return

    n = state.session.rsa_n
    e = state.session.rsa_e
    d = state.session.rsa_d

    message_str = input("\nEnter message to sign: ").strip()
    if not message_str:
        print("Empty message — aborting.")
        return

    message_bytes = message_str.encode("utf-8")

    sign_result   = rsa_sign(message_bytes, d, n)
    verify_result = rsa_verify(message_bytes, sign_result["sig"], e, n)

    state.session.sig_message = message_str
    state.session.sig_last    = sign_result["sig"]

    k = lambda sym, exp: _label(state, sym, exp)

    step = TraceStep(
        module="RSA-SIG",
        title="RSA Digital Signature (Requirement 4)",
        goal=(
            "Sign a message with the private key (n, d) using SHA-256 as the digest, "
            "then verify the signature with the public key (n, e)."
        ),
        inputs={
            k("message", "message"):         message_str,
            k("d", "private_exponent_d"):    str(d),
            k("n", "modulus_n"):             str(n),
        },
        algorithm_steps=[
            "Compute h = SHA-256(message)  — manual Merkle-Damgård construction.",
            "Reduce h mod n so it fits the modulus.",
            "Sign:   sig = h^d mod n  (square-and-multiply, private key).",
            "Verify: h'  = sig^e mod n  (square-and-multiply, public key).",
            "Accept if h' == h mod n.",
        ],
        outputs={
            k("sha256_digest", "sha256_digest"):    sign_result["h_mod"] and f"{sign_result['h']:064x}",
            k("h_mod_n", "h_mod_n"):               str(sign_result["h_mod"]),
            k("sig", "signature_sig"):             str(sign_result["sig"]),
            k("h_prime", "h_prime_recovered"):     str(verify_result["h_recovered"]),
            "Signature valid":                     str(verify_result["valid"]),
        },
        trace_summary=sign_result["trace_summary"] + ["---"] + verify_result["trace_summary"],
        trace_full=sign_result["trace_full"]    + ["---"] + verify_result["trace_full"],
        pros=[
            "Only the holder of d can produce a valid signature; anyone with (n, e) can verify",
            "SHA-256 digest binds the signature tightly to the exact message content",
            "Trace exposes every SHA-256 round and every modexp square-and-multiply step",
        ],
        cons=[
            "Textbook RSA-sign with no padding (PSS) is malleable — use PSS in production",
            "SHA-256 digest is 256 bits; if n < 2^256 the digest is reduced mod n, losing entropy.",
            "Signature size equals key size — large for bulk data",
        ],
        pitfalls=[
            "Never sign the raw message — always sign a hash; this prevents length-extension attacks",
            "Reusing (d, n) across sign and encrypt contexts weakens security",
            "A deterministic hash means the same message always gives the same sig, enabling replay attacks without nonces.",
        ],
        code_ref=[
            "src/cryptolab/crypto/hash.py::{sha256, sha256_trace}",
            "src/cryptolab/crypto/rsa.py::{rsa_sign, rsa_verify}",
            "src/cryptolab/crypto/math.py::{modexp, modexp_trace}",
        ],
    )

    state.trace.add(step)
    save_trace(state.exports_dir / "trace.json", [s.to_json_obj() for s in state.trace.steps()])
    _render_step_to_terminal(state, step)
    _back_to_menu(state)

def _project_design_notes_module(state) -> None:
    """ 
    Inentionally does not clear the trace so it can be appended
    to the most recent crypto run and exported as part of the final report.
    """
    step = TraceStep(
        module="NOTES",
        title="Project Design Notes / Sources / Demo Notes",
        goal=(
            "Explanation: Why the project was designed this way and what sources it relies on," \
            "and answer questions inside export."
        ),
        inputs={
            "Language": "Python",
            "Project structure": "crypto/, ui/, io/, models/, tests/, exports/",
            "Recommendation for demo order": "2 -> 3 -> 4 -> 5 -> 6 -> 7 -> 8 -> e",
        },
        algorithm_steps=[
            "Use Python for readability and built-in big int arithmetic.",
            "Separate the project into modules: crypto/, ui/, io/, models/, tests/, exports/.",
            "Use RSA for key generation, textbook encryption/decryption and digital signatures.",
            "Use Diffie-Hellman to demonstrate shared-secret key exchange over an insecure channel.",
            "Use a KDF after Diffie-Hellman so the shared secret becomes a fixed-size DES key and IV.",
            "Use DES-CBC because DES is a classic textbook block cipher and CBC is a standard block mode covered in class.",
            "Use trace levels and export files so the everyone can see both the summary level and full internal computation steps. ",
            "Use code-view snippets so the demo can show the real implementation directly from the source files.",
            
        ],
        outputs={
            "Why Python": "Readable, fast to prototype, strong for teaching and supports arbitrary-sized integers.",
            "Why e = 65537": "Common RSA public exponent; fast and widely used in practice.",
            "Why Miller-Rabin rounds = 24": "Very low false-prime probability while staying fast for demo.",
            "Why the PRNG fallback constant exists": "Avoid the all-zero xorshift state and use a stable non-zero seed",
            "Why DES was chosen": "Textbook cipher that is easier to implement manually than AES",
            "Why KDF after DH": "Turns the shared secret into a fixed-size DES key and IV",
            "Primary source set": "Chapter2, chapter 4, chapter 7, chapter 8, chapter 9 and the respective course PDFs.",
        },
        trace_summary=[
            "Python was chosen because it is readable, quick to iterate in, and already supports the big integers needed for RSA and DH.",
            "Folder split keeps the repo clean: crypto = algorithms, ui = terminal flow, io = exports/storage, models = session state.",
            "RSA uses e = 65537 because it is the standard public exponent and makes modular exponentiation efficient.",
            "Miller-Rabin uses 24 rounds because it keeps false-prime probability low while remaining fast enough for the demo.",
            "The PRNG fallback constant is used so xorshift never starts in the all-zero state, which would break the generator.",
            "Diffie-Hellman produces a shared secret, but the KDF is needed to derive a fixed-size DES key and IV from it.",
            "DES-CBC was chosen because DES is a classic cipher and CBC clearly demonstrates IVs and chaining.",
            "The HTML/Markdown export exists to make marking and class demonstration easier.",
        ],
        trace_full=[
            "Why Python: Python was chosen because it is easier to read in a live demo, faster to prototype during development, and already supports arbitrary-sized integers. That is essential because RSA and Diffie-Hellman use values that grow far beyond normal 32-bit or 64-bit machine integers.",
            "What big-integer arithemetic means: In many languages, integers have a fixed size and can overflow and in this project, python integers automatically expand to hold larger values so the implementation can focus on modular arithmetic, prime generation and exponentiation instead of overflow handling.",
            "What the project folders are for: crypto/ contains the actual algorithms and math. ui/ contains the terminal menu and trace rendering. io/ contains exports and saved files. models/ contains session state. tests/ verifies correctness. exports/  stores generated reports. Used to keep a clean structure and to keep presentation and everything separated and easier to explain.",
            "Main project flow: First generate RSA keys, then run Diffie-Hellman to create a shared secret. Then derive a DES key and IV from that secret, then encrypt/decrypt with DES-CBC, then sign/verify with RSA and finally export the results. Steps depend on the earlier ones.",
            "How Diffie-Hellman demonstrates a shared secret: Alice compute A = g^a mod p and Bob computes B = g^b mod p. Alice then computes s_alice = B^a mod p and Bob computes s_bob = A^b mod p. Because modular exponentiation composes correctly  both sides will arrive at the same shared secret s without directly sending s itself over the channel.",
            "Why a KDF is needed after Diffie-Hellman: The DH shared secret is just one large integer. DES cannot use an arbitrary-size integer directly. DES expects fixed-sized symmetric material so the KDF converts the shared secret into an 8-byte DES key and an 8-byte IV.",
            "Why the fixed-size DES values is important: DES is a fixed-block, fixed-key cipher. The key and IV must each be the right size so the encryption and decryption work properly. The KDF step is what bridges the gap between the large DH integer and the exact lengths needed by DES-CBC.",
            "Why DES was chosen instead of AES: AES is stronger but it is more complicated to implement manually because of the finite-field arithmetic and a more complex internal structure. DES is older and weaker but it's easier to implement and explain round by round which makes it better for a course demo.",
            "Why CBC mode was chosen: CBC makes the first block depend on the IV and every later block depend on the previous ciphertext block. This clearly demonstrates the purpose of block chaining and shows why encrypting each block independently would reveal visible patterns.",
            "What an IV is and why it matters: An initialization vector is the first block-sized value mixed into CBC encryption before the first plaintext block is encrypted. Its role is to prevent is to prevent identical messages from always starting with identical ciphertext patterns.",
            "What chaining means in CBC: After the first block, each plaintext block is XORed with the previous ciphertext block before encryption. Meaning the encryption of one block influences the next block which is why the mode is called chained.",
            "Why e = 65537: It is a standard RSA public exponent because it is efficent for modular exponentiation and widely used in practice. It is large enough to avoid weak tiny exponents but still small enough to keep encryption and verification super fast.",
            "What false-prime probability means: Miller-Rabin is probabilistic. When it says number is probably prime there is a very small chance that the number is actually composite. Each additional round reduces that chance further so more rounds increase the overall confidence in the result.",
            "Why Miller-Rabin rounds = 24: 24 rounds gives a very low false-prime probability  while still running quickly enough for a live demo. The point is to balance the confidence and speed.",
            "Why the PRNG fallback constant: XORshift-style generators must never start with internal state 0. If the state were all zero every future shift/XOR would keep producing zero, so the generator would be stuck forever.",
            "What an all-zero xorshift state is: It is the broken PRNG case where the internal state is 0. Because the update rule only shifts and XORs that zero value, every output would remain 0. Fallback constant prevents that failure.",
        ],
        code_ref=[
            "src/cryptolab/ui/menu.py::_project_design_notes_module",
            "src/cryptolab/crypto/prng.py::XorShift64Star",
            "src/cryptolab/crypto/rsa.py::rsa_generate_keypair",
            "src/cryptolab/crypto/dh.py::dh_key_exchange",
            "src/cryptolab/crypto/kdf.py::derive_des_key_iv",
            "src/cryptolab/crypto/des/modes.py::{encrypt_cbc_trace, decrypt_cbc_trace}",
            "src/cryptolab/crypto/hash.py::{sha256, sha256_trace}",
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
       # print(f" n) Notation mode: {state.config.notation_mode}")

        print("\nModules:")
        print(" 1) Demo (UI + Trace + Export demo)")
        print(" 2) RSA Key Generation (Requirement 1)")
        print(" 3) Diffie-Hellman Key Exchange (Requirement 2)")
        print(" 4) RSA Encrypt / Decrypt     (needs RSA keys from step 2)")
        print(" 5) KDF: Derive DES Key + IV  (needs DH secret from step 3)")
        print(" 6) DES-CBC Encrypt / Decrypt (needs KDF from step 5)")
        print(" 7) RSA Digital Signature     (needs RSA keys from step 2)")
        print(" 8) Project design notes / source / demo notes")

        print("\nOther:")
        print(" e) Export report (HTML + Markdown)")
        print(" r) Reset session (clear trace and reset state)")
        print(" x) Exit")

        choice = input("\nSelect: ").strip().lower()

        if choice == "t":
            state.config.trace_level = state.config.trace_level.next()
            continue
        if choice == "c":
            state.config.code_view = not state.config.code_view
            continue
       # if choice == "n":
        #    state.config.notation_mode = "EXPANDED" if state.config.notation_mode == "SYMBOLS" else "SYMBOLS"
         #   continue 
        if choice == "1":
            _demo_module(state)
            continue
        if choice == "2":
            _rsa_keygen_module(state)
            continue
        if choice == "3":
            _dh_key_exchange_module(state)
            continue
        if choice == "4":
            _rsa_encrypt_decrypt_module(state)
            continue
        if choice == "5":
            _kdf_module(state)
            continue
        if choice == "6":
            _des_cbc_module(state)
            continue
        if choice == "7":
            _rsa_signature_module(state)
            continue
        if choice == "8":
            _project_design_notes_module(state)
            continue
        if choice == "e":
            _export(state)
            continue
        if choice == "r":
            state.session.wipe()
            state.trace.clear()
            print("\nSession wiped and starting fresh.\n")
            continue
        if choice == "x":
            print("\nExiting Cryptolab. Goodbye!\n")
            return
        
        print("Invalid choice. Please try again.")