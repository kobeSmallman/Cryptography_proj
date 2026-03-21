CryptoLab - Manual Cryptosystem CPSC 3730
Kobe Smallman and Jesse Van Schothorst
Repo: https://github.com/kobeSmallman/Cryptography_proj.git

Project:
    This project is a manual cryptography explorer built for the programming project in CPSC 3730 as the 2nd option. The goal is implement the following: 
1. Key generation 
2. Key exchange 
3. Message encryption and decryption 
4. Digital signature 
5. Step-by-step outputs of each function and a user-friendly interface 

language being used: Python

It is a menu based UI with exports that produce an HTML report with some nice visual design. 

Included: Clear pros & cons discussion for each module presented. 

Without the use of cryptographic libraries or any built in cryptographic functions.
Rules:
The use of cryptographic libraries or built-in cryptographic functions is not allowed. All 
algorithms and functions must be implemented manually. 

Using:
Python modules for UI, formatting, file I/O, JSON, etc. 
Packaging tools to run the src/ layout
testing tools (pytest)

Layout:

src/
    cryptolab/
    main.py
    main.py
    ui/
    io/
    models/
    crypto/
    tests/
    exports/ -> Which are genrated and not commited.

Explanation of each folder:
ui/
Menu system, toggles like trace/code/notation and display formatting

models/
sessions state to remember what values are existing right now: keys, dervied 
key/IV, ciphertext, signature, and more

io/ 
this is where we save/load and export which includes generating the following:
exports/reports.html
exports/transcript.md
exports.session.json

crypto/
Manual algorithms implementations which includes:
helper functions like gcd, extended Euclid, modular inverse, modular exponentitation
prime testing & generation
RSA -> keygen and signature
Diffie-Hellman key exchange 
DES -> block cipher and CBC mode (encryption/decryption)
hash which is used for signatures

tests/
Unit tests per module 

User experience workflow:
Choose module and see a clean step by step breakdown then an option to export a report that demonstrates the manual implementation

Menu:
Off / Summary / FUll
off: final results only
summary: lecture-like with intermediate values
FULL: Shows everything relevant like the DES rounds and modexp steps, etc.

Code view: On & Off
On: the output includes code references (file & function) and the HTML report shows the collapsible used code sections

Any time we leave a module the program will ask 
1: Continue (keep all session values and traces)
2: Restart - wipe session state and start fresh 
Reason: In case anyone needs to leave and come back the option to save from where you left off would help both us and the grader.

Program tasks:
Key generation (RSA):
Generate primes p and q 
Compute n = p * q
Compute phi_n = (p - 1) * (q - 1)
e such that gcd(e, phi_n) = 1
Compute d = e^-1 mod phi_n
Store public key (n, e) and private key (n, d)

Key exchange (Diffie-Hellman)
prime p and generator g
compute A = g^a mod p and B = g^b mod p
shared secret is s=B^a mod p = A^b mod p

KDF (derive symmetric key and IV)
Derive a DES key k and IV from teh shared secret s

Message encryption & decryption (DES in CBC mode)
DES block cipher implemented
CBC mode implemented 
Encrypt & Decrypt: C_i = E_K(P_i XOR C_{i-1}) with IV for i=0 and P_i = D_K(C_i) XOR C_{i-1} with IV for i=0 (respectively)

Digital signature (RSA sign & verify)
compute digest h = H(m) using a manual hash implementation
signature: sig = h^d mod n
verfication: h_prime = sig^e mod n, compare h_prime == h


How to install and run:
----------------------------
pip install -e .

python -m cryptolab

python -m pytest tests/ -v

view how_to_run_program.txt to see simple walkthrough of program