# Security Review

Scope: full repository scan for hardcoded secrets, SQL injection, unvalidated input,
insecure dependencies, permissive CORS, exposed debug endpoints, missing authentication
checks — plus the cryptographic implementations themselves.

## Not applicable / nothing found

| Category | Result |
| --- | --- |
| Hardcoded API keys / secrets | None. Only test key literals in `*/tests/*` and docs. |
| SQL injection | No database or SQL layer exists. |
| Overly permissive CORS | No HTTP server or CORS configuration exists. |
| Exposed debug endpoints | No web/RPC endpoints exist. Debug output is local GUI/CLI only. |
| Missing authentication checks | No service, session, or authorization layer exists. |

The project is a local PyQt5 + Python (+ Verilog) crypto toolkit, so the classic web
vulnerability classes above do not apply. The real risk lives in the crypto code.

## Critical (fixed)

1. **"AES" was repeating-key XOR.** `aes_core.py` contained AES tables and key
   expansion, but `encrypt`/`decrypt` called `_xor_encrypt(plaintext, self.key)` for
   every mode; `aes_core_simple.py` was XOR-only. Any data "encrypted" with either
   module was trivially recoverable (known-plaintext or key-length statistics).
   *Fix:* `aes_core.py` now implements real AES (S-box, key expansion, rounds) with
   ECB/CBC/CFB/OFB/CTR; `aes_core_simple.py` is backed by `cryptography`'s AES.
   Verified against the FIPS-197 known-answer vectors and cross-checked with
   `cryptography` for all five modes and all three key sizes.

2. **Zero-padding instead of PKCS#7.** Padding was `\x00` fill removed with
   `rstrip(b'\x00')`, corrupting any plaintext that legitimately ends in zero bytes.
   *Fix:* PKCS#7 padding with validation on removal.

3. **RSA key material from `random`.** `random.getrandbits`/`random.randrange` (Mersenne
   Twister) generated the primes, the Miller-Rabin witnesses, and the 256-bit session
   key in `key_exchange`. MT output is predictable from observed state, so private keys
   and session keys were guessable.
   *Fix:* all of these now use `secrets` (OS CSPRNG).

4. **Textbook (unpadded) RSA signatures.** `sign` raw-exponentiated the bare SHA-256
   hash and `verify` compared integers, which admits existential forgery.
   *Fix:* EMSA-PKCS1-v1_5 encoding (RFC 8017 §9.2) with the full encoded block compared
   in constant time on verification.

5. **PKCS#1 v1.5 encryption padding used possibly-zero random bytes** and accepted any
   separator position, so plaintext could be silently truncated and short/malformed
   padding accepted.
   *Fix:* non-zero random padding, enforced ciphertext block size, and a minimum
   8-byte padding string on decryption.

## Medium (fixed)

- **Key/private-key files written with default permissions** (world-readable umask
  dependent) in `file_crypto.save_key` and the RSA GUI private-key export.
  *Fix:* files are created via `os.open(..., 0o600)`.
- **IV mismatch in the AES GUI file flow:** `encrypt_file` generated its own IV and
  ignored the IV shown in the GUI, so users decrypting with the displayed IV failed.
  *Fix:* `encrypt_file` accepts an IV and the GUI passes the configured one.
- **Unvalidated key input in the AES GUI:** any hex length was accepted and failed later
  deep in the cipher. *Fix:* keys must be 128/192/256-bit.
- **ECB offered without warning.** *Fix:* both AES modules emit a warning on ECB.
- **1024-bit RSA offered without warning.** *Fix:* `RSA(1024)` warns.
- **Unbounded dependency floors** (`cryptography>=3.4.0` allows versions with known
  CVEs). *Fix:* floors raised in `requirements.txt`.

## Hygiene (fixed)

- A complete `venv/` (5161 files, including a vulnerable `cryptography` 3.4.8),
  `.DS_Store`, and `__pycache__/*.pyc` were committed despite being in `.gitignore`.
  All are now untracked.

## Recommended follow-ups (not done here)

- Add authenticated encryption (AES-GCM) — the current modes provide confidentiality
  only, so ciphertext tampering is undetectable.
- Derive AES keys from passwords with a KDF (PBKDF2/scrypt) if that flow is ever added.
- Replace the hand-rolled RSA with `cryptography`'s OAEP/PSS for production use; the
  pure-Python modular exponentiation is not constant-time and leaks via timing.
- `hex_to_key` left-pads odd-length hex; consider rejecting malformed input instead.
