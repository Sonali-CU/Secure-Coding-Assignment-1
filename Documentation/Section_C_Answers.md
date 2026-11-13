# Section C: Cryptographic Security

**Scenario: E-commerce application.** The application stores customer information, passwords, payment-related information and transaction records. An assessment found passwords stored in plain text and sensitive information sent without adequate protection.

The answers refer to the implementation in `Section_D_Cryptography/` (modules named in each answer) and to the test results in `Test_Results.md`.

---

## 1. Protecting sensitive customer information with encryption

**Answer.** Use layered protection:

1. **In transit:** TLS for every connection (see question 3).
2. **At rest:** encrypt sensitive fields such as postal address, identity numbers and internal notes with AES-256-GCM, and encrypt the database storage volume.
3. **Minimise:** do not store data that is not needed. Card numbers should never be stored. Store the token returned by the payment processor instead. This keeps the application largely outside the scope of PCI DSS.
4. **Keep keys apart from data** (see question 6).

Demonstrated in `encryption.py`: an account record is encrypted with the customer ID as associated data, so a ciphertext cannot be moved to another customer's record.

## 2. Securely storing user passwords using Argon2 or bcrypt

**Answer.** Store only a salted, slow, memory-hard hash of the password, never the password. Argon2id is recommended by OWASP. It is memory-hard, so attackers cannot run cheap parallel guesses on GPUs.

- Library: `argon2-cffi`, `PasswordHasher(time_cost=3, memory_cost=64 MiB, parallelism=4)`.
- The salt is generated randomly for each password and stored inside the hash string, so two users with the same password get different hashes.
- Verification uses the library's constant-time comparison.
- Also apply: minimum password length (10 characters in the banking app), a limit on maximum length to bound the work an attacker can force, rate limiting and lockout for repeated failures, checks against lists of breached passwords, and rehashing a stored password when the parameters are strengthened (`needs_rehash`).
- Do not use MD5, SHA-1 or unsalted SHA-256: they are too fast for passwords. bcrypt is an acceptable alternative with a cost factor of at least 12, but it truncates input at 72 bytes.

Implementation: `password_security.py`. Banking application: Werkzeug's `generate_password_hash` (scrypt, salted) is used for stored user passwords there, and Argon2id is used in the cryptography project, as the assignment requires.

## 3. Secure communication between client and server using HTTPS/TLS

**Answer.** Use TLS 1.2 at minimum, preferably 1.3. Disable SSL 3.0, TLS 1.0 and TLS 1.1. Allow only AEAD cipher suites with forward secrecy (ECDHE with AES-GCM or ChaCha20-Poly1305). In production:

- obtain a certificate from a public CA (for example Let's Encrypt) and renew it automatically;
- redirect all HTTP traffic to HTTPS;
- send `Strict-Transport-Security` (HSTS);
- set session cookies with the `Secure` flag;
- test the configuration with `testssl.sh` or SSL Labs.

Implementation: `https_server.py` sets `minimum_version = TLSv1_2` and an ECDHE+AEAD cipher list. The demonstration shows a trusted client receiving 200 over TLS 1.3, a client without the certificate being rejected, and TLS 1.1 being refused (test `test_tls_1_1_is_refused`).

**Limitations of the self-signed certificate used here:** anyone can create one, so trust depends entirely on how the certificate file reaches the client. Browsers warn about it. It cannot be revoked through normal channels and has no automatic renewal. It is acceptable for local testing only.

## 4. Using AES-GCM to protect confidential customer data

**Answer.** AES-GCM is authenticated encryption: it provides confidentiality and detects tampering in a single operation.

- Key: 256 bits, from a cryptographically secure random source.
- Nonce: 96 bits, **freshly generated for every encryption** and stored with the ciphertext. Reusing a nonce with the same key lets an attacker recover data and forge messages, so the number of messages per key must be limited and keys rotated well before about 2^32 messages with random nonces.
- Associated data (AAD): fields such as the customer ID that are authenticated but not encrypted. Binding the ciphertext to its record stops record-swapping attacks.
- Any change to the nonce, ciphertext, tag or AAD makes decryption fail. The application returns one generic error and never returns partial plaintext.

Implementation: `encryption.py`. The demonstration encrypts a card-like string with AAD `customer:42`, shows that the plaintext is not visible, shows successful decryption, and shows rejection for a wrong key, a wrong AAD and an invalid key length.

## 5. Ensuring integrity and authenticity of messages using HMAC

**Answer.** HMAC-SHA256 combines a secret key with the message. Only holders of the key can produce or verify a valid tag, so the tag proves both integrity and origin. Use it for signed API requests, webhooks, signed tokens and internal messages.

- Verify with `hmac.compare_digest`, which compares in constant time, so timing does not reveal how many leading bytes matched.
- Use a separate key for HMAC and encryption. Reusing one key for two purposes can weaken both.
- Key length: at least 32 bytes.

Implementation: `hmac_security.py`. The demonstration signs a transfer message, verifies the untouched message, and shows that changing the amount from 500.00 to 5000.00 is detected.

## 6. Generating, storing and managing cryptographic keys securely

**Answer.**

1. **Generate** with `secrets.token_bytes` (the operating system CSPRNG). Never derive keys from passwords or from predictable values.
2. **Store** outside the source code. Production options are a cloud KMS (AWS KMS, Azure Key Vault, Google Cloud KMS), HashiCorp Vault, or a hardware security module for the highest assurance. Keys must never be committed to version control, written to logs or included in backups without encryption.
3. **Envelope encryption:** data is encrypted with a data-encryption key, and that key is wrapped with a key-encryption key held in the KMS. Rotating the outer key does not require re-encrypting all the data.
4. **Restrict and audit** key access with least privilege, and log each use.
5. **Rotate** keys on a schedule and after any suspected compromise, keeping old keys only as long as they are needed to decrypt old data.
6. **Destroy** retired keys securely.

Implementation: `key_management.py`. Keys are created exclusively with owner-only permissions (0600 on POSIX), a world-readable key file is refused, a key may be supplied through an environment variable for a secrets manager, and rotation archives the old key. On Windows, NTFS permissions must be set by an ACL (see README), because POSIX mode bits are not enforced there.

## 7. Preventing replay attacks during sensitive financial transactions

**Answer.** An attacker who captures a valid signed transfer must not be able to submit it again. Defences:

- a unique nonce in each message, recorded by the server for at least the length of the acceptance window;
- a timestamp inside the MAC, with messages outside a short window (for example 60 seconds) rejected;
- a MAC over the nonce and timestamp as well as the payload, so they cannot be altered;
- an idempotency key for each transaction, so a legitimate client retry does not execute the transfer twice;
- TLS, which prevents capture on the network but does not stop replay of a message captured elsewhere.

Implementation: `ReplayGuard` in `hmac_security.py`. The demonstration shows a first submission accepted, the same submission rejected as a replay, a validly signed message from one hour earlier rejected for its timestamp, and a message with an edited amount rejected for its MAC.

## 8. Selecting appropriate cryptographic algorithms and avoiding outdated algorithms (MD5, DES)

**Answer.** Use algorithms that current guidance (NIST, OWASP, IETF) approves:

| Purpose | Use | Avoid |
|---|---|---|
| Symmetric encryption | AES-256-GCM, ChaCha20-Poly1305 | DES, 3DES, RC4, ECB mode, unauthenticated CBC |
| Hashing / integrity | SHA-256, SHA-3, HMAC-SHA256 | MD5, SHA-1 |
| Password storage | Argon2id (bcrypt as an alternative) | Any fast hash, plain or unsalted |
| Asymmetric signatures | Ed25519, ECDSA P-256 | RSA below 2048 bits |
| Key exchange and TLS | ECDHE, TLS 1.2 and 1.3 | SSL 3.0, TLS 1.0, TLS 1.1, static RSA key exchange |

MD5 is broken for collision resistance; SHA-1 has practical collisions; DES has a 56-bit key that can be searched exhaustively. Design for crypto-agility: put algorithm names in configuration so they can be replaced without rewriting code. Check current guidance before choosing, because recommendations change over time.

## 9. Ensuring sensitive information is not exposed through logs or error messages

**Answer.**

- Never log passwords, session tokens, keys, full card numbers or complete personal identifiers. Mask what must be shown (for example the last four digits of a card).
- Use structured logging with a filter that removes known sensitive field names.
- Return generic messages to users ("invalid username or password", "request failed, reference 8f3a") and record the full exception server-side with that reference.
- Switch debug mode off in production so stack traces are never shown.
- Restrict who can read log storage, and set retention limits.
- Authentication failures are logged with the username only. The password is never logged. The login page gives the same message whether the username or the password is wrong, and the same work is done for both, so the response does not reveal which accounts exist.

Implementation: the banking application's `audit()` helper writes actions without secrets, and the cryptography demonstration prints hashes and ciphertext but never keys.

## 10. Verifying the effectiveness of cryptographic controls through security testing

**Answer.**

- **Unit and negative tests:** round-trip tests, plus tests that show each tamper case is rejected (wrong key, modified ciphertext, modified nonce, modified tag, wrong associated data). These are in `Section_D_Cryptography/tests/test_crypto.py`.
- **Known-answer tests (recommended, not included in this project):** compare outputs with published test vectors for AES-GCM (NIST SP 800-38D) and HMAC-SHA256 (RFC 4231). The current tests check behaviour (round trips and rejections), not fixed vectors.
- **Static analysis:** Bandit and Semgrep to find weak algorithms, hard-coded secrets and insecure use of random numbers.
- **Dependency scanning:** `pip-audit` or Dependabot for known vulnerabilities in `cryptography` and `argon2-cffi`.
- **TLS testing:** `testssl.sh`, `sslyze` or SSL Labs against the deployed host, checking protocol versions, ciphers, certificate chain, HSTS and forward secrecy.
- **Penetration testing and code review** focused on key handling, logging and error paths.
- **Log review:** search logs and error pages for known test secrets to confirm they never appear.

The automated tests in this project (48 cryptography tests and 61 RBAC tests) are listed with their results in `Test_Results.md`.
