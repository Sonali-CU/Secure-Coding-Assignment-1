"""Section D - main executable demonstration of all required cryptographic functions.

    python main.py

Every section header has the form  "== [Sxx] title ==". The screenshot tool in Screenshots/ uses
these headers, so keep them if you edit this file.  All output is plain ASCII so it displays
correctly in Windows PowerShell.
"""
import base64
import ssl
import sys
import time
from pathlib import Path

import encryption
import hmac_security
import https_server
import key_management
import password_security
from encryption import DecryptionError
from hmac_security import ReplayGuard
from key_management import KeyStore


def banner(tag, title):
    print(f"\n== [{tag}] {title} ==")


def main():
    print("SecureBank cryptography demonstration")
    print("Libraries: argon2-cffi (Argon2id), cryptography (AES-GCM), Python hmac/hashlib, ssl (TLS)")

    # ------------------------------------------------------------------ Task 7: key management
    banner("K7", "Task 7 - Key generation, storage and management")
    store = KeyStore()
    aes_key = store.get_key("aes_data", 32)
    mac_key = store.get_key("hmac_signing", 32)
    for name in ("aes_data", "hmac_signing"):
        info = store.describe(name)
        print(f"key '{name}': {info['size_bits']} bits, file permissions {info['permissions']}")
        print(f"   stored in: {info['file']}")
    print("Key values are never printed. Keys are read from a file outside the source code or from an")
    print("environment variable (AES_DATA_KEY_B64 / HMAC_SIGNING_KEY_B64) in production.")

    # ------------------------------------------------------------------ Tasks 1 & 2: Argon2id
    banner("S10", "Task 1 - Argon2id password hash generation")
    password = "Correct#Horse2026"
    stored_hash = password_security.hash_password(password)
    print("Algorithm: Argon2id (argon2-cffi), time_cost=3, memory_cost=64 MiB, parallelism=4")
    print("Stored value (plaintext password is not stored):")
    print(stored_hash)
    print("Same password hashed again gives a different value (random salt):",
          password_security.hash_password(password) != stored_hash)

    banner("S11", "Task 2 - Password verification: CORRECT password")
    result = password_security.verify_password(stored_hash, password)
    print(f"verify_password(stored_hash, <correct password>) -> {result}")

    banner("S12", "Task 2 - Password verification: INCORRECT password")
    for attempt in ["correct#horse2026", "Correct#Horse2025", ""]:
        shown = repr(attempt) if attempt else "(empty string)"
        print(f"verify_password(stored_hash, {shown}) -> {password_security.verify_password(stored_hash, attempt)}")
    print("verify_password(stored_hash, <malformed hash>) ->",
          password_security.verify_password("not-a-real-hash", password))

    # ------------------------------------------------------------------ Tasks 3 & 4: AES-GCM
    banner("S13", "Task 3 - AES-256-GCM encryption")
    secret = "Card 4111 1111 1111 1111, expires 12/29"
    aad = "customer:42"           # associated data: binds the ciphertext to this customer record
    blob = encryption.encrypt(aes_key, secret.encode("utf-8"), aad.encode("utf-8"))
    print("Algorithm: AES-256-GCM. Nonce: 12 bytes, freshly generated for this encryption.")
    print("Nonce (hex):         ", blob[:12].hex())
    print("Ciphertext+tag (b64):", base64.b64encode(blob[12:]).decode("ascii"))
    print("Plaintext present in output?", secret.encode("utf-8") in blob)
    second = encryption.encrypt(aes_key, secret.encode("utf-8"), aad.encode("utf-8"))
    print("Second encryption uses a different nonce:", blob[:12] != second[:12])

    banner("S14", "Task 4 - AES-256-GCM decryption")
    recovered = encryption.decrypt(aes_key, blob, aad.encode("utf-8")).decode("utf-8")
    print("Correct key and AAD -> recovered:", recovered)
    for label, attempt in [
        ("Wrong key", lambda: encryption.decrypt(encryption.generate_key(), blob, aad.encode("utf-8"))),
        ("Wrong associated data (record swap)", lambda: encryption.decrypt(aes_key, blob, b"customer:43")),
        ("Invalid key length (16 bytes)", lambda: encryption.decrypt(b"x" * 16, blob, aad.encode("utf-8"))),
    ]:
        try:
            attempt()
            print(f"{label}: DECRYPTED (unexpected)")
        except DecryptionError as error:
            print(f"{label}: REJECTED - {error}")
        except ValueError as error:
            print(f"{label}: REJECTED - {error}")

    # ------------------------------------------------------------------ Tasks 5 & 6: HMAC
    banner("S15", "Task 5 - HMAC-SHA256 generation")
    message = b"transfer from=ACC-1001 to=ACC-2002 amount=500.00 currency=USD"
    tag = hmac_security.generate(mac_key, message)
    print("Message:    ", message.decode("ascii"))
    print("HMAC-SHA256:", tag)

    banner("S16", "Task 6 - HMAC verification (constant-time comparison)")
    print("Unmodified message with correct key ->", hmac_security.verify(mac_key, message, tag))
    print("Same message with a different key   ->",
          hmac_security.verify(encryption.generate_key(), message, tag))

    banner("S17", "Task 6 - Tampered message detection and replay protection")
    tampered = message.replace(b"500.00", b"5000.00")
    print("Amount changed 500.00 -> 5000.00, original tag ->",
          hmac_security.verify(mac_key, tampered, tag), "(modified message detected)")
    guard = ReplayGuard(mac_key, window_seconds=60)
    signed = guard.sign({"to": "ACC-2002", "amount": "500.00"})
    print("First submission of a signed message:  ", guard.accept(signed))
    print("Same message submitted again (replay): ", guard.accept(signed))
    stale = guard.sign({"to": "ACC-2002", "amount": "500.00"}, timestamp=int(time.time()) - 3600)
    print("Validly signed message from one hour ago:", guard.accept(stale))
    forged = guard.sign({"to": "ACC-2002", "amount": "500.00"})
    forged["body"]["payload"]["amount"] = "5000.00"
    print("Payload edited after signing:          ", guard.accept(forged))

    # ------------------------------------------------------------------ Task 8: HTTPS
    banner("S18", "Task 8 - HTTPS server running and client verification")
    cert_path, key_path = https_server.ensure_self_signed_certificate()
    print(f"Certificate: {cert_path}")
    print("Self-signed, RSA 3072-bit, SHA-256, valid 365 days, SAN = localhost, 127.0.0.1")
    print(f"Private key: {key_path} (never committed; owner-only permissions on POSIX)")
    server, _thread = https_server.start_server(cert_path, key_path, port=0)
    port = server.server_port
    print(f"HTTPS server listening on https://127.0.0.1:{port} (TLS 1.2+ only)")
    try:
        status, body, tls = https_server.verified_get(port, cert_path, "/")
        print(f"Client with the certificate as trust anchor: GET / -> HTTP {status}")
        print(f"   body: {body}")
        print(f"   TLS protocol: {tls['protocol']}   cipher: {tls['cipher']}")
        print(f"   certificate verified: {tls['certificate_verified']}   HSTS: {tls['hsts']}")
        try:
            import http.client
            untrusted = http.client.HTTPSConnection("localhost", port, context=ssl.create_default_context(),
                                                    timeout=10)
            untrusted.request("GET", "/")
            print("Client without the certificate in its trust store: connected (unexpected)")
        except ssl.SSLCertVerificationError as error:
            print(f"Client without the certificate in its trust store: REJECTED ({error.verify_message})")
    finally:
        server.shutdown()
        print("HTTPS server stopped.")

    print("\nALL DEMONSTRATIONS COMPLETED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
