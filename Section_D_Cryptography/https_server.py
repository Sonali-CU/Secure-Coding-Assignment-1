"""HTTPS server and client verification (Task 8).

Run the server for browser testing:
    python https_server.py            -> https://127.0.0.1:8443  (Ctrl+C to stop)

Design
------
* A self-signed RSA-3072 certificate for localhost / 127.0.0.1 is generated with the 'cryptography'
  library (no OpenSSL command line needed, so it works the same on Windows).
* The server accepts TLS 1.2 and 1.3 only and uses ECDHE key exchange with AEAD ciphers
  (forward secrecy, authenticated encryption).
* The client verifies the certificate chain and host name against the certificate file it trusts.

LIMITATIONS OF SELF-SIGNED CERTIFICATES
* Nobody independent vouches for the certificate, so anyone can create one for any name. Trust only
  comes from distributing the certificate file to clients by a trusted route.
* Browsers and operating systems show a warning for them, and users learn to click through warnings.
* They cannot be revoked through normal channels, and there is no automatic renewal.
* For production use a certificate from a public CA (for example Let's Encrypt via certbot),
  served behind a reverse proxy such as nginx, with HSTS enabled.
"""
import datetime
import http.client
import ipaddress
import os
import ssl
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from flask import Flask, jsonify
from werkzeug.serving import make_server

BASE_DIR = Path(__file__).resolve().parent
CERT_DIR = BASE_DIR / "certs"
TLS_CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!MD5:!RC4:!3DES:!DES"
IS_POSIX = os.name == "posix"


def ensure_self_signed_certificate(cert_dir: Path = CERT_DIR, days: int = 365):
    """Create certs/cert.pem and certs/key.pem if missing. Returns (cert_path, key_path)."""
    cert_path, key_path = cert_dir / "cert.pem", cert_dir / "key.pem"
    if cert_path.exists() and key_path.exists():
        return cert_path, key_path

    cert_dir.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureBank Assignment (self-signed, local only)"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_bytes = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption())
    if IS_POSIX:
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(key_bytes)
    else:
        key_path.write_bytes(key_bytes)
    return cert_path, key_path


def build_server_context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2        # SSL 3.0, TLS 1.0 and 1.1 are refused
    context.set_ciphers(TLS_CIPHERS)
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return context


def build_client_context(ca_file: Path) -> ssl.SSLContext:
    """Client that trusts only the given certificate and checks the host name."""
    context = ssl.create_default_context(cafile=str(ca_file))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def create_demo_app() -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def index():
        return jsonify(message="HTTPS connection established", transport="TLS")

    @app.after_request
    def hsts(response):
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    return app


def start_server(cert_path: Path, key_path: Path, port: int = 0):
    """Start the HTTPS server in a background thread. Port 0 picks a free port."""
    server = make_server("127.0.0.1", port, create_demo_app(), threaded=True,
                         ssl_context=build_server_context(cert_path, key_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def verified_get(port: int, ca_file: Path, path: str = "/"):
    """Client request that verifies the certificate. Returns (status, body, tls_info)."""
    context = build_client_context(ca_file)
    connection = http.client.HTTPSConnection("localhost", port, context=context, timeout=10)
    connection.connect()                        # TLS handshake; certificate is verified here
    sock = connection.sock                      # keep a reference: http.client may drop it after the response
    connection.request("GET", path)
    response = connection.getresponse()
    tls_info = {
        "protocol": sock.version(),
        "cipher": sock.cipher()[0],
        "certificate_verified": sock.getpeercert() != {},
        "hsts": response.getheader("Strict-Transport-Security"),
    }
    body = response.read().decode("utf-8")
    connection.close()
    return response.status, body, tls_info


if __name__ == "__main__":
    cert, key = ensure_self_signed_certificate()
    app = create_demo_app()
    context = build_server_context(cert, key)
    print(f"Serving HTTPS on https://127.0.0.1:8443  (certificate: {cert})")
    print("Press Ctrl+C to stop.")
    app.run(host="127.0.0.1", port=8443, ssl_context=context, debug=False)
