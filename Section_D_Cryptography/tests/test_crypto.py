"""Automated tests for the Section D cryptography project (password, AES-GCM, HMAC, keys, HTTPS)."""
import base64
import ssl
import stat
import sys
import time

import pytest

import encryption
import hmac_security
import https_server
import key_management
import password_security
from encryption import DecryptionError, NONCE_SIZE, TAG_SIZE
from hmac_security import ReplayGuard
from key_management import KeyManagementError, KeyStore

IS_POSIX = sys.platform != "win32"


# ============================================================================ password hashing
@pytest.fixture(scope="module")
def stored():
    return password_security.hash_password("Correct#Horse2026")


def test_hash_is_argon2id_and_not_plaintext(stored):
    assert stored.startswith("$argon2id$")
    assert "Correct#Horse2026" not in stored


def test_correct_password_succeeds(stored):
    assert password_security.verify_password(stored, "Correct#Horse2026") is True


def test_incorrect_password_fails(stored):
    assert password_security.verify_password(stored, "correct#horse2026") is False
    assert password_security.verify_password(stored, "Correct#Horse2025") is False


def test_empty_password_fails(stored):
    assert password_security.verify_password(stored, "") is False


def test_same_password_gets_different_salts():
    assert password_security.hash_password("Same#Password1") != password_security.hash_password("Same#Password1")


def test_malformed_hash_is_handled_safely():
    assert password_security.verify_password("not-a-hash", "anything") is False
    assert password_security.verify_password(None, "anything") is False


def test_hash_rejects_empty_and_non_string_input():
    with pytest.raises(ValueError):
        password_security.hash_password("")
    with pytest.raises(TypeError):
        password_security.hash_password(12345)


def test_current_parameters_do_not_need_rehash(stored):
    assert password_security.needs_rehash(stored) is False


# ============================================================================ AES-256-GCM
@pytest.fixture()
def key():
    return encryption.generate_key()


AAD = b"customer:42"


def test_encrypt_decrypt_round_trip(key):
    blob = encryption.encrypt(key, b"secret payload", AAD)
    assert encryption.decrypt(key, blob, AAD) == b"secret payload"


def test_ciphertext_does_not_contain_plaintext(key):
    blob = encryption.encrypt(key, b"4111111111111111", AAD)
    assert b"4111111111111111" not in blob


def test_fresh_nonce_for_every_encryption(key):
    nonces = {encryption.encrypt(key, b"same data", AAD)[:NONCE_SIZE] for _ in range(200)}
    assert len(nonces) == 200                 # no nonce reuse across 200 encryptions


def test_nonce_is_twelve_bytes(key):
    assert len(encryption.encrypt(key, b"x")) == NONCE_SIZE + 1 + TAG_SIZE


def test_wrong_key_fails(key):
    blob = encryption.encrypt(key, b"secret", AAD)
    with pytest.raises(DecryptionError):
        encryption.decrypt(encryption.generate_key(), blob, AAD)


def test_modified_ciphertext_fails_authentication(key):
    blob = bytearray(encryption.encrypt(key, b"secret payload", AAD))
    blob[NONCE_SIZE] ^= 0x01                  # flip one bit of the ciphertext
    with pytest.raises(DecryptionError):
        encryption.decrypt(key, bytes(blob), AAD)


def test_modified_nonce_fails_authentication(key):
    blob = bytearray(encryption.encrypt(key, b"secret payload", AAD))
    blob[0] ^= 0x01                           # flip one bit of the nonce
    with pytest.raises(DecryptionError):
        encryption.decrypt(key, bytes(blob), AAD)


def test_modified_tag_fails_authentication(key):
    blob = bytearray(encryption.encrypt(key, b"secret payload", AAD))
    blob[-1] ^= 0x01                          # flip one bit of the authentication tag
    with pytest.raises(DecryptionError):
        encryption.decrypt(key, bytes(blob), AAD)


def test_wrong_associated_data_fails(key):
    blob = encryption.encrypt(key, b"secret payload", AAD)
    with pytest.raises(DecryptionError):
        encryption.decrypt(key, blob, b"customer:43")   # ciphertext moved to another record


def test_truncated_blob_fails_safely(key):
    with pytest.raises(DecryptionError):
        encryption.decrypt(key, b"short", AAD)


def test_invalid_key_length_is_rejected_without_leaking_key(key):
    with pytest.raises(ValueError) as info:
        encryption.encrypt(b"too-short", b"data")
    assert "too-short" not in str(info.value)


def test_non_bytes_key_is_rejected(key):
    with pytest.raises(TypeError):
        encryption.encrypt("a-string-key-not-bytes-0000000000000000", b"data")


def test_empty_plaintext_round_trip(key):
    assert encryption.decrypt(key, encryption.encrypt(key, b""), None) == b""


def test_text_helpers_round_trip(key):
    token = encryption.encrypt_text(key, "Sensitive note", "customer:7")
    assert base64.b64decode(token, validate=True)
    assert encryption.decrypt_text(key, token, "customer:7") == "Sensitive note"


def test_text_helper_rejects_invalid_base64(key):
    with pytest.raises(DecryptionError):
        encryption.decrypt_text(key, "%%% not base64 %%%", "customer:7")


# ============================================================================ HMAC-SHA256
@pytest.fixture()
def mac_key():
    return encryption.generate_key()


MESSAGE = b"transfer from=1001 to=2002 amount=500.00"


def test_hmac_tag_is_64_hex_characters(mac_key):
    tag = hmac_security.generate(mac_key, MESSAGE)
    assert len(tag) == 64 and all(c in "0123456789abcdef" for c in tag)


def test_valid_hmac_verifies(mac_key):
    tag = hmac_security.generate(mac_key, MESSAGE)
    assert hmac_security.verify(mac_key, MESSAGE, tag) is True


def test_modified_message_fails_hmac_verification(mac_key):
    tag = hmac_security.generate(mac_key, MESSAGE)
    tampered = MESSAGE.replace(b"500.00", b"5000.00")
    assert hmac_security.verify(mac_key, tampered, tag) is False


def test_wrong_key_fails_hmac_verification(mac_key):
    tag = hmac_security.generate(mac_key, MESSAGE)
    assert hmac_security.verify(encryption.generate_key(), MESSAGE, tag) is False


def test_modified_tag_fails_hmac_verification(mac_key):
    tag = hmac_security.generate(mac_key, MESSAGE)
    bad_tag = ("0" if tag[0] != "0" else "1") + tag[1:]
    assert hmac_security.verify(mac_key, MESSAGE, bad_tag) is False


def test_hmac_verify_handles_wrong_types_safely(mac_key):
    assert hmac_security.verify(mac_key, MESSAGE, None) is False
    assert hmac_security.verify(mac_key, "text-not-bytes", "00") is False


def test_hmac_uses_constant_time_comparison():
    """The verify function must compare with hmac.compare_digest (source-level check)."""
    import inspect
    assert "compare_digest" in inspect.getsource(hmac_security.verify)


def test_hmac_rejects_short_key():
    with pytest.raises(ValueError):
        hmac_security.generate(b"short", MESSAGE)


def test_replay_guard_accepts_once_then_rejects_replay(mac_key):
    guard = ReplayGuard(mac_key)
    message = guard.sign({"amount": "10.00"})
    assert guard.accept(message) == "ACCEPTED"
    assert guard.accept(message).startswith("REJECTED: replay")


def test_replay_guard_rejects_stale_message(mac_key):
    guard = ReplayGuard(mac_key, window_seconds=60)
    message = guard.sign({"amount": "10.00"}, timestamp=int(time.time()) - 3600)
    assert guard.accept(message).startswith("REJECTED: timestamp")


def test_replay_guard_rejects_tampered_payload(mac_key):
    guard = ReplayGuard(mac_key)
    message = guard.sign({"amount": "10.00"})
    message["body"]["payload"]["amount"] = "9999.00"
    assert guard.accept(message).startswith("REJECTED: MAC")


def test_replay_guard_rejects_malformed_message(mac_key):
    assert ReplayGuard(mac_key).accept({"nonsense": True}).startswith("REJECTED: malformed")


# ============================================================================ key management
@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.delenv("TEST_KEY_B64", raising=False)
    return KeyStore(tmp_path / "keys")


def test_key_is_created_with_32_bytes(store):
    assert len(store.get_key("test", 32)) == 32


def test_same_key_is_returned_on_later_calls(store):
    assert store.get_key("test", 32) == store.get_key("test", 32)


@pytest.mark.skipif(not IS_POSIX, reason="POSIX permission bits are not used on Windows")
def test_key_file_is_owner_only(store):
    store.get_key("test", 32)
    mode = stat.S_IMODE((store.directory / "test.key").stat().st_mode)
    assert mode == 0o600


@pytest.mark.skipif(not IS_POSIX, reason="POSIX permission bits are not used on Windows")
def test_world_readable_key_file_is_refused(store):
    store.get_key("test", 32)
    (store.directory / "test.key").chmod(0o644)
    with pytest.raises(KeyManagementError):
        store.get_key("test", 32)


def test_key_from_environment_variable(store, monkeypatch):
    value = base64.b64encode(b"k" * 32).decode()
    monkeypatch.setenv("TEST_KEY_B64", value)
    assert store.get_key("test", 32) == b"k" * 32


def test_invalid_environment_key_is_rejected_safely(store, monkeypatch):
    monkeypatch.setenv("TEST_KEY_B64", "not-base64-!!")
    with pytest.raises(KeyManagementError):
        store.get_key("test", 32)
    monkeypatch.setenv("TEST_KEY_B64", base64.b64encode(b"short").decode())
    with pytest.raises(KeyManagementError) as info:
        store.get_key("test", 32)
    assert "short" not in str(info.value)


def test_key_name_is_validated_against_path_traversal(store):
    with pytest.raises(ValueError):
        store.get_key("../escape", 32)


def test_rotation_archives_old_key_and_creates_new(store):
    original = store.get_key("rotating", 32)
    new = store.rotate("rotating", 32)
    assert new != original
    archives = list(store.directory.glob("rotating.*.old"))
    assert len(archives) == 1
    assert archives[0].read_bytes() == original


def test_describe_never_returns_key_material(store):
    key = store.get_key("described", 32)
    info = store.describe("described")
    assert info["size_bits"] == 256
    assert all(not isinstance(v, (bytes, bytearray)) for v in info.values())
    assert key.hex() not in repr(info) and base64.b64encode(key).decode() not in repr(info)


# ============================================================================ HTTPS
@pytest.fixture(scope="module")
def tls_material(tmp_path_factory):
    cert_dir = tmp_path_factory.mktemp("certs")
    return https_server.ensure_self_signed_certificate(cert_dir)


@pytest.fixture(scope="module")
def running_server(tls_material):
    cert, key = tls_material
    server, _thread = https_server.start_server(cert, key, port=0)
    yield server
    server.shutdown()


def test_server_context_refuses_old_tls_versions(tls_material):
    cert, key = tls_material
    context = https_server.build_server_context(cert, key)
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2


def test_client_with_trusted_certificate_gets_200(running_server, tls_material):
    cert, _ = tls_material
    status, body, tls = https_server.verified_get(running_server.server_port, cert, "/")
    assert status == 200
    assert "HTTPS connection established" in body
    assert tls["protocol"] in {"TLSv1.2", "TLSv1.3"}
    assert tls["certificate_verified"] is True
    assert "max-age" in tls["hsts"]


def test_client_without_trusted_certificate_is_rejected(running_server):
    import http.client
    connection = http.client.HTTPSConnection("localhost", running_server.server_port,
                                             context=ssl.create_default_context(), timeout=10)
    with pytest.raises(ssl.SSLCertVerificationError):
        connection.connect()


def test_tls_1_1_is_refused(running_server, tls_material):
    cert, _ = tls_material
    context = ssl.create_default_context(cafile=str(cert))
    try:
        context.maximum_version = ssl.TLSVersion.TLSv1_1
        context.minimum_version = ssl.TLSVersion.TLSv1_1
    except ValueError:
        pytest.skip("this OpenSSL build cannot offer TLS 1.1 at all, so it is refused by default")
    import socket
    with pytest.raises((ssl.SSLError, OSError)):
        with socket.create_connection(("localhost", running_server.server_port), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname="localhost"):
                pass
