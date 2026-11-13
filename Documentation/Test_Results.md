# Test Results and Completion Matrix

## 1. Automated test results

| Suite | Command (run in the folder) | Result | Raw log |
|---|---|---|---|
| Section B: RBAC | `python -m pytest -v` in `Section_B_RBAC` | **61 passed**, 0 failed | `raw_test_logs/Section_B_RBAC_pytest.txt` |
| Section D: cryptography | `python -m pytest -v` in `Section_D_Cryptography` | **48 passed**, 0 failed, 2 warnings | `raw_test_logs/Section_D_Cryptography_pytest.txt` |
| Section D: demonstration | `python main.py` | ends with `ALL DEMONSTRATIONS COMPLETED`, exit code 0 | `Screenshots/Cryptography/full_run_output.txt` |

The two warnings come from using `ssl.TLSVersion.TLSv1_1` in the test that confirms TLS 1.1 is refused. The warning is expected and does not affect the result.

## 2. Live application checks (browser and HTTP)

Status codes returned by the running RBAC application, recorded in `Screenshots/RBAC/capture_log.txt`:

| Request | Expected | Actual |
|---|---|---|
| Unauthenticated `GET /customer/dashboard` | 401 | 401 |
| Customer `GET /customer/dashboard` | 200 | 200 |
| Customer `GET /profile` (own) | 200 | 200 |
| Customer `GET /customers/2` (another customer) | 404 | 404 |
| Customer `GET /admin/dashboard` | 403 | 403 |
| Manager `GET /manager/dashboard` | 200 | 200 |
| Manager `GET /manager/transactions` | 200 | 200 |
| Manager `GET /admin/users` | 403 | 403 |
| Administrator `GET /admin/dashboard` | 200 | 200 |
| Administrator `GET /admin/users` | 200 | 200 |
| Administrator `GET /admin/roles` | 200 | 200 |
| Administrator `GET /admin/audit` | 200 | 200 |
| HTTPS `GET https://127.0.0.1:8443/` (browser) | 200 | 200 |
| HTTPS client verifying the certificate (`main.py`) | 200, TLS 1.2 or higher | 200, TLSv1.3 |
| HTTPS client without the certificate in its trust store | rejected | rejected (certificate verify failed) |

## 3. Requirement test mapping

### Section B: RBAC (assignment "Automated Security Testing")

| Required test | Test function(s) | Result |
|---|---|---|
| Unauthenticated request → 401 | `test_unauthenticated_requests_get_401` (14 URLs), `test_unauthenticated_state_change_gets_401` | Pass |
| Customer accesses own profile → 200 | `test_customer_views_own_profile_200` | Pass |
| Customer accesses another customer's profile → 403 or 404 | `test_customer_cannot_view_another_customer_404`, `test_customer_404_is_identical_for_existing_and_missing_records` | Pass (404) |
| Customer accesses admin page → 403 | `test_customer_cannot_access_admin_pages_403` | Pass |
| Manager accesses customer records → 200 | `test_manager_views_customer_records_200` | Pass |
| Manager attempts administrative operations → 403 | `test_manager_cannot_manage_users_403`, `test_manager_cannot_change_permissions_403` | Pass |
| Administrator manages users → 200 | `test_admin_manages_users_200`, `test_admin_creates_user`, `test_admin_assigns_role` | Pass |
| Expired or invalid session → 401 | `test_invalid_session_id_returns_401`, `test_idle_session_expires_returns_401`, `test_absolute_session_lifetime_expires_returns_401`, `test_forged_session_cookie_is_rejected` | Pass |
| Unauthorized role modification rejected | `test_unauthorized_role_modification_rejected_for_customer`, `test_unauthorized_role_modification_rejected_for_manager` | Pass |

Additional RBAC tests (61 in total): logout and replayed cookies, CSRF enforcement, security headers, cookie flags, input validation (script injection, weak password, negative and NaN amounts), protected admin permissions, self-demotion and self-deactivation, session revocation on deactivation, least privilege for administrators, forged role headers, and immediate effect of permission changes.

### Section D: Cryptography (assignment "Automated Security Testing")

| Required test | Test function(s) | Result |
|---|---|---|
| Correct password succeeds | `test_correct_password_succeeds` | Pass |
| Incorrect password fails | `test_incorrect_password_fails`, `test_empty_password_fails` | Pass |
| AES-GCM encryption and decryption succeeds | `test_encrypt_decrypt_round_trip`, `test_empty_plaintext_round_trip` | Pass |
| Wrong AES key fails | `test_wrong_key_fails` | Pass |
| Modified ciphertext fails authentication | `test_modified_ciphertext_fails_authentication` | Pass |
| Modified nonce fails authentication | `test_modified_nonce_fails_authentication` | Pass |
| Modified tag fails authentication | `test_modified_tag_fails_authentication` | Pass |
| Valid HMAC succeeds | `test_valid_hmac_verifies` | Pass |
| Modified message fails HMAC verification | `test_modified_message_fails_hmac_verification` | Pass |
| Invalid key handling works safely | `test_invalid_key_length_is_rejected_without_leaking_key`, `test_non_bytes_key_is_rejected`, `test_hmac_rejects_short_key`, `test_invalid_environment_key_is_rejected_safely` | Pass |

Additional cryptography tests (48 in total): fresh nonce for 200 encryptions, wrong associated data (record swap), malformed and truncated blobs, constant-time HMAC source check, replay guard (accepted, replayed, stale, tampered, malformed), key file permissions (POSIX), refusal of a world-readable key file, key rotation, key name validation, metadata that never reveals key material, HTTPS minimum TLS version, trusted client, untrusted client, and TLS 1.1 refused.

## 4. Completion matrix

Legend: **Yes** = done and verified in this build. **Partly** = done with a stated limitation. **No** = not done.

### 4.1 Theory answers

| Requirement | Implemented | Tested | Screenshot | Notes |
|---|---|---|---|---|
| Section A: 9 answers (banking scenario) | Yes | n/a (document) | n/a | `Documentation/Section_A_Answers.md`; each answer cites the code and test |
| Section C: 10 answers | Yes | n/a (document) | n/a | `Documentation/Section_C_Answers.md`; known-answer tests are recommended, not included |

### 4.2 Section B: practical RBAC requirements

| Requirement | Implemented | Tested | Screenshot | Notes |
|---|---|---|---|---|
| 1. Deny access to unauthenticated or unauthorized users | Yes | Yes | `11`, `13` | 401 and 403 |
| 2. Server-side authorization checks | Yes | Yes | `05`, `13` | every protected route |
| 3. Role-based permissions | Yes | Yes | `08`, `09` | permissions editable by admin |
| 4. Customers cannot access other customers' records | Yes | Yes | `04` | 404 |
| 5. Administrative pages restricted to administrators | Yes | Yes | `05`, `13` | |
| 6. Ownership verified before update or delete | Yes | Yes | `03` | profile edit uses session user only; no delete of customer records is offered |
| 7. Privilege escalation prevented | Yes | Yes | n/a | role and status ignored in profile form; roles need `roles:assign` |
| 8. Logout and session expiration | Yes | Yes | n/a | idle 15 min, absolute 8 h |
| Flask-SQLAlchemy, SQLite, Werkzeug hashing, decorators | Yes | Yes | n/a | |
| CSRF protection on browser forms | Yes | Yes | n/a | Flask-WTF |
| Secure cookie configuration | Yes | Yes | n/a | `Secure` flag depends on `SESSION_COOKIE_SECURE` (off for local HTTP) |
| Input validation and sanitisation | Yes | Yes | n/a | allow-lists, length limits, autoescaping |
| Web interface with separate dashboards | Yes | Yes | `02`, `06`, `07` | |
| Seeded demo accounts documented in README | Yes | Yes | `01` | development only |

### 4.3 Section D: practical cryptography requirements

| Requirement | Implemented | Tested | Screenshot | Notes |
|---|---|---|---|---|
| 1. Password hashing with Argon2id | Yes | Yes | `10` | argon2-cffi |
| 2. Correct and incorrect password verification | Yes | Yes | `11`, `12` | |
| 3. AES-256-GCM encryption | Yes | Yes | `13` | fresh 12-byte nonce |
| 4. AES-GCM decryption | Yes | Yes | `14` | |
| 5. HMAC-SHA256 generation | Yes | Yes | `15` | |
| 6. HMAC verification and tamper detection | Yes | Yes | `16`, `17` | constant-time comparison |
| 7. Secure key generation, storage and management | Yes | Yes | `09` | Windows needs an ACL (see README) |
| 8. HTTPS configuration and client verification | Yes | Yes | `18`, `18b` | self-signed; limitations explained |
| Security constraints (fresh nonce, no reuse, authentication, constant-time HMAC, no hard-coded secrets, self-signed explanation, no custom crypto) | Yes | Yes | n/a | see `Implementation_Explanation.md` §3 |

### 4.4 Deliverable and verification items

| Item | Status | Notes |
|---|---|---|
| Source code for both projects | Yes | |
| requirements files | Yes | root, Section B, Section D, tools |
| Documentation (`Section_A_Answers.md`, `Section_C_Answers.md`, `Implementation_Explanation.md`, `Test_Results.md`) | Yes | |
| Genuine screenshots in `RBAC/`, `Cryptography/`, `Testing/` | Yes | browser screenshots are real; terminal images are renders of captured output (see `Screenshots/README.md`) |
| README with Windows PowerShell commands | Yes | **commands not yet executed on Windows** (see section 5) |
| `.env.example` | Yes | |
| `.gitignore` | Yes | |
| ZIP without venv, caches, temporary files, real secrets or keys | Yes | verified in §6 |
| All automated tests run and passing | Yes | 61 + 48 passed |

## 5. Not verified, and why

- **Windows PowerShell commands.** Every command in the README was written for PowerShell and follows its syntax, but the build ran on Linux. The first run on Windows may reveal path or activation differences. The likely problem is the execution-policy line, which the README covers.
- **Native Windows terminal screenshots.** Not captured. The terminal images are renders of captured output. Instructions for replacing them are in `Screenshots/README.md`.
- **Other browsers.** Only Chromium was used.
- **Customer-initiated transfers.** Not implemented. The assignment does not require them; managers create and review transactions instead.
- **Login rate limiting.** Not implemented; recommended in `Section_C_Answers.md`.

## 6. Packaging checks

Checked on the final ZIP (`Secure_Coding_Assignment_1.zip`, 97 files):

- The ZIP passes an integrity test (`testzip` reports no errors).
- It contains no `.venv`, `__pycache__`, `.pytest_cache`, `instance/`, `secure_keys/`, `certs/`, `*.key`, `*.pem`, `*.db`, `*.log`, `*.old` or `.env` entries.
- It was extracted into an empty folder and, from there: `pytest` in `Section_B_RBAC` gave 61 passed; `pytest` in `Section_D_Cryptography` gave 48 passed; `python main.py` exited with code 0 and printed `ALL DEMONSTRATIONS COMPLETED`; `python init_db.py` followed by `python app.py` served `/login` with 200 and returned 401 for `/profile` without a session.
