# Implementation Explanation

This document maps every requirement of the assignment to the code that implements it. Each claim names a file and, where relevant, a test.

## 1. Project layout

```
Secure_Coding_Assignment_1/
├── Section_B_RBAC/            Flask web application (Section B)
│   ├── app.py                 routes, deny-by-default gate, security headers, error pages
│   ├── models.py              SQLAlchemy models: User, Role, Permission, Transaction, UserSession, AuditLog
│   ├── auth.py                login sessions, idle/absolute expiry, permission decorator, ownership check
│   ├── permissions.py         permission catalogue, role definitions, protected admin permissions
│   ├── validation.py          allow-list input validation
│   ├── seed.py                roles, permissions and DEVELOPMENT demo accounts
│   ├── init_db.py             database initialisation / reset
│   ├── config.py              configuration from environment variables
│   ├── extensions.py          SQLAlchemy and CSRF objects
│   ├── templates/             Jinja2 pages (autoescaped)
│   ├── static/css/style.css   interface styling (no external resources)
│   ├── tests/                 pytest suite (61 tests)
│   └── requirements.txt
├── Section_D_Cryptography/    Python cryptography project (Section D)
│   ├── main.py                runs every required demonstration in order
│   ├── password_security.py   Argon2id hashing and verification
│   ├── encryption.py          AES-256-GCM encryption and decryption
│   ├── hmac_security.py       HMAC-SHA256 generation/verification and replay guard
│   ├── key_management.py      key generation, storage, permissions and rotation
│   ├── https_server.py        self-signed certificate, TLS server, verified client
│   ├── tests/test_crypto.py   pytest suite (48 tests)
│   └── requirements.txt
├── Documentation/             theory answers, this file, test results
├── Screenshots/               RBAC/, Cryptography/, Testing/ (see Screenshots/README.md)
├── tools/                     scripts that create the screenshots from real runs
├── README.md                  setup and run instructions (Windows PowerShell)
├── requirements.txt           all runtime and test dependencies
├── .env.example               template of configuration variables (no real secrets)
└── .gitignore                 excludes virtual environments, caches, keys, certificates, databases
```

## 2. Section B: Flask RBAC application

### 2.1 Technology

| Requirement | Implementation |
|---|---|
| Flask | `app.py` (Flask 3.1.3) |
| Flask-SQLAlchemy and SQLite | `models.py`, `extensions.py`; database file `Section_B_RBAC/instance/bank.db` (created by `init_db.py`) |
| Secure sessions | Server-side `UserSession` table; the cookie holds only a random id (`auth.py`) |
| Werkzeug password hashing | `User.set_password` uses `generate_password_hash` (scrypt with random salt) |
| Role-based decorators | `@permission_required(...)` in `auth.py` |
| CSRF protection | Flask-WTF `CSRFProtect` on every POST; each form includes `csrf_token()` |
| Parameterised queries | All database access uses the SQLAlchemy ORM (`db.select(...)`, bound parameters) |

### 2.2 Roles and permissions

| Role | Permissions (from `permissions.py`) |
|---|---|
| Customer | `profile:view_own`, `profile:update_own`, `transactions:view_own` |
| Manager | `customers:view`, `transactions:view`, `transactions:manage` |
| Administrator | `users:manage`, `roles:assign`, `permissions:manage` |

Managers cannot manage users, roles or permissions. Administrators cannot review transactions (separation of duties). Changes to a role's permissions are stored in the database and take effect on the next request.

### 2.3 Route table

| Route | Method | Permission | Notes |
|---|---|---|---|
| `/`, `/health`, `/login` | GET/POST | public | login is CSRF-protected and returns 401 on failure |
| `/logout` | POST | authenticated | revokes the server-side session |
| `/dashboard` | GET | authenticated | redirects to the role's dashboard |
| `/customer/dashboard` | GET | `profile:view_own` | customers only |
| `/profile` | GET | `profile:view_own` | own record only |
| `/profile/edit` | GET/POST | `profile:update_own` | only name, email and phone are read from the form |
| `/customers/<id>` | GET | ownership or `customers:view` | 404 for another customer's record |
| `/manager/dashboard` | GET | `customers:view` | |
| `/manager/customers` | GET | `customers:view` | |
| `/manager/transactions` | GET | `transactions:view` | |
| `/manager/transactions` | POST | `transactions:manage` | create a pending transaction |
| `/manager/transactions/<id>/status` | POST | `transactions:manage` | approve or reject a pending transaction |
| `/admin/dashboard` | GET | `users:manage` | |
| `/admin/users` | GET | `users:manage` | user and role management page |
| `/admin/users/new` | GET/POST | `users:manage` and `roles:assign` | create a user |
| `/admin/users/<id>/role` | POST | `roles:assign` | change a role; own role cannot be changed |
| `/admin/users/<id>/status` | POST | `users:manage` | activate or deactivate; own account cannot be deactivated; sessions revoked |
| `/admin/roles` | GET | `permissions:manage` | permission matrix |
| `/admin/roles/<id>` | POST | `permissions:manage` | core administrator permissions cannot be removed |
| `/admin/audit` | GET | `users:manage` | audit log |

### 2.4 Security requirements

| Requirement | How it is met | Evidence (test) |
|---|---|---|
| Deny access by default | `deny_by_default()` runs before every request; endpoints not in `PUBLIC_ENDPOINTS` need a valid session, otherwise 401 (including unknown URLs) | `test_unauthenticated_requests_get_401` |
| Server-side authorization on every protected route | `@permission_required` on each route; role read from the database each request | `test_customer_cannot_access_admin_pages_403` and others |
| Verify resource ownership | `load_customer_for_actor()` (`auth.py`) | `test_customer_cannot_view_another_customer_404` |
| Prevent IDOR | Profile edit has no ID parameter; ID routes use the ownership helper; 404 for non-owned records, identical to a missing record | `test_customer_404_is_identical_for_existing_and_missing_records` |
| Prevent privilege escalation | Role and status fields are ignored in profile updates; role changes need `roles:assign`; unknown roles rejected | `test_customer_updates_only_own_profile_fields`, `test_unauthorized_role_modification_rejected_for_customer` |
| No authorization from client-side JavaScript or HTML | Hidden links are cosmetic; the server ignores `X-Role` headers and forged cookies | `test_forged_role_header_is_ignored`, `test_forged_session_cookie_is_rejected` |
| Secure login and logout | Generic failure message, same work for unknown users, session rotated on login, server-side revocation on logout | `test_failed_login_returns_401_with_generic_message`, `test_logout_revokes_server_session_even_if_cookie_is_replayed` |
| Session expiration | Idle timeout (15 min, sliding) and absolute timeout (8 h), enforced in the database | `test_idle_session_expires_returns_401`, `test_absolute_session_lifetime_expires_returns_401` |
| Secure cookie configuration | `HttpOnly`, `SameSite=Strict`, `Secure` when `SESSION_COOKIE_SECURE=1` | `test_session_cookie_has_secure_attributes` |
| CSRF protection | Flask-WTF tokens on every POST form | `test_login_form_requires_csrf_token`, `test_state_changing_form_requires_csrf_token` |
| Validate and sanitise input | Allow-lists and length limits in `validation.py`; Jinja2 autoescaping | `test_profile_input_validation_rejects_script_injection`, `test_amount_validation_rejects_negative_amount` |
| 401 unauthenticated, 403 insufficient permission | `abort(401)` and `abort(403)`; error pages render with the matching code | `test_unauthenticated_requests_get_401`, `test_customer_cannot_access_admin_pages_403` |
| 404 or 403 for unauthorized resource access | customers receive 404 for other customers' records; 403 for missing permission | `test_customer_cannot_view_another_customer_404` |
| Security headers | CSP, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, `Cache-Control: no-store` on authenticated pages | `test_security_headers_present`, `test_authenticated_pages_are_not_cached` |

### 2.5 Interface

Each role has its own dashboard: customer (account summary and own transactions), manager (customer counts, pending transactions, transaction review), administrator (users, active accounts, roles, recent audit events). Screenshots are in `Screenshots/RBAC/`.

### 2.6 Demo accounts (development only)

Seeded by `seed.py` when the database is first created. Listed in the README and on the login page when `SHOW_DEMO_CREDENTIALS=1`.

## 3. Section D: cryptography project

| Task | Module and function | Libraries | Test |
|---|---|---|---|
| 1. Argon2id password hashing | `password_security.hash_password` | argon2-cffi, `PasswordHasher(time_cost=3, memory_cost=64 MiB, parallelism=4)` | `test_hash_is_argon2id_and_not_plaintext`, `test_same_password_gets_different_salts` |
| 2. Password verification | `password_security.verify_password` | argon2-cffi | `test_correct_password_succeeds`, `test_incorrect_password_fails` |
| 3. AES-256-GCM encryption | `encryption.encrypt` | cryptography `AESGCM`, fresh 12-byte nonce per call | `test_fresh_nonce_for_every_encryption` (200 encryptions, no nonce repeated) |
| 4. AES-256-GCM decryption | `encryption.decrypt` | cryptography `AESGCM` | `test_encrypt_decrypt_round_trip`, `test_wrong_key_fails` |
| 5. HMAC-SHA256 generation | `hmac_security.generate` | Python `hmac`, `hashlib` | `test_hmac_tag_is_64_hex_characters`, `test_valid_hmac_verifies` |
| 6. HMAC verification and tamper detection | `hmac_security.verify` (uses `hmac.compare_digest`) | Python `hmac` | `test_modified_message_fails_hmac_verification`, `test_modified_tag_fails_hmac_verification` |
| 7. Key generation, storage and management | `key_management.KeyStore` | `secrets`, `os` | `test_key_file_is_owner_only`, `test_world_readable_key_file_is_refused`, `test_key_from_environment_variable`, `test_rotation_archives_old_key_and_creates_new` |
| 8. HTTPS configuration and client verification | `https_server.py` | `ssl`, `cryptography` (certificate), Flask | `test_client_with_trusted_certificate_gets_200`, `test_client_without_trusted_certificate_is_rejected`, `test_tls_1_1_is_refused` |

Security constraints from the assignment:

- **Fresh 12-byte nonce for every AES-GCM encryption:** `os.urandom(12)` inside `encrypt`; tested by `test_fresh_nonce_for_every_encryption`.
- **Never reuse a nonce with the same key:** a nonce is never passed in from the caller, so reuse is not possible through this API.
- **Authenticate ciphertext and detect modification:** GCM tag verification; tests for modified ciphertext, nonce and tag.
- **Constant-time HMAC verification:** `hmac.compare_digest`; a test checks the source uses it.
- **No hard-coded production secrets:** keys come from `secure_keys/` (outside the source files, excluded from the ZIP) or from `<NAME>_KEY_B64` environment variables. The Flask `SECRET_KEY` is read from the environment.
- **Self-signed certificate limitations:** explained in the `https_server.py` docstring and in `Section_C_Answers.md` question 3.
- **No custom cryptography:** every primitive comes from `argon2-cffi`, `cryptography` or the Python standard library.

## 4. Automated testing

- `Section_B_RBAC/tests/test_rbac.py`: 61 tests covering every RBAC case the assignment requires (see `Test_Results.md`).
- `Section_D_Cryptography/tests/test_crypto.py`: 48 tests covering every cryptographic case the assignment requires.

Raw output: `Documentation/raw_test_logs/`. Rendered images: `Screenshots/Testing/`.

## 5. Design decisions and trade-offs

- **404 rather than 403 for another customer's record.** The assignment allows either. 404 avoids confirming that an account number exists.
- **Server-side session table rather than signed cookie sessions.** It allows immediate revocation on logout, deactivation and role changes, and it enforces the absolute lifetime.
- **Permissions read from the database on each request.** A change to a role takes effect immediately; there is no cached permission set to become stale.
- **Argon2id in the cryptography project and Werkzeug scrypt in the web application.** Both are salted and memory-hard. The assignment requires Argon2 for Section D; the web application uses Werkzeug's built-in hashing as the assignment permits.
- **Self-signed certificate with a 365-day validity.** Acceptable for a local demonstration only (see limitations).

## 6. Known limitations

- Customers cannot initiate transfers; transactions are created and reviewed by managers. A customer transfer flow would apply the ownership rule described in `Section_A_Answers.md` question 8.
- No login rate limiting or account lockout (recommended in `Section_C_Answers.md` question 2).
- Demo passwords are published in the README by design; they are for development only.
- The development web server (`app.run`) is used. A production deployment would use gunicorn or waitress behind a TLS-terminating reverse proxy.
- The Windows PowerShell commands in the README were written for Windows but were executed in a Linux environment during the build (see `Test_Results.md`).
- Key files use POSIX permission bits. On Windows, an ACL must be applied (command in README).
- The TLS 1.1 test uses a deprecated `ssl.TLSVersion` constant, which produces two warnings in the crypto test run.
