# Screenshots

Every image in this folder was produced from a real run during the build. Nothing was drawn or edited by hand. The tools that produced them are in `../tools/`.

## How each kind of image was made

| Kind | Method | Where |
|---|---|---|
| **Browser screenshots of the web application** | Chromium (Playwright) opened `http://127.0.0.1:5000` while `app.py` was running and logged in with the demo accounts | `RBAC/` (`tools/capture_rbac.py`) |
| **Browser screenshot of the HTTPS server** | Chromium opened `https://127.0.0.1:8443` while `https_server.py` was running; certificate errors were ignored because the certificate is self-signed | `Cryptography/18b_...` (`tools/capture_crypto.py`) |
| **Terminal images** (cryptography steps and test results) | The text is the captured output of `python main.py` and `pytest -v`. It was drawn with a styled HTML page and saved as PNG, so it looks like a terminal but is not an operating-system screenshot | `Cryptography/09`–`18`, `Testing/` |

The full captured text of the cryptography run is in `Cryptography/full_run_output.txt`, and the full pytest logs are in `../Documentation/raw_test_logs/`.

## RBAC/ (browser screenshots, Section B)

| File | Shows | Requirement | Server response |
|---|---|---|---|
| `01_login_page.png` | Login page with development demo accounts | 1 | 200 |
| `02_customer_dashboard.png` | Customer dashboard with own transactions | 2 | 200 |
| `03_customer_profile.png` | Customer's own profile | 3 | 200 |
| `04_customer_other_customer_record_denied.png` | Customer requesting another customer's record | 4 | 404 |
| `05_customer_admin_page_denied.png` | Customer requesting the administrator dashboard | 5 | 403 |
| `06_manager_dashboard.png` | Manager dashboard | 6 | 200 |
| `07_admin_dashboard.png` | Administrator dashboard | 7 | 200 |
| `08_admin_user_and_role_management.png` | User list with role assignment and activate/deactivate | 8 | 200 |
| `09_admin_roles_and_permissions.png` | Permission matrix for each role | 8 | 200 |
| `10_admin_audit_log.png` | Audit log of logins, denials and changes | 8 | 200 |
| `11_unauthenticated_request_401.png` | Request without login | (401 requirement) | 401 |
| `12_manager_transactions.png` | Manager transaction review | (manager requirement) | 200 |
| `13_manager_admin_page_denied.png` | Manager requesting the user administration page | (403 requirement) | 403 |
| `capture_log.txt` | Each request, the status the server returned, and the note | | |

## Cryptography/ (Section D)

| File | Shows | Requirement |
|---|---|---|
| `09_key_management_metadata.png` | Key sizes, file permissions and location (values are not printed) | 7 |
| `10_argon2_hash_generation.png` | Argon2id hash of a password | 10 |
| `11_password_verification_correct.png` | Correct password verified | 11 |
| `12_password_verification_incorrect.png` | Incorrect and malformed inputs rejected | 12 |
| `13_aes_gcm_encryption.png` | AES-256-GCM encryption with a fresh nonce | 13 |
| `14_aes_gcm_decryption.png` | Decryption with the correct key; wrong key, wrong associated data and invalid key rejected | 14 |
| `15_hmac_generation.png` | HMAC-SHA256 tag generated | 15 |
| `16_hmac_verification.png` | Valid HMAC accepted; wrong key rejected | 16 |
| `17_tampered_message_rejection.png` | Modified amount rejected; replay, stale and edited messages rejected | 17 |
| `18_https_server_running_terminal.png` | Terminal output of the HTTPS check: TLS version, cipher, verified certificate | 18 |
| `18b_https_server_running_browser.png` | Browser showing the HTTPS server responding | 18 |
| `full_run_output.txt` | Complete captured output of `main.py` | |

## Testing/ (automated test results)

| File | Shows | Requirement |
|---|---|---|
| `01_rbac_pytest_results.png` | All 61 RBAC tests, each with PASSED | 9 and 19 |
| `02_crypto_pytest_results.png` | All 48 cryptography tests, each with PASSED | 9 and 19 |

## Regenerating the images on Windows

Start the RBAC application in one PowerShell window (`python app.py` in `Section_B_RBAC`). In a second window:

```powershell
python -m pip install -r tools\requirements-tools.txt
python -m playwright install chromium
python tools\capture_rbac.py
python tools\capture_crypto.py
python tools\capture_tests.py
```

Stop the application (Ctrl+C) before running `capture_crypto.py`, because that script starts the HTTPS server on port 8443 and does not need the web application.

### Native Windows terminal screenshots (optional)

If your lecturer wants real PowerShell screenshots, take them yourself:

1. Run the command in PowerShell from the project folder, for example `python main.py` in `Section_D_Cryptography`.
2. Press **Win + Shift + S**, select the window or the output area, and save the image as PNG.
3. Save it in `Screenshots\Cryptography\` with the same file name as the rendered image, and the rendered version will be replaced.

Repeat with `python -m pytest -v` for the test results.

## Items not captured in this environment

None of the 19 required screenshots is missing. Two points should be stated plainly:

- The terminal images (`09`–`18` and `Testing/`) are renders of captured text, as explained at the top of this file. They are not operating-system screenshots, and the steps above describe how to replace them.
- The browser screenshots were taken with Chromium on Linux. The layout is the same on Windows, but the fonts differ slightly.
