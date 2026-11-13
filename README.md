# Secure Coding Assignment 1: Authorization, Access Control and Cryptography

This package contains two working Python projects:

1. **Section_B_RBAC**: a SecureBank web application built with Flask, Flask-SQLAlchemy, SQLite, Flask-WTF (CSRF) and role-based access control for three roles: customer, manager and administrator.
2. **Section_D_Cryptography**: Argon2id password hashing, AES-256-GCM, HMAC-SHA256, key management and an HTTPS server with a verifying client.

Theory answers are in `Documentation/`. Screenshots are in `Screenshots/`. Test results are in `Documentation/Test_Results.md`.

Neither project needs paid APIs, cloud services or a separate database server. Everything runs locally.

**GitHub Repository**: [https://github.com/Sonali-CU/Secure-Coding-Assignment-1](https://github.com/Sonali-CU/Secure-Coding-Assignment-1)

---

## 1. Requirements

- Windows 10 or 11 with PowerShell 5.1 or later (PowerShell 7 also works).
- Python 3.11 or newer, from python.org or the Microsoft Store. Tick **"Add python.exe to PATH"** during installation.
- Internet access only for the one-time `pip install` step.
- A modern browser (Edge, Chrome or Firefox) to use the web application.

Fully verified and passing natively on Windows 11 with Python 3.13.7. See `Documentation/Test_Results.md` for full results.

---

## 2. Installation (PowerShell)

Open PowerShell and go to the project folder:

```powershell
cd C:\path\to\Secure_Coding_Assignment_1
```

Create and activate a virtual environment:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell reports that running scripts is disabled, allow scripts for this window only and try again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Install the dependencies:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Check the installation:

```powershell
python -c "import flask, argon2, cryptography; print('dependencies OK')"
```

---

## 3. Section B: Flask RBAC web application

### 3.1 Configure and initialise the database

```powershell
cd Section_B_RBAC

# Create a random secret for signing sessions and CSRF tokens (use it in this window)
$env:SECRET_KEY = python -c "import secrets; print(secrets.token_urlsafe(48))"

# Create the SQLite database and the demo accounts (safe to run again)
python init_db.py
```

The database file is `Section_B_RBAC\instance\bank.db`. To delete all data and start again: `python init_db.py --reset`.

### 3.2 Run the automated tests

```powershell
python -m pytest -v
```

Expected result: `61 passed`.

### 3.3 Start the web application

```powershell
python app.py
```

Open **http://127.0.0.1:5000** in your browser. Press **Ctrl+C** in PowerShell to stop the server.

### 3.4 Demo accounts (development only)

These passwords are published on purpose so the application can be marked. They must never be used anywhere else. Set `SHOW_DEMO_CREDENTIALS=0` for any shared deployment.

| Role | Username | Password | Home page |
|---|---|---|---|
| Customer | `customer` | `Customer#2026` | `/customer/dashboard` |
| Customer (second) | `customer2` | `Customer2#2026` | `/customer/dashboard` |
| Manager | `manager` | `Manager#2026` | `/manager/dashboard` |
| Administrator | `admin` | `Admin#2026` | `/admin/dashboard` |

### 3.5 What to try

- Log in as **customer**. Open *My profile* and *Edit profile*. Try to open `/admin/dashboard`: you get **403**. Open `/customers/2`: you get **404**.
- Log in as **manager**. Review a pending transaction. Create a new transaction. Try `/admin/users`: **403**.
- Log in as **admin**. Create a user, change a role, open *Roles & permissions* and the *Audit log*.
- Log out, then open `/customer/dashboard` in the same browser: you get **401**.

### 3.6 Session settings

`SESSION_IDLE_MINUTES` (default 15) and `SESSION_ABSOLUTE_HOURS` (default 8) are read from the environment. Set `SESSION_COOKIE_SECURE=1` only when the site is served over HTTPS.

---

## 4. Section D: Cryptography

```powershell
cd ..\Section_D_Cryptography
```

### 4.1 Run every demonstration

```powershell
python main.py
```

The output runs through key management, Argon2id hashing and verification, AES-256-GCM encryption and decryption, HMAC generation and verification, tamper and replay rejection, and the HTTPS check. It ends with `ALL DEMONSTRATIONS COMPLETED`.

### 4.2 Run the automated tests

```powershell
python -m pytest -v
```

Expected result: `48 passed` (two deprecation warnings about `ssl.TLSVersion.TLSv1_1` are expected).

### 4.3 Start HTTPS

```powershell
python https_server.py
```

Open **https://127.0.0.1:8443** in your browser. The browser will show a certificate warning because the certificate is self-signed. Choose *Advanced* and then *Proceed*. Press **Ctrl+C** to stop.

Command-line check (in a second PowerShell window; `curl.exe` is included with Windows 10 and later):

```powershell
curl.exe --cacert certs\cert.pem https://127.0.0.1:8443/
```

Expected output: `{"message":"HTTPS connection established","transport":"TLS"}`.

### 4.4 Key storage on Windows

Keys are stored in `Section_D_Cryptography\secure_keys\`. Windows ignores the POSIX permission bits that the code sets, so restrict the folder to your own account:

```powershell
icacls .\secure_keys /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F"
```

To supply keys from a secrets manager instead of files, set `AES_DATA_KEY_B64` and `HMAC_SIGNING_KEY_B64` (base64 of 32 random bytes) in the environment.

---

## 5. Screenshots

| Folder | Contents |
|---|---|
| `Screenshots/RBAC/` | 13 browser screenshots of the running web application, plus `capture_log.txt` with the HTTP status of each page |
| `Screenshots/Cryptography/` | Output of each cryptographic step (rendered from the captured run), and a browser screenshot of the HTTPS server |
| `Screenshots/Testing/` | Verbose pytest results for both projects |

`Screenshots/README.md` lists every file and explains how each image was produced. To regenerate them on Windows, see that file.

---

## 6. Expected outputs (summary)

| Check | Expected |
|---|---|
| `GET /profile` without login | 401 |
| Customer `GET /profile` | 200 |
| Customer `GET /customers/2` | 404 |
| Customer `GET /admin/dashboard` | 403 |
| Manager `GET /manager/customers` | 200 |
| Manager `GET /admin/users` | 403 |
| Administrator `GET /admin/users` | 200 |
| Section B `pytest` | 61 passed |
| Section D `pytest` | 48 passed |
| Section D `main.py` | ends with `ALL DEMONSTRATIONS COMPLETED` |
| Tampered HMAC message | `False` (rejected) |
| Replayed signed message | `REJECTED: replay` |

---

## 7. Project structure and documentation

- `Section_B_RBAC/`: Flask application, templates, static files, tests.
- `Section_D_Cryptography/`: cryptography modules, `main.py`, HTTPS server, tests.
- `Documentation/Section_A_Answers.md`: nine authorization questions.
- `Documentation/Section_C_Answers.md`: ten cryptography questions.
- `Documentation/Implementation_Explanation.md`: requirement-to-code mapping, route table, design decisions, limitations.
- `Documentation/Test_Results.md`: test results and the completion matrix.
- `Screenshots/`: images described above.
- `tools/`: scripts that generate the screenshots from real runs (optional).

---

## 8. Security notes and limitations

- Demo passwords are public by design. Do not deploy with them, with `SHOW_DEMO_CREDENTIALS=1`, or without setting `SECRET_KEY`.
- The HTTPS certificate is self-signed. It is for local testing only. Browsers warn about it and it cannot be revoked through normal channels. See `Section_D_Cryptography/https_server.py`.
- The development server (`app.run`) is not for production. Use a WSGI server behind a TLS-terminating reverse proxy.
- No login rate limiting is implemented (recommended in `Section_C_Answers.md`).
- Customer-initiated transfers are not implemented; managers create and review transactions.

---

## 9. Manual steps (for the student)

1. Add your name, student ID and date to the cover of the report, if the report is used.
2. Check the assignment's submission format and deadline in your LMS.
3. If your lecturer requires the code on GitHub, create a **private** repository and upload the project (not `.venv`, `secure_keys`, `certs` or `instance`).
4. Run the project once on your own Windows machine following sections 2 to 4 and confirm the expected results in section 6. Replace the screenshots in `Screenshots/` with your own if the brief requires screenshots from your computer (see `Screenshots/README.md`).
5. Before uploading, remove `.venv`, `Section_B_RBAC\instance`, `Section_D_Cryptography\secure_keys` and `Section_D_Cryptography\certs`.
