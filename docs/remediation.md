# SecureShop — Remediation & Hardening Guide

This document describes the defensive security controls applied to resolve all identified vulnerabilities in SecureShop, fulfilling Section 11 of the assignment.

---

## 1. Remediation Summary Matrix

| Vulnerability | Before | Fix Applied | After |
| :--- | :--- | :--- | :--- |
| **Broken Access Control** | Vulnerable | Authorization check | Fixed |
| **Injection** | Vulnerable | Parameterized query | Fixed |
| **Security Misconfiguration** | Vulnerable | Safe configuration | Fixed |
| **Authentication/Session** | Vulnerable | Secure session handling | Fixed |
| **Outdated Component** | Old version | Updated version | Fixed |

> [!NOTE]
> In accordance with laboratory requirements, scan confirmation is not pre-claimed. The table above reflects application-level code and architecture remediation. Run OWASP ZAP according to `docs/zap_testing.md` to capture and record the final scan verification.

---

## 2. Technical Remediation Details

### 2.1 Broken Access Control (A01:2021)
* **File:** `routes/admin.py` and `routes/user.py`
* **Root Cause:** Missing role check on administrative endpoints and missing owner check on user-specific resources.
* **Fix Applied:**
  1. Role-Based Access Control (RBAC): Enforced `session.get('role') == 'admin'` for all `/admin/*` routes. Non-admin users receive HTTP 403 Forbidden.
  2. IDOR Protection: Profile (`/profile/<id>`) and order (`/order/<id>`) handlers verify that `session['user_id'] == requested_id` or that the user has the `admin` role. Unauthorized requests trigger HTTP 403 Forbidden.

**Code Comparison:**
```python
# BEFORE (Vulnerable):
if "user_id" not in session:
    return redirect(url_for("auth.login"))
# Any logged-in user can access admin functions!

# AFTER (Remediated):
if "user_id" not in session:
    return redirect(url_for("auth.login"))
if session.get("role") != "admin":
    current_app.logger.warning(f"Unauthorized admin access by User #{session.get('user_id')}")
    abort(403)
```

---

### 2.2 Injection — SQL Injection (A03:2021)
* **File:** `routes/public.py`
* **Root Cause:** User input from `request.args.get('q')` was concatenated directly into a raw SQL query string.
* **Fix Applied:** Replaced raw string interpolation with SQLite parameterized queries using `?` placeholders.

**Code Comparison:**
```python
# BEFORE (Vulnerable):
raw_sql = f"SELECT * FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'"
cursor.execute(raw_sql)

# AFTER (Remediated):
safe_param = f"%{query}%"
cursor.execute(
    "SELECT * FROM products WHERE name LIKE ? OR description LIKE ?",
    (safe_param, safe_param)
)
```

---

### 2.3 Security Misconfiguration (A05:2021)
* **File:** `app.py` and `config.py`
* **Root Cause:** Debug mode enabled in runtime environment (`debug=True`), absence of defensive HTTP headers, and server banner version exposure.
* **Fix Applied:**
  1. Set `DEBUG = False` and `TESTING = False`.
  2. Implemented generic error handlers for 403, 404, and 500 without stack trace disclosure.
  3. Enforced defensive HTTP security headers via `@app.after_request` middleware:
     - `X-Frame-Options: DENY` (prevents Clickjacking)
     - `X-Content-Type-Options: nosniff` (prevents MIME sniffing)
     - `Content-Security-Policy: default-src 'self'; ...` (mitigates XSS)
     - `Referrer-Policy: strict-origin-when-cross-origin`
     - Sanitized `Server` header (`Server: SecureShop-Production`).

**Code Comparison:**
```python
# BEFORE (Vulnerable):
app.run(debug=True)
# Defensive HTTP security headers omitted

# AFTER (Remediated):
app.run(debug=False)
response.headers["X-Frame-Options"] = "DENY"
response.headers["X-Content-Type-Options"] = "nosniff"
response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; script-src 'self' https://cdn.jsdelivr.net;"
```

---

### 2.4 Authentication / Session Weakness (A07:2021)
* **File:** `config.py` and `routes/auth.py`
* **Root Cause:** Plaintext password storage, static hardcoded `SECRET_KEY`, missing `HttpOnly` and `SameSite` cookie flags, and session fixation.
* **Fix Applied:**
  1. Cryptographic Password Hashing: Replaced cleartext password storage with salted one-way hashes generated via `werkzeug.security.generate_password_hash` (`scrypt` / `PBKDF2`).
  2. Secure Key Generation: Implemented `secrets.token_hex(32)` for cryptographically secure session signing.
  3. Hardened Cookie Flags: Set `SESSION_COOKIE_HTTPONLY = True` (blocks JavaScript access) and `SESSION_COOKIE_SAMESITE = 'Lax'` (mitigates CSRF).
  4. Session Fixation Prevention: Invoked `session.clear()` on login prior to setting authenticated user data.

**Code Comparison:**
```python
# BEFORE (Vulnerable):
SECRET_KEY = "super_secret_hardcoded_lab_key_do_not_use_in_prod"
SESSION_COOKIE_HTTPONLY = False
SESSION_COOKIE_SAMESITE = None
# Plaintext password inserted into database

# AFTER (Remediated):
SECRET_KEY = secrets.token_hex(32)
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
hashed_pw = generate_password_hash(password, method="scrypt")
session.clear()  # Purges old session upon successful authentication
```

---

### 2.5 Outdated Component (A06:2021)
* **File:** `requirements.txt`
* **Root Cause:** Pinned outdated dependency `Werkzeug==2.2.2` vulnerable to cookie cache leakage (CVE-2023-30861).
* **Fix Applied:** Upgraded dependency specification to modern patched versions (`Werkzeug>=3.1.9`).

**Specification Comparison:**
```diff
- Werkzeug==2.2.2
+ Werkzeug>=3.1.9
```

---

## 3. How to Switch Between Vulnerable and Secure Modes

The application supports three easy methods to switch between the baseline and remediated states:

### Method 1: Command Line Flag (Recommended for Scans)
```bash
# Start in Baseline Vulnerable Mode:
python app.py --mode vulnerable --port 8080

# Start in Hardened Secure Mode:
python app.py --mode secure --port 8080
```

### Method 2: Web Interface Toggle
Click the **"Switch Mode"** button located on the top banner of any page in the running web application. The banner color and active configuration switch dynamically.

### Method 3: Environment Variable
```bash
# Windows PowerShell:
$env:SECURESHOP_MODE="secure"
python app.py

# Windows Command Prompt:
set SECURESHOP_MODE=secure
python app.py
```

---

## 4. Retesting & Verification Procedure

1. **Automated Unit & Security Tests:**  
   Execute the included automated security verification suite to confirm code-level remediation:
   ```bash
   python -m unittest tests/test_security.py
   python -m unittest tests/test_functional.py
   ```
   Both test suites will pass, validating before vs. after security controls.

2. **OWASP ZAP Retest:**  
   Execute the retest steps in `docs/zap_testing.md` against `http://127.0.0.1:8080` in secure mode, and record the reduced alert profile in your assignment report.
