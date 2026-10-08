# SecureShop — Vulnerability Documentation

This document provides a technical assessment of the four primary controlled vulnerabilities implemented in the SecureShop educational laboratory, following the required reporting schema.

---

### Finding 1

Name: Broken Function Level Authorization & Insecure Direct Object References (IDOR)  
OWASP Category: A01:2021 – Broken Access Control  
Affected URL: `http://127.0.0.1:8080/admin/dashboard`, `http://127.0.0.1:8080/admin/products`, `http://127.0.0.1:8080/admin/users`, `http://127.0.0.1:8080/profile/<user_id>`, `http://127.0.0.1:8080/order/<order_id>`  
Affected functionality: Administrative Management Console, User Directory, Inventory Control, and Customer Order Receipts  

WHAT?  
What vulnerability exists?  
The application contains two distinct Broken Access Control weaknesses:
1. **Broken Function Level Authorization (BFLA):** The administrative routes (`/admin/dashboard`, `/admin/products`, `/admin/users`) allow any authenticated standard customer to view and manage administrative functions without possessing the `admin` role.
2. **Insecure Direct Object Reference (IDOR):** The `/profile/<id>` and `/order/<id>` endpoints display private customer profiles and full order receipts (including home shipping addresses and purchased items) solely based on an incrementing integer ID in the URL, without verifying whether the requesting session owns the record.

WHERE?  
Where in the application does it occur?  
- `routes/admin.py` in the `enforce_admin_check()` function (lines 10–30):
  ```python
  # LAB VULNERABILITY: A01 Broken Access Control
  # In vulnerable mode, the check only verifies that 'user_id' is in session, omitting role validation
  ```
- `routes/user.py` in the `profile()` and `order_detail()` route handlers (lines 25–33 and lines 205–214).

WHY?  
Why does the weakness exist?  
The developers implemented an incomplete authentication check assuming that merely being logged in was sufficient to grant access. The authorization check failed to verify `session.get('role') == 'admin'` for administrative routes, and failed to compare `session.get('user_id') == user_id` for personal user data access.

IMPACT?  
What could an attacker potentially achieve?  
An attacker with standard customer credentials (e.g. `alice`) can:
- Access the administrator dashboard.
- View, create, and delete store products and inventory.
- View the entire user directory, including other users' usernames, emails, and credentials.
- Harvest personal home addresses and order histories belonging to other customers by traversing order IDs (`/order/101`, `/order/102`, etc.).

EVIDENCE:  
What evidence should be collected using OWASP ZAP or controlled manual testing?  
- **Manual Testing Evidence:** Log in as standard customer `alice` (`alice` / `AlicePass456!`). Navigate directly to `http://127.0.0.1:8080/admin/dashboard`. The browser loads the administrative console with HTTP 200 OK. Navigate to `http://127.0.0.1:8080/order/102` (owned by `bob`) and verify that Bob's order receipt and shipping address are displayed.
- **OWASP ZAP Evidence:** Configure ZAP with an authenticated customer session. Spider or send a GET request to `/admin/dashboard` and `/order/102`. Record the HTTP request headers, session cookie, and the HTTP 200 response body showing the admin interface and unauthorized order data.

REMEDIATION:  
How should it be fixed?  
Implement centralized, server-side Role-Based Access Control (RBAC) and strict object ownership checks:
1. In `enforce_admin_check()`, verify `if session.get("role") != "admin": abort(403)`.
2. In `profile()` and `order_detail()`, verify that `session.get("user_id") == record["user_id"]` or `session.get("role") == "admin"`. If not, abort with HTTP 403 Forbidden.

RETEST:  
What should be tested after the fix?  
1. Run SecureShop in secure mode (`python app.py --mode secure`).
2. Log in as standard user `alice` and attempt to browse `http://127.0.0.1:8080/admin/dashboard`. Verify that the server responds with HTTP 403 Forbidden.
3. Attempt to access `http://127.0.0.1:8080/order/102` (Bob's order). Verify that the server returns HTTP 403 Forbidden.
4. Log in as `admin` and confirm that administrative access is properly retained.

---

### Finding 2

Name: Unsanitized SQL Query Construction (SQL Injection)  
OWASP Category: A03:2021 – Injection  
Affected URL: `http://127.0.0.1:8080/search?q=<payload>`  
Affected functionality: Product Catalogue Search  

WHAT?  
What vulnerability exists?  
The product search functionality constructs a raw SQL query using string formatting (`f"SELECT ... '%{query}%'"`) with user-supplied input from the `q` query string parameter. This allows an attacker to break out of the SQL string delimiter and execute arbitrary SQLite commands within the local database.

WHERE?  
Where in the application does it occur?  
- `routes/public.py` in the `search()` view function (lines 49–82):
  ```python
  # LAB VULNERABILITY: A03 Injection
  raw_sql = f"SELECT * FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'"
  cursor.execute(raw_sql)
  ```

WHY?  
Why does the weakness exist?  
The developer concatenated user input directly into the dynamic SQL query string instead of utilizing parameterized queries or ORM abstractions.

IMPACT?  
What could an attacker potentially achieve?  
An attacker can alter the query semantics using boolean tautologies (`' OR '1'='1`) to extract unlisted products, or use `UNION SELECT` statements to exfiltrate confidential data from other tables within the local SQLite database (such as dumping password hashes, usernames, and emails from the `users` table).

EVIDENCE:  
What evidence should be collected using OWASP ZAP or controlled manual testing?  
- **Manual Testing Evidence:** In the browser, navigate to:
  `http://127.0.0.1:8080/search?q='%20UNION%20SELECT%20id,%20username,%20email,%20password,%20role,%20bio,%20created_at%20FROM%20users--`
  Or test tautology: `http://127.0.0.1:8080/search?q='%20OR%20'1'='1`
  Observe that the application executes the raw query and displays records from the database in the search results cards.
- **OWASP ZAP Evidence:** In ZAP, run an Active Scan against the `/search?q=test` endpoint. ZAP will inject SQL syntax test payloads (e.g. `'`, `''`, `OR 1=1`) and flag an "SQL Injection - SQLite" alert based on syntax errors or differential response lengths. Save the alert details, HTTP request, and HTTP response.

REMEDIATION:  
How should it be fixed?  
Replace raw string concatenation with parameterized SQL queries using SQLite's native `?` positional placeholders:
```python
safe_param = f"%{query}%"
cursor.execute(
    "SELECT * FROM products WHERE name LIKE ? OR description LIKE ?",
    (safe_param, safe_param)
)
```
The database engine compiles the SQL query structure in advance and treats the user parameter strictly as literal data, preventing command alteration.

RETEST:  
What should be tested after the fix?  
1. In secure mode (`--mode secure`), submit the test payload `' OR '1'='1` in the search bar.
2. Confirm that the application returns "No products found matching your search term" (HTTP 200) instead of dumping all products.
3. Submit `' UNION SELECT ...` and confirm that it returns zero results without SQL syntax errors.
4. Confirm legitimate searches (e.g. `Hardware`) continue to return valid product items.

---

### Finding 3

Name: Framework Debug Mode Active & Missing HTTP Defensive Security Headers  
OWASP Category: A05:2021 – Security Misconfiguration  
Affected URL: `http://127.0.0.1:8080/`, `http://127.0.0.1:8080/debug/error` (and all application routes)  
Affected functionality: Global Application Server Configuration & Error Handling  

WHAT?  
What vulnerability exists?  
1. **Interactive Debugger & Stack Trace Exposure:** The Flask application runs with `debug=True`, exposing the Werkzeug interactive traceback console, server internal paths, Python runtime environment details, and local source code on unhandled exceptions.
2. **Missing HTTP Security Headers:** The web server omits industry-standard defensive HTTP headers, including `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`, and `Referrer-Policy`.
3. **Banner Information Leakage:** The `Server` HTTP header explicitly broadcasts underlying component names and versions (`Server: Werkzeug/2.2.2 Python/3.14 (Vulnerable-Lab-Server)`).

WHERE?  
Where in the application does it occur?  
- `config.py` in `VulnerableConfig`:
  ```python
  # LAB VULNERABILITY: A05 Security Misconfiguration
  DEBUG = True
  TESTING = True
  ```
- `app.py` in the `apply_security_headers()` middleware (lines 48–70) and `debug_error()` endpoint (lines 72–85).

WHY?  
Why does the weakness exist?  
Development configurations were left active in the runtime environment without environment-specific hardening, and default HTTP response handling was not augmented with security headers.

IMPACT?  
What could an attacker potentially achieve?  
- Detailed stack traces provide an attacker with exact file system paths, database schema references, and library versions, simplifying further exploit development.
- Missing `X-Frame-Options` exposes the application to Clickjacking attacks where the UI is framed within an attacker's website.
- Missing `X-Content-Type-Options` allows MIME-type sniffing attacks.
- Missing `Content-Security-Policy` increases vulnerability to script injection.
- Exposed `Server` banner aids automated reconnaissance.

EVIDENCE:  
What evidence should be collected using OWASP ZAP or controlled manual testing?  
- **Manual Testing Evidence:** Navigate to `http://127.0.0.1:8080/debug/error`. Observe the interactive Werkzeug traceback page displaying local directory paths (`C:\Users\...`), Python source snippets, and execution frames. Inspect response headers using browser developer tools (F12 Network tab) or curl:
  ```bash
  curl -I http://127.0.0.1:8080/
  ```
  Note the presence of `Server: Werkzeug/2.2.2...` and the complete absence of `X-Frame-Options`, `X-Content-Type-Options`, and `Content-Security-Policy`.
- **OWASP ZAP Evidence:** ZAP Passive Scanner generates Low/Medium alerts:
  - "Missing Anti-clickjacking Header (`X-Frame-Options`)"
  - "`X-Content-Type-Options` Header Missing"
  - "Content Security Policy (CSP) Header Not Set"
  - "Server Leaks Information via 'Server' HTTP Response Header"
  Record these alerts and their associated HTTP request/response headers in the ZAP Alerts tab.

REMEDIATION:  
How should it be fixed?  
1. Set `debug = False` in production configurations.
2. Implement custom HTTP error handlers (403, 404, 500) that render generic user-friendly templates without leaking stack traces or variable states.
3. Configure defensive HTTP headers on all outgoing responses:
   - `X-Frame-Options: DENY`
   - `X-Content-Type-Options: nosniff`
   - `Content-Security-Policy: default-src 'self'; ...`
   - `Referrer-Policy: strict-origin-when-cross-origin`
   - Sanitize or suppress the `Server` header (`Server: SecureShop-Production`).

RETEST:  
What should be tested after the fix?  
1. In secure mode (`--mode secure`), navigate to `http://127.0.0.1:8080/debug/error`. Verify that a clean HTTP 500 error page is returned without stack traces.
2. Inspect HTTP headers using `curl -I http://127.0.0.1:8080/` or browser DevTools. Confirm `X-Frame-Options`, `X-Content-Type-Options`, and `Content-Security-Policy` are present.
3. Rerun ZAP Passive Scan and verify that the security header alerts are resolved.

---

### Finding 4

Name: Plaintext Password Storage & Insecure Session Cookie Attributes  
OWASP Category: A07:2021 – Identification and Authentication Failures  
Affected URL: `http://127.0.0.1:8080/register`, `http://127.0.0.1:8080/login`, `http://127.0.0.1:8080/admin/users`  
Affected functionality: Account Registration, Credential Authentication, and Session Cookie Management  

WHAT?  
What vulnerability exists?  
1. **Plaintext Password Storage:** User passwords supplied during registration are stored in the database in raw cleartext without any cryptographic one-way hashing algorithm.
2. **Hardcoded Predictable Secret Key:** The Flask session signing key is hardcoded to a static well-known string (`super_secret_hardcoded_lab_key_do_not_use_in_prod`).
3. **Insecure Session Cookie Flags:** The session cookie lacks the `HttpOnly` flag (`SESSION_COOKIE_HTTPONLY = False`) and lacks `SameSite` protection (`SESSION_COOKIE_SAMESITE = None`).
4. **Session Fixation:** The user session ID is not cleared or regenerated upon authentication.

WHERE?  
Where in the application does it occur?  
- `config.py` in `VulnerableConfig`:
  ```python
  # LAB VULNERABILITY: A07 Authentication/Session Weakness
  SECRET_KEY = "super_secret_hardcoded_lab_key_do_not_use_in_prod"
  SESSION_COOKIE_HTTPONLY = False
  SESSION_COOKIE_SECURE = False
  SESSION_COOKIE_SAMESITE = None
  PASSWORD_HASHING = "plaintext"
  ```
- `routes/auth.py` in `register()` (lines 42–46) and `login()` (lines 94–98 and 108–116).

WHY?  
Why does the weakness exist?  
The application relied on simplified development defaults for credential storage and failed to configure cryptographic password hashing or secure session cookie attributes.

IMPACT?  
What could an attacker potentially achieve?  
- Anyone who accesses the database (via SQL injection, local access, or backup inspection) immediately obtains all user and administrator passwords without requiring password cracking.
- Missing `HttpOnly` allows client-side JavaScript (`document.cookie`) to read session identifiers if an XSS vulnerability exists.
- Static `SECRET_KEY` allows an attacker knowing the key to forge arbitrary Flask session cookies offline (e.g. crafting an administrative cookie with `user_id=1, role='admin'`).
- Missing `SameSite` attribute exposes the session to Cross-Site Request Forgery (CSRF).

EVIDENCE:  
What evidence should be collected using OWASP ZAP or controlled manual testing?  
- **Manual Testing Evidence:** 
  1. Open browser developer console (F12) while logged into SecureShop. Execute:
     ```javascript
     console.log("Session cookie readable via JS:", document.cookie);
     ```
     Observe that the `session` cookie is printed, proving the absence of `HttpOnly`.
  2. Inspect SQLite database directly:
     ```sql
     SELECT id, username, password, password_algo FROM users;
     ```
     Verify that passwords (`AdminPass123!`, `AlicePass456!`, etc.) are visible in plaintext.
- **OWASP ZAP Evidence:** In ZAP, inspect the `Set-Cookie` header in the HTTP response after logging in:
  ```http
  Set-Cookie: session=...; Path=/
  ```
  ZAP Passive Scan generates the alert: "Cookie No HttpOnly Flag" and "Cookie without SameSite Attribute". Capture screenshots of these alerts in ZAP.

REMEDIATION:  
How should it be fixed?  
1. Implement salted, slow one-way cryptographic password hashing (e.g. `scrypt` or `PBKDF2-HMAC-SHA256`) using `werkzeug.security.generate_password_hash()`.
2. Generate a random, cryptographically secure 256-bit secret key at startup (`secrets.token_hex(32)`) or load it from a secure environment variable (`FLASK_SECRET_KEY`).
3. Set `SESSION_COOKIE_HTTPONLY = True` so cookies cannot be accessed via client-side scripts.
4. Set `SESSION_COOKIE_SAMESITE = 'Lax'` to prevent cross-site request forgery.
5. Call `session.clear()` upon successful login to prevent session fixation.

RETEST:  
What should be tested after the fix?  
1. Start SecureShop in secure mode (`--mode secure`).
2. Register a new user account (e.g. `testuser`).
3. Query the database (`SELECT password, password_algo FROM users WHERE username = 'testuser'`). Confirm that the stored password starts with `scrypt:` or `pbkdf2:sha256:` and is not cleartext.
4. Inspect the `Set-Cookie` header on login. Verify that `HttpOnly` and `SameSite=Lax` are present.
5. In browser console, verify that `document.cookie` no longer displays the session token.
6. Retest with ZAP and confirm that "Cookie No HttpOnly Flag" alert disappears.
