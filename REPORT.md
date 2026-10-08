# APPLICATION SECURITY & RED TEAM ASSESSMENT REPORT
## SecureShop Internal E-Commerce Platform
**Assessment Workflow:** BUILD → EXPOSE → SCAN → INVESTIGATE → SAFELY VALIDATE → FIX → RETEST → REPORT  
**Date:** October 1, 2026  
**Assessor:** Red Team Security Engineer & Application Developer  
**Target Environment:** `http://127.0.0.1:5000` (Local Lab Instance)  
**Security Framework Alignment:** OWASP Top 10:2021  

---

## 1. Executive Summary

Modern web applications depend heavily on multi-tiered architectures, third-party libraries, and frameworks. Insecure development practices and outdated components introduce substantial vulnerabilities that allow unauthorized access, data compromise, and system manipulation.

This report documents an end-to-end security assessment of **SecureShop**, an internal e-commerce web application developed for hardware security tokens and privacy peripherals. The assessment followed a dual Red Team / Blue Team methodology:
1. **Application Development:** SecureShop was built using Python and Flask, implementing public catalogue browsing, customer authentication, personal profile and order tracking, dynamic cart checkout, and an administrative management portal.
2. **Controlled Weakness Injection:** Controlled security weaknesses spanning six OWASP Top 10:2021 categories were implemented to establish an educational laboratory baseline.
3. **DAST Vulnerability Scanning:** An automated Dynamic Application Security Testing (DAST) assessment was executed using **OWASP ZAP 2.15.0** against the baseline application.
4. **Vulnerability Investigation:** Scanner alerts were triaged and investigated at the source code level to eliminate false positives and document the root cause (**What, Where, Why, Impact, and Evidence**).
5. **Safe Validation:** Each weakness was verified safely in a local, non-weaponized testing environment.
6. **Remediation & Hardening:** Architectural and code-level fixes were applied, including parameterized SQL queries, strict role-based access control, cryptographic password hashing (`scrypt`/`PBKDF2`), strict HTTP security headers, and dependency upgrades.
7. **Retesting & Verification:** An automated security test suite was executed against both the vulnerable baseline and remediated postures, demonstrating a 100% remediation pass rate.

---

## 2. Target Application Architecture

### 2.1 Component Architecture
SecureShop is structured into four primary modules:
- **Public Services (`routes/public.py`):** Landing page, product catalogue with category filtering, individual item specifications, and search functionality.
- **Identity & Access Management (`routes/auth.py`):** User registration, credential authentication, session establishment, and session termination.
- **Customer Services (`routes/user.py`):** User profile viewer, status updates, session-backed shopping cart, transaction checkout, and order receipt viewing.
- **Administrative Operations (`routes/admin.py`):** System dashboard, inventory stock and product creation/deletion, and user directory management.
- **Persistence Layer (`database.py`):** Relational storage backed by SQLite (`secureshop.db`), maintaining `users`, `products`, `orders`, and `order_items` tables.

```
+-------------------------------------------------------------------------+
|                              Client Browser                             |
+-------------------------------------------------------------------------+
                                     |
               HTTP Requests (Port 5000) / Session Cookies
                                     v
+-------------------------------------------------------------------------+
|                        SecureShop Application Core                      |
|                                                                         |
|  +--------------------+  +--------------------+  +-------------------+  |
|  |    Public Module   |  |   Auth Blueprint   |  |   User Blueprint  |  |
|  |  Catalogue/Search  |  |   Register/Login   |  |   Profile/Orders  |  |
|  +--------------------+  +--------------------+  +-------------------+  |
|                                     |                                   |
|                        +-----------------------+                        |
|                        |    Admin Blueprint    |                        |
|                        |   Products / Users    |                        |
|                        +-----------------------+                        |
+-------------------------------------------------------------------------+
                                     |
                   SQL Operations (Direct vs Parameterized)
                                     v
+-------------------------------------------------------------------------+
|                         SQLite Database Engine                          |
|         Tables: users | products | orders | order_items                 |
+-------------------------------------------------------------------------+
```

---

## 3. Outdated Technology Requirement (OWASP A06:2021)

As mandated by Section 7 of the assignment specification, the application's baseline incorporates outdated third-party dependencies with known security advisories.

### 3.1 Primary Component Analysis: Werkzeug
- **Component Name:** `Werkzeug` (WSGI web application library underpinning Flask)
- **Version Used in Baseline:** `2.2.2`
- **Current Patched Version:** `3.1.9`
- **Security Advisory / CVE Reference:** **CVE-2023-30861**
- **CVSS v3.1 Base Score:** 7.5 (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **Vulnerability Description & Risk:**
  In Werkzeug versions prior to 2.2.3 / 2.3.0, when an application sets a cookie (such as Flask's default session cookie) without explicitly configuring caching headers, Werkzeug omits the `Vary: Cookie` HTTP response header. When the application is deployed behind shared caching infrastructure (such as Content Delivery Networks, HTTP accelerators like Varnish, or enterprise caching reverse proxies), the cache server cannot distinguish between distinct clients and may cache responses containing sensitive session cookies. Subsequent unauthenticated visitors requesting the same cached URL receive the cached `Set-Cookie` header containing the original user's authenticated session, leading to complete account takeover.

### 3.2 Secondary Component Analysis: urllib3
- **Component Name:** `urllib3`
- **Version Used in Baseline:** `1.26.5`
- **Current Patched Version:** `2.8.0`
- **Security Advisory / CVE Reference:** **CVE-2023-43804**
- **CVSS v3.1 Base Score:** 8.1 (High)
- **Vulnerability Description & Risk:**
  When executing HTTP requests that encounter cross-origin HTTP 30x redirects, affected versions of `urllib3` fail to strip sensitive `Cookie` request headers. An attacker operating a destination server can entice an internal application to follow a redirect and harvest internal session tokens and authentication cookies.

### 3.3 Dependency Remediation Path
Upgrading dependencies in `requirements_secure.txt` resolves these advisories:
```diff
- Flask==2.2.2
- Werkzeug==2.2.2
- urllib3==1.26.5
+ Flask>=3.1.3
+ Werkzeug>=3.1.9
+ urllib3>=2.8.0
```

---

## 4. Phase 2 — OWASP ZAP DAST Assessment

### 4.1 Scan Configuration & Parameters
- **Scan Date:** October 1, 2026
- **Target URL:** `http://127.0.0.1:5000`
- **DAST Tool:** OWASP Zed Attack Proxy (ZAP)
- **Tool Version:** 2.15.0
- **Scan Type:** Automated Spider + Active Scan Policy (OWASP Top 10 Baseline)
- **Authentication Method:** Form-based authentication targeting `/login` with credentials `username=alice` / `password=AlicePass456!`

### 4.2 Scanner Alert Summary
| Alert Category | Severity | Alert Count | OWASP Mapping |
| :--- | :--- | :---: | :--- |
| SQL Injection | **High** | 1 | A03:2021 — Injection |
| Cross-Site Scripting (Reflected) | **High** | 1 | A03:2021 — Injection |
| Missing Anti-Clickjacking Header (`X-Frame-Options`) | **Medium** | 6 | A05:2021 — Security Misconfiguration |
| Content Security Policy (CSP) Header Not Set | **Medium** | 6 | A05:2021 — Security Misconfiguration |
| Missing `X-Content-Type-Options: nosniff` | **Low** | 6 | A05:2021 — Security Misconfiguration |
| Server Leaks Version Information via `Server` Header | **Low** | 6 | A05:2021 — Security Misconfiguration |
| Cookie Without `HttpOnly` / `SameSite` Attribute | **Medium** | 2 | A07:2021 — Identification & Authentication |
| Total Identified Alerts | — | **28** | — |

*(Note: Inherent architectural vulnerabilities such as IDOR and Missing Function Level Authorization are business-logic flaws requiring manual testing and context-aware validation, as generic automated crawlers cannot deduce object ownership models without manual rule specification.)*

---

## 5. Phase 3 — Detailed Finding Investigation

### Finding 1: Insecure Direct Object Reference (IDOR) on Customer Profiles & Orders
- **OWASP Category:** A01:2021 — Broken Access Control (CWE-639)
- **What:** The application permits authenticated users to access and inspect confidential profiles and order invoices belonging to other customers by modifying the numeric ID in the URL.
- **Where:** 
  - `GET /profile/<int:user_id>` (handled by `routes/user.py::profile`)
  - `GET /order/<int:order_id>` (handled by `routes/user.py::order_detail`)
- **Why:** The route handlers verify that a user is authenticated (`"user_id" in session`), but fail to validate whether the authenticated user ID matches the target record's owner (`session['user_id'] == requested_user_id`).
- **Impact:** An attacker authenticated with any low-privilege customer account can sequentially iterate through numeric IDs (`/profile/1`, `/profile/2`, `/order/101`, `/order/102`) to extract full names, email addresses, personal bios, full billing and shipping home addresses, purchase histories, and total transaction figures across all company accounts.
- **Evidence:** Authenticating as `alice` (User ID `2`) and issuing `GET /profile/3` returns HTTP 200 containing Customer `bob`'s email (`bob@secureshop.local`). Similarly, issuing `GET /order/102` exposes Bob's delivery address (`108 Binary Blvd, Cyberspace, NY 10001`).

---

### Finding 2: Broken Function Level Authorization (BFLA) on Administrative Console
- **OWASP Category:** A01:2021 — Broken Access Control (CWE-285)
- **What:** The administrative console and product/user deletion endpoints do not restrict access based on administrative roles.
- **Where:** 
  - `GET /admin/` and `GET /admin/dashboard`
  - `GET /admin/users` and `GET /admin/products`
  - `GET /admin/users/delete/<id>` and `GET /admin/products/delete/<id>`
- **Why:** `routes/admin.py::enforce_admin_check` only validates that a session cookie exists, completely omitting role verification (`session.get('role') == 'admin'`).
- **Impact:** Any standard customer account can access the administrator dashboard, inspect user registration records, delete catalogue products, and delete other user accounts.
- **Evidence:** Authenticating as customer `alice` and requesting `GET /admin/dashboard` yields HTTP 200 OK and renders the administrator management console.

---

### Finding 3: SQL Injection in Product Search
- **OWASP Category:** A03:2021 — Injection (CWE-89)
- **What:** The product search query parameter `q` is directly interpolated into a raw SQL statement string without parameterization or sanitization.
- **Where:** `GET /search?q=<payload>` (handled by `routes/public.py::search`)
- **Why:** The route constructs the query using an f-string:
  ```python
  raw_sql = f"SELECT * FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'"
  cursor.execute(raw_sql)
  ```
- **Impact:** An external attacker can break out of the SQL string context using quotes and inject SQL tautologies (`' OR '1'='1`) or `UNION SELECT` expressions to extract records from other tables (e.g. `users` credentials, hashes, and session data) or corrupt the database.
- **Evidence:** Submitting `GET /search?q=' OR '1'='1` breaks the search filter and returns all catalogue products in the database regardless of keyword match.

---

### Finding 4: Reflected Cross-Site Scripting (XSS)
- **OWASP Category:** A03:2021 — Injection (CWE-79)
- **What:** The application reflects untrusted user input directly into the HTML response without HTML entity encoding.
- **Where:** Parameter `q` reflected on `/search` (rendered via `templates/search_results.html`)
- **Why:** The template bypasses Jinja2's auto-escaping mechanism by applying the `| safe` filter to the search query variable:
  ```html
  <span class="badge bg-light text-dark border fs-6">{{ query | safe }}</span>
  ```
- **Impact:** An attacker can craft a malicious link containing embedded JavaScript payloads. When a user clicks the link, the script executes within the victim's browser context, enabling session hijacking, DOM manipulation, or redirection to malicious destinations.
- **Evidence:** Requesting `GET /search?q=<script>alert('SECURESHOP_XSS')</script>` causes the raw script tags to be returned unescaped in the HTTP response body.

---

### Finding 5: Security Misconfiguration — Debug Mode & Missing Defensive Headers
- **OWASP Category:** A05:2021 — Security Misconfiguration (CWE-16, CWE-1021, CWE-693)
- **What:** The web server runs with debug mode enabled, leaks internal server/runtime versions, and fails to transmit standard defensive HTTP security headers.
- **Where:** Global HTTP response headers across all endpoints.
- **Why:** 
  1. The application initializes with `app.run(debug=True)`.
  2. The WSGI middleware omits headers: `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`, and `Permissions-Policy`.
  3. The `Server` header advertises `Werkzeug/2.2.2 Python/3.14`.
- **Impact:** 
  - Missing `X-Frame-Options` allows malicious sites to frame the application in an invisible iframe, facilitating UI redressing / Clickjacking attacks.
  - Missing `X-Content-Type-Options` enables MIME-sniffing attacks.
  - Missing CSP permits execution of untrusted inline scripts and cross-site injection.
  - Server banner disclosure informs attackers of exact version numbers, simplifying target profiling for known CVE exploits.
- **Evidence:** HTTP response inspects reveal complete absence of security headers and exposes the header:
  `Server: Werkzeug/2.2.2 Python/3.14 (Vulnerable-Lab-Server)`.

---

### Finding 6: Identification and Authentication Failures — Insecure Passwords & Weak Sessions
- **OWASP Category:** A07:2021 — Identification and Authentication Failures (CWE-256, CWE-384, CWE-798)
- **What:** User passwords are stored as plaintext in the database, registration allows single-character passwords, and session cookies are signed with a static, publicly known secret key.
- **Where:** 
  - `routes/auth.py::register`
  - `config.py::VulnerableConfig::SECRET_KEY`
- **Why:**
  1. Registration executes `INSERT INTO users (..., password, password_algo) VALUES (..., ?, 'plaintext')`.
  2. Flask's `SECRET_KEY` is hardcoded to `"super_secret_hardcoded_lab_key_do_not_use_in_prod"`.
  3. Session cookies lack `HttpOnly` and `SameSite` flags.
- **Impact:** A read-only database compromise immediately exposes all user credentials. Knowledge of the static `SECRET_KEY` allows attackers to forge arbitrary session cookies offline, authenticating as any user without credentials.
- **Evidence:** Direct database query reveals customer passwords stored in clear text (`admin: AdminPass123!`, `alice: AlicePass456!`).

---

### Finding 7: Security Logging and Monitoring Failures — Plaintext Credential Logging
- **OWASP Category:** A09:2021 — Security Logging and Monitoring Failures (CWE-532, CWE-778)
- **What:** The application logs unredacted user credentials to standard output and log files during authentication attempts.
- **Where:** `routes/auth.py::login`
- **Why:** The handler logs user input directly:
  ```python
  current_app.logger.warning(
      f"[INSECURE LOG] Login attempt for user='{username}' with raw plaintext password='{password}'"
  )
  ```
- **Impact:** Server logs aggregated in centralized logging systems (e.g. ELK, Splunk, CloudWatch) expose user passwords to internal personnel, auditors, and logging systems, violating regulatory standards (PCI-DSS, GDPR).
- **Evidence:** Inspecting the console log during login reveals:
  `[INSECURE LOG] Login attempt for user='alice' with raw plaintext password='AlicePass456!'`.

---

## 6. Safe Validation & Proof-of-Concept Summary

In accordance with Section 6 of the assignment specification ("You are not required to use a real weaponized exploit. The objective is to demonstrate the security weakness safely and explain its impact"), all validations were executed locally using benign strings and access-control checks:

| Vulnerability | Safe Test Method | Observed Result in Vulnerable Mode |
| :--- | :--- | :--- |
| **A01 IDOR** | Authenticated as User #2 (`alice`), navigated to `/profile/3` and `/order/102`. | Successfully viewed Bob's profile and order receipt (HTTP 200). |
| **A01 BFLA** | Authenticated as User #2 (`alice`), navigated to `/admin/dashboard`. | Successfully loaded Admin Console (HTTP 200). |
| **A03 SQLi** | Supplied tautology `' OR '1'='1` in search parameter `q`. | Retrieved all database products, confirming logical query alteration. |
| **A03 XSS** | Passed benign string `<script>alert('SECURESHOP_XSS')</script>`. | Rendered as unescaped DOM element. |
| **A05 Headers**| Inspected HTTP response headers using `curl -I` / test client. | Confirmed absence of `X-Frame-Options`, `CSP`, and `X-Content-Type-Options`. |
| **A07 Auth** | Registered test user `vuln_user` with password `ClearTextPassword123`. | Database confirmed password stored as literal string. |
| **A09 Logs** | Executed login request and examined stdout. | Verified password logged to standard output. |

---

## 7. Remediation Implementation & Source Code Diffs

### 7.1 Remediation of A01: Broken Access Control (IDOR & BFLA)
**File:** `routes/user.py` and `routes/admin.py`
```diff
--- a/routes/user.py (Vulnerable)
+++ b/routes/user.py (Remediated)
@@ -19,6 +19,13 @@ def profile(user_id):
+    # Enforce Object Ownership Check
+    if mode == "secure":
+        if current_uid != user_id and not is_admin:
+            current_app.logger.warning(
+                f"[SECURITY INCIDENT] Unauthorized IDOR access attempt by User #{current_uid} on Profile #{user_id}"
+            )
+            abort(403)
```

```diff
--- a/routes/admin.py (Vulnerable)
+++ b/routes/admin.py (Remediated)
@@ -14,6 +14,13 @@ def enforce_admin_check():
     if "user_id" not in session:
         return False, redirect(url_for("auth.login"))
+    
+    # Enforce Role-Based Access Control
+    if mode == "secure":
+        if session.get("role") != "admin":
+            current_app.logger.warning(f"Unauthorized admin access by User #{session.get('user_id')}")
+            abort(403)
     return True, None
```

---

### 7.2 Remediation of A03: SQL Injection
**File:** `routes/public.py`
```diff
--- a/routes/public.py (Vulnerable)
+++ b/routes/public.py (Remediated)
@@ -48,7 +48,7 @@ def search():
-    raw_sql = f"SELECT * FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'"
-    cursor.execute(raw_sql)
+    safe_param = f"%{query}%"
+    cursor.execute(
+        "SELECT * FROM products WHERE name LIKE ? OR description LIKE ?",
+        (safe_param, safe_param)
+    )
```

---

### 7.3 Remediation of A03: Reflected XSS
**File:** `templates/search_results.html`
```diff
--- a/templates/search_results.html (Vulnerable)
+++ b/templates/search_results.html (Remediated)
@@ -7,7 +7,7 @@
-    <span class="badge bg-light text-dark border fs-6">{{ query | safe }}</span>
+    <span class="badge bg-light text-dark border fs-6">{{ query }}</span>
```

---

### 7.4 Remediation of A05: Security Misconfiguration
**File:** `app.py`
```diff
--- a/app.py (Vulnerable)
+++ b/app.py (Remediated)
@@ -42,6 +42,16 @@ def create_app(mode=None):
     @app.after_request
     def apply_security_headers(response):
+        if mode == "secure":
+            response.headers["X-Frame-Options"] = "DENY"
+            response.headers["X-Content-Type-Options"] = "nosniff"
+            response.headers["Content-Security-Policy"] = (
+                "default-src 'self'; "
+                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
+                "script-src 'self' https://cdn.jsdelivr.net; "
+                "font-src 'self' https://cdn.jsdelivr.net; "
+                "img-src 'self' data: https:;"
+            )
+            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
+            response.headers["Server"] = "SecureShop-Production"
         return response
```

---

### 7.5 Remediation of A07: Authentication & Password Hashing
**File:** `routes/auth.py`
```diff
--- a/routes/auth.py (Vulnerable)
+++ b/routes/auth.py (Remediated)
@@ -40,8 +40,8 @@ def register():
-        cursor.execute("INSERT INTO users (..., password, password_algo) VALUES (..., ?, 'plaintext')", (..., password))
+        hashed_pw = generate_password_hash(password, method="scrypt")
+        cursor.execute("INSERT INTO users (..., password, password_algo) VALUES (..., ?, 'werkzeug_pbkdf2')", (..., hashed_pw))
```

---

### 7.6 Remediation of A09: Security Logging
**File:** `routes/auth.py`
```diff
--- a/routes/auth.py (Vulnerable)
+++ b/routes/auth.py (Remediated)
@@ -62,7 +62,7 @@ def login():
-        current_app.logger.warning(f"Login attempt: user={username}, password={password}")
+        current_app.logger.info(f"Login attempt received for user='{username}' [CREDENTIALS REDACTED]")
```

---

## 8. Phase 5 — Retesting & Verification Evidence

An automated regression testing suite (`tests/test_security.py`) was developed to verify each vulnerability and validate the remediated controls.

### 8.1 Automated Test Execution Log
```
======================================================================
SecureShop Automated Security Verification Suite
Target: http://127.0.0.1:5000 | Python 3.14
======================================================================

[+] Evidence A01 (Vuln): Alice successfully viewed Bob's profile data via IDOR!
[+] Evidence A01 (Vuln): Alice successfully accessed Bob's order #102 receipt via IDOR!
[+] Evidence A01 (Fixed): IDOR attempt on /profile/3 returned HTTP 403 Forbidden.
[+] Evidence A01 (Fixed): IDOR attempt on /order/102 returned HTTP 403 Forbidden.

[+] Evidence A01 BFLA (Vuln): Customer Alice reached Admin Dashboard (HTTP 200)!
[+] Evidence A01 BFLA (Fixed): Customer Alice blocked from Admin Dashboard (HTTP 403)!

[+] Evidence A03 SQLi (Vuln): Tautology query returned all products due to SQL injection!
[+] Evidence A03 SQLi (Fixed): Parameterized query successfully neutralized injection!

[+] Evidence A03 XSS (Vuln): Unescaped script payload rendered in HTML response!
[+] Evidence A03 XSS (Fixed): Payload safely escaped as HTML entities!

[+] Evidence A05 (Vuln): Defensive security headers completely missing; server leaks: Werkzeug/2.2.2 Python/3.14
[+] Evidence A05 (Fixed): X-Frame-Options, CSP, and X-Content-Type-Options enforced!

[+] Evidence A07 (Vuln): Password stored in database as raw cleartext: ClearTextPassword123
[+] Evidence A07 (Fixed): Password cryptographically hashed: scrypt:32768:8:1$...

----------------------------------------------------------------------
Ran 7 tests in 0.923s

OK (7 passed, 0 failed, 0 errors)
```

### 8.2 Before vs. After Security Posture Comparison

| Security Control | Baseline (Vulnerable Mode) | Post-Remediation (Secure Mode) | Status |
| :--- | :--- | :--- | :---: |
| **Object Access Control** | Anyone can view any profile/order | Verified ownership check returns HTTP 403 | **RESOLVED** |
| **Admin Authorization** | Regular customers can reach `/admin` | Strict role validation returns HTTP 403 | **RESOLVED** |
| **Search Queries** | Dynamic string concatenation (`' OR '1'='1`) | SQLite parameterized binding (`?`) | **RESOLVED** |
| **Input Reflection** | Unescaped output via `\| safe` | Default context-aware HTML escaping | **RESOLVED** |
| **Security Headers** | None (`X-Frame-Options`, `CSP` missing) | Strict headers (`DENY`, `nosniff`, `CSP`) | **RESOLVED** |
| **Server Banner** | Leaks Werkzeug and Python versions | Sanitized to generic application identifier | **RESOLVED** |
| **Password Storage** | Plaintext (`AdminPass123!`) | Cryptographic `scrypt` / `PBKDF2` hashing | **RESOLVED** |
| **Session Secret** | Hardcoded static string | Cryptographically random `token_hex(32)` | **RESOLVED** |
| **Cookie Attributes** | `HttpOnly=False`, `SameSite=None` | `HttpOnly=True`, `SameSite=Lax` | **RESOLVED** |
| **Audit Logging** | Plaintext credentials logged to stdout | Sensitive data redacted from all logs | **RESOLVED** |
| **Component Currency** | Outdated `Werkzeug 2.2.2` (CVE-2023-30861) | Upgraded to patched `Werkzeug >= 3.1.9` | **RESOLVED** |

---

## 9. Conclusion & Enterprise Recommendations

The SecureShop assessment successfully demonstrated the entire application security lifecycle:
1. **Identification:** Baseline automated DAST scanning and manual code inspection effectively uncovered critical vulnerabilities across multiple OWASP categories.
2. **Investigation:** Root-cause analysis traced each issue to specific implementation flaws rather than framework deficiencies.
3. **Remediation:** Application of defense-in-depth principles (parameterization, robust authentication, least-privilege authorization, and defensive headers) eliminated all identified risks without compromising core e-commerce business functionality.
4. **Verification:** Automated regression testing provided empirical proof of before-and-after posture improvement.

### Key Recommendations for Ongoing Application Security:
1. **Adopt Automated Software Composition Analysis (SCA):** Integrate tools such as `pip-audit` or Dependabot into CI/CD pipelines to alert on known CVEs in third-party libraries.
2. **Shift-Left Static Application Security Testing (SAST):** Incorporate linters and static analyzers (e.g. Bandit, Semgrep) to intercept raw SQL queries and unsafe template rendering during code commits.
3. **Centralized Access Control Enforcement:** Centralize authorization checks within declarative middleware or decorators (`@login_required`, `@admin_required`, `@ownership_required`) to prevent accidental omission in new endpoints.
4. **Mandate Strict Security Headers:** Enforce defensive headers at the reverse proxy layer (e.g. NGINX, Cloudflare) as a baseline infrastructure standard.
