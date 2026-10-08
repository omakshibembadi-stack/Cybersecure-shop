# SecureShop — E-Commerce Red Team & Application Security Assessment Lab

[![Security Posture: Lab Dual-Mode](https://img.shields.io/badge/Security%20Mode-Vulnerable%20%7C%20Fixed-blue.svg)](#)
[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-success.svg)](#)
[![DAST Tool](https://img.shields.io/badge/DAST%20Target-OWASP%20ZAP%202.15%2B-orange.svg)](#)
[![Local Only](https://img.shields.io/badge/Scope-127.0.0.1%3A5000%20Local%20Only-red.svg)](#)

---

## 1. Project Title

**SecureShop: An Educational E-Commerce Web Application for Red Team Assessment, DAST Scanning, Vulnerability Investigation, and Secure Code Remediation**

---

## 2. Project Objective

SecureShop is built specifically to fulfill the practical requirements of the **Red Team / Application Security Assignment**. It models the complete security lifecycle:

$$\text{BUILD} \longrightarrow \text{EXPOSE} \longrightarrow \text{SCAN (OWASP ZAP)} \longrightarrow \text{INVESTIGATE} \longrightarrow \text{EXPLOIT/VALIDATE SAFELY} \longrightarrow \text{FIX} \longrightarrow \text{RETEST} \longrightarrow \text{REPORT}$$

### Core Objectives:
1. **Build a Functional E-Commerce Application:** A complete, realistic online store featuring public catalog browsing, user authentication, customer shopping carts, checkout, order histories, and administrative back-office management.
2. **Expose Controlled Vulnerabilities:** Intentionally implement controlled security weaknesses spanning 6 distinct OWASP Top 10 categories within an isolated local lab.
3. **DAST Scanning with OWASP ZAP:** Provide crawlable routes and standard HTTP forms enabling automated spidering, active scanning, and passive alert analysis with OWASP Zed Attack Proxy (ZAP).
4. **Investigate Scanner Findings:** Deep-dive into each alert to answer: *What was found? Where is it located? Why does the code allow it? What is the impact? What is the technical evidence?*
5. **Safely Validate Weaknesses:** Prove exploitability in a controlled manner without destructive actions or weaponized exploits.
6. **Remediate at Code Level:** Refactor and harden the application into a secure production-grade state.
7. **Retest and Demonstrate Improvement:** Verify through automated test suites and re-scans that all vulnerabilities have been neutralized.

---

## 3. Technology Stack

* **Programming Language:** Python (Python 3.10+, verified on Python 3.14)
* **Web Framework:** Flask (WSGI web framework with modular Blueprints)
* **Database Engine:** SQLite 3 (`database.db`, embedded and self-contained)
* **Template Engine:** Jinja2 (HTML templating with layout inheritance)
* **Front-End Styling & UI:** HTML5, CSS3, JavaScript, Bootstrap 5.3.3, Bootstrap Icons
* **Security Testing Suite:** OWASP ZAP (Zed Attack Proxy), Python `unittest` framework

---

## 4. Application Architecture

SecureShop implements a classic three-tier architecture running entirely on the local loopback interface:

```
+---------------------------------------------------------------------------------+
|                       Client Browser / OWASP ZAP DAST                           |
|       (Storefront UI, Admin Console, Spider Crawler, Active Attack Payloads)    |
+---------------------------------------------------------------------------------+
                                        |
                            HTTP / Port 5000 (Local Only)
                                        v
+---------------------------------------------------------------------------------+
|                        Flask Web Application Layer                              |
|   - Modular Blueprints: Public, Auth, User, Admin                               |
|   - Dual Operational State: Vulnerable (Baseline) vs. Fixed (Remediated)        |
|   - Security Controls: Session Management, Error Handlers, Security Headers     |
+---------------------------------------------------------------------------------+
                                        |
                         Raw SQL (Vuln) vs Parameterized SQL (Fixed)
                                        v
+---------------------------------------------------------------------------------+
|                         SQLite Relational Database                              |
|           Tables: users | products | orders | order_items                       |
+---------------------------------------------------------------------------------+
```

### Directory Structure:
```text
SecureShop/
├── app.py                      # Main entrypoint / unified dual-mode runner
├── requirements.txt            # Project dependencies
├── database.db                 # Initialized SQLite database
├── database.py                 # SQLite database helper & schema initialization
├── schema.sql                  # Database schema & demo seed records
├── config.py                   # Configuration profiles (Vulnerable vs. Secure)
├── README.md                   # Comprehensive project documentation
├── REPORT.md                   # Detailed Red Team security report
├── run_vulnerable.bat          # Windows 1-click launcher for Vulnerable mode
├── run_fixed.bat               # Windows 1-click launcher for Fixed mode
├── run_tests.bat               # Windows 1-click test suite runner
│
├── vulnerable/                 # STANDALONE VULNERABLE APPLICATION
│   ├── app.py                  # Vulnerable standalone server
│   ├── database.py             # Database connector for vulnerable instance
│   ├── database.db             # Vulnerable SQLite database (plaintext passwords)
│   ├── schema.sql              # Vulnerable database schema
│   ├── requirements.txt        # Outdated dependencies (A06 CVE baseline)
│   ├── templates/              # Jinja2 templates
│   └── static/                 # CSS, JS, and image assets
│
├── fixed/                      # STANDALONE REMEDIATED SECURE APPLICATION
│   ├── app.py                  # Remediated standalone server
│   ├── database.py             # Database connector for fixed instance
│   ├── database.db             # Secure SQLite database (salted scrypt hashes)
│   ├── schema.sql              # Remediated database schema
│   ├── requirements.txt        # Modern, patched dependencies
│   ├── security.log            # Structured security audit log
│   ├── templates/              # Jinja2 templates
│   └── static/                 # CSS, JS, and image assets
│
├── templates/                  # Root Jinja templates (layout, storefront, admin)
├── static/                     # CSS stylesheets, JS scripts, placeholder images
├── instance/                   # Flask instance directory
├── screenshots/                # OWASP ZAP scan evidence & architecture diagrams
│   ├── architecture_flow.svg   # Security lifecycle pipeline diagram
│   ├── zap_scan_matrix.svg     # DAST findings matrix (Before vs. After)
│   └── README.md               # Evidence capture log
│
└── tests/                      # Automated test suites
    ├── test_security.py        # Exploit validation & defense verification tests
    ├── test_functional.py      # Core e-commerce workflow functional tests
    └── test_standalone_versions.py # Validation tests for vulnerable/ & fixed/ apps
```

---

## 5. Installation Steps

### Prerequisites:
* Windows 10/11 (or Linux/macOS)
* Python 3.10 or higher installed (or the standard Windows `py` launcher)

### Setup Instructions on Windows:

```cmd
:: 1. Open Command Prompt or PowerShell and navigate to the project directory
cd C:\Users\omaks\.gemini\antigravity\scratch\SecureShop

:: 2. Create a virtual environment
py -m venv venv

:: 3. Activate the virtual environment
venv\Scripts\activate

:: 4. Install all project dependencies
pip install -r requirements.txt

:: 5. Initialize the SQLite database with seed records
python database.py
```

---

## 6. How to Run Vulnerable Version

You can start the intentionally vulnerable version using any of the three options below:

### Option A: Using the Root Runner (Default)
```cmd
venv\Scripts\activate
python app.py
```
*(By default, `app.py` runs in `vulnerable` mode on port 5000).*

### Option B: Using the Standalone `vulnerable/` Directory
```cmd
venv\Scripts\activate
python vulnerable/app.py
```
*(Or `cd vulnerable && python app.py`).*

### Option C: Using the 1-Click Windows Batch Script
Double-click `run_vulnerable.bat` in Windows Explorer.

The vulnerable application will start at:
**`http://127.0.0.1:5000`**

---

## 7. Demo Credentials

The database is pre-seeded with realistic demonstration accounts:

| Role | Username | Password | Purpose / Notes |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin` | `AdminPass123!` | Elevated administrative portal access (`/admin/dashboard`) |
| **Normal User 1** | `alice` | `AlicePass456!` | Standard customer; owns Order #101 and #103 |
| **Normal User 2** | `bob` | `BobPass789!` | Standard customer; owns Order #102 |

---

## 8. Application Functionality

### Public Functionality:
1. **Home Page (`/`):** Features store hero banners, featured security products, quick navigation, and active security mode indicator.
2. **User Registration (`/register`):** Account registration with form validation and account persistence.
3. **User Login (`/login`):** Authentication form with session creation and role detection.
4. **Product Listing / Catalogue (`/products`):** Interactive inventory grid with category filtering (Hardware, Peripherals, Storage, Displays).
5. **Product Search (`/search`):** Search bar allowing query filtering across product titles and descriptions.
6. **Product Details (`/product/<id>`):** Detailed item specification view with warehouse stock count and "Add to Cart" action.

### Authenticated Customer Functionality:
7. **User Profile (`/profile` and `/profile/<id>`):** Customer account management showing email, role, biography, and bio update form.
8. **Shopping Cart (`/cart`):** Session-backed cart supporting adding items (`/cart/add/<id>`), removing items (`/cart/remove/<id>`), and clearing the cart (`/cart/clear`).
9. **Order History (`/orders`):** Customer order log listing previous purchases, timestamps, totals, and statuses.
10. **Order Receipt / Invoice (`/order/<id>`):** Itemized breakdown of order items, unit prices, total amount, and delivery address.
11. **Checkout (`/checkout` and `/cart/checkout`):** Order placement workflow validating shipping address and generating invoices.

### Administrative Functionality:
12. **Admin Login Portal (`/admin/login`):** Dedicated back-office login portal.
13. **Admin Dashboard (`/admin` and `/admin/dashboard`):** Business metrics including total registered users, active catalogue items, gross sales revenue, and recent orders.
14. **Product Inventory Management (`/admin/products`):** View inventory table, add new products (`/admin/products/add`), and delete products (`/admin/products/delete/<id>`).
15. **User Management Directory (`/admin/users`):** View all registered user accounts and delete users (`/admin/users/delete/<id>`).

---

## 9. Vulnerabilities Intentionally Introduced

SecureShop intentionally includes 6 controlled security weaknesses from different OWASP Top 10 categories:

### 1. A01:2021 – Broken Access Control (IDOR & Admin BFLA)
* **IDOR on User Profiles (`/profile/<id>`):** The controller checks if the user is logged in, but fails to verify that `session['user_id'] == id` or `session['role'] == 'admin'`. Authenticated customer `alice` (User #2) can view and modify `bob`'s private profile (`/profile/3`).
* **IDOR on Customer Orders (`/order/<id>`):** Fails to verify order ownership. Authenticated customer `alice` can view `bob`'s order receipt (`/order/102`) and leak his physical shipping address.
* **Broken Function-Level Authorization (`/admin/*`):** The administrative dashboard only checked `if 'user_id' in session:` without validating `session.get('role') == 'admin'`. As a result, standard customer `alice` can browse `/admin/dashboard`, add/delete products, and delete user accounts.

### 2. A03:2021 – Injection (SQL Injection in Search)
* **Endpoint:** `GET /search?q=`
* **Flaw:** The query string is directly interpolated into raw SQL via Python string formatting:
  ```python
  # INTENTIONALLY VULNERABLE FOR SECURITY LAB
  raw_sql = f"SELECT * FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'"
  cursor.execute(raw_sql)
  ```
* **Demonstration Payload (Tautology):** `' OR '1'='1` (returns all products).
* **Demonstration Payload (Data Extraction):** `' UNION SELECT id, username, email, password, role, 0.0, bio FROM users --` (dumps all user credentials into the product cards).

### 3. A05:2021 – Security Misconfiguration (Debug Mode & Missing Headers)
* **Flaw 1:** Flask `DEBUG = True` is enabled. Unhandled exceptions (such as visiting `/debug/error`) trigger the interactive Werkzeug debugging traceback, disclosing the source code, internal file paths, Python environment variables, and the debugger PIN.
* **Flaw 2:** Missing HTTP security headers. Responses omit `X-Frame-Options` (vulnerable to Clickjacking), `X-Content-Type-Options: nosniff` (vulnerable to MIME confusion), and `Content-Security-Policy` (CSP).
* **Flaw 3:** Information disclosure banner: broadcasts `Server: Werkzeug/2.2.2 Python/3.14 (Vulnerable-Lab-Server)`.

### 4. A06:2021 – Vulnerable / Outdated Component
* **Component:** `Werkzeug==2.2.2` (and `Jinja2==3.1.2`)
* **Known Advisory:** **CVE-2023-30861** (CVSS 7.5 High). Older Werkzeug releases omit the `Vary: Cookie` header when setting cookies. When deployed behind a reverse proxy or caching CDN, downstream caches can cache responses containing `Set-Cookie`, leaking authenticated user session cookies to other clients.
* **Jinja2 Advisory:** **CVE-2024-34064** (CVSS 5.3 Medium), attribute injection vulnerability.

### 5. A07:2021 – Authentication / Session Weakness
* **Plaintext Password Storage:** User passwords are saved directly into the database as raw cleartext strings (`password_algo = 'plaintext'`).
* **Hardcoded Secret Key:** `SECRET_KEY = "super_secret_hardcoded_lab_key_do_not_use_in_prod"`, allowing attackers to forge arbitrary session cookies offline.
* **Insecure Cookie Attributes:** `SESSION_COOKIE_HTTPONLY = False` allows client-side JavaScript to read the session cookie via `document.cookie` (session hijacking). `SESSION_COOKIE_SAMESITE = None` leaves cookies vulnerable to CSRF.
* **Session Fixation:** The session ID is not cleared upon login.
* **User Enumeration:** Login feedback explicitly reveals whether the username exists or password was incorrect.

### 6. A09:2021 – Security Logging & Monitoring Failures
* **Flaw:** The application does not maintain a persistent security audit log. Failed login attempts and unauthorized IDOR attempts are not recorded. Furthermore, login routines log raw plaintext passwords to stdout:
  ```python
  app.logger.warning(f"[INSECURE LOG] Login attempt for user='{username}' with raw password='{password}'")
  ```

---

## 10. OWASP Category Mapping

| Vulnerability ID | OWASP Category | Specific Weakness | CWE ID |
| :--- | :--- | :--- | :--- |
| **VULN-01** | **A01:2021 – Broken Access Control** | Insecure Direct Object Reference (IDOR) on `/profile/<id>` and `/order/<id>` | CWE-639 |
| **VULN-02** | **A01:2021 – Broken Access Control** | Broken Function-Level Authorization (BFLA) on `/admin/*` routes | CWE-285 |
| **VULN-03** | **A03:2021 – Injection** | SQL Injection via raw string concatenation in `/search?q=` | CWE-89 |
| **VULN-04** | **A05:2021 – Security Misconfiguration** | Debug mode enabled & unhandled traceback disclosure on `/debug/error` | CWE-200 / CWE-497 |
| **VULN-05** | **A05:2021 – Security Misconfiguration** | Missing defensive HTTP headers (`X-Frame-Options`, `CSP`, `nosniff`) | CWE-1021 / CWE-693 |
| **VULN-06** | **A06:2021 – Vulnerable/Outdated Components** | Outdated `Werkzeug==2.2.2` vulnerable to cookie cache leak (CVE-2023-30861) | CWE-1104 |
| **VULN-07** | **A07:2021 – Identification & Auth Failures** | Plaintext password storage, hardcoded secret, and insecure cookie attributes | CWE-256 / CWE-1004 |
| **VULN-08** | **A09:2021 – Security Logging Failures** | Insecure credential logging & absence of security audit trail | CWE-532 / CWE-778 |

---

## 11. How to Perform OWASP ZAP Testing

OWASP Zed Attack Proxy (ZAP) is the primary Dynamic Application Security Testing (DAST) tool for this lab.

### Step 1: Start the Vulnerable Application
```cmd
python app.py --mode vulnerable --port 5000
```
Verify the site is live at `http://127.0.0.1:5000`.

### Step 2: Configure OWASP ZAP Scope
1. Open OWASP ZAP.
2. In the ZAP menu, click **File &rarr; New Session**.
3. Under **Sites**, enter `http://127.0.0.1:5000`.
4. Right-click `http://127.0.0.1:5000` &rarr; **Include in Context &rarr; Default Context**.
5. In Context settings, ensure in-scope targets are strictly limited to `\Qhttp://127.0.0.1:5000\E.*`.

### Step 3: Spider & Crawl the Application
1. In the Sites tree, right-click `http://127.0.0.1:5000` &rarr; **Attack &rarr; Spider...**
2. Check **Recurse** and click **Start Scan**.
3. ZAP will map all routes: `/`, `/login`, `/register`, `/products`, `/search`, `/product/1`, `/cart`, `/profile`, `/orders`, `/admin/login`, `/admin/dashboard`, etc.

### Step 4: Run Active Scan
1. In the Sites tree, right-click `http://127.0.0.1:5000` &rarr; **Attack &rarr; Active Scan...**
2. In the Active Scan dialog, select the **Default Policy**.
3. Click **Start Scan**.
4. Observe the **Alerts** tab as ZAP tests SQL injection payloads, cookie attributes, error handlers, and HTTP headers.

### Step 5: Manual Exploration & Exploitation Verification
1. Open ZAP's Quick Start tab and click **Manual Explore** using the built-in browser (or configure Firefox with proxy `127.0.0.1:8080`).
2. Log in as `alice` (`AlicePass456!`).
3. Change the URL from `/profile/2` to `/profile/3` &rarr; Confirm IDOR (Bob's email is revealed).
4. Navigate to `/admin/dashboard` &rarr; Confirm Broken Admin Access Control (customer Alice accesses admin portal).
5. In the search box, input `' OR '1'='1` &rarr; Confirm SQL injection returns all products.
6. Browse to `http://127.0.0.1:5000/debug/error` &rarr; Confirm Werkzeug interactive traceback disclosure.

### Step 6: Generate ZAP Scan Report
In ZAP, navigate to **Report &rarr; Generate Report...**, select **Traditional HTML Report**, and save it as `zap_vulnerable_report.html`.

---

## 12. How to Interpret Findings

When reviewing DAST scanner output, analyze each finding using the **Five Investigative Questions**:

### Finding 1: SQL Injection in Product Search
* **What?** High-severity SQL Injection (CWE-89).
* **Where?** `GET /search?q=<payload>`
* **Why?** User input is directly formatted into the SQL query string using Python f-strings without sanitization or parameter binding.
* **Impact?** Complete database compromise, authentication bypass, data exfiltration, or table modification.
* **Evidence?** Inputting `' OR '1'='1` returns all 6 products; payload `' UNION SELECT id, username, email, password, role, 0.0, bio FROM users --` dumps user accounts into product cards.

### Finding 2: Insecure Direct Object Reference (IDOR)
* **What?** High-severity Broken Access Control (CWE-639).
* **Where?** `GET /profile/<id>` and `GET /order/<id>`
* **Why?** The controller fails to verify whether the requesting user owns the object or possesses admin privileges.
* **Impact?** Confidentiality breach: customers can read and modify other users' personal information and view sensitive order delivery addresses.
* **Evidence?** Requesting `/profile/3` while authenticated as User #2 (`alice`) returns HTTP 200 OK containing Bob's private email.

### Finding 3: Missing Anti-Clickjacking & Security Headers
* **What?** Medium-severity Security Misconfiguration (CWE-1021, CWE-693).
* **Where?** Global HTTP response headers across all routes.
* **Why?** Flask does not set defensive headers by default unless configured via middleware.
* **Impact?** Clickjacking attacks (framing in malicious iframes), MIME-type sniffing, cross-site script execution.
* **Evidence?** HTTP response headers completely lack `X-Frame-Options`, `Content-Security-Policy`, and `X-Content-Type-Options`.

### Finding 4: Insecure Session Cookie Flags
* **What?** Medium-severity Identification & Authentication Failure (CWE-1004).
* **Where?** `Set-Cookie: session=...` header.
* **Why?** `SESSION_COOKIE_HTTPONLY` is set to `False` and `SESSION_COOKIE_SAMESITE` is `None`.
* **Impact?** Session tokens can be stolen via client-side JavaScript execution (`document.cookie`), enabling account takeover.
* **Evidence?** ZAP flags the `session` cookie for missing `HttpOnly` and `SameSite` attributes.

---

## 13. Remediation Performed

All identified weaknesses have been fixed in the `fixed/` version and when running `app.py --mode secure`:

### 1. Remediating A01 (Broken Access Control):
* Added strict ownership validation in profile and order controllers:
  ```python
  if current_uid != user_id and not is_admin:
      logger.warning(f"[SECURITY INCIDENT] Unauthorized IDOR attempt by User #{current_uid} on Profile #{user_id}")
      abort(403)
  ```
* Implemented strict Role-Based Access Control on administrative routes:
  ```python
  if session.get("role") != "admin":
      abort(403)
  ```

### 2. Remediating A03 (SQL Injection):
* Replaced string concatenation with SQLite parameterized queries using `?` placeholders:
  ```python
  safe_param = f"%{query}%"
  cursor.execute(
      "SELECT * FROM products WHERE name LIKE ? OR description LIKE ?",
      (safe_param, safe_param)
  )
  ```

### 3. Remediating A05 (Security Misconfiguration):
* Set `DEBUG = False` and `TESTING = False`.
* Implemented custom 403, 404, and 500 error handlers returning generic, sanitized error pages.
* Added an `@app.after_request` middleware injecting defense-in-depth headers:
  ```python
  response.headers["X-Frame-Options"] = "DENY"
  response.headers["X-Content-Type-Options"] = "nosniff"
  response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; script-src 'self' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net; img-src 'self' data: https:;"
  response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
  response.headers["Server"] = "SecureShop-Production"
  ```

### 4. Remediating A06 (Vulnerable Components):
* Upgraded `Werkzeug` to `>=3.1.3` (fixes CVE-2023-30861).
* Upgraded `Jinja2` to `>=3.1.6` (fixes CVE-2024-34064).
* Pinned updated versions in `fixed/requirements.txt`.

### 5. Remediating A07 (Authentication Weaknesses):
* Generated a cryptographically secure 256-bit secret key: `secrets.token_hex(32)`.
* Enforced cookie attributes: `SESSION_COOKIE_HTTPONLY = True` and `SESSION_COOKIE_SAMESITE = 'Lax'`.
* Implemented salted password hashing via `werkzeug.security.generate_password_hash(password, method='scrypt')`.
* Prevented session fixation via `session.clear()` upon authentication.
* Generic authentication feedback: "Invalid username or password".

### 6. Remediating A09 (Security Logging):
* Configured structured audit logging writing to `security.log`.
* Logged all failed login attempts, unauthorized IDOR attempts, and administrative actions with timestamps and client IP addresses while redacting passwords.

---

## 14. How to Run Fixed Version

Start the remediated secure version using any of the three options below:

### Option A: Using the Root Runner
```cmd
venv\Scripts\activate
python app.py --mode secure --port 5000
```
*(Or `python app.py --fixed`).*

### Option B: Using the Standalone `fixed/` Directory
```cmd
venv\Scripts\activate
python fixed/app.py
```
*(Or `cd fixed && python app.py`).*

### Option C: Using the 1-Click Windows Batch Script
Double-click `run_fixed.bat` (or `run_secure.bat`) in Windows Explorer.

The fixed application will start at:
**`http://127.0.0.1:5000`**

---

## 15. Before/After Security Comparison

### Comprehensive Vulnerability & Remediation Matrix:

| ID | OWASP Category | Vulnerability | Affected URL | Impact | Fix Applied | Retest Verification |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | **A01: Broken Access Control** | IDOR on Profile Data | `/profile/<id>` | Authenticated customer views/edits another customer's profile | Enforced `current_uid == id or is_admin` ownership check | User #2 accessing `/profile/3` returns **HTTP 403 Forbidden** |
| **SEC-02** | **A01: Broken Access Control** | IDOR on Order Invoices | `/order/<id>` | Customer leaks another user's invoice and physical shipping address | Enforced `order.user_id == current_uid` validation | User #2 accessing `/order/102` returns **HTTP 403 Forbidden** |
| **SEC-03** | **A01: Broken Access Control** | Broken Admin Authorization (BFLA) | `/admin/dashboard`, `/admin/products`, `/admin/users` | Customer account accesses admin back-office and deletes inventory/users | Enforced `session['role'] == 'admin'` check | Customer accessing `/admin/*` returns **HTTP 403 Forbidden** |
| **SEC-04** | **A03: Injection** | SQL Injection in Search | `/search?q=` | Arbitrary SQL execution, data exfiltration, database takeover | Parameterized query using `?` placeholders | Tautology `' OR '1'='1` returns **0 records**; SQL syntax neutralized |
| **SEC-05** | **A05: Security Misconfiguration** | Debug Mode & Stack Trace Leak | `/debug/error` | Internal source paths and interactive console disclosed | Set `DEBUG = False`, added generic 403/404/500 error handlers | Returns **clean HTTP 500 error page**; zero stack trace leakage |
| **SEC-06** | **A05: Security Misconfiguration** | Missing Security Headers | Global / All Routes | Clickjacking, MIME sniffing, cross-site scripting risks | Middleware injected `X-Frame-Options`, `CSP`, `nosniff`, `Referrer-Policy` | ZAP reports **0 missing header alerts** |
| **SEC-07** | **A06: Outdated Components** | Vulnerable Dependency (CVE-2023-30861) | `Werkzeug==2.2.2` | Downstream proxy cache leaks session cookies across clients | Upgraded dependencies to `Werkzeug>=3.1.3` and `Jinja2>=3.1.6` | Dependency audit clean; `Vary: Cookie` properly set |
| **SEC-08** | **A07: Authentication Failures** | Plaintext Passwords & Cookie Flags | `/register`, `/login`, SQLite database | Passwords readable on DB compromise; cookies stealable via XSS | Salted `scrypt` hashing, random 256-bit secret, `HttpOnly`, `SameSite=Lax` | Passwords stored as hashes; cookies protected from JavaScript |
| **SEC-09** | **A09: Logging Failures** | Plaintext Password Logging & No Audit | `/login`, `/admin/*` | Credentials leaked into logs; attacks go unnoticed | Redacted passwords; structured logging to `security.log` | Security audit trail actively records failed logins and IDOR attempts |

### Automated Test Suite Execution:
Run all 17 automated verification tests:
```cmd
python -m unittest discover -s tests -p "test_*.py" -v
```
**Result:** 17 tests passed in 2.7s (0 failures, 0 errors).

---

## 16. Limitations

* **Local Laboratory Scope:** The application is architected specifically as a local security training lab. In a real-world enterprise deployment, TLS/HTTPS encryption with valid public CA certificates would be mandatory for transit security (`SESSION_COOKIE_SECURE = True`).
* **Embedded Database:** SQLite is used for zero-configuration portability. In large-scale enterprise deployments, a client-server relational database (PostgreSQL/MySQL) with connection pooling and database firewalling would be utilized.
* **Single-Server Logging:** Security logs are written to a local flat file (`security.log`). In enterprise environments, logs would be forwarded via Syslog or agents to a centralized SIEM (Splunk, Elastic SIEM, Google Chronicle) with automated alerting rules.

---

## 17. Security Disclaimer

> [!CAUTION]
> **Authorized Local Security Laboratory Notice:**  
> SecureShop is designed **strictly for authorized educational security training, academic research, and local lab assessment**.  
> The application must run **ONLY locally** on `http://127.0.0.1:5000` or `http://localhost:5000`.  
> **DO NOT** target, scan, attack, or deploy this application against any public website, university system, production environment, cloud infrastructure, or systems belonging to any other person. Testing without explicit written authorization is strictly prohibited.
