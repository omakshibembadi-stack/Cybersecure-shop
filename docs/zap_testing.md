# SecureShop — OWASP ZAP Security Testing Protocol & Execution Guide

This document is a manual security testing protocol for assessing SecureShop using **OWASP ZAP (Zed Attack Proxy)**.

> [!IMPORTANT]
> **No Pre-Populated Scan Data:**  
> In accordance with academic integrity and laboratory guidelines, scan results are **not fabricated**.  
> This document provides the structured 18-step testing workflow, configuration parameters, and ready-to-fill observation tables for you to populate during your manual testing session.

---

## 1. Manual Execution Checklist

Follow this checklist sequentially during your lab testing:

- [ ] **Step 1:** Start SecureShop in baseline vulnerable mode (`python app.py --mode vulnerable --port 8080`).
- [ ] **Step 2:** Open a local web browser and confirm the application is responding at `http://127.0.0.1:8080`.
- [ ] **Step 3:** Launch OWASP ZAP on your local machine.
- [ ] **Step 4:** Configure the target URL: `http://127.0.0.1:8080` in ZAP. Ensure your scope is strictly limited to this local address (do not scan external hosts).
- [ ] **Step 5:** Crawl/spider the application using the **ZAP Traditional Spider** (and optionally the AJAX Spider) to discover all routes (`/`, `/products`, `/product/1`, `/search`, `/login`, `/register`, `/cart`, `/orders`, `/admin/login`, `/admin/dashboard`).
- [ ] **Step 6:** Perform an **Active Scan** against the target nodes mapped in the Sites tree (especially `/search?q=` and form endpoints).
- [ ] **Step 7:** Record the scan date and time.
- [ ] **Step 8:** Record the installed OWASP ZAP version (e.g. 2.14.0, 2.15.0).
- [ ] **Step 9:** Record the exact target URL tested (`http://127.0.0.1:8080`).
- [ ] **Step 10:** Record the scan type utilized (e.g. Passive Scan, Traditional Spider + Active Scan).
- [ ] **Step 11:** Record the total number of alerts generated across all risk categories.
- [ ] **Step 12:** Categorize alerts by severity levels (High, Medium, Low, Informational).
- [ ] **Step 13:** Record the affected URLs and specific parameters flagged for each alert.
- [ ] **Step 14:** Save screenshots of significant alerts, raw HTTP requests, and HTTP responses as evidence.
- [ ] **Step 15:** Investigate significant findings by manually verifying them in the application source code (`app.py`, `routes/`, `config.py`).
- [ ] **Step 16:** Switch SecureShop to the remediated state (`python app.py --mode secure --port 8080` or via the top navigation toggle).
- [ ] **Step 17:** Run OWASP ZAP Spider and Scan again against the remediated application.
- [ ] **Step 18:** Compare the before (vulnerable) and after (secure) scan results to verify vulnerability resolution.

---

## 2. Scan Execution Metadata Log

*(Fill in these details when executing your scan in ZAP)*

* **Scan Date & Time:** `[ Enter Date & Time, e.g. 2026-10-01 15:30 ]`
* **OWASP ZAP Version:** `[ Enter ZAP Version from Help -> About, e.g. ZAP 2.15.0 ]`
* **Target URL:** `http://127.0.0.1:8080`
* **Scan Profile / Policy:** `[ e.g. Default Policy / Full Active Scan ]`
* **Total Alerts Identified (Baseline):** `[ Enter Total Count ]`
  * High Risk: `[ Count ]`
  * Medium Risk: `[ Count ]`
  * Low Risk: `[ Count ]`
  * Informational: `[ Count ]`

---

## 3. ZAP Findings & Investigation Table (Template)

Record findings from your baseline scan in the template below:

| Finding | Severity | URL | Evidence | Status |
| :--- | :--- | :--- | :--- | :--- |
| *Example: SQL Injection - SQLite* | *High* | `http://127.0.0.1:8080/search?q=` | *Syntax error or differential response* | *Investigated* |
| *Example: Missing Anti-clickjacking Header* | *Medium* | `http://127.0.0.1:8080/` | *X-Frame-Options header missing* | *Investigated* |
| *Example: Cookie No HttpOnly Flag* | *Low* | `http://127.0.0.1:8080/login` | *Set-Cookie: session=... lacks HttpOnly* | *Investigated* |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

---

## 4. Manual Verification & Evidence Collection Guide

When triaging ZAP findings, collect the following concrete evidence items for your assignment submission:

### A. SQL Injection (A03:2021)
1. **Target:** `http://127.0.0.1:8080/search`
2. **Payload to Submit:** `' OR '1'='1` or `' UNION SELECT id, username, email, password, role, bio, created_at FROM users--`
3. **Evidence to Capture:**
   - Screenshot of ZAP Alert tab showing "SQL Injection".
   - Screenshot of browser displaying extracted database records in the search cards.
   - Raw HTTP Request/Response headers from ZAP History tab.

### B. Broken Access Control / BFLA (A01:2021)
1. **Target:** `http://127.0.0.1:8080/admin/dashboard`
2. **Procedure:** Log in as standard customer `alice` (`alice` / `AlicePass456!`). Direct the browser to the admin URL.
3. **Evidence to Capture:**
   - Screenshot showing customer `alice` accessing the administrative console with HTTP 200.
   - Screenshot of the IDOR access to `http://127.0.0.1:8080/order/102` (Bob's private order).

### C. Security Misconfiguration (A05:2021)
1. **Target:** `http://127.0.0.1:8080/debug/error`
2. **Procedure:** Browse to `/debug/error` while in vulnerable mode.
3. **Evidence to Capture:**
   - Screenshot of the Werkzeug interactive traceback console displaying internal directory paths and Python code frames.
   - Response header capture showing `Server: Werkzeug/2.2.2 Python/3.14 (Vulnerable-Lab-Server)` and missing security headers (`X-Frame-Options`, `Content-Security-Policy`).

### D. Authentication / Session Weakness (A07:2021)
1. **Target:** `http://127.0.0.1:8080/login`
2. **Procedure:** Inspect `Set-Cookie` header in ZAP and verify that `HttpOnly` and `SameSite` flags are missing.
3. **Evidence to Capture:**
   - Screenshot of ZAP alert "Cookie No HttpOnly Flag".
   - Screenshot of browser developer console showing `document.cookie` reading the session token.

---

## 5. Post-Remediation Verification Scan

After applying fixes (running in `--mode secure`):
1. In ZAP, create a new session or clear previous alerts.
2. Rerun the Spider and Active Scan against `http://127.0.0.1:8080`.
3. Verify that high-severity injection alerts and configuration alerts are eliminated.
4. Record final alert counts and compare before vs. after security posture.
