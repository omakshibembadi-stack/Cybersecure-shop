# SecureShop — Security Testing & OWASP ZAP Evidence Artifacts

This directory contains visual artifacts, scan matrices, and evidence documentation captured during the Red Team / Application Security assessment lifecycle:

$$\text{Build} \longrightarrow \text{Expose} \longrightarrow \text{Scan (OWASP ZAP)} \longrightarrow \text{Investigate} \longrightarrow \text{Safely Validate} \longrightarrow \text{Fix} \longrightarrow \text{Retest}$$

---

## 1. Visual Evidence Artifacts

* [architecture_flow.svg](file:///screenshots/architecture_flow.svg): End-to-end security pipeline and architecture flow illustrating the transition from the vulnerable baseline to the remediated production posture.
* [zap_scan_matrix.svg](file:///screenshots/zap_scan_matrix.svg): Comprehensive OWASP ZAP 2.15.0 DAST assessment matrix contrasting baseline vulnerability alerts against post-remediation verification retests.

---

## 2. Evidence Capture Log (OWASP ZAP & Manual Exploitation)

### Artifact 1: A03 — SQL Injection Verification
* **Endpoint:** `GET /search?q=%27+OR+%271%27%3D%271`
* **Vulnerable Behavior:** Database returned all 6 inventory items regardless of search term due to unescaped tautology concatenation:
  ```sql
  SELECT * FROM products WHERE name LIKE '%' OR '1'='1%' OR description LIKE '%' OR '1'='1%'
  ```
* **Safe User Data Extraction Proof:**
  Payload: `' UNION SELECT id, username, email, password, role, 0.0, bio FROM users --`
  Rendered user accounts (`admin`, `alice`, `bob`) with plaintext passwords directly into product catalogue cards.
* **Remediated Behavior:** Query executed via parameterized binding (`?` placeholders). Output returns 0 records and neutralizes punctuation.

### Artifact 2: A01 — IDOR on Profile & Orders
* **Endpoints:** `GET /profile/3` and `GET /order/102`
* **Session Context:** Authenticated as customer `alice` (User ID #2).
* **Vulnerable Behavior:** Alice received HTTP 200 OK and viewed Bob's private email (`bob@secureshop.local`), bio, and home delivery address (`108 Binary Blvd, Cyberspace, NY 10001`).
* **Remediated Behavior:** Alice received HTTP 403 Forbidden with security incident audit logged to `security.log`.

### Artifact 3: A01 — Broken Function-Level Authorization (Admin Portal)
* **Endpoints:** `GET /admin/dashboard`, `GET /admin/products`, `GET /admin/users`
* **Session Context:** Authenticated as customer `alice` (Role: `customer`).
* **Vulnerable Behavior:** Endpoint checked only `if 'user_id' in session:`, permitting regular customer `alice` to view administrative financial totals and delete items.
* **Remediated Behavior:** Endpoint strictly checks `session.get('role') == 'admin'`, returning HTTP 403 Forbidden for customer sessions.

### Artifact 4: A05 — Security Misconfiguration (Debug Mode & Headers)
* **Vulnerable Headers:**
  ```http
  HTTP/1.1 200 OK
  Server: Werkzeug/2.2.2 Python/3.14 (Vulnerable-Lab-Server)
  (Missing: X-Frame-Options, X-Content-Type-Options, Content-Security-Policy)
  ```
* **Remediated Headers:**
  ```http
  HTTP/1.1 200 OK
  Server: SecureShop-Production
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; script-src 'self' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net; img-src 'self' data: https:;
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: geolocation=(), microphone=(), camera=()
  ```

### Artifact 5: A06 — Outdated Component (CVE-2023-30861)
* **Component:** `Werkzeug==2.2.2` &rarr; Upgraded to `Werkzeug>=3.1.3`.
* **Remediation Evidence:** Upgraded in `requirements.txt` and verified via `pip list`.

### Artifact 6: A07 — Plaintext Passwords & Cookie Flags
* **Vulnerable Database Proof:** SQLite query `SELECT username, password FROM users` returned `AdminPass123!`, `AlicePass456!`, `BobPass789!`.
* **Remediated Database Proof:** SQLite query returns salted cryptographic hashes (`scrypt:32768:8:1$...`).
* **Cookie Attributes:** `HttpOnly; SameSite=Lax` verified in response `Set-Cookie` header.

### Artifact 7: A09 — Logging & Monitoring Failures
* **Vulnerable Behavior:** Credentials dumped into stdout: `[INSECURE LOG] Login attempt for user='alice' with raw password='AlicePass456!'`.
* **Remediated Behavior:** Structured audit trail recorded to `security.log` with redacted credentials and IP addresses.
