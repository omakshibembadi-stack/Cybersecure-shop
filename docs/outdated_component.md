# SecureShop — Outdated Component Analysis (OWASP A06:2021)

This document details the intentionally outdated third-party dependency selected for the SecureShop Red Team / Application Security laboratory assignment, satisfying Section 6 of the assignment requirements.

---

## 1. Component Overview

* **Component Name:** `Werkzeug` (The foundational WSGI web application library underpinning Flask)
* **Package Ecosystem:** Python / PyPI (`pip install Werkzeug`)
* **Version Used in Baseline Lab:** `2.2.2`
* **Current / Latest Version Identified:** `3.1.9` (and `3.1.x` series)

---

## 2. Why the Old Version is Risky

In modern multi-tiered web architectures, web applications frequently sit behind caching reverse proxies, HTTP accelerators (e.g., Varnish, Nginx cache), or Content Delivery Networks (CDNs).

In `Werkzeug` versions prior to **2.2.3** (and 2.3.0+), when an application modifies or sets an HTTP cookie (such as Flask's session cookie) on a response that does not explicitly declare a `Cache-Control` header, Werkzeug **omits the `Vary: Cookie` header** from the HTTP response.

### Technical Failure Mechanism:
1. When a client performs an action that results in a `Set-Cookie` header (e.g., logging in or adding items to a cart), the server emits the response without `Vary: Cookie`.
2. An intermediate shared caching proxy or CDN caches the response along with the `Set-Cookie` header because it assumes the response is static or cacheable for subsequent clients.
3. When a second, unauthenticated user visits the same endpoint, the shared cache delivers the cached response, including the first user's `Set-Cookie: session=...` header.
4. The second user's browser accepts this cookie, resulting in an immediate **session hijacking and account takeover** without requiring credential theft or interception.

Additionally, older versions of Werkzeug running with debug mode enabled contain weaknesses in debugger PIN computation and exception handling that facilitate local information disclosure.

---

## 3. Relevant CVE & Security Advisory

* **Primary CVE Identifier:** **CVE-2023-30861**
* **CVSS v3.1 Base Score:** **7.5 (High)**
* **CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
* **CWE Classification:** `CWE-524: Use of Cache Containing Sensitive Information`
* **Affected Versions:** `Werkzeug < 2.2.3` and `< 2.3.0`
* **Patched Versions:** `Werkzeug >= 2.2.3`, `Werkzeug >= 2.3.0`, `Werkzeug 3.0.x`, `Werkzeug 3.1.x`

---

## 4. Official Sources & References

1. **National Vulnerability Database (NVD):**  
   [https://nvd.nist.gov/vuln/detail/CVE-2023-30861](https://nvd.nist.gov/vuln/detail/CVE-2023-30861)
2. **GitHub Security Advisory (GHSA):**  
   [https://github.com/pallets/werkzeug/security/advisories/GHSA-x2xv-85ph-pvg8](https://github.com/pallets/werkzeug/security/advisories/GHSA-x2xv-85ph-pvg8)
3. **PyPI Package Repository:**  
   [https://pypi.org/project/Werkzeug/](https://pypi.org/project/Werkzeug/)
4. **Pallets Project Security Bulletin:**  
   Werkzeug release 2.2.3 security release notes addressing cookie cache leakage.

---

## 5. Controlled Lab Environment Notice

> [!IMPORTANT]
> **Educational Scope Statement:**  
> The outdated version of `Werkzeug (2.2.2)` is intentionally pinned in the laboratory baseline **strictly for educational demonstration** within this authorized local testing environment (`http://127.0.0.1:8080`).  
> It must never be deployed on public internet servers, production networks, or university infrastructure.

---

## 6. Remediation & Upgrade Path

To eliminate this vulnerability, the dependency must be upgraded to a patched release:

### Before (Vulnerable Baseline):
```txt
Werkzeug==2.2.2
```

### After (Remediated Production State):
```txt
Werkzeug>=3.1.9
```

Upgrading to `Werkzeug >= 3.1.9` ensures that responses setting cookies include appropriate `Vary: Cookie` headers or strict cache controls, preventing shared cache poisoning and session leakage.
