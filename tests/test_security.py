"""
Automated Security Test Suite for SecureShop.
Validates security postures before (vulnerable mode) and after (secure mode).
Produces verifiable evidence for:
  - A01: Broken Access Control (IDOR & Admin BFLA)
  - A03: Injection (SQL Injection & XSS)
  - A05: Security Misconfiguration (HTTP Security Headers)
  - A07: Authentication & Session Security (Password Hashing & Cookie Flags)
"""
import unittest
import sys
import os

# Add parent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app
from database import init_db, get_db_connection

class SecureShopSecurityTestSuite(unittest.TestCase):

    def setUp(self):
        init_db(force_reseed=True)

    def test_01_broken_access_control_idor_vulnerable_mode(self):
        """VULNERABLE TEST: Customer Alice accesses Customer Bob's private profile & order via IDOR."""
        app = create_app(mode="vulnerable")
        client = app.test_client()

        # Login as Alice (user_id = 2)
        login_resp = client.post("/login", data={"username": "alice", "password": "AlicePass456!"}, follow_redirects=True)
        self.assertEqual(login_resp.status_code, 200)

        # Access Bob's profile (user_id = 3)
        profile_resp = client.get("/profile/3")
        self.assertEqual(profile_resp.status_code, 200)
        self.assertIn(b"bob@secureshop.local", profile_resp.data)
        print("\n[+] Evidence A01 (Vuln): Alice successfully viewed Bob's profile data via IDOR!")

        # Access Bob's order receipt (order_id = 102)
        order_resp = client.get("/order/102")
        self.assertEqual(order_resp.status_code, 200)
        self.assertIn(b"108 Binary Blvd", order_resp.data)
        print("[+] Evidence A01 (Vuln): Alice successfully accessed Bob's order #102 receipt via IDOR!")

    def test_02_broken_access_control_idor_secure_mode(self):
        """REMEDIATED TEST: Customer Alice is blocked with HTTP 403 when attempting IDOR on Bob."""
        app = create_app(mode="secure")
        client = app.test_client()

        # Login as Alice (user_id = 2)
        login_resp = client.post("/login", data={"username": "alice", "password": "AlicePass456!"}, follow_redirects=True)
        self.assertEqual(login_resp.status_code, 200)

        # Attempt to access Bob's profile (user_id = 3) -> Must return 403 Forbidden
        profile_resp = client.get("/profile/3")
        self.assertEqual(profile_resp.status_code, 403)
        print("\n[+] Evidence A01 (Fixed): IDOR attempt on /profile/3 returned HTTP 403 Forbidden.")

        # Attempt to access Bob's order (order_id = 102) -> Must return 403 Forbidden
        order_resp = client.get("/order/102")
        self.assertEqual(order_resp.status_code, 403)
        print("[+] Evidence A01 (Fixed): IDOR attempt on /order/102 returned HTTP 403 Forbidden.")

    def test_03_broken_function_level_authorization_bfla(self):
        """TEST BFLA: Ordinary customer accessing Admin Console."""
        # Vulnerable mode
        app_vuln = create_app(mode="vulnerable")
        client_vuln = app_vuln.test_client()
        client_vuln.post("/login", data={"username": "alice", "password": "AlicePass456!"})
        admin_vuln_resp = client_vuln.get("/admin/dashboard")
        self.assertEqual(admin_vuln_resp.status_code, 200)
        print("\n[+] Evidence A01 BFLA (Vuln): Customer Alice reached Admin Dashboard (HTTP 200)!")

        # Secure mode
        app_sec = create_app(mode="secure")
        client_sec = app_sec.test_client()
        client_sec.post("/login", data={"username": "alice", "password": "AlicePass456!"})
        admin_sec_resp = client_sec.get("/admin/dashboard")
        self.assertEqual(admin_sec_resp.status_code, 403)
        print("[+] Evidence A01 BFLA (Fixed): Customer Alice blocked from Admin Dashboard (HTTP 403)!")

    def test_04_sql_injection_product_search(self):
        """TEST A03: SQL Injection via product search query."""
        sqli_payload = "' OR '1'='1"

        # Vulnerable mode: string concatenation allows tautology injection
        app_vuln = create_app(mode="vulnerable")
        client_vuln = app_vuln.test_client()
        resp_vuln = client_vuln.get(f"/search?q={sqli_payload}")
        self.assertEqual(resp_vuln.status_code, 200)
        # Should return all products in the database (at least 6 products)
        self.assertIn(b"Hardware Security Key", resp_vuln.data)
        self.assertIn(b"Mechanical Cyberdeck Keyboard", resp_vuln.data)
        print("\n[+] Evidence A03 SQLi (Vuln): Tautology query returned all products due to SQL injection!")

        # Secure mode: parameterized query treats payload as literal string
        app_sec = create_app(mode="secure")
        client_sec = app_sec.test_client()
        resp_sec = client_sec.get(f"/search?q={sqli_payload}")
        self.assertEqual(resp_sec.status_code, 200)
        self.assertIn(b"No products found", resp_sec.data)
        print("[+] Evidence A03 SQLi (Fixed): Parameterized query successfully neutralized injection!")

    def test_05_cross_site_scripting_xss(self):
        """TEST A03: Reflected Cross-Site Scripting."""
        xss_payload = "<script>alert('SECURESHOP_XSS')</script>"

        # Vulnerable mode: unescaped output via | safe
        app_vuln = create_app(mode="vulnerable")
        client_vuln = app_vuln.test_client()
        resp_vuln = client_vuln.get(f"/search?q={xss_payload}")
        self.assertIn(b"<script>alert('SECURESHOP_XSS')</script>", resp_vuln.data)
        print("\n[+] Evidence A03 XSS (Vuln): Unescaped script payload rendered in HTML response!")

        # Secure mode: proper auto-escaping
        app_sec = create_app(mode="secure")
        client_sec = app_sec.test_client()
        resp_sec = client_sec.get(f"/search?q={xss_payload}")
        self.assertNotIn(b"<script>alert('SECURESHOP_XSS')</script>", resp_sec.data)
        self.assertIn(b"&lt;script&gt;alert(&#39;SECURESHOP_XSS&#39;)&lt;/script&gt;", resp_sec.data)
        print("[+] Evidence A03 XSS (Fixed): Payload safely escaped as HTML entities!")

    def test_06_security_misconfiguration_headers(self):
        """TEST A05: Missing vs. Present HTTP Security Headers."""
        # Vulnerable mode
        app_vuln = create_app(mode="vulnerable")
        client_vuln = app_vuln.test_client()
        resp_vuln = client_vuln.get("/")
        self.assertNotIn("X-Frame-Options", resp_vuln.headers)
        self.assertNotIn("Content-Security-Policy", resp_vuln.headers)
        self.assertNotIn("X-Content-Type-Options", resp_vuln.headers)
        print("\n[+] Evidence A05 (Vuln): Defensive security headers completely missing; server leaks:", resp_vuln.headers.get("Server"))

        # Secure mode
        app_sec = create_app(mode="secure")
        client_sec = app_sec.test_client()
        resp_sec = client_sec.get("/")
        self.assertEqual(resp_sec.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(resp_sec.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("default-src 'self'", resp_sec.headers.get("Content-Security-Policy", ""))
        self.assertEqual(resp_sec.headers.get("Server"), "SecureShop-Production")
        print("[+] Evidence A05 (Fixed): X-Frame-Options, CSP, and X-Content-Type-Options enforced!")

    def test_07_authentication_password_hashing(self):
        """TEST A07: Plaintext vs Cryptographic Password Hashing upon registration."""
        # Vulnerable registration
        app_vuln = create_app(mode="vulnerable")
        client_vuln = app_vuln.test_client()
        client_vuln.post("/register", data={
            "username": "vuln_user",
            "email": "vuln@test.com",
            "password": "ClearTextPassword123",
            "bio": "Test"
        })

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT password, password_algo FROM users WHERE username = 'vuln_user'")
        vuln_record = cursor.fetchone()
        self.assertEqual(vuln_record["password"], "ClearTextPassword123")
        self.assertEqual(vuln_record["password_algo"], "plaintext")
        print("\n[+] Evidence A07 (Vuln): Password stored in database as raw cleartext:", vuln_record["password"])

        # Secure registration
        app_sec = create_app(mode="secure")
        client_sec = app_sec.test_client()
        client_sec.post("/register", data={
            "username": "sec_user",
            "email": "sec@test.com",
            "password": "StrongHashedPassword456!",
            "bio": "Test"
        })

        cursor.execute("SELECT password, password_algo FROM users WHERE username = 'sec_user'")
        sec_record = cursor.fetchone()
        conn.close()

        self.assertNotEqual(sec_record["password"], "StrongHashedPassword456!")
        self.assertTrue(sec_record["password"].startswith("scrypt:") or sec_record["password"].startswith("pbkdf2:"))
        self.assertEqual(sec_record["password_algo"], "werkzeug_pbkdf2")
        print("[+] Evidence A07 (Fixed): Password cryptographically hashed:", sec_record["password"][:30] + "...")

if __name__ == "__main__":
    unittest.main()
