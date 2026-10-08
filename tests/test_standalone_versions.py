"""
Automated Test Suite for Standalone Vulnerable and Fixed Application Versions.
Verifies that:
1. vulnerable/app.py accurately exhibits all intended security weaknesses.
2. fixed/app.py remediates every vulnerability with defensive controls.
"""
import unittest
import sys
import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

class StandaloneVersionsTestSuite(unittest.TestCase):

    def test_vulnerable_standalone_app(self):
        """Test vulnerable/app.py standalone execution and weaknesses."""
        # Add vulnerable directory to sys.path
        vuln_dir = os.path.join(BASE_DIR, "vulnerable")
        sys.path.insert(0, vuln_dir)
        
        import vulnerable.database as vuln_db
        vuln_db.init_db(force_reseed=True)
        from vulnerable.app import app as vuln_app

        client = vuln_app.test_client()

        # 1. SQL Injection Test
        resp = client.get("/search?q=%27+OR+%271%27%3D%271")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Hardware Security Key", resp.data)
        self.assertIn(b"Anti-Glare 27-inch 4K Monitor", resp.data)

        # 2. Plaintext Password Login & IDOR Test
        client.post("/login", data={"username": "alice", "password": "AlicePass456!"}, follow_redirects=True)
        idor_resp = client.get("/profile/3")
        self.assertEqual(idor_resp.status_code, 200)
        self.assertIn(b"bob@secureshop.local", idor_resp.data)

        # 3. Order IDOR Test
        order_resp = client.get("/order/102")
        self.assertEqual(order_resp.status_code, 200)
        self.assertIn(b"108 Binary Blvd", order_resp.data)

        # 4. Broken Function Authorization (Admin Access for Customer Alice)
        admin_resp = client.get("/admin/dashboard")
        self.assertEqual(admin_resp.status_code, 200)
        self.assertIn(b"Admin Dashboard", admin_resp.data)

        # 5. Security Misconfiguration Headers
        home_resp = client.get("/")
        self.assertNotIn("X-Frame-Options", home_resp.headers)
        self.assertIn("Vulnerable-Lab-Server", home_resp.headers.get("Server", ""))

        print("\n[+] Standalone vulnerable/app.py passed all vulnerability verification checks!")

    def test_fixed_standalone_app(self):
        """Test fixed/app.py standalone execution and defensive remediations."""
        fixed_dir = os.path.join(BASE_DIR, "fixed")
        sys.path.insert(0, fixed_dir)

        import fixed.database as fixed_db
        fixed_db.init_db(force_reseed=True)
        from fixed.app import app as fixed_app

        client = fixed_app.test_client()

        # 1. SQL Injection Parameterized Neutralization
        resp = client.get("/search?q=%27+OR+%271%27%3D%271")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"No products found", resp.data)

        # 2. Login as Customer Alice
        client.post("/login", data={"username": "alice", "password": "AlicePass456!"}, follow_redirects=True)

        # 3. IDOR Prevention (Must return 403 Forbidden)
        idor_resp = client.get("/profile/3")
        self.assertEqual(idor_resp.status_code, 403)

        # 4. Order IDOR Prevention (Must return 403 Forbidden)
        order_resp = client.get("/order/102")
        self.assertEqual(order_resp.status_code, 403)

        # 5. Role-Based Access Control on Admin Portal (Must return 403 Forbidden)
        admin_resp = client.get("/admin/dashboard")
        self.assertEqual(admin_resp.status_code, 403)

        # 6. Defensive Security Headers
        home_resp = client.get("/")
        self.assertEqual(home_resp.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(home_resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("Content-Security-Policy", home_resp.headers)
        self.assertEqual(home_resp.headers.get("Server"), "SecureShop-Production")

        print("[+] Standalone fixed/app.py passed all remediation verification checks!")

if __name__ == "__main__":
    unittest.main()
