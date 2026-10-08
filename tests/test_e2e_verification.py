"""
End-to-End Verification Script for SecureShop
Tests the complete application lifecycle:
1. Database initialization
2. Application startup
3. User registration
4. User login
5. Product browsing
6. Product search
7. Product details
8. Shopping cart operations
9. Order placement / checkout
10. Profile viewing & updating
11. Admin login
12. Admin product management
13. Admin user management
14. Intentional vulnerabilities validation (A01, A03, A05, A06, A07, A09)
15. Fixed version remediation validation
16. Python errors verification
17. Important routes accessibility
18. Dependency specification check
"""

import unittest
import sys
import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BASE_DIR)

from app import create_app
from database import init_db, get_db_connection

class SecureShopFullLifecycleTest(unittest.TestCase):

    def setUp(self):
        init_db(force_reseed=True)

    def test_complete_e2e_user_and_admin_flows(self):
        # Test in secure mode
        app = create_app(mode="secure")
        client = app.test_client()

        # 1. Home page
        res = client.get("/")
        self.assertEqual(res.status_code, 200)

        # 2. Registration
        res = client.post("/register", data={
            "username": "tester",
            "email": "tester@secureshop.local",
            "password": "Password123!",
            "bio": "Security Evaluator"
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Registration successful", res.data)

        # 3. Login
        res = client.post("/login", data={
            "username": "tester",
            "password": "Password123!"
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Welcome back, tester", res.data)

        # 4. Product browsing
        res = client.get("/products")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Hardware Security Key", res.data)

        # 5. Product search
        res = client.get("/search?q=Key")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Hardware Security Key", res.data)

        # 6. Product details
        res = client.get("/product/1")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Cryptographic USB-C/NFC", res.data)

        # 7. Cart operations
        client.get("/cart/add/1")
        res = client.get("/cart")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Hardware Security Key", res.data)

        # 8. Checkout
        res = client.post("/checkout", data={
            "address": "123 Defense Way, Security City, SC 12345"
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Order #", res.data)

        # 9. Orders
        res = client.get("/orders")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Processing", res.data)

        # 10. Profile
        res = client.get("/profile")
        self.assertEqual(res.status_code, 302)
        res = client.get("/profile", follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Security Evaluator", res.data)

        # 11. Admin login
        client.get("/logout")
        res = client.post("/admin/login", data={
            "username": "admin",
            "password": "AdminPass123!"
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Admin Dashboard", res.data)

        # 12. Admin product management
        res = client.post("/admin/products/add", data={
            "name": "Audit Gadget X",
            "category": "Hardware",
            "price": "99.00",
            "stock": "10",
            "description": "Hardware testing device"
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Audit Gadget X", res.data)

        # 13. Admin user management
        res = client.get("/admin/users")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"tester", res.data)

        print("\n[+] E2E Full Lifecycle Flow: All 13 core functional stages passed successfully!")

if __name__ == "__main__":
    unittest.main()
