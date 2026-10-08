"""
Functional Test Suite for SecureShop E-Commerce Application.
Validates all core operational functionality required by Section 14:
  1. Registration
  2. Login
  3. Product listing
  4. Search
  5. Cart
  6. Orders
  7. Admin login
  8. Admin product management
"""
import unittest
import sys
import os

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app
from database import init_db, get_db_connection

class SecureShopFunctionalTestSuite(unittest.TestCase):

    def setUp(self):
        # Fresh database initialization before tests
        init_db(force_reseed=True)
        self.app = create_app(mode="secure")
        self.client = self.app.test_client()

    def test_01_user_registration(self):
        """Test 1: User Registration workflow."""
        resp = self.client.post("/register", data={
            "username": "newuser",
            "email": "newuser@secureshop.local",
            "password": "SecurePassword123!",
            "bio": "New test shopper bio."
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Registration successful", resp.data)

        # Verify record in database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = 'newuser'")
        user = cursor.fetchone()
        conn.close()
        self.assertIsNotNone(user)
        self.assertEqual(user["email"], "newuser@secureshop.local")

    def test_02_user_login_and_logout(self):
        """Test 2: User Login and Logout authentication workflow."""
        # Login with seed user Alice
        login_resp = self.client.post("/login", data={
            "username": "alice",
            "password": "AlicePass456!"
        }, follow_redirects=True)
        self.assertEqual(login_resp.status_code, 200)
        self.assertIn(b"Welcome back, alice", login_resp.data)

        # Logout
        logout_resp = self.client.get("/logout", follow_redirects=True)
        self.assertEqual(logout_resp.status_code, 200)
        self.assertIn(b"You have been signed out successfully", logout_resp.data)

    def test_03_product_listing(self):
        """Test 3: Product Listing catalogue and details view."""
        # Catalogue view
        resp = self.client.get("/products")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Hardware Security Key", resp.data)
        self.assertIn(b"Mechanical Cyberdeck Keyboard", resp.data)

        # Product details view
        detail_resp = self.client.get("/product/1")
        self.assertEqual(detail_resp.status_code, 200)
        self.assertIn(b"Hardware Security Key (FIDO2/U2F)", detail_resp.data)
        self.assertIn(b"Cryptographic USB-C/NFC hardware security token", detail_resp.data)

    def test_04_product_search(self):
        """Test 4: Product Search functionality."""
        search_resp = self.client.get("/search?q=Key")
        self.assertEqual(search_resp.status_code, 200)
        self.assertIn(b"Hardware Security Key", search_resp.data)

    def test_05_shopping_cart(self):
        """Test 5: Shopping Cart management (add, view, remove)."""
        # Add product 1 to cart
        add_resp = self.client.get("/cart/add/1", follow_redirects=True)
        self.assertEqual(add_resp.status_code, 200)

        # View cart
        cart_resp = self.client.get("/cart")
        self.assertEqual(cart_resp.status_code, 200)
        self.assertIn(b"Hardware Security Key", cart_resp.data)

        # Remove from cart
        remove_resp = self.client.get("/cart/remove/1", follow_redirects=True)
        self.assertEqual(remove_resp.status_code, 200)
        self.assertIn(b"Your shopping cart is empty", remove_resp.data)

    def test_06_checkout_and_order_history(self):
        """Test 6: Cart Checkout and Order History generation."""
        # Log in as Alice
        self.client.post("/login", data={"username": "alice", "password": "AlicePass456!"})

        # Add product to cart
        self.client.get("/cart/add/2")

        # Checkout
        checkout_resp = self.client.post("/cart/checkout", data={
            "address": "777 Hackers Way, Laboratory Building B"
        }, follow_redirects=True)
        self.assertEqual(checkout_resp.status_code, 200)
        self.assertIn(b"Order #", checkout_resp.data)

        # View Order History
        orders_resp = self.client.get("/orders")
        self.assertEqual(orders_resp.status_code, 200)
        self.assertIn(b"777 Hackers Way", orders_resp.data)

    def test_07_admin_login(self):
        """Test 7: Admin Login portal."""
        admin_login_resp = self.client.post("/admin/login", data={
            "username": "admin",
            "password": "AdminPass123!"
        }, follow_redirects=True)
        self.assertEqual(admin_login_resp.status_code, 200)
        self.assertIn(b"Admin Dashboard", admin_login_resp.data)

    def test_08_admin_product_management(self):
        """Test 8: Admin Product Management (create, list, delete)."""
        # Log in as Admin
        self.client.post("/login", data={"username": "admin", "password": "AdminPass123!"})

        # Add new product
        add_resp = self.client.post("/admin/products/add", data={
            "name": "Zero-Knowledge Hardware Wallet",
            "category": "Hardware",
            "price": "199.99",
            "stock": "20",
            "description": "Air-gapped cryptocurrency and identity cold wallet."
        }, follow_redirects=True)
        self.assertEqual(add_resp.status_code, 200)
        self.assertIn(b"Zero-Knowledge Hardware Wallet", add_resp.data)

        # Retrieve new product ID from database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM products WHERE name = 'Zero-Knowledge Hardware Wallet'")
        new_prod = cursor.fetchone()
        conn.close()
        self.assertIsNotNone(new_prod)

        # Delete product
        del_resp = self.client.get(f"/admin/delete_product/{new_prod['id']}", follow_redirects=True)
        # Note: route in admin.py is /admin/products/delete/<id>
        del_resp = self.client.get(f"/admin/products/delete/{new_prod['id']}", follow_redirects=True)
        self.assertEqual(del_resp.status_code, 200)
        self.assertIn(b"deleted successfully", del_resp.data)

if __name__ == "__main__":
    unittest.main()
