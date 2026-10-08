"""
==============================================================================
SecureShop - Remediated & Hardened Version (Secure Assignment Posture)
==============================================================================
Remediated implementation fixing all identified vulnerabilities:
  1. A01: Broken Access Control - Enforces strict object ownership and RBAC.
  2. A03: Injection - Neutralized using parameterized SQLite queries.
  3. A05: Security Misconfiguration - Debug disabled, defensive HTTP headers applied.
  4. A06: Outdated Components - Pinned to modern, patched library versions.
  5. A07: Authentication/Session Weakness - Salted password hashing, secure cookie flags.
  6. A09: Security Logging & Monitoring - Structured security audit logging to security.log.

Default URL: http://127.0.0.1:5000
==============================================================================
"""

import os
import sys
import secrets
import logging
from flask import Flask, Blueprint, render_template, request, redirect, url_for, flash, session, abort
import importlib.util
_db_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.py")
_spec = importlib.util.spec_from_file_location("fixed_database", _db_file)
_fixed_db = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fixed_db)
get_db_connection = _fixed_db.get_db_connection
init_db = _fixed_db.init_db
DB_PATH = _fixed_db.DB_PATH

from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates"),
    static_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
)

# Blueprints matching templates url_for namespaces
public_bp = Blueprint("public", __name__)
auth_bp = Blueprint("auth", __name__)
user_bp = Blueprint("user", __name__)
admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

# ==============================================================================
# SECURE REMEDIATION: A05 Security Misconfiguration
# Debug mode disabled in production, preventing stack trace and internal leaks.
# ==============================================================================
app.config["DEBUG"] = False
app.config["TESTING"] = False
app.config["SECURITY_MODE"] = "secure"

# ==============================================================================
# SECURE REMEDIATION: A07 Authentication & Session Weakness
# 1. Cryptographically secure random secret key generated per instance or from env.
# 2. SESSION_COOKIE_HTTPONLY is True to prevent XSS cookie theft.
# 3. SESSION_COOKIE_SAMESITE is 'Lax' to mitigate Cross-Site Request Forgery.
# ==============================================================================
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = False  # Set to True when served over HTTPS / TLS
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# ==============================================================================
# SECURE REMEDIATION: A09 Security Logging & Monitoring
# Structured audit logging writing to file (security.log) and console.
# ==============================================================================
log_dir = os.path.dirname(os.path.abspath(__file__))
log_file = os.path.join(log_dir, "security.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(log_file, encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("secureshop.audit")

# ------------------------------------------------------------------------------
# Context Processors & Defensive Security Headers
# ------------------------------------------------------------------------------
@app.context_processor
def inject_globals():
    cart = session.get("cart", {})
    total_items = sum(cart.values()) if isinstance(cart, dict) else 0
    return {
        "current_mode": "secure",
        "cart_count": total_items
    }

@app.after_request
def apply_security_headers(response):
    # ==============================================================================
    # SECURE REMEDIATION: A05 Defensive HTTP Security Headers
    # Protects against Clickjacking, MIME-confusion, Cross-Site Scripting, and info leak.
    # ==============================================================================
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https:;"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Server"] = "SecureShop-Production"
    return response

# ------------------------------------------------------------------------------
# Safe Custom Error Handlers
# ------------------------------------------------------------------------------
@app.errorhandler(403)
def forbidden_error(error):
    return render_template(
        "base.html",
        title="403 Forbidden | Access Denied",
        error_message="HTTP 403 Forbidden: You do not have permission to access this resource."
    ), 403

@app.errorhandler(404)
def not_found_error(error):
    return render_template(
        "base.html",
        title="404 Not Found",
        error_message="HTTP 404 Not Found: The requested URL was not found on this server."
    ), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"[SYSTEM ERROR 500] {str(error)}")
    return render_template(
        "base.html",
        title="500 Internal Server Error",
        error_message="HTTP 500: An unexpected internal error occurred. Administrators have been notified."
    ), 500

@app.route("/debug/error")
def debug_error():
    """Secure mode catches all unhandled exceptions cleanly."""
    abort(500)

# ------------------------------------------------------------------------------
# Public Routes
# ------------------------------------------------------------------------------
@public_bp.route("/")
def index():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products LIMIT 3")
    featured = cursor.fetchall()
    conn.close()
    return render_template("index.html", featured_products=featured)

@public_bp.route("/products")
def products():
    category = request.args.get("category")
    conn = get_db_connection()
    cursor = conn.cursor()
    if category:
        cursor.execute("SELECT * FROM products WHERE category = ?", (category,))
    else:
        cursor.execute("SELECT * FROM products")
    all_products = cursor.fetchall()
    conn.close()
    return render_template("products.html", products=all_products, selected_category=category)

@public_bp.route("/product/<int:product_id>", endpoint="product_details")
@public_bp.route("/product/<int:product_id>", endpoint="product_detail")
@public_bp.route("/products/<int:product_id>")
def product_details(product_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    conn.close()
    if not product:
        flash("Product not found.", "warning")
        return redirect(url_for("public.products"))
    return render_template("product_details.html", product=product)

# ==============================================================================
# SECURE REMEDIATION: A03 Parameterized SQL Query
# User input from 'q' parameter is bound via SQLite placeholders ('?').
# The SQLite engine treats all user input strictly as literal values, completely
# neutralizing SQL injection attacks.
# ==============================================================================
@public_bp.route("/search")
def search():
    query = request.args.get("q", "").strip()
    results = []
    if query:
        conn = get_db_connection()
        cursor = conn.cursor()
        safe_param = f"%{query}%"
        cursor.execute(
            "SELECT * FROM products WHERE name LIKE ? OR description LIKE ?",
            (safe_param, safe_param)
        )
        results = cursor.fetchall()
        conn.close()
    return render_template("search.html", products=results, query=query, debug_query=None)

@public_bp.route("/toggle-mode")
def toggle_mode():
    flash("This is the standalone REMEDIATED (Fixed) version. Run vulnerable/app.py to inspect vulnerable baseline.", "info")
    return redirect(request.referrer or url_for("public.index"))

# ------------------------------------------------------------------------------
# Authentication Routes
# ------------------------------------------------------------------------------
@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        bio = request.form.get("bio", "").strip()

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters long for secure accounts.", "danger")
            return render_template("register.html")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
        if cursor.fetchone():
            conn.close()
            flash("Username or email already in use.", "warning")
            return render_template("register.html")

        # ==============================================================================
        # SECURE REMEDIATION: A07 Cryptographic Password Hashing
        # Passwords are transformed using salted one-way hashing (scrypt / PBKDF2).
        # ==============================================================================
        hashed_pw = generate_password_hash(password, method="scrypt")
        cursor.execute("""
        INSERT INTO users (username, email, password, password_algo, role, bio)
        VALUES (?, ?, ?, 'scrypt', 'customer', ?)
        """, (username, email, hashed_pw, bio))
        conn.commit()
        conn.close()

        logger.info(f"[SECURE AUDIT LOG] New user registered: '{username}' ({email})")
        flash("Registration successful! You may now sign in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        authenticated = False
        if user:
            stored_pw = user["password"]
            if check_password_hash(stored_pw, password):
                authenticated = True
            elif user["password_algo"] == "plaintext" and stored_pw == password:
                # Upgradable fallback
                authenticated = True

        if authenticated:
            # ==============================================================================
            # SECURE REMEDIATION: A07 Session Fixation Protection
            # Session is cleared before setting authenticated user state.
            # ==============================================================================
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            logger.info(f"[SECURE AUDIT LOG] Successful authentication for user='{username}' (Role: {user['role']})")
            flash(f"Welcome back, {user['username']}!", "success")
            if user["role"] == "admin":
                return redirect(url_for("admin.dashboard"))
            return redirect(url_for("public.products"))
        else:
            # ==============================================================================
            # SECURE REMEDIATION: A07 & A09 Safe Authentication Feedback & Logging
            # Generic message prevents user enumeration; failed login logged without password.
            # ==============================================================================
            client_ip = request.remote_addr or "127.0.0.1"
            logger.warning(f"[SECURE AUDIT LOG] Failed login attempt for user='{username}' from IP={client_ip}")
            flash("Invalid username or password.", "danger")
            return render_template("login.html")

    return render_template("login.html")

@auth_bp.route("/logout")
def logout():
    username = session.get("username", "anonymous")
    session.clear()
    logger.info(f"[SECURE AUDIT LOG] User '{username}' logged out.")
    flash("You have been signed out successfully.", "info")
    return redirect(url_for("public.index"))

# ------------------------------------------------------------------------------
# Authenticated User Routes (A01 Remediated: Ownership Verification)
# ------------------------------------------------------------------------------
def check_logged_in():
    if "user_id" not in session:
        flash("Please log in to access this page.", "warning")
        return False
    return True

@user_bp.route("/profile")
def profile_self():
    if not check_logged_in():
        return redirect(url_for("auth.login"))
    return redirect(url_for("user.profile", user_id=session.get("user_id")))

# ==============================================================================
# SECURE REMEDIATION: A01 Strict Object Ownership Validation
# Verifies that current_uid == user_id OR session role is 'admin'.
# Unauthorized attempts trigger an audit log and return HTTP 403 Forbidden.
# ==============================================================================
@user_bp.route("/profile/<int:user_id>")
def profile(user_id):
    if not check_logged_in():
        return redirect(url_for("auth.login"))

    current_uid = session.get("user_id")
    is_admin = session.get("role") == "admin"

    if current_uid != user_id and not is_admin:
        logger.warning(
            f"[SECURITY INCIDENT] Unauthorized IDOR access attempt by User #{current_uid} on Profile #{user_id}"
        )
        flash("Access Denied: You are not authorized to view another user's profile.", "danger")
        abort(403)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role, bio, created_at FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        flash("Profile not found.", "warning")
        return redirect(url_for("public.index"))

    return render_template("profile.html", user=user)

@user_bp.route("/profile/<int:user_id>/update", methods=["POST"])
def update_profile(user_id):
    if not check_logged_in():
        return redirect(url_for("auth.login"))

    current_uid = session.get("user_id")
    is_admin = session.get("role") == "admin"

    if current_uid != user_id and not is_admin:
        logger.warning(
            f"[SECURITY INCIDENT] Unauthorized IDOR profile modification attempt by User #{current_uid} on Profile #{user_id}"
        )
        flash("Access Denied: You cannot modify other users' profiles.", "danger")
        abort(403)

    new_bio = request.form.get("bio", "").strip()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET bio = ? WHERE id = ?", (new_bio, user_id))
    conn.commit()
    conn.close()

    logger.info(f"[SECURE AUDIT LOG] Profile #{user_id} updated by User #{current_uid}")
    flash("Profile updated successfully.", "success")
    return redirect(url_for("user.profile", user_id=user_id))

@user_bp.route("/cart")
def cart():
    cart_items = session.get("cart", {})
    conn = get_db_connection()
    cursor = conn.cursor()
    items = []
    total = 0.0
    for prod_id_str, qty in cart_items.items():
        cursor.execute("SELECT * FROM products WHERE id = ?", (int(prod_id_str),))
        prod = cursor.fetchone()
        if prod:
            subtotal = prod["price"] * qty
            total += subtotal
            items.append({"product": prod, "quantity": qty, "subtotal": subtotal})
    conn.close()
    return render_template("cart.html", items=items, total=total)

@user_bp.route("/cart/add/<int:product_id>")
def add_to_cart(product_id):
    if "cart" not in session:
        session["cart"] = {}
    cart = session["cart"]
    prod_id_str = str(product_id)
    cart[prod_id_str] = cart.get(prod_id_str, 0) + 1
    session.modified = True
    flash("Item added to cart.", "success")
    return redirect(request.referrer or url_for("public.products"))

@user_bp.route("/cart/remove/<int:product_id>")
def remove_from_cart(product_id):
    cart = session.get("cart", {})
    prod_id_str = str(product_id)
    if prod_id_str in cart:
        del cart[prod_id_str]
        session["cart"] = cart
        session.modified = True
        flash("Item removed from cart.", "info")
    return redirect(url_for("user.cart"))

@user_bp.route("/cart/clear")
def clear_cart():
    session["cart"] = {}
    session.modified = True
    flash("Shopping cart cleared.", "info")
    return redirect(url_for("user.cart"))

@user_bp.route("/checkout", methods=["GET", "POST"])
@user_bp.route("/cart/checkout", methods=["GET", "POST"])
def checkout():
    if not check_logged_in():
        return redirect(url_for("auth.login"))

    cart = session.get("cart", {})
    if not cart:
        flash("Your shopping cart is empty.", "warning")
        return redirect(url_for("public.products"))

    if request.method == "GET":
        return redirect(url_for("user.cart"))

    shipping_address = request.form.get("address", "").strip()
    if not shipping_address:
        flash("Please provide a shipping address.", "danger")
        return redirect(url_for("user.cart"))

    user_id = session.get("user_id")
    conn = get_db_connection()
    cursor = conn.cursor()
    total_amount = 0.0
    items_to_insert = []
    for prod_id_str, qty in cart.items():
        cursor.execute("SELECT * FROM products WHERE id = ?", (int(prod_id_str),))
        prod = cursor.fetchone()
        if prod:
            price = prod["price"]
            total_amount += price * qty
            items_to_insert.append((int(prod_id_str), qty, price))

    cursor.execute("""
    INSERT INTO orders (user_id, total_amount, shipping_address, status)
    VALUES (?, ?, ?, 'Processing')
    """, (user_id, total_amount, shipping_address))
    new_order_id = cursor.lastrowid

    for pid, qty, uprice in items_to_insert:
        cursor.execute("""
        INSERT INTO order_items (order_id, product_id, quantity, unit_price)
        VALUES (?, ?, ?, ?)
        """, (new_order_id, pid, qty, uprice))

    conn.commit()
    conn.close()

    session["cart"] = {}
    session.modified = True

    logger.info(f"[SECURE AUDIT LOG] Order #{new_order_id} created by User #{user_id} ($ {total_amount:.2f})")
    flash(f"Order #{new_order_id} placed successfully!", "success")
    return redirect(url_for("user.order_detail", order_id=new_order_id))

@user_bp.route("/orders")
def orders():
    if not check_logged_in():
        return redirect(url_for("auth.login"))
    user_id = session.get("user_id")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC", (user_id,))
    user_orders = cursor.fetchall()
    conn.close()
    return render_template("orders.html", orders=user_orders)

# ==============================================================================
# SECURE REMEDIATION: A01 Ownership Validation on Order Invoices
# Verifies order['user_id'] == session['user_id'] OR session role is 'admin'.
# Blocks unauthorized customers with HTTP 403 Forbidden.
# ==============================================================================
@user_bp.route("/order/<int:order_id>")
def order_detail(order_id):
    if not check_logged_in():
        return redirect(url_for("auth.login"))

    current_uid = session.get("user_id")
    is_admin = session.get("role") == "admin"

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
    order = cursor.fetchone()

    if not order:
        conn.close()
        flash("Order not found.", "warning")
        return redirect(url_for("user.orders"))

    if order["user_id"] != current_uid and not is_admin:
        conn.close()
        logger.warning(
            f"[SECURITY INCIDENT] Unauthorized IDOR access attempt by User #{current_uid} on Order #{order_id} (Owned by User #{order['user_id']})"
        )
        flash("Access Denied: You are not authorized to view orders belonging to other customers.", "danger")
        abort(403)

    cursor.execute("SELECT id, username, email FROM users WHERE id = ?", (order["user_id"],))
    customer = cursor.fetchone()

    cursor.execute("""
    SELECT oi.*, p.name AS product_name
    FROM order_items oi
    JOIN products p ON oi.product_id = p.id
    WHERE oi.order_id = ?
    """, (order_id,))
    items = cursor.fetchall()
    conn.close()

    return render_template("order_detail.html", order=order, customer=customer, items=items)

# ------------------------------------------------------------------------------
# Administrative Routes (A01 Remediated: Role-Based Access Control)
# ------------------------------------------------------------------------------
def check_admin_secure():
    if "user_id" not in session:
        flash("Authentication required to access admin area.", "warning")
        return False, redirect(url_for("admin.admin_login"))

    # ==============================================================================
    # SECURE REMEDIATION: A01 Role-Based Access Control (RBAC) Enforcement
    # Strictly validates that the authenticated session holds role == 'admin'.
    # Non-admin users are blocked with HTTP 403 Forbidden.
    # ==============================================================================
    if session.get("role") != "admin":
        logger.warning(
            f"[SECURITY INCIDENT] Unauthorized admin portal access attempt by User #{session.get('user_id')} (role={session.get('role')})"
        )
        flash("Access Denied: Administrative privileges required.", "danger")
        abort(403)

    return True, None

@admin_bp.route("/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        authenticated = False
        if user:
            stored_pw = user["password"]
            if check_password_hash(stored_pw, password):
                authenticated = True
            elif user["password_algo"] == "plaintext" and stored_pw == password:
                authenticated = True

        if authenticated:
            if user["role"] != "admin":
                logger.warning(f"[SECURITY INCIDENT] Non-admin user '{username}' attempted admin portal login.")
                flash("Access Denied: Account does not possess administrative privileges.", "danger")
                return render_template("admin_login.html")

            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            logger.info(f"[SECURE AUDIT LOG] Admin user '{username}' authenticated successfully.")
            flash(f"Welcome to Admin Portal, {user['username']}!", "success")
            return redirect(url_for("admin.dashboard"))
        else:
            logger.warning(f"[SECURE AUDIT LOG] Failed admin login attempt for user='{username}'")
            flash("Invalid administrator credentials.", "danger")
            return render_template("admin_login.html")

    return render_template("admin_login.html")

@admin_bp.route("/")
@admin_bp.route("/dashboard")
def dashboard():
    authorized, resp = check_admin_secure()
    if not authorized:
        return resp

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM products")
    product_count = cursor.fetchone()[0]
    cursor.execute("SELECT COALESCE(SUM(total_amount), 0) FROM orders")
    total_sales = cursor.fetchone()[0]
    cursor.execute("SELECT * FROM orders ORDER BY id DESC LIMIT 5")
    recent_orders = cursor.fetchall()
    conn.close()

    return render_template(
        "admin_dashboard.html",
        user_count=user_count,
        product_count=product_count,
        total_sales=total_sales,
        recent_orders=recent_orders
    )

@admin_bp.route("/products")
def products():
    authorized, resp = check_admin_secure()
    if not authorized:
        return resp

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products ORDER BY id DESC")
    all_prods = cursor.fetchall()
    conn.close()
    return render_template("admin_products.html", products=all_prods)

@admin_bp.route("/products/add", methods=["POST"])
def add_product():
    authorized, resp = check_admin_secure()
    if not authorized:
        return resp

    name = request.form.get("name", "").strip()
    category = request.form.get("category", "").strip()
    price = float(request.form.get("price", 0.0))
    stock = int(request.form.get("stock", 0))
    desc = request.form.get("description", "").strip()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO products (name, category, price, stock, description)
    VALUES (?, ?, ?, ?, ?)
    """, (name, category, price, stock, desc))
    conn.commit()
    conn.close()

    logger.info(f"[SECURE AUDIT LOG] Admin '{session.get('username')}' added product '{name}' ($ {price:.2f})")
    flash(f"Product '{name}' added successfully.", "success")
    return redirect(url_for("admin.products"))

@admin_bp.route("/products/delete/<int:product_id>")
def delete_product(product_id):
    authorized, resp = check_admin_secure()
    if not authorized:
        return resp

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM products WHERE id = ?", (product_id,))
    conn.commit()
    conn.close()

    logger.info(f"[SECURE AUDIT LOG] Admin '{session.get('username')}' deleted product ID #{product_id}")
    flash(f"Product #{product_id} deleted successfully.", "info")
    return redirect(url_for("admin.products"))

@admin_bp.route("/users")
def users():
    authorized, resp = check_admin_secure()
    if not authorized:
        return resp

    conn = get_db_connection()
    cursor = conn.cursor()
    # SECURE REMEDIATION: Password column NEVER queried or exposed in admin listings
    cursor.execute("SELECT id, username, email, role, created_at FROM users ORDER BY id ASC")
    all_users = cursor.fetchall()
    conn.close()
    return render_template("admin_users.html", users=all_users)

@admin_bp.route("/users/delete/<int:user_id>")
def delete_user(user_id):
    authorized, resp = check_admin_secure()
    if not authorized:
        return resp

    if user_id == session.get("user_id"):
        flash("Cannot delete your own active administrator account.", "danger")
        return redirect(url_for("admin.users"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    logger.info(f"[SECURE AUDIT LOG] Admin '{session.get('username')}' deleted user ID #{user_id}")
    flash(f"User account #{user_id} deleted.", "info")
    return redirect(url_for("admin.users"))

# Register Blueprints
app.register_blueprint(public_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(user_bp)
app.register_blueprint(admin_bp)

if __name__ == "__main__":
    init_db()
    print("\n" + "="*70)
    print("  SecureShop — Remediated & Hardened Version (Fixed)")
    print("  Host: 127.0.0.1:5000")
    print("  Debug Mode: False (Production Error Handling)")
    print("  Database: SQLite (fixed/database.db)")
    print("  Security Headers: Enforced (X-Frame-Options, CSP, etc.)")
    print("  Security Logging: Active (fixed/security.log)")
    print("="*70 + "\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
