"""
Administrative management routes: Dashboard, Inventory Management, User Directory, and Admin Login.
Demonstrates A01 (Broken Access Control / Broken Function Level Authorization).
"""
from flask import Blueprint, render_template, request, redirect, url_for, session, current_app, flash, abort
from database import get_db_connection
from werkzeug.security import check_password_hash

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

def enforce_admin_check():
    """
    Checks administrative privilege according to current mode.
    Vulnerable mode: allows any logged-in user (fails to verify role == 'admin').
    Secure mode: strictly enforces role == 'admin'.
    """
    mode = current_app.config.get("SECURITY_MODE", "vulnerable")

    if "user_id" not in session:
        flash("Authentication required to access administrative resources.", "warning")
        return False, redirect(url_for("admin.admin_login"))

    # LAB VULNERABILITY: A01 Broken Access Control
    # In vulnerable mode, the authorization check only verifies that 'user_id' exists in session.
    # It fails to verify that the logged-in user possesses administrative privileges (role == 'admin').
    # As a result, any standard customer (such as 'alice' or 'bob') can access the administrative
    # dashboard, view confidential user data, and modify or delete inventory products.
    if mode == "secure":
        # SECURE REMEDIATION: Strict Role-Based Access Control (RBAC) enforcement
        if session.get("role") != "admin":
            current_app.logger.warning(
                f"[SECURITY INCIDENT] Unauthorized admin area access attempt by User #{session.get('user_id')} (role={session.get('role')})"
            )
            flash("Access Denied: Administrative privileges required.", "danger")
            abort(403)

    return True, None

@admin_bp.route("/login", methods=["GET", "POST"])
def admin_login():
    """
    Dedicated Administrative Login Portal.
    """
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
            mode = current_app.config.get("SECURITY_MODE", "vulnerable")
            stored_pw = user["password"]
            if mode == "vulnerable":
                if stored_pw == password or check_password_hash(stored_pw, password):
                    authenticated = True
            else:
                if user["password_algo"] == "plaintext" and stored_pw == password:
                    authenticated = True
                elif check_password_hash(stored_pw, password):
                    authenticated = True

        if authenticated:
            mode = current_app.config.get("SECURITY_MODE", "vulnerable")
            # In secure mode, verify they are actually an admin
            if mode == "secure" and user["role"] != "admin":
                flash("Access Denied: Account does not possess administrative privileges.", "danger")
                return render_template("admin_login.html")

            if mode == "secure":
                session.clear()

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            flash(f"Welcome to Admin Portal, {user['username']}!", "success")
            return redirect(url_for("admin.dashboard"))
        else:
            flash("Invalid administrator credentials.", "danger")
            return render_template("admin_login.html")

    return render_template("admin_login.html")

@admin_bp.route("/")
@admin_bp.route("/dashboard")
def dashboard():
    authorized, resp = enforce_admin_check()
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
    authorized, resp = enforce_admin_check()
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
    authorized, resp = enforce_admin_check()
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

    mode = current_app.config.get("SECURITY_MODE", "vulnerable")
    if mode == "secure":
        current_app.logger.info(f"[SECURE AUDIT LOG] Admin '{session.get('username')}' added product '{name}'")

    flash(f"Product '{name}' added successfully.", "success")
    return redirect(url_for("admin.products"))

@admin_bp.route("/products/delete/<int:product_id>")
def delete_product(product_id):
    authorized, resp = enforce_admin_check()
    if not authorized:
        return resp

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM products WHERE id = ?", (product_id,))
    conn.commit()
    conn.close()

    mode = current_app.config.get("SECURITY_MODE", "vulnerable")
    if mode == "secure":
        current_app.logger.info(f"[SECURE AUDIT LOG] Admin '{session.get('username')}' deleted product ID #{product_id}")

    flash(f"Product #{product_id} deleted successfully.", "info")
    return redirect(url_for("admin.products"))

@admin_bp.route("/users")
def users():
    authorized, resp = enforce_admin_check()
    if not authorized:
        return resp

    mode = current_app.config.get("SECURITY_MODE", "vulnerable")
    conn = get_db_connection()
    cursor = conn.cursor()

    if mode == "vulnerable":
        # In vulnerable mode: password column exposed in admin view
        cursor.execute("SELECT id, username, email, role, password, password_algo, created_at FROM users ORDER BY id ASC")
    else:
        # SECURE REMEDIATION: Never query or expose passwords in administrative listings
        cursor.execute("SELECT id, username, email, role, created_at FROM users ORDER BY id ASC")

    all_users = cursor.fetchall()
    conn.close()

    return render_template("admin_users.html", users=all_users)

@admin_bp.route("/users/delete/<int:user_id>")
def delete_user(user_id):
    authorized, resp = enforce_admin_check()
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

    mode = current_app.config.get("SECURITY_MODE", "vulnerable")
    if mode == "secure":
        current_app.logger.info(f"[SECURE AUDIT LOG] Admin '{session.get('username')}' deleted user ID #{user_id}")

    flash(f"User account #{user_id} deleted.", "info")
    return redirect(url_for("admin.users"))
