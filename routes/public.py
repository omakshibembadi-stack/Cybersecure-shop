"""
Public-facing store routes: Index, Product Catalogue, Details, Search, and Lab Mode Toggle.
Demonstrates A03 (SQL Injection).
"""
from flask import Blueprint, render_template, request, redirect, url_for, session, current_app, flash
from database import get_db_connection

public_bp = Blueprint("public", __name__)

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

@public_bp.route("/search")
def search():
    query = request.args.get("q", "").strip()
    mode = current_app.config.get("SECURITY_MODE", "vulnerable")
    debug_query = None
    results = []

    if query:
        conn = get_db_connection()
        cursor = conn.cursor()

        if mode == "vulnerable":
            # LAB VULNERABILITY: A03 Injection
            # In vulnerable mode, user input from request.args.get('q') is directly formatted
            # into the raw SQL query string via string interpolation (f-string) without sanitization
            # or parameter binding. An attacker can supply SQLite payloads like:
            #   ' UNION SELECT id, username, email, password, role, bio, created_at FROM users--
            # or:
            #   ' OR '1'='1
            raw_sql = f"SELECT * FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'"
            debug_query = raw_sql
            try:
                cursor.execute(raw_sql)
                results = cursor.fetchall()
            except Exception as e:
                flash(f"Database Query Error: {e}", "danger")
                results = []
        else:
            # SECURE REMEDIATION: Parameterized SQL Query
            # Placeholders ('?') ensure SQLite treats all user input strictly as literal string values,
            # completely preventing SQL injection.
            safe_param = f"%{query}%"
            cursor.execute(
                "SELECT * FROM products WHERE name LIKE ? OR description LIKE ?",
                (safe_param, safe_param)
            )
            results = cursor.fetchall()

        conn.close()

    return render_template("search.html", products=results, query=query, debug_query=debug_query)

@public_bp.route("/toggle-mode")
def toggle_mode():
    current_mode = current_app.config.get("SECURITY_MODE", "vulnerable")
    new_mode = "secure" if current_mode == "vulnerable" else "vulnerable"
    current_app.config["SECURITY_MODE"] = new_mode

    # Configure session cookie settings dynamically
    if new_mode == "secure":
        current_app.config["SESSION_COOKIE_HTTPONLY"] = True
        current_app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    else:
        current_app.config["SESSION_COOKIE_HTTPONLY"] = False
        current_app.config["SESSION_COOKIE_SAMESITE"] = None

    flash(f"Switched application security mode to: {new_mode.upper()}", "info")
    return redirect(request.referrer or url_for("public.index"))
