"""
Authenticated user routes: Profiles, Cart, Checkout, and Order History.
Demonstrates A01 (Broken Access Control / Insecure Direct Object References).
"""
from flask import Blueprint, render_template, request, redirect, url_for, session, current_app, flash, abort
from database import get_db_connection

user_bp = Blueprint("user", __name__)

def login_required_check():
    if "user_id" not in session:
        flash("Please log in to access this resource.", "warning")
        return False
    return True

@user_bp.route("/profile")
def profile_self():
    if not login_required_check():
        return redirect(url_for("auth.login"))
    return redirect(url_for("user.profile", user_id=session.get("user_id")))

@user_bp.route("/profile/<int:user_id>")
def profile(user_id):
    if not login_required_check():
        return redirect(url_for("auth.login"))

    mode = current_app.config.get("SECURITY_MODE", "vulnerable")
    current_uid = session.get("user_id")
    is_admin = session.get("role") == "admin"

    # LAB VULNERABILITY: A01 Broken Access Control (Insecure Direct Object Reference - IDOR)
    # In vulnerable mode, the endpoint does not verify whether the requesting user owns this profile (current_uid == user_id)
    # or has an administrator role. Any authenticated user can view other users' private profiles by altering the URL ID.
    if mode == "secure":
        # SECURE REMEDIATION: Strict Object Ownership Validation
        if current_uid != user_id and not is_admin:
            current_app.logger.warning(
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
        flash("User profile does not exist.", "warning")
        return redirect(url_for("public.index"))

    return render_template("profile.html", user=user)

@user_bp.route("/profile/<int:user_id>/update", methods=["POST"])
def update_profile(user_id):
    if not login_required_check():
        return redirect(url_for("auth.login"))

    mode = current_app.config.get("SECURITY_MODE", "vulnerable")
    current_uid = session.get("user_id")
    is_admin = session.get("role") == "admin"

    # LAB VULNERABILITY: A01 Broken Access Control (IDOR Update)
    if mode == "secure":
        if current_uid != user_id and not is_admin:
            flash("Access Denied: You cannot modify other users' profiles.", "danger")
            abort(403)

    new_bio = request.form.get("bio", "").strip()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET bio = ? WHERE id = ?", (new_bio, user_id))
    conn.commit()
    conn.close()

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
            items.append({
                "product": prod,
                "quantity": qty,
                "subtotal": subtotal
            })

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

    flash("Item added to your shopping cart.", "success")
    return redirect(request.referrer or url_for("public.products"))

@user_bp.route("/cart/remove/<int:product_id>")
def remove_from_cart(product_id):
    cart = session.get("cart", {})
    prod_id_str = str(product_id)
    if prod_id_str in cart:
        del cart[prod_id_str]
        session["cart"] = cart
        session.modified = True
        flash("Item removed from your cart.", "info")

    return redirect(url_for("user.cart"))

@user_bp.route("/cart/clear")
def clear_cart():
    session["cart"] = {}
    session.modified = True
    flash("Your shopping cart has been cleared.", "info")
    return redirect(url_for("user.cart"))

@user_bp.route("/checkout", methods=["GET", "POST"])
@user_bp.route("/cart/checkout", methods=["GET", "POST"])
def checkout():
    if not login_required_check():
        return redirect(url_for("auth.login"))

    cart = session.get("cart", {})
    if not cart:
        flash("Your shopping cart is empty.", "warning")
        return redirect(url_for("public.products"))

    if request.method == "GET":
        return redirect(url_for("user.cart"))

    shipping_address = request.form.get("address", "").strip()
    if not shipping_address:
        flash("Please provide a valid shipping address.", "danger")
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

    flash(f"Order #{new_order_id} placed successfully!", "success")
    return redirect(url_for("user.order_detail", order_id=new_order_id))

@user_bp.route("/orders")
def orders():
    if not login_required_check():
        return redirect(url_for("auth.login"))

    user_id = session.get("user_id")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC", (user_id,))
    user_orders = cursor.fetchall()
    conn.close()

    return render_template("orders.html", orders=user_orders)

@user_bp.route("/order/<int:order_id>")
def order_detail(order_id):
    if not login_required_check():
        return redirect(url_for("auth.login"))

    mode = current_app.config.get("SECURITY_MODE", "vulnerable")
    current_uid = session.get("user_id")
    is_admin = session.get("role") == "admin"

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
    order = cursor.fetchone()

    if not order:
        conn.close()
        flash("Order record not found.", "warning")
        return redirect(url_for("user.orders"))

    # LAB VULNERABILITY: A01 Broken Access Control (IDOR on Orders)
    # In vulnerable mode, any user can view any customer's order receipt and personal address
    if mode == "secure":
        # SECURE REMEDIATION: Order ownership validation
        if order["user_id"] != current_uid and not is_admin:
            conn.close()
            current_app.logger.warning(
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
