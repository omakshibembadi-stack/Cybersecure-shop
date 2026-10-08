"""
Authentication routes: Registration, Login, Logout.
Demonstrates A07 (Authentication/Session Weakness).
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_db_connection

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        bio = request.form.get("bio", "").strip()

        mode = current_app.config.get("SECURITY_MODE", "vulnerable")

        if not username or not email or not password:
            flash("All required fields must be filled out.", "danger")
            return render_template("register.html")

        # In secure mode: enforce password complexity
        if mode == "secure":
            if len(password) < 8:
                flash("Password must be at least 8 characters long for secure accounts.", "danger")
                return render_template("register.html")

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check existing user
        cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
        if cursor.fetchone():
            conn.close()
            flash("Username or Email already registered.", "warning")
            return render_template("register.html")

        # LAB VULNERABILITY: A07 Authentication/Session Weakness
        # In vulnerable mode:
        # Passwords are saved directly in cleartext into the database. If the database file is read
        # or dumped via SQL Injection, credentials are immediately compromised without any brute-force effort.
        if mode == "vulnerable":
            cursor.execute("""
            INSERT INTO users (username, email, password, password_algo, role, bio)
            VALUES (?, ?, ?, 'plaintext', 'customer', ?)
            """, (username, email, password, bio))
        else:
            # SECURE REMEDIATION: Cryptographic Password Hashing
            # Passwords are transformed using salted one-way hashing (scrypt / PBKDF2).
            hashed_pw = generate_password_hash(password, method="scrypt" if hasattr(generate_password_hash, "__name__") else "pbkdf2:sha256")
            cursor.execute("""
            INSERT INTO users (username, email, password, password_algo, role, bio)
            VALUES (?, ?, ?, 'werkzeug_pbkdf2', 'customer', ?)
            """, (username, email, hashed_pw, bio))

        conn.commit()
        conn.close()

        flash("Registration successful! You may now sign in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        mode = current_app.config.get("SECURITY_MODE", "vulnerable")

        # LAB VULNERABILITY: A07 Authentication/Session Weakness - Logging cleartext credentials
        if mode == "vulnerable":
            current_app.logger.warning(
                f"[INSECURE LOG] Login attempt for user='{username}' with raw plaintext password='{password}'"
            )
        else:
            current_app.logger.info(
                f"[SECURE AUDIT LOG] Login attempt received for user='{username}' [CREDENTIALS REDACTED]"
            )

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        authenticated = False
        if user:
            stored_password = user["password"]
            algo = user["password_algo"]

            if mode == "vulnerable":
                # In vulnerable mode: direct cleartext string comparison
                if stored_password == password or check_password_hash(stored_password, password):
                    authenticated = True
            else:
                # In secure mode: verify using constant-time cryptographic hash comparison
                if algo == "plaintext":
                    if stored_password == password:
                        authenticated = True
                else:
                    if check_password_hash(stored_password, password):
                        authenticated = True

        if authenticated:
            # LAB VULNERABILITY: A07 Authentication/Session Weakness - Session Fixation
            # In vulnerable mode, existing session tokens are reused without regeneration.
            # In secure mode: session.clear() purges previous session state to protect against session fixation.
            if mode == "secure":
                session.clear()

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash(f"Welcome back, {user['username']}!", "success")

            if user["role"] == "admin":
                return redirect(url_for("admin.dashboard"))
            return redirect(url_for("public.products"))
        else:
            if mode == "vulnerable":
                # Leaking user account existence
                if not user:
                    flash("User does not exist in the database.", "danger")
                else:
                    flash("Incorrect password for specified user.", "danger")
            else:
                # Generic authentication failure message
                flash("Invalid username or password.", "danger")

            return render_template("login.html")

    return render_template("login.html")

@auth_bp.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out successfully.", "info")
    return redirect(url_for("public.index"))
