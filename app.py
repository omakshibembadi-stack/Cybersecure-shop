"""
SecureShop - E-Commerce Red Team / Application Security Assessment Lab
Main entry point for application startup.
Supports dual-mode execution:
  - Vulnerable Mode (Baseline for DAST / OWASP ZAP scanning)
  - Secure Mode (Remediated, hardened configuration)
Default URL: http://127.0.0.1:5000
"""
import argparse
import os
import sys
import logging
from flask import Flask, render_template, session, make_response, request, abort
from config import get_config
from database import init_db, DB_PATH
from routes.auth import auth_bp
from routes.public import public_bp
from routes.user import user_bp
from routes.admin import admin_bp

def create_app(mode=None):
    app = Flask(__name__)
    config_obj = get_config(mode)
    app.config.from_object(config_obj)

    # Configure Logging
    logging.basicConfig(
        level=logging.DEBUG if app.config.get("DEBUG") else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    # Register Blueprints
    app.register_blueprint(public_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(admin_bp)

    # Context processor to expose mode, cart count, and user state to all templates
    @app.context_processor
    def inject_global_template_vars():
        cart = session.get("cart", {})
        total_items = sum(cart.values()) if isinstance(cart, dict) else 0
        return {
            "current_mode": app.config.get("SECURITY_MODE", "vulnerable"),
            "cart_count": total_items
        }

    # Security Headers Middleware
    @app.after_request
    def apply_security_headers(response):
        mode = app.config.get("SECURITY_MODE", "vulnerable")
        if mode == "secure":
            # SECURE REMEDIATION: A05 Defensive HTTP Security Headers
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
        else:
            # LAB VULNERABILITY: A05 Security Misconfiguration
            # Explicitly omitting defensive security headers (Clickjacking / MIME sniffing / CSP)
            # and broadcasting detailed server component version information to clients and DAST scanners.
            response.headers["Server"] = "Werkzeug/2.2.2 Python/3.14 (Vulnerable-Lab-Server)"

        return response

    # LAB VULNERABILITY: A05 Security Misconfiguration - Controlled Exception Trigger
    @app.route("/debug/error")
    def debug_error():
        """
        Controlled lab endpoint to demonstrate stack trace disclosure.
        In vulnerable mode: unhandled exception triggers Werkzeug interactive debugger traceback.
        In secure mode: caught by 500 error handler returning clean generic error page.
        """
        mode = app.config.get("SECURITY_MODE", "vulnerable")
        if mode == "vulnerable":
            # Deliberately raise unhandled error to show Werkzeug debug traceback
            raise RuntimeError("DEBUG_EXCEPTION: Unhandled lab test error. Werkzeug interactive debugger exposed!")
        else:
            abort(500)

    # Error Handlers
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
            error_message="HTTP 404 Not Found: The requested URL was not found on the server."
        ), 404

    @app.errorhandler(500)
    def internal_error(error):
        mode = app.config.get("SECURITY_MODE", "vulnerable")
        if mode == "vulnerable":
            # In vulnerable mode with debug=False (fallback), still show error string
            return f"<h1>500 Internal Server Error (Lab Debug Mode)</h1><p>{str(error)}</p>", 500
        return render_template(
            "base.html",
            title="500 Internal Error",
            error_message="HTTP 500: An unexpected internal server error occurred. Please contact the administrator."
        ), 500

    return app

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SecureShop Red Team Security Assessment Lab")
    parser.add_argument(
        "--mode",
        choices=["vulnerable", "secure", "fixed"],
        default=os.environ.get("SECURESHOP_MODE", "vulnerable"),
        help="Operational security mode: 'vulnerable' (default baseline) or 'secure'/'fixed' (remediated)"
    )
    parser.add_argument("--fixed", action="store_true", help="Run in remediated fixed/secure mode")
    parser.add_argument("--vulnerable", action="store_true", help="Run in intentionally vulnerable mode")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind (default: 5000)")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    parser.add_argument("--reseed", action="store_true", help="Re-initialize database with fresh seed data")
    args = parser.parse_args()

    active_mode = "secure" if (args.fixed or args.mode in ["secure", "fixed"]) else "vulnerable"
    if args.vulnerable:
        active_mode = "vulnerable"

    # Initialize database if missing or requested
    if args.reseed or not os.path.exists(DB_PATH):
        init_db(force_reseed=True)

    app = create_app(mode=active_mode)
    
    # LAB VULNERABILITY: A05 Security Misconfiguration
    # Flask debug mode is enabled when in vulnerable mode, exposing interactive debugging console
    is_debug = (active_mode == "vulnerable")

    print("\n" + "="*70)
    print("  SecureShop — Red Team / Application Security College Lab")
    print(f"  Active Mode    : [{active_mode.upper()}]")
    print(f"  Local Address  : http://{args.host}:{args.port}")
    print(f"  Debug Mode     : {is_debug}")
    print(f"  Database Engine: SQLite3 ({DB_PATH})")
    print("="*70 + "\n")

    app.run(host=args.host, port=args.port, debug=is_debug)
