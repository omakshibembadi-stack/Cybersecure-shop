"""
Configuration module for SecureShop.
Supports both 'vulnerable' (lab baseline) and 'secure' (remediated) operational modes.
"""
import os
import secrets

class BaseConfig:
    SECURITY_MODE = os.environ.get("SECURESHOP_MODE", "vulnerable").lower()
    DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.db")
    PORT = 5000
    HOST = "127.0.0.1"

class VulnerableConfig(BaseConfig):
    SECURITY_MODE = "vulnerable"
    
    # LAB VULNERABILITY: A05 Security Misconfiguration
    # Flask debug mode enabled exposes Werkzeug interactive traceback and PIN console
    DEBUG = True
    TESTING = True

    # LAB VULNERABILITY: A07 Authentication/Session Weakness
    # 1. Hardcoded weak, predictable secret key allows offline cookie forging
    # 2. Insecure session cookie attributes: missing HttpOnly allows XSS cookie theft,
    #    and missing SameSite allows cross-site request forgery
    # 3. Plaintext password handling
    SECRET_KEY = "super_secret_hardcoded_lab_key_do_not_use_in_prod"
    SESSION_COOKIE_HTTPONLY = False
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_SAMESITE = None
    PASSWORD_HASHING = "plaintext"

class SecureConfig(BaseConfig):
    SECURITY_MODE = "secure"
    
    # SECURE REMEDIATION: A05 Security Misconfiguration
    # Debug mode disabled in production, preventing stack trace and internal info leaks
    DEBUG = False
    TESTING = False

    # SECURE REMEDIATION: A07 Authentication/Session Weakness
    # Cryptographically secure random secret key generated per instance or from environment
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = False  # Set to True when served over HTTPS / TLS in production
    SESSION_COOKIE_SAMESITE = "Lax"
    PASSWORD_HASHING = "werkzeug_pbkdf2"

def get_config(mode=None):
    if mode is None:
        mode = os.environ.get("SECURESHOP_MODE", "vulnerable").lower()
    if mode == "secure":
        return SecureConfig
    return VulnerableConfig
