
from pathlib import Path
import os
import sys

from dotenv import load_dotenv



# BASE DIRECTORY AND ENVIRONMENT VARIABLES


BASE_DIR = Path(__file__).resolve().parent.parent

# Load the local .env file during development.
# On Render, environment variables come from the dashboard.
load_dotenv(BASE_DIR / ".env")


 
# SECURITY SETTINGS
#

SECRET_KEY = os.getenv("SECRET_KEY", "")

DEBUG = os.getenv("DEBUG", "False").lower() == "true"

# Local development and the test suite need *some* key: Django refuses to sign
# cookies and messages with an empty one. This fallback is deliberately obvious
# and only applies when DEBUG is on or a test run is in progress, so production
# (DEBUG=False, no test command) still fails loudly if the variable is missing.
if not SECRET_KEY and (DEBUG or "test" in sys.argv):
    SECRET_KEY = "dev-insecure-secret-key-greenhill-local-only"

ALLOWED_HOSTS = [
    host.strip()
    for host in os.getenv(
        "ALLOWED_HOSTS",
        "127.0.0.1,localhost,greenhill-auth-backend2.onrender.com",
    ).split(",")
    if host.strip()
]


 
# INSTALLED APPLICATIONS
#

INSTALLED_APPS = [
    # Django applications
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    # Third-party applications
    "corsheaders",
    "rest_framework",
    "drf_spectacular",
     "oauth2_provider",

    # GreenHill applications
    "authentication",
]


 
# MIDDLEWARE


MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",

    # Handle cross-origin requests before CommonMiddleware.
    "corsheaders.middleware.CorsMiddleware",

    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",

    # Keeps the session manager's device list in step with real sessions.
    # Must come after AuthenticationMiddleware (it needs request.user) and
    # before MessageMiddleware, which is irrelevant but documents intent.
    "authentication.middleware.UserSessionMiddleware",

    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]



# URLS, TEMPLATES AND WSGI


ROOT_URLCONF = "config.urls"

# ---------------------------------------------------------------------------
# Where an unauthenticated browser is sent.
#
# django-oauth-toolkit's /o/authorize/ view applies @login_required. Pointing
# LOGIN_URL at the Google sign-in start means an app can simply redirect the
# browser to /o/authorize/... and the whole round trip -- sign in, then return
# to the authorization request -- happens without the app doing anything.
# Django appends ?next=<the full authorize URL> automatically.
# ---------------------------------------------------------------------------

LOGIN_URL = "/auth/google/login/"
LOGIN_REDIRECT_URL = "/auth/me/"

# The `next` round trip only ever returns to this host.
LOGIN_URL_ALLOWED_HOSTS = ALLOWED_HOSTS

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"



# DATABASE

# Configure these variables in the Render dashboard.
# Use the connection details from your new PostgreSQL DB.

if os.getenv("DB_NAME"):
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.getenv("DB_NAME"),
            "USER": os.getenv("DB_USER"),
            "PASSWORD": os.getenv("DB_PASSWORD"),
            "HOST": os.getenv("DB_HOST"),
            "PORT": os.getenv("DB_PORT", "5432"),
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }



# CACHE

# Used by DRF throttling (the login rate limit) and by the session manager.
#
# With no REDIS_URL the default LocMemCache is per-process, which means a rate
# limit of "10/minute" is really "10/minute per gunicorn worker". That is
# acceptable locally but too loose in production: set REDIS_URL there and
# every worker shares one counter.
#
# The Redis backend needs the `redis` package. If REDIS_URL is set but the
# package is missing, fall back to LocMemCache rather than crashing the whole
# site on boot.

REDIS_URL = os.getenv("REDIS_URL", "").strip()

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "greenhill-auth",
    }
}

if REDIS_URL:
    try:
        import redis  # noqa: F401
    except ImportError:
        import warnings

        warnings.warn(
            "REDIS_URL is set but the 'redis' package is not installed; "
            "falling back to a per-process cache.",
            RuntimeWarning,
            stacklevel=2,
        )
    else:
        CACHES = {
            "default": {
                "BACKEND": "django.core.cache.backends.redis.RedisCache",
                "LOCATION": REDIS_URL,
            }
        }


# PASSWORD VALIDATION

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "UserAttributeSimilarityValidator"
        ),
    },
    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "MinimumLengthValidator"
        ),
    },
    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "CommonPasswordValidator"
        ),
    },
    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "NumericPasswordValidator"
        ),
    },
]



# INTERNATIONALIZATION


LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True



# STATIC FILES


STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"



# EMAIL

# Console email is suitable for development.
# Configure a real email provider before sending production emails.

EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"



# CORS SETTINGS

# Allow requests from the frontend applications listed here.

CORS_ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://localhost:5174",
    "https://greenhill-auth-frontend2.onrender.com",
    "https://165.232.50.141.sslip.io",
    "https://138.197.193.101/",
]

# An origin never carries a path, and a trailing slash makes django-cors-headers
# raise `corsheaders.E014`, which is a *system check error*: it aborts every
# management command, including `manage.py test`. Normalising here means one
# stray slash can never take the whole project down again.
CORS_ALLOWED_ORIGINS = [origin.rstrip("/") for origin in CORS_ALLOWED_ORIGINS]


SESSION_COOKIE_AGE = int(os.getenv("SESSION_COOKIE_AGE", str(60 * 60 * 8)))  # 8 hours

# `login()` already cycles the key; HttpOnly keeps it away from JavaScript in
# the three frontends, which have no reason to read it.
SESSION_COOKIE_HTTPONLY = True

# How often (in seconds) the session manager rewrites `last_seen_at` for a
# browser. One write per request would mean a database write on every page
# load across all three systems.
SESSION_TOUCH_INTERVAL = int(os.getenv("SESSION_TOUCH_INTERVAL", "60"))

# Only the database backend keeps sessions server-side. The cookie and cached
# backends store the session data in the browser, which would make "revoke
# this device" impossible.
SESSION_ENGINE = "django.contrib.sessions.backends.db"



# CSRF SETTINGS

# Trust these frontend origins for Django CSRF protection.
# Include the scheme (https:// or http://) and no trailing slash.

CSRF_TRUSTED_ORIGINS = [
    "http://localhost:5173",
    "http://localhost:5174",
    "https://greenhill-auth-frontend2.onrender.com",
    "https://165.232.50.141.sslip.io",
    "https://138.197.193.101",
]

# Same normalisation as CORS above: Django rejects a trusted origin that has a
# trailing slash, and by default silently ignores nothing — the check fails.
CSRF_TRUSTED_ORIGINS = [origin.rstrip("/") for origin in CSRF_TRUSTED_ORIGINS]


# SESSION AND COOKIE SECURITY

# These settings support cookie-based sessions when the frontend
# and backend are hosted on separate HTTPS origins.

SESSION_COOKIE_SAMESITE = "Lax" if DEBUG else "None"
SESSION_COOKIE_SECURE = not DEBUG

CSRF_COOKIE_SAMESITE = "Lax" if DEBUG else "None"
CSRF_COOKIE_SECURE = not DEBUG



# RENDER HTTPS CONFIGURATION


SECURE_PROXY_SSL_HEADER = (
    "HTTP_X_FORWARDED_PROTO",
    "https",
)


# TRANSPORT SECURITY

# These are opt-in (default off) so that local runs, the test suite and the
# Django test client keep working over plain http. A production deployment
# MUST set SECURE_SSL_REDIRECT=True and SECURE_HSTS_SECONDS=31536000.
#
# `manage.py check --deploy` warns about every one of these that is left at its
# insecure default, which is the intended reminder.

SECURE_SSL_REDIRECT = os.getenv("SECURE_SSL_REDIRECT", "False").lower() == "true"

SECURE_HSTS_SECONDS = int(os.getenv("SECURE_HSTS_SECONDS", "0"))

SECURE_HSTS_INCLUDE_SUBDOMAINS = SECURE_HSTS_SECONDS > 0
SECURE_HSTS_PRELOAD = SECURE_HSTS_SECONDS > 0

# Do not let a browser guess a content type and execute something unexpected.
SECURE_CONTENT_TYPE_NOSNIFF = True

SECURE_REFERRER_POLICY = "same-origin"

# The IdP never needs to be framed by anyone, not even the three systems.
X_FRAME_OPTIONS = "DENY"



# DJANGO REST FRAMEWORK


REST_FRAMEWORK = {
    "DEFAULT_SCHEMA_CLASS": (
        "drf_spectacular.openapi.AutoSchema"
    ),
    "DEFAULT_THROTTLE_RATES": {
        "login": "10/minute",
    },
}


# API DOCUMENTATION


SPECTACULAR_SETTINGS = {
    "TITLE": "GreenHill Authentication API",
    "DESCRIPTION": (
        "API documentation for the GreenHill "
        "centralized authentication system."
    ),
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
}



# DEFAULT PRIMARY KEY


DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# GreenHill Single Sign-On (OAuth 2.0 + OpenID Connect)
#
# Every value that matters is set explicitly rather than inherited, because
# several django-oauth-toolkit 3.4 defaults are unsafe for a production SSO
# provider:
#   REFRESH_TOKEN_EXPIRE_SECONDS   -> None (refresh tokens never expire)
#   REFRESH_TOKEN_REUSE_PROTECTION -> False
#   ID_TOKEN_EXPIRE_SECONDS        -> 36000 (10 hours)
#   OIDC_RP_INITIATED_LOGOUT_ENABLED -> False
#   ALLOWED_REDIRECT_URI_SCHEMES   -> ["http", "https"]
OAUTH2_PROVIDER = {

    "OAUTH2_VALIDATOR_CLASS": (
        "authentication.oauth_validators.GreenHillOAuth2Validator"
    ),

    # ---- Discovery identity ----

    "OIDC_ENABLED": True,
    "OIDC_RSA_PRIVATE_KEY": os.environ.get(
        "OIDC_RSA_PRIVATE_KEY", ""
    ),
    "OIDC_ISS_ENDPOINT": os.environ.get(
        "OIDC_ISS_ENDPOINT",
        "https://greenhill-auth-backend2.onrender.com/o",
    ),

    # ---- Token lifetimes ----

    # Short-lived access token, long-lived refresh token: a relying party can
    # keep the user signed in without holding a long-lived bearer credential.
    "ACCESS_TOKEN_EXPIRE_SECONDS": 3600,
    "ID_TOKEN_EXPIRE_SECONDS": 3600,
    "REFRESH_TOKEN_EXPIRE_SECONDS": 60 * 60 * 24 * 14,

    "ROTATE_REFRESH_TOKEN": True,
    # Rotating without reuse detection buys nothing: a stolen refresh token
    # would simply rotate alongside the real one. With this on, replaying a
    # used token invalidates the entire token family.
    "REFRESH_TOKEN_REUSE_PROTECTION": True,

    # ---- Authorization code flow hardening ----

    "PKCE_REQUIRED": True,

    # Only https in production. http stays available under DEBUG so localhost
    # frontends keep working.
    "ALLOWED_REDIRECT_URI_SCHEMES": (
        ["http", "https"] if DEBUG else ["https"]
    ),

    # "auto" suppresses the consent screen for clients flagged
    # skip_authorization. All three systems are first-party, so the prompt is
    # friction without security benefit.
    "REQUEST_APPROVAL_PROMPT": "auto",

    # ---- RP-initiated logout ----

    "OIDC_RP_INITIATED_LOGOUT_ENABLED": True,
    "OIDC_RP_INITIATED_LOGOUT_DELETE_TOKENS": True,
    "OIDC_RP_INITIATED_LOGOUT_ALWAYS_PROMPT": True,

    # ---- RFC 9700 / OAuth 2.0 Security BCP ----

    # Behaviour gates: the insecure request is rejected instead of warned about.
    # None of these grants are used by this service or by the three systems.
    "COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT": True,
    "COMPLIANT_BCP_RFC9700_PASSWORD_GRANT": True,
    "COMPLIANT_BCP_RFC9700_PKCE_METHOD": True,
    "COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS": True,

    # Configuration gates: promote RFC 9700 violations of the covered settings
    # from `check --deploy` warnings to errors.
    "COMPLIANT_BCP_RFC9700_REFRESH_TOKEN": True,
    "COMPLIANT_BCP_RFC9700_REDIRECT_URI_SCHEME": True,
    "COMPLIANT_BCP_RFC9700_REDIRECT_URI_MATCHING": True,
    "COMPLIANT_BCP_RFC9700_PKCE_REQUIRED": True,

    # Deliberately NOT enabled yet, because their exact runtime effect has not
    # been reviewed against the frontends:
    #   COMPLIANT_BCP_RFC9700_ACCESS_TOKEN_TRANSPORT
    #       would reject bearer tokens supplied outside the Authorization header
    #   COMPLIANT_BCP_RFC9700_TOKEN_STORAGE
    #       constrains how tokens are persisted

    "SCOPES": {
        "openid": "Authenticate users",
        "profile": "Read basic profile information",
        "email": "Read user email address",
        "eid": "Access Executive Intelligence Dashboard",
        "procurement": "Access Procurement Management",
        "incident": "Access Incident Management",
    },
}


LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
        },
    },
    "loggers": {
        "django.request": {
            "handlers": ["console"],
            "level": "ERROR",
            "propagate": False,
        },
    },
}
