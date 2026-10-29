
from pathlib import Path
import os

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
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]



# URLS, TEMPLATES AND WSGI


ROOT_URLCONF = "config.urls"

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
]

CORS_ALLOW_CREDENTIALS = True



# CSRF SETTINGS

# Trust these frontend origins for Django CSRF protection.
# Include the scheme (https:// or http://) and no trailing slash.

CSRF_TRUSTED_ORIGINS = [
    "http://localhost:5173",
    "http://localhost:5174",
    "https://greenhill-auth-frontend2.onrender.com",
]


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



# DJANGO REST FRAMEWORK


REST_FRAMEWORK = {
    "DEFAULT_SCHEMA_CLASS": (
        "drf_spectacular.openapi.AutoSchema"
    ),
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
OAUTH2_PROVIDER = {

    
    "OAUTH2_VALIDATOR_CLASS": (
        "authentication.oauth_validators.GreenHillOAuth2Validator"
    ),

    "OIDC_ENABLED": True,
    "OIDC_RSA_PRIVATE_KEY": os.environ.get(
        "OIDC_RSA_PRIVATE_KEY", ""
    ),
    "OIDC_ISS_ENDPOINT": os.environ.get(
        "OIDC_ISS_ENDPOINT",
        "https://greenhill-auth-backend2.onrender.com/o",
    ),
    "ACCESS_TOKEN_EXPIRE_SECONDS": 3600,
    "ROTATE_REFRESH_TOKEN": True,
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