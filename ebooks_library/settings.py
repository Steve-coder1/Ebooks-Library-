import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = 'replace-me-in-production'
DEBUG = True
ALLOWED_HOSTS = ['*']


def env_bool(name, default=False):
    return os.getenv(name, str(int(default))).strip().lower() in ('1', 'true', 'yes', 'on')

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sitemaps',
    'accounts',
    'library',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'accounts.middleware.TokenSessionMiddleware',
]

ROOT_URLCONF = 'ebooks_library.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'library.context_processors.site_notifications',
            ],
        },
    },
]

WSGI_APPLICATION = 'ebooks_library.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 12}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
AUTH_USER_MODEL = 'accounts.User'

# HTTPS enforcement is opt-in in this starter project to avoid local runserver redirect loops.
# Set DJANGO_FORCE_HTTPS=1 in production/staging or behind a TLS-terminating proxy.
# In DEBUG, forcing HTTPS requires explicit DJANGO_FORCE_HTTPS_IN_DEBUG=1 as an extra safety guard.
FORCE_HTTPS = env_bool('DJANGO_FORCE_HTTPS', default=False)
if DEBUG and not env_bool('DJANGO_FORCE_HTTPS_IN_DEBUG', default=False):
    FORCE_HTTPS = False
SESSION_COOKIE_SECURE = FORCE_HTTPS
CSRF_COOKIE_SECURE = FORCE_HTTPS
SECURE_SSL_REDIRECT = FORCE_HTTPS

TOKEN_SESSION_IDLE_TIMEOUT_SECONDS = 1800
PASSWORD_RESET_TOKEN_TTL_SECONDS = 3600
LOGIN_RATE_LIMIT_ATTEMPTS = 5
LOGIN_RATE_LIMIT_WINDOW_SECONDS = 300
LOGIN_RATE_LIMIT_LOCK_SECONDS = 900

EBOOK_STORAGE_ROOT = BASE_DIR / 'protected_media'
EBOOK_DOWNLOAD_TOKEN_MAX_AGE_SECONDS = 600

CODE_RATE_LIMIT_ATTEMPTS = 8
CODE_RATE_LIMIT_WINDOW_SECONDS = 300
CODE_RATE_LIMIT_LOCK_SECONDS = 900
CODE_CAPTCHA_TRIGGER_ATTEMPTS = 3
CODE_DOWNLOAD_SESSION_TTL_SECONDS = 600

CODE_FAILURE_ALERT_THRESHOLD = 20

REVIEW_RATE_LIMIT_ATTEMPTS = 5
REVIEW_RATE_LIMIT_WINDOW_SECONDS = 300

CATEGORY_CACHE_TTL_SECONDS = 600

SECURE_HSTS_SECONDS = 31536000 if FORCE_HTTPS else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = FORCE_HTTPS
SECURE_HSTS_PRELOAD = FORCE_HTTPS
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SESSION_COOKIE_HTTPONLY = True

PASSWORD_RESET_RATE_LIMIT_ATTEMPTS = 5
PASSWORD_RESET_RATE_LIMIT_WINDOW_SECONDS = 3600
PASSWORD_RESET_RATE_LIMIT_LOCK_SECONDS = 3600
LOG_RETENTION_DAYS = 90
STAGING_ENVIRONMENT = False
