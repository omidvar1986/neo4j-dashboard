from pathlib import Path
import os
from dotenv import load_dotenv

# Load environment variables from .env file
# Load environment variables from .env file only if it exists (local development)
if (BASE_DIR / '.env').exists():
    load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
SECRET_KEY = os.getenv('SECRET_KEY', 'django-insecure-sx42i2cydw$405*%s0e_*rwr@t&ixl_6h53*dr0c9+#itt^z6y')

DEBUG = os.getenv('DEBUG', 'True').lower() == 'true'

if not DEBUG:
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True

ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')

# Logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{asctime} - {levelname} - {name} - {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} - {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'debug.log',
            'formatter': 'verbose',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
        'dashboard': {
            'handlers': ['file', 'console'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'mozilla_django_oidc',  # Keycloak/OIDC authentication
    'dashboard',
    'testcases',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
]

# Add OIDC middleware only when Keycloak is enabled
# Note: KEYCLOAK_ENABLED is checked after it's defined below, so we'll add it conditionally

ROOT_URLCONF = 'neo4j_dashboard.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'neo4j_dashboard.wsgi.application'

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('POSTGRES_NAME', 'neo_dashboard'),
        'USER': os.getenv('POSTGRES_USER', 'neo4j_dashboard_user'),
        'PASSWORD': os.getenv('POSTGRES_PASSWORD', 'Milad1986'),
        # اصلاح برای داکر: هاست باید نام سرویس داکر باشد
        'HOST': os.getenv('POSTGRES_HOST', 'postgres'),
        # اصلاح برای داکر: پورت باید پورت داخلی کانتینر باشد
        'PORT': os.getenv('POSTGRES_PORT', '5432'),
    }
}

# Session Configuration
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
SESSION_COOKIE_AGE = 1209600

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATICFILES_DIRS = [
    BASE_DIR / "dashboard/static",
]
STATIC_ROOT = BASE_DIR / "staticfiles"

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Custom User Model
AUTH_USER_MODEL = 'dashboard.user'

# Authentication Settings
KEYCLOAK_ENABLED = os.getenv('KEYCLOAK_ENABLED', 'True').lower() == 'true'

if KEYCLOAK_ENABLED:
    # Use OIDC authentication when Keycloak is enabled
    AUTHENTICATION_BACKENDS = (
        'dashboard.auth.KeycloakOIDCBackend',
        'django.contrib.auth.backends.ModelBackend',  # Fallback to local auth
    )
    LOGIN_URL = 'oidc_authentication_init'
    LOGIN_REDIRECT_URL = 'dashboard:home'
    LOGOUT_REDIRECT_URL = 'dashboard:login'  # Redirect to login page after logout
else:
    # Use local authentication when Keycloak is disabled
    AUTHENTICATION_BACKENDS = (
        'django.contrib.auth.backends.ModelBackend',
    )
    LOGIN_URL = 'dashboard:login'
    LOGIN_REDIRECT_URL = 'dashboard:home'
    LOGOUT_REDIRECT_URL = 'dashboard:login'

# CSRF Configuration
CSRF_TRUSTED_ORIGINS = [
    'https://qa-dash-neo.nxbo.ir',
    'http://qa-dash-neo.nxbo.ir',
]

# Neo4j Configuration
# Neo4j URI باید به نام سرویس داکر (neo4j) اشاره کند
NEO4J_URI = os.getenv('NEO4J_URI', 'bolt://neo4j:7687')
NEO4J_USER = os.getenv('NEO4J_USER', 'neo4j')
NEO4J_PASSWORD = os.getenv('NEO4J_PASSWORD', 'Milad1986')

# MongoDB Configuration for Test Cases
try:
    import mongoengine
    MONGODB_HOST = os.getenv('MONGODB_HOST', 'localhost')
    MONGODB_PORT = int(os.getenv('MONGODB_PORT', '27017'))
    MONGODB_USER = os.getenv('MONGODB_USER', 'mongodb_user')
    MONGODB_PASSWORD = os.getenv('MONGODB_PASSWORD', 'Milad1986')
    MONGODB_DB = os.getenv('MONGODB_DB', 'testcases_db')

    # Connect to MongoDB
    mongoengine.connect(
        db=MONGODB_DB,
        host=MONGODB_HOST,
        port=MONGODB_PORT,
        username=MONGODB_USER,
        password=MONGODB_PASSWORD,
        authentication_source='admin'
    )
except Exception as e:
    # MongoDB connection will be established when needed
    print(f"Warning: MongoDB connection not available: {e}")
    MONGODB_HOST = os.getenv('MONGODB_HOST', 'localhost')
    MONGODB_PORT = int(os.getenv('MONGODB_PORT', '27017'))
    MONGODB_USER = os.getenv('MONGODB_USER', 'mongodb_user')
    MONGODB_PASSWORD = os.getenv('MONGODB_PASSWORD', 'Milad1986')
    MONGODB_DB = os.getenv('MONGODB_DB', 'testcases_db')

# Keycloak/OIDC Configuration
if KEYCLOAK_ENABLED:
    # Keycloak Server Configuration
    KEYCLOAK_SERVER_URL = os.getenv('KEYCLOAK_SERVER_URL', 'http://localhost:8080').rstrip('/')
    KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'master')
    
    # Build OIDC endpoints from Keycloak server URL and realm
    OIDC_OP_AUTHORIZATION_ENDPOINT = os.getenv(
        'KEYCLOAK_AUTHORIZATION_ENDPOINT',
        f'{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth'
    )
    OIDC_OP_TOKEN_ENDPOINT = os.getenv(
        'KEYCLOAK_TOKEN_ENDPOINT',
        f'{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token'
    )
    OIDC_OP_USER_ENDPOINT = os.getenv(
        'KEYCLOAK_USERINFO_ENDPOINT',
        f'{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/userinfo'
    )
    OIDC_OP_LOGOUT_ENDPOINT = os.getenv(
        'KEYCLOAK_LOGOUT_ENDPOINT',
        f'{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/logout'
    )
    OIDC_OP_JWKS_ENDPOINT = f'{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs'
    
    # OIDC Client Configuration
    OIDC_RP_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', '')
    OIDC_RP_CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET', '')
    OIDC_RP_SIGN_ALGO = 'RS256'
    OIDC_RP_SCOPES = os.getenv('KEYCLOAK_SCOPE', 'openid profile email')
    
    # OIDC Redirect URI
    OIDC_REDIRECT_URI = os.getenv('KEYCLOAK_REDIRECT_URI', 'http://localhost:8000/oidc/callback/')
    
    # OIDC Claim Mappings
    OIDC_RP_USERNAME_CLAIM = os.getenv('KEYCLOAK_USERNAME_CLAIM', 'preferred_username')
    OIDC_RP_EMAIL_CLAIM = os.getenv('KEYCLOAK_EMAIL_CLAIM', 'email')
    OIDC_RP_FIRST_NAME_CLAIM = os.getenv('KEYCLOAK_FIRST_NAME_CLAIM', 'given_name')
    OIDC_RP_LAST_NAME_CLAIM = os.getenv('KEYCLOAK_LAST_NAME_CLAIM', 'family_name')
    OIDC_RP_GROUPS_CLAIM = os.getenv('KEYCLOAK_GROUPS_CLAIM', 'groups')
    
    # OIDC User Creation/Update Settings
    OIDC_CREATE_USER = os.getenv('KEYCLOAK_AUTO_CREATE_USERS', 'True').lower() == 'true'
    OIDC_UPDATE_USER = os.getenv('KEYCLOAK_AUTO_UPDATE_USERS', 'True').lower() == 'true'
    
    # OIDC Session Settings
    OIDC_RENEW_ID_TOKEN_EXPIRY_SECONDS = int(os.getenv('KEYCLOAK_SESSION_TIMEOUT', '3600'))
    
    # OIDC Issuer (for token validation)
    OIDC_OP_ISSUER = os.getenv(
        'KEYCLOAK_ISSUER',
        f'{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}'
    )
    
    # Additional OIDC Settings
    OIDC_STORE_ACCESS_TOKEN = True
    OIDC_STORE_ID_TOKEN = True
    OIDC_VERIFY_KID = True
    OIDC_USE_NONCE = True
    
    # Log OIDC configuration (without secrets)
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"Keycloak OIDC enabled for realm: {KEYCLOAK_REALM}")
    logger.info(f"Keycloak Server URL: {KEYCLOAK_SERVER_URL}")
    logger.info(f"OIDC Client ID: {OIDC_RP_CLIENT_ID}")
    logger.info(f"OIDC Redirect URI: {OIDC_REDIRECT_URI}")
    
    # Add OIDC middleware when Keycloak is enabled (must be after AuthenticationMiddleware)
    MIDDLEWARE.append('mozilla_django_oidc.middleware.SessionRefresh')