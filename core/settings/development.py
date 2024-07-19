from .base import *


# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'django_jwt_auth_db',
        'USER': 'v2dent',
        'HOST': 'localhost',
        'PASSWORD': 'Chelsea24462!',
        'PORT': 5432,
    }
}
