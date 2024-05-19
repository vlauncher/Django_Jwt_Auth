# backend/settings/__init__.py

import os


if os.getenv('ENVIRONMENT') == 'production':
    from .production import *
else:
    from .development import *