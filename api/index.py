# File: api/index.py (REQUIRED for Vercel deployment)

import sys
import os

# Add the directory containing verify_server.py to the path
# This assumes your directory structure is:
# /api/index.py
# /src/core/verify_server.py
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src', 'core')))

# Import the Flask app instance named 'app' from verify_server.py
from verify_server import app
