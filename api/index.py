# File: api/index.py (REQUIRED for Vercel deployment)

import sys
import os

# 1. Define the correct path to the source code directory (src/core)
# This finds the directory containing verify_server.py relative to api/index.py
SOURCE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src', 'core'))
sys.path.insert(0, SOURCE_DIR)

# 2. Import the Flask app instance named 'app' from verify_server.py.
# Vercel needs to find a variable named 'app' or 'handler' at the top level.
from verify_server import app
