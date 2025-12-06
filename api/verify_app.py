# api/verify_app.py

import sys
import os
from pathlib import Path

# Vercel needs to find 'src.core' for imports, so we add the root directory 
# of the project (which contains the 'src' folder) to the Python path.
# Path(__file__).resolve() gets the absolute path of this file.
# .parent.parent moves up two levels to the project root (from api/verify_app.py to root)
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
sys.path.insert(0, PROJECT_ROOT)

# Import the Flask application instance from your core module
# The app instance must be named 'application' for Vercel deployment.
from src.core.verify_server import app as application

# This file is now complete. Vercel will execute this file to start the serverless function.