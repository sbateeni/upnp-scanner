#!/usr/bin/env python3
"""
Run script for the restructured web interface
"""

import sys
import os

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from web.app import app
    print("Starting restructured web interface...")
    print("Navigate to http://localhost:8080")
    app.run(host='localhost', port=8080, debug=True)
except ImportError as e:
    print(f"Error importing web application: {e}")
    print("Make sure all required files exist in the web/ directory")
    print("Refer to web/README.md for the directory structure")
except Exception as e:
    print(f"Error starting web interface: {e}")
    import traceback
    traceback.print_exc()