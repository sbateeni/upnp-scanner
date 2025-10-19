#!/usr/bin/env python3
"""
Test script to start the web interface with debugging
"""

import sys
import os

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    print("Starting web interface test...")
    from web_interface import main
    print("Web interface module loaded successfully")
    main()
except Exception as e:
    print(f"Error starting web interface: {e}")
    import traceback
    traceback.print_exc()