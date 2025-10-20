#!/usr/bin/env python3
"""
Simple test to check if web app imports correctly
"""

import sys
import os

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    print("Testing web app import...")
    from web.app import app
    print("✅ Web app imported successfully!")
    
    # Check if routes are registered
    print(f"✅ App has {len(app.url_map._rules)} routes registered")
    
    # List some routes
    print("Some registered routes:")
    for rule in list(app.url_map._rules)[:5]:
        print(f"  {rule.rule} -> {rule.endpoint}")
        
    print("✅ Web app is ready!")
    
except Exception as e:
    print(f"❌ Error importing web app: {e}")
    import traceback
    traceback.print_exc()