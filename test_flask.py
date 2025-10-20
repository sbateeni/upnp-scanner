#!/usr/bin/env python3
"""
Test script to check if Flask app is working
"""

try:
    print("Importing Flask app...")
    from web.app import app
    print("Flask app imported successfully!")
    print("App routes:")
    for rule in app.url_map.iter_rules():
        print(f"  {rule.rule} -> {rule.endpoint}")
except Exception as e:
    print(f"Error importing Flask app: {e}")
    import traceback
    traceback.print_exc()