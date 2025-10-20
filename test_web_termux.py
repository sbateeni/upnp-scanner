#!/usr/bin/env python3
"""
Test script to diagnose web interface issues in Termux
"""

import sys
import os

print("Testing web interface in Termux environment...")
print("=" * 50)

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Test 1: Check if Flask is installed
print("Test 1: Checking Flask installation...")
try:
    import flask
    print(f"✅ Flask version {flask.__version__} is installed")
except ImportError as e:
    print(f"❌ Flask is not installed: {e}")
    sys.exit(1)

# Test 2: Check if web.app module can be imported
print("\nTest 2: Checking web.app module...")
try:
    from web.app import app, run_app
    print("✅ web.app module imported successfully")
except ImportError as e:
    print(f"❌ Error importing web.app: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 3: Check if all routes can be imported
print("\nTest 3: Checking route modules...")
route_modules = [
    'web.routes.main_routes',
    'web.routes.scan_routes', 
    'web.routes.camera_routes',
    'web.routes.surrounding_routes',
    'web.routes.history_routes',
    'web.routes.settings_routes',
    'web.routes.api_routes'
]

for module_name in route_modules:
    try:
        __import__(module_name)
        print(f"✅ {module_name} imported successfully")
    except ImportError as e:
        print(f"❌ Error importing {module_name}: {e}")
        import traceback
        traceback.print_exc()

# Test 4: Check if templates directory exists
print("\nTest 4: Checking templates directory...")
templates_dir = os.path.join(os.path.dirname(__file__), 'web', 'templates')
if os.path.exists(templates_dir):
    print(f"✅ Templates directory found at {templates_dir}")
    # List some template files
    try:
        templates = os.listdir(templates_dir)
        print(f"   Found {len(templates)} template files:")
        for template in templates[:5]:  # Show first 5
            print(f"   - {template}")
    except Exception as e:
        print(f"   ❌ Error listing templates: {e}")
else:
    print(f"❌ Templates directory not found at {templates_dir}")

# Test 5: Check if static directory exists
print("\nTest 5: Checking static directory...")
static_dir = os.path.join(os.path.dirname(__file__), 'web', 'static')
if os.path.exists(static_dir):
    print(f"✅ Static directory found at {static_dir}")
else:
    print(f"❌ Static directory not found at {static_dir}")

print("\n" + "=" * 50)
print("Test completed!")