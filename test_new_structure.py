#!/usr/bin/env python3
"""
Test script to verify the new web interface structure
"""

import os

def test_structure():
    """Test that all required files and directories exist"""
    required_paths = [
        'web',
        'web/app.py',
        'web/routes',
        'web/routes/__init__.py',
        'web/routes/main_routes.py',
        'web/routes/scan_routes.py',
        'web/routes/camera_routes.py',
        'web/routes/surrounding_routes.py',
        'web/routes/history_routes.py',
        'web/routes/settings_routes.py',
        'web/routes/api_routes.py',
        'web/templates',
        'web/templates/base.html',
        'web/templates/main.html',
        'web/templates/scan.html',
        'web/templates/cameras.html',
        'web/templates/surrounding.html',
        'web/templates/history.html',
        'web/templates/settings.html',
        'web/static',
        'web/static/css',
        'web/static/css/style.css',
        'web/static/js',
        'web/static/js/script.js'
    ]
    
    missing_paths = []
    for path in required_paths:
        if not os.path.exists(path):
            missing_paths.append(path)
    
    if missing_paths:
        print("❌ Missing paths:")
        for path in missing_paths:
            print(f"  - {path}")
        return False
    else:
        print("✅ All required files and directories exist!")
        print("\n📁 Project structure:")
        print("web/")
        print("├── app.py")
        print("├── routes/")
        print("│   ├── __init__.py")
        print("│   ├── main_routes.py")
        print("│   ├── scan_routes.py")
        print("│   ├── camera_routes.py")
        print("│   ├── surrounding_routes.py")
        print("│   ├── history_routes.py")
        print("│   ├── settings_routes.py")
        print("│   └── api_routes.py")
        print("├── templates/")
        print("│   ├── base.html")
        print("│   ├── main.html")
        print("│   ├── scan.html")
        print("│   ├── cameras.html")
        print("│   ├── surrounding.html")
        print("│   ├── history.html")
        print("│   └── settings.html")
        print("└── static/")
        print("    ├── css/")
        print("    │   └── style.css")
        print("    └── js/")
        print("        └── script.js")
        return True

if __name__ == "__main__":
    test_structure()