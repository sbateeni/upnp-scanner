#!/usr/bin/env python3
"""
Web Interface for Advanced Network Scanner
This file has been restructured into a modular Flask application.
The new structure can be found in the 'web' directory:
- web/app.py: Main Flask application
- web/routes/: Route handlers
- web/templates/: HTML templates
- web/static/: CSS, JavaScript, and other static files

To run the new web interface, use:
python web/app.py
"""

# Instead of just showing an informational message, let's actually run the new web interface
try:
    # Import and run the new web interface
    from web.app import run_app
    print("Starting restructured web interface...")
    print("Navigate to http://localhost:8080")
    run_app()
except ImportError as e:
    # Fallback to the old informational message if there's an import error
    print("Web Interface Restructured")
    print("==========================")
    print("This web interface has been restructured into a modular Flask application.")
    print("The new structure is organized as follows:")
    print("- web/app.py: Main Flask application")
    print("- web/routes/: Route handlers")
    print("- web/templates/: HTML templates")
    print("- web/static/: CSS, JavaScript, and other static files")
    print("")
    print("To run the new web interface, use:")
    print("python web/app.py")
    print("")
    print("The web interface will be available at http://localhost:8080")
    print("")
    print("Import error:", e)
except Exception as e:
    print(f"Error starting web interface: {e}")
    import traceback
    traceback.print_exc()