#!/usr/bin/env python3
"""
Web Interface for Advanced Network Scanner
This provides a simple web-based interface alternative to the CLI
"""

import os
import sys

# 🔧 الحل: إضافة المسار الجذر للمشريع إلى sys.path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

import subprocess
import platform
from flask import Flask, render_template, request, jsonify, send_file
from scanner.core import AdvancedNetworkScanner
from scanner.report import save_results_csv, save_results_xml, save_results_html
from utils.network_visualizer import generate_network_map, print_summary_stats
from utils.helpers import cleanup_old_logs
from utils.persistent_storage import persistent_storage
import json
import threading
from datetime import datetime
import webbrowser
import time

# Initialize Flask app
app = Flask(__name__, 
            template_folder='templates',
            static_folder='static')

# Initialize scanner
scanner = AdvancedNetworkScanner()

# Global variables to store scan results
scan_results = []
camera_results = []
scan_status = "idle"  # idle, scanning, complete
scan_progress = 0
scanner_thread = None

def get_scan_results():
    """Get current scan results"""
    return scan_results

def update_scan_results(results):
    """Update scan results"""
    global scan_results
    scan_results = results

def get_camera_results():
    """Get current camera results"""
    return camera_results

def update_camera_results(results):
    """Update camera results"""
    global camera_results
    camera_results = results

# Clean up old log files on startup
cleanup_old_logs()

# Flag to track if routes have been registered
_routes_registered = False

def register_routes():
    """Register all routes with the app"""
    global _routes_registered
    if _routes_registered:
        return
    
    # Import all routes AFTER the app is fully initialized
    from web.routes import main_routes, scan_routes, camera_routes, surrounding_routes, history_routes, settings_routes, api_routes, routers_routes
    
    # Register the routes with the app
    app.register_blueprint(main_routes.bp)
    app.register_blueprint(scan_routes.bp)
    app.register_blueprint(camera_routes.bp)
    app.register_blueprint(surrounding_routes.bp)
    app.register_blueprint(history_routes.bp)
    app.register_blueprint(settings_routes.bp)
    app.register_blueprint(api_routes.bp)
    app.register_blueprint(routers_routes.bp)
    
    _routes_registered = True

def run_app():
    """Run the Flask application"""
    print("Starting Flask application...")
    try:
        # Register routes
        register_routes()
        print(f"Routes registered successfully! Total routes: {len(app.url_map._rules)}")
        print("Running on http://localhost:8080")
        app.run(host='localhost', port=8080, debug=True)
    except Exception as e:
        print(f"Error running Flask app: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    run_app()