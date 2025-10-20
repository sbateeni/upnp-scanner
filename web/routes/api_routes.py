import json
import subprocess
import platform
import os
import threading
from flask import Blueprint, jsonify, request

# Create a blueprint for API routes
bp = Blueprint('api', __name__)

# Import scanner only when needed to avoid circular imports
def get_scanner():
    import web.app
    if not web.app.scanner:
        from scanner.core import AdvancedNetworkScanner
        web.app.scanner = AdvancedNetworkScanner()
    return web.app.scanner

@bp.route('/api/status')
def api_status():
    import web.app
    status_data = {
        'status': web.app.scan_status,
        'progress': web.app.scan_progress,
        'results_count': len(web.app.get_scan_results()),
        'camera_results_count': len(web.app.get_camera_results())
    }
    return jsonify(status_data)

@bp.route('/api/results')
def api_results():
    import web.app
    return jsonify(web.app.get_scan_results())

@bp.route('/api/cameras')
def api_cameras():
    import web.app
    return jsonify(web.app.get_camera_results())

@bp.route('/api/history')
def api_history():
    import web.app
    try:
        history = web.app.persistent_storage.get_scan_history(20)
        return jsonify(history)
    except Exception as e:
        return jsonify([])

@bp.route('/api/scan_network', methods=['POST'])
def api_scan_network():
    import web.app
    global scanner_thread
    data = request.get_json()
    
    network = data.get('network', '192.168.1.0/24')
    scan_type = data.get('scan_type', 'full')
    
    # Start scan in background
    web.app.scan_status = "running"
    web.app.scan_progress = 0
    
    # Get scanner instance
    scanner = get_scanner()
        
    if scan_type == 'cameras':
        scanner_thread = threading.Thread(target=run_camera_detection, args=(network,))
    else:
        scanner_thread = threading.Thread(target=run_scan, args=(network,))
        
    scanner_thread.daemon = True
    scanner_thread.start()
    
    return jsonify({'status': 'started', 'network': network, 'scan_type': scan_type})

@bp.route('/api/update_github', methods=['POST'])
def api_update_github():
    # Handle GitHub update
    try:
        # Check if we're in a git repository
        if not os.path.exists(".git"):
            return jsonify({'status': 'error', 'message': 'Not a git repository'}), 400
            
        # Detect if we're in Termux
        is_termux = "termux" in platform.platform().lower()
        
        if is_termux:
            # Use a more compatible approach for Termux
            # First, fetch the latest changes
            result = subprocess.run(["git", "fetch"], capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                return jsonify({'status': 'error', 'message': f'Fetch failed: {result.stderr}'}), 500
                
            # Then merge the changes
            result = subprocess.run(["git", "merge", "origin/main"], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Check if requirements.txt was updated
                if "requirements.txt" in result.stdout:
                    try:
                        subprocess.run(["pip", "install", "-r", "requirements.txt"], 
                                     capture_output=True, text=True, timeout=60)
                        return jsonify({'status': 'success', 'message': 'Update successful with requirements updated'})
                    except subprocess.TimeoutExpired:
                        return jsonify({'status': 'success', 'message': 'Update successful but requirements update timed out'})
                else:
                    return jsonify({'status': 'success', 'message': 'Update successful'})
            else:
                return jsonify({'status': 'error', 'message': f'Update failed: {result.stderr}'}), 500
        else:
            # Standard update method for other environments
            result = subprocess.run(["git", "pull"], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Check if requirements.txt was updated
                if "requirements.txt" in result.stdout:
                    subprocess.run(["pip", "install", "-r", "requirements.txt"], 
                                 capture_output=True, text=True, timeout=60)
                    return jsonify({'status': 'success', 'message': 'Update successful with requirements updated'})
                else:
                    return jsonify({'status': 'success', 'message': 'Update successful'})
            else:
                return jsonify({'status': 'error', 'message': f'Update failed: {result.stderr}'}), 500
        
    except FileNotFoundError:
        return jsonify({'status': 'error', 'message': 'Git is not installed'}), 500
    except subprocess.TimeoutExpired:
        return jsonify({'status': 'error', 'message': 'Update operation timed out'}), 500
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Error during update: {str(e)}'}), 500

def run_scan(network):
    import web.app
    try:
        scanner = get_scanner()
        scanner.scan_network(network)
        web.app.update_scan_results(scanner.exploited_devices)
        web.app.scan_status = "completed"
        web.app.scan_progress = 100
    except Exception as e:
        web.app.scan_status = "error"
        web.app.scan_progress = 0
        print(f"Scan error: {e}")

def run_camera_detection(network):
    import web.app
    try:
        scanner = get_scanner()
        cameras = scanner.detect_cameras(network)
        web.app.update_camera_results(cameras)
        web.app.scan_status = "completed"
        web.app.scan_progress = 100
    except Exception as e:
        web.app.scan_status = "error"
        web.app.scan_progress = 0
        print(f"Camera detection error: {e}")

@bp.route('/api/discover_routers')
def api_discover_routers():
    """API endpoint to discover surrounding routers."""
    try:
        scanner = get_scanner()
        routers = scanner.discover_surrounding_routers()
        return jsonify({
            'status': 'success',
            'routers': routers,
            'count': len(routers)
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@bp.route('/api/list_wifi_adapters')
def api_list_wifi_adapters():
    """API endpoint to list available WiFi adapters."""
    try:
        scanner = get_scanner()
        adapters = scanner.list_wifi_adapters()
        return jsonify({
            'status': 'success',
            'adapters': adapters,
            'count': len(adapters)
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@bp.route('/api/discover_routers_on_adapter', methods=['POST'])
def api_discover_routers_on_adapter():
    """API endpoint to discover surrounding routers on a specific adapter."""
    try:
        data = request.get_json()
        adapter_name = data.get('adapter_name')
        
        if not adapter_name:
            return jsonify({
                'status': 'error',
                'message': 'Adapter name is required'
            }), 400
            
        scanner = get_scanner()
        routers = scanner.discover_surrounding_routers_on_adapter(adapter_name)
        return jsonify({
            'status': 'success',
            'routers': routers,
            'count': len(routers)
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
