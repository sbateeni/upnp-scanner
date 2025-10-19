import json
import subprocess
import platform
import os
import threading
from flask import jsonify, request
from web.app import app, scanner, get_scan_results, update_scan_results, get_camera_results, update_camera_results, scan_status, scan_progress, scanner_thread, persistent_storage
from scanner.core import AdvancedNetworkScanner

@app.route('/api/status')
def api_status():
    status_data = {
        'status': scan_status,
        'progress': scan_progress,
        'results_count': len(get_scan_results()),
        'camera_results_count': len(get_camera_results())
    }
    return jsonify(status_data)

@app.route('/api/results')
def api_results():
    return jsonify(get_scan_results())

@app.route('/api/cameras')
def api_cameras():
    return jsonify(get_camera_results())

@app.route('/api/history')
def api_history():
    try:
        history = persistent_storage.get_scan_history(20)
        return jsonify(history)
    except Exception as e:
        return jsonify([])

@app.route('/api/scan_network', methods=['POST'])
def api_scan_network():
    global scanner_thread, scan_status, scan_progress, scanner
    data = request.get_json()
    
    network = data.get('network', '192.168.1.0/24')
    scan_type = data.get('scan_type', 'full')
    
    # Start scan in background
    scan_status = "running"
    scan_progress = 0
    
    if not scanner:
        scanner = AdvancedNetworkScanner()
        
    if scan_type == 'cameras':
        scanner_thread = threading.Thread(target=run_camera_detection, args=(network,))
    else:
        scanner_thread = threading.Thread(target=run_scan, args=(network,))
        
    scanner_thread.daemon = True
    scanner_thread.start()
    
    return jsonify({'status': 'started', 'network': network, 'scan_type': scan_type})

@app.route('/api/update_github', methods=['POST'])
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
    global scan_status, scan_progress, scanner
    try:
        if scanner:
            scanner.scan_network(network)
            update_scan_results(scanner.exploited_devices)
            scan_status = "completed"
            scan_progress = 100
    except Exception as e:
        scan_status = "error"
        scan_progress = 0
        print(f"Scan error: {e}")

def run_camera_detection(network):
    global scan_status, scan_progress, scanner
    try:
        if scanner:
            camera_results = scanner.detect_cameras(network)
            update_camera_results(camera_results)
            scan_status = "completed"
            scan_progress = 100
    except Exception as e:
        scan_status = "error"
        scan_progress = 0
        print(f"Camera detection error: {e}")