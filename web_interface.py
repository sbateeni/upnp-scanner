#!/usr/bin/env python3
"""
Web Interface for Advanced Network Scanner
This provides a simple web-based interface alternative to the CLI
"""

import threading
import json
import os
import sys
import subprocess
import platform
from typing import List, Dict, Any
from scanner.core import AdvancedNetworkScanner
from utils.security import is_safe_network, validate_port_list
from utils.network_visualizer import print_summary_stats
from utils.persistent_storage import persistent_storage

# Global variables for scan results and status
_scan_results: List[Dict[str, Any]] = []
_camera_results: List[Dict[str, Any]] = []
scan_status = "idle"  # idle, running, completed, error
scan_progress = 0
scanner_thread = None
scanner = None

def get_scan_results():
    """Get current scan results"""
    return _scan_results

def get_camera_results():
    """Get current camera detection results"""
    return _camera_results

def update_scan_results(results):
    """Update scan results"""
    global _scan_results
    _scan_results = results

def update_camera_results(results):
    """Update camera detection results"""
    global _camera_results
    _camera_results = results

def simple_web_server():
    """Create a simple HTTP server for the web interface"""
    try:
        from http.server import HTTPServer, BaseHTTPRequestHandler
        from urllib.parse import parse_qs
        import urllib.parse
    except Exception as e:
        print(f"Error importing required modules: {e}")
        return None
        
    class ScannerHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/':
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                
                html = self.generate_main_page()
                self.wfile.write(html.encode())
                
            elif self.path == '/scan':
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                
                html = self.generate_scan_page()
                self.wfile.write(html.encode())
                
            elif self.path == '/results':
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                
                html = self.generate_results_page()
                self.wfile.write(html.encode())
                
            elif self.path == '/cameras':
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                
                html = self.generate_cameras_page()
                self.wfile.write(html.encode())
                
            elif self.path == '/history':
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                
                html = self.generate_history_page()
                self.wfile.write(html.encode())
                
            elif self.path == '/settings':
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                
                html = self.generate_settings_page()
                self.wfile.write(html.encode())
                
            elif self.path == '/api/status':
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                
                status_data = {
                    'status': scan_status,
                    'progress': scan_progress,
                    'results_count': len(get_scan_results()),
                    'camera_results_count': len(get_camera_results())
                }
                self.wfile.write(json.dumps(status_data).encode())
                
            elif self.path == '/api/results':
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                
                self.wfile.write(json.dumps(get_scan_results()).encode())
                
            elif self.path == '/api/cameras':
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                
                self.wfile.write(json.dumps(get_camera_results()).encode())
                
            elif self.path == '/api/history':
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                
                try:
                    history = persistent_storage.get_scan_history(20)
                    self.wfile.write(json.dumps(history).encode())
                except Exception as e:
                    self.wfile.write(json.dumps([]).encode())
                
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'Not Found')
        
        def do_POST(self):
            if self.path == '/api/scan_network':
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data.decode())
                
                network = data.get('network', '192.168.1.0/24')
                scan_type = data.get('scan_type', 'full')
                
                # Start scan in background
                global scanner_thread, scan_status, scan_progress, scanner
                scan_status = "running"
                scan_progress = 0
                
                if not scanner:
                    scanner = AdvancedNetworkScanner()
                    
                if scan_type == 'cameras':
                    scanner_thread = threading.Thread(target=self.run_camera_detection, args=(network,))
                else:
                    scanner_thread = threading.Thread(target=self.run_scan, args=(network,))
                    
                scanner_thread.daemon = True
                scanner_thread.start()
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'started', 'network': network, 'scan_type': scan_type}).encode())
            
            elif self.path == '/api/update_github':
                # Handle GitHub update
                try:
                    # Check if we're in a git repository
                    if not os.path.exists(".git"):
                        self.send_response(400)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({'status': 'error', 'message': 'Not a git repository'}).encode())
                        return
                    
                    # Detect if we're in Termux
                    is_termux = "termux" in platform.platform().lower()
                    
                    if is_termux:
                        # Use a more compatible approach for Termux
                        # First, fetch the latest changes
                        result = subprocess.run(["git", "fetch"], capture_output=True, text=True, timeout=30)
                        if result.returncode != 0:
                            self.send_response(500)
                            self.send_header('Content-type', 'application/json')
                            self.end_headers()
                            self.wfile.write(json.dumps({'status': 'error', 'message': f'Fetch failed: {result.stderr}'}).encode())
                            return
                            
                        # Then merge the changes
                        result = subprocess.run(["git", "merge", "origin/main"], capture_output=True, text=True, timeout=30)
                        
                        if result.returncode == 0:
                            # Check if requirements.txt was updated
                            if "requirements.txt" in result.stdout:
                                try:
                                    subprocess.run(["pip", "install", "-r", "requirements.txt"], 
                                                 capture_output=True, text=True, timeout=60)
                                    self.wfile.write(json.dumps({'status': 'success', 'message': 'Update successful with requirements updated'}).encode())
                                except subprocess.TimeoutExpired:
                                    self.wfile.write(json.dumps({'status': 'success', 'message': 'Update successful but requirements update timed out'}).encode())
                            else:
                                self.wfile.write(json.dumps({'status': 'success', 'message': 'Update successful'}).encode())
                        else:
                            self.send_response(500)
                            self.send_header('Content-type', 'application/json')
                            self.end_headers()
                            self.wfile.write(json.dumps({'status': 'error', 'message': f'Update failed: {result.stderr}'}).encode())
                            return
                    else:
                        # Standard update method for other environments
                        result = subprocess.run(["git", "pull"], capture_output=True, text=True, timeout=30)
                        
                        if result.returncode == 0:
                            # Check if requirements.txt was updated
                            if "requirements.txt" in result.stdout:
                                subprocess.run(["pip", "install", "-r", "requirements.txt"], 
                                             capture_output=True, text=True, timeout=60)
                                self.wfile.write(json.dumps({'status': 'success', 'message': 'Update successful with requirements updated'}).encode())
                            else:
                                self.wfile.write(json.dumps({'status': 'success', 'message': 'Update successful'}).encode())
                        else:
                            self.send_response(500)
                            self.send_header('Content-type', 'application/json')
                            self.end_headers()
                            self.wfile.write(json.dumps({'status': 'error', 'message': f'Update failed: {result.stderr}'}).encode())
                            return
                    
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                
                except FileNotFoundError:
                    self.send_response(500)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'status': 'error', 'message': 'Git is not installed'}).encode())
                except subprocess.TimeoutExpired:
                    self.send_response(500)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'status': 'error', 'message': 'Update operation timed out'}).encode())
                except Exception as e:
                    self.send_response(500)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'status': 'error', 'message': f'Error during update: {str(e)}'}).encode())
        
        def run_scan(self, network):
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
        
        def run_camera_detection(self, network):
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
        
        def generate_main_page(self):
            return '''
<!DOCTYPE html>
<html>
<head>
    <title>Advanced Network Scanner - Dashboard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        :root {
            --primary: #3498db;
            --secondary: #2c3e50;
            --success: #27ae60;
            --warning: #f39c12;
            --danger: #e74c3c;
            --light: #ecf0f1;
            --dark: #34495e;
        }
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72, #2a5298);
            color: #333;
            line-height: 1.6;
        }
        .container {
            width: 90%;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background: rgba(255, 255, 255, 0.9);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        h1 {
            color: var(--secondary);
            margin-bottom: 10px;
            font-size: 2.5rem;
        }
        .subtitle {
            color: var(--dark);
            font-size: 1.2rem;
        }
        .nav {
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 10px;
            margin: 20px 0;
        }
        .nav a {
            display: inline-block;
            padding: 12px 20px;
            background: var(--primary);
            color: white;
            text-decoration: none;
            border-radius: 5px;
            transition: all 0.3s ease;
            font-weight: 500;
        }
        .nav a:hover {
            background: #2980b9;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .card {
            background: rgba(255, 255, 255, 0.9);
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }
        .card h2 {
            color: var(--secondary);
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--light);
        }
        .status-card {
            background: linear-gradient(135deg, #3498db, #8e44ad);
            color: white;
        }
        .status-card h2 {
            color: white;
            border-bottom: 2px solid rgba(255, 255, 255, 0.3);
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin: 20px 0;
        }
        .stat-box {
            background: rgba(255, 255, 255, 0.2);
            border-radius: 8px;
            padding: 15px;
            text-align: center;
        }
        .stat-value {
            font-size: 2rem;
            font-weight: bold;
            margin: 10px 0;
        }
        .stat-label {
            font-size: 0.9rem;
            opacity: 0.9;
        }
        .progress-container {
            margin: 20px 0;
        }
        .progress-label {
            display: flex;
            justify-content: space-between;
            margin-bottom: 5px;
        }
        .progress {
            height: 20px;
            background: #bdc3c7;
            border-radius: 10px;
            overflow: hidden;
        }
        .progress-bar {
            height: 100%;
            background: linear-gradient(90deg, var(--primary), var(--success));
            border-radius: 10px;
            width: ''' + str(scan_progress) + '''%;
            transition: width 0.5s ease;
        }
        .recent-results {
            max-height: 300px;
            overflow-y: auto;
        }
        .result-item {
            padding: 12px;
            background: var(--light);
            margin: 8px 0;
            border-radius: 5px;
            border-left: 4px solid var(--primary);
        }
        .result-item.critical {
            border-left-color: var(--danger);
        }
        .result-item.high {
            border-left-color: var(--warning);
        }
        .quick-actions {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .action-btn {
            padding: 15px;
            background: var(--success);
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 1rem;
            text-align: center;
            transition: all 0.3s ease;
        }
        .action-btn:hover {
            background: #229954;
            transform: translateY(-2px);
        }
        .action-btn.warning {
            background: var(--warning);
        }
        .action-btn.warning:hover {
            background: #e67e22;
        }
        .action-btn.danger {
            background: var(--danger);
        }
        .action-btn.danger:hover {
            background: #c0392b;
        }
        .action-btn.info {
            background: var(--primary);
        }
        .action-btn.info:hover {
            background: #2980b9;
        }
        footer {
            text-align: center;
            padding: 20px;
            color: rgba(255, 255, 255, 0.7);
            margin-top: 30px;
        }
        @media (max-width: 768px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
            .stats-grid {
                grid-template-columns: 1fr;
            }
            .nav {
                flex-direction: column;
            }
            .nav a {
                width: 100%;
                text-align: center;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Advanced Network Scanner</h1>
            <p class="subtitle">Professional Network Security Assessment Tool</p>
        </header>
        
        <div class="nav">
            <a href="/">Dashboard</a>
            <a href="/scan">Scan Network</a>
            <a href="/results">Vulnerabilities</a>
            <a href="/cameras">Cameras</a>
            <a href="/history">Scan History</a>
            <a href="/settings">Settings</a>
        </div>
        
        <div class="dashboard-grid">
            <div class="card status-card">
                <h2>⚡ System Status</h2>
                <div class="stats-grid">
                    <div class="stat-box">
                        <div class="stat-value">''' + str(scan_progress) + '''%</div>
                        <div class="stat-label">Progress</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">''' + scan_status + '''</div>
                        <div class="stat-label">Status</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">''' + str(len(get_scan_results())) + '''</div>
                        <div class="stat-label">Vulnerabilities</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">''' + str(len(get_camera_results())) + '''</div>
                        <div class="stat-label">Cameras</div>
                    </div>
                </div>
                
                <div class="progress-container">
                    <div class="progress-label">
                        <span>Scan Progress</span>
                        <span>''' + str(scan_progress) + '''%</span>
                    </div>
                    <div class="progress">
                        <div class="progress-bar"></div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <h2>📊 Quick Statistics</h2>
                <div class="stats-grid">
                    <div class="stat-box">
                        <div class="stat-value" id="totalScans">0</div>
                        <div class="stat-label">Total Scans</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value" id="totalVulns">0</div>
                        <div class="stat-label">Vulnerabilities</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value" id="totalDevices">0</div>
                        <div class="stat-label">Devices</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value" id="totalCameras">0</div>
                        <div class="stat-label">Cameras</div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <h2>⚡ Quick Actions</h2>
                <div class="quick-actions">
                    <button class="action-btn" onclick="startQuickScan()">Quick Scan</button>
                    <button class="action-btn info" onclick="detectCameras()">Find Cameras</button>
                    <button class="action-btn warning" onclick="viewHistory()">View History</button>
                    <button class="action-btn danger" onclick="clearResults()">Clear Results</button>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>🔍 Recent Results</h2>
            <div class="recent-results" id="recentResults">
                ''' + ('<p>No results yet. Run a scan to get started.</p>' if len(get_scan_results()) == 0 and len(get_camera_results()) == 0 else self.generate_recent_results_html(get_scan_results()[:3], get_camera_results()[:3])) + '''
            </div>
        </div>
    </div>
    
    <footer>
        <p>Advanced Network Scanner &copy; 2023 | Professional Security Tool</p>
    </footer>
    
    <script>
        // Update statistics
        function updateStats() {
            fetch('/api/history')
            .then(response => response.json())
            .then(history => {
                // For now, we'll just show the length of history as total scans
                document.getElementById('totalScans').textContent = history.length;
            })
            .catch(error => {
                console.log('Error fetching history:', error);
            });
        }
        
        // Generate recent results HTML
        function generateRecentResults(results, cameraResults) {
            let html = '';
            
            if (results.length > 0) {
                html += '<h3>Vulnerabilities</h3>';
                results.forEach(result => {
                    // Determine severity class
                    let severityClass = '';
                    if (result.description && result.description.toLowerCase().includes('critical')) {
                        severityClass = 'critical';
                    } else if (result.description && result.description.toLowerCase().includes('high')) {
                        severityClass = 'high';
                    }
                    
                    html += `
                    <div class="result-item ${severityClass}">
                        <strong>${result.ip || 'Unknown IP'}:${result.port || 'Unknown Port'}</strong><br>
                        <small>Service: ${result.service || 'Unknown'}</small><br>
                        <small>CVE: ${result.cve_id || 'Unknown'}</small>
                    </div>
                    `;
                });
            }
            
            if (cameraResults.length > 0) {
                html += '<h3>Cameras</h3>';
                cameraResults.forEach(camera => {
                    html += `
                    <div class="result-item">
                        <strong>${camera.ip || 'Unknown IP'}</strong><br>
                        <small>Type: ${camera.device_type || 'Unknown'}</small><br>
                        <small>Vendor: ${camera.vendor || 'Unknown'}</small>
                    </div>
                    `;
                });
            }
            
            if (html === '') {
                html = '<p>No recent results.</p>';
            }
            
            return html;
        }
        
        // Start quick scan
        function startQuickScan() {
            if (confirm('Start quick vulnerability scan on 192.168.1.0/24?')) {
                fetch('/api/scan_network', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        network: '192.168.1.0/24',
                        scan_type: 'full'
                    })
                })
                .then(response => response.json())
                .then(data => {
                    alert('Vulnerability scan started: ' + data.network);
                    // Refresh the page to show progress
                    setTimeout(() => location.reload(), 1000);
                })
                .catch(error => {
                    alert('Error starting scan: ' + error);
                });
            }
        }
        
        // Detect cameras
        function detectCameras() {
            const network = prompt('Enter network to scan for cameras (e.g., 192.168.1.0/24):', '192.168.1.0/24');
            if (network) {
                if (confirm('Start camera detection on ' + network + '?')) {
                    fetch('/api/scan_network', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            network: network,
                            scan_type: 'cameras'
                        })
                    })
                    .then(response => response.json())
                    .then(data => {
                        alert('Camera detection started: ' + data.network);
                        // Refresh the page to show progress
                        setTimeout(() => location.reload(), 1000);
                    })
                    .catch(error => {
                        alert('Error starting camera detection: ' + error);
                    });
                }
            }
        }
        
        // View history
        function viewHistory() {
            window.location.href = '/history';
        }
        
        // Clear results
        function clearResults() {
            if (confirm('Clear all current results?')) {
                // This would be implemented in a real application
                alert('Results cleared');
                location.reload();
            }
        }
        
        // Initialize
        updateStats();
        
        // Poll for status updates
        setInterval(() => {
            fetch('/api/status')
            .then(response => response.json())
            .then(status => {
                document.querySelector('.progress-bar').style.width = status.progress + '%';
                document.querySelector('.progress-label span:last-child').textContent = status.progress + '%';
                document.querySelector('.stat-box:nth-child(2) .stat-value').textContent = status.status;
                document.querySelector('.stat-box:nth-child(3) .stat-value').textContent = status.results_count;
                document.querySelector('.stat-box:nth-child(4) .stat-value').textContent = status.camera_results_count;
            });
        }, 2000);
    </script>
</body>
</html>
            '''
        
        def generate_recent_results_html(self, results, camera_results):
            """Generate HTML for recent results"""
            html = ''
            
            if results:
                html += '<h3>Vulnerabilities</h3>'
                for result in results[:3]:  # Limit to first 3
                    # Determine severity class
                    severity_class = ''
                    if result.get('description', '').lower().find('critical') != -1:
                        severity_class = 'critical'
                    elif result.get('description', '').lower().find('high') != -1:
                        severity_class = 'high'
                    
                    html += f'''
                    <div class="result-item {severity_class}">
                        <strong>{result.get('ip', 'Unknown IP')}:{result.get('port', 'Unknown Port')}</strong><br>
                        <small>Service: {result.get('service', 'Unknown')}</small><br>
                        <small>CVE: {result.get('cve_id', 'Unknown')}</small>
                    </div>
                    '''
            
            if camera_results:
                html += '<h3>Cameras</h3>'
                for camera in camera_results[:3]:  # Limit to first 3
                    html += f'''
                    <div class="result-item">
                        <strong>{camera.get('ip', 'Unknown IP')}</strong><br>
                        <small>Type: {camera.get('device_type', 'Unknown')}</small><br>
                        <small>Vendor: {camera.get('vendor', 'Unknown')}</small>
                    </div>
                    '''
            
            if not html:
                html = '<p>No recent results.</p>'
                
            return html
        
        def generate_scan_page(self):
            return '''
<!DOCTYPE html>
<html>
<head>
    <title>Scan Network - Advanced Network Scanner</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        :root {
            --primary: #3498db;
            --secondary: #2c3e50;
            --success: #27ae60;
            --warning: #f39c12;
            --danger: #e74c3c;
            --light: #ecf0f1;
            --dark: #34495e;
        }
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72, #2a5298);
            color: #333;
            line-height: 1.6;
        }
        .container {
            width: 90%;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background: rgba(255, 255, 255, 0.9);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        h1 {
            color: var(--secondary);
            margin-bottom: 10px;
        }
        .nav {
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 10px;
            margin: 20px 0;
        }
        .nav a {
            display: inline-block;
            padding: 12px 20px;
            background: var(--primary);
            color: white;
            text-decoration: none;
            border-radius: 5px;
            transition: all 0.3s ease;
        }
        .nav a:hover {
            background: #2980b9;
            transform: translateY(-2px);
        }
        .card {
            background: rgba(255, 255, 255, 0.9);
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
        }
        .form-group {
            margin: 20px 0;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: var(--dark);
        }
        input, select, textarea {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        input:focus, select:focus, textarea:focus {
            border-color: var(--primary);
            outline: none;
        }
        button {
            background: var(--success);
            color: white;
            padding: 14px 25px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: all 0.3s ease;
            width: 100%;
        }
        button:hover {
            background: #229954;
            transform: translateY(-2px);
        }
        .advanced-options {
            background: var(--light);
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }
        .status {
            padding: 20px;
            background: var(--light);
            border-radius: 8px;
            margin: 20px 0;
            display: none;
        }
        .progress {
            height: 20px;
            background: #bdc3c7;
            border-radius: 10px;
            margin: 15px 0;
            overflow: hidden;
        }
        .progress-bar {
            height: 100%;
            background: linear-gradient(90deg, var(--primary), var(--success));
            border-radius: 10px;
            width: 0%;
            transition: width 0.5s ease;
        }
        .tabs {
            display: flex;
            margin-bottom: 20px;
            border-bottom: 2px solid var(--light);
        }
        .tab {
            padding: 12px 20px;
            cursor: pointer;
            background: var(--light);
            border: none;
            font-weight: 600;
        }
        .tab.active {
            background: var(--primary);
            color: white;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        .scan-types {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .scan-type {
            padding: 20px;
            border: 2px solid var(--light);
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        .scan-type:hover {
            border-color: var(--primary);
            background: rgba(52, 152, 219, 0.1);
        }
        .scan-type.selected {
            border-color: var(--primary);
            background: rgba(52, 152, 219, 0.2);
        }
        .scan-type h3 {
            color: var(--secondary);
            margin-bottom: 10px;
        }
        .scan-type-icon {
            font-size: 2rem;
            margin-bottom: 10px;
        }
        @media (max-width: 768px) {
            .nav {
                flex-direction: column;
            }
            .nav a {
                width: 100%;
                text-align: center;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 Network Scan Configuration</h1>
            <p>Configure and start your network security scan</p>
        </header>
        
        <div class="nav">
            <a href="/">Dashboard</a>
            <a href="/scan">Scan Network</a>
            <a href="/results">Vulnerabilities</a>
            <a href="/cameras">Cameras</a>
            <a href="/history">Scan History</a>
            <a href="/settings">Settings</a>
        </div>
        
        <div class="card">
            <h2>Select Scan Type</h2>
            <div class="scan-types">
                <div class="scan-type" onclick="selectScanType('full')" id="full-type">
                    <div class="scan-type-icon">🛡️</div>
                    <h3>Full Network Scan</h3>
                    <p>Complete vulnerability assessment of all devices</p>
                </div>
                <div class="scan-type" onclick="selectScanType('cameras')" id="cameras-type">
                    <div class="scan-type-icon">📹</div>
                    <h3>Camera Detection</h3>
                    <p>Find IP cameras, DVRs, and NVR systems</p>
                </div>
                <div class="scan-type" onclick="selectScanType('ports')" id="ports-type">
                    <div class="scan-type-icon">🔓</div>
                    <h3>Port Scan</h3>
                    <p>Scan specific ports on network devices</p>
                </div>
            </div>
            
            <form id="scanForm">
                <div class="form-group">
                    <label for="network">Network CIDR:</label>
                    <input type="text" id="network" name="network" value="192.168.1.0/24" placeholder="e.g., 192.168.1.0/24">
                </div>
                
                <input type="hidden" id="scanType" name="scanType" value="full">
                
                <button type="submit">Start Scan</button>
            </form>
        </div>
        
        <div class="card">
            <div class="tabs">
                <button class="tab active" onclick="switchTab('basic')">Basic Scan</button>
                <button class="tab" onclick="switchTab('advanced')">Advanced Options</button>
                <button class="tab" onclick="switchTab('schedule')">Schedule</button>
            </div>
            
            <div id="basic" class="tab-content active">
                <p>Select a scan type above and enter your network range to begin.</p>
            </div>
            
            <div id="advanced" class="tab-content">
                <div class="advanced-options">
                    <div class="form-group">
                        <label for="ports">Custom Ports (comma-separated):</label>
                        <input type="text" id="ports" name="ports" placeholder="e.g., 22,80,443,3389">
                    </div>
                    
                    <div class="form-group">
                        <label for="excludeIps">Exclude IPs (comma-separated):</label>
                        <input type="text" id="excludeIps" name="excludeIps" placeholder="e.g., 192.168.1.1,192.168.1.254">
                    </div>
                    
                    <div class="form-group">
                        <label for="scanProfile">Scan Profile:</label>
                        <select id="scanProfile" name="scanProfile">
                            <option value="quick">Quick Scan</option>
                            <option value="standard" selected>Standard Scan</option>
                            <option value="comprehensive">Comprehensive Scan</option>
                            <option value="stealth">Stealth Scan</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label>
                            <input type="checkbox" id="saveResults" name="saveResults" checked> 
                            Save results to persistent storage
                        </label>
                    </div>
                    
                    <div class="form-group">
                        <label>
                            <input type="checkbox" id="generateReport" name="generateReport" checked> 
                            Generate detailed report
                        </label>
                    </div>
                </div>
            </div>
            
            <div id="schedule" class="tab-content">
                <div class="advanced-options">
                    <p>Scheduled scans coming in future versions.</p>
                    <p>For now, you can use system cron jobs or task scheduler to run scans automatically.</p>
                </div>
            </div>
        </div>
        
        <div class="status" id="statusDiv">
            <h3>Scan Status</h3>
            <p id="statusText">Starting scan...</p>
            <div class="progress">
                <div class="progress-bar" id="progressBar"></div>
            </div>
        </div>
    </div>
    
    <script>
        // Select scan type
        function selectScanType(type) {
            // Remove selected class from all
            document.querySelectorAll('.scan-type').forEach(el => {
                el.classList.remove('selected');
            });
            
            // Add selected class to clicked element
            document.getElementById(type + '-type').classList.add('selected');
            
            // Set hidden input value
            document.getElementById('scanType').value = type;
        }
        
        // Switch tabs
        function switchTab(tabName) {
            // Hide all tab contents
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // Remove active class from all tabs
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab content
            document.getElementById(tabName).classList.add('active');
            
            // Add active class to clicked tab
            event.target.classList.add('active');
        }
        
        // Form submission
        document.getElementById('scanForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const network = document.getElementById('network').value;
            const scanType = document.getElementById('scanType').value;
            
            // Show status
            document.getElementById('statusDiv').style.display = 'block';
            document.getElementById('statusText').textContent = 'Starting scan on ' + network + '...';
            
            // Send scan request
            fetch('/api/scan_network', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    network: network,
                    scan_type: scanType
                })
            })
            .then(response => response.json())
            .then(data => {
                document.getElementById('statusText').textContent = 'Scan started: ' + data.network;
                
                // Poll for status updates
                const statusInterval = setInterval(() => {
                    fetch('/api/status')
                    .then(response => response.json())
                    .then(status => {
                        document.getElementById('progressBar').style.width = status.progress + '%';
                        document.getElementById('statusText').textContent = 'Status: ' + status.status + ' (' + status.progress + '%)';
                        
                        if (status.status === 'completed' || status.status === 'error') {
                            clearInterval(statusInterval);
                            if (status.status === 'completed') {
                                document.getElementById('statusText').textContent = 'Scan completed!';
                                // Redirect based on scan type
                                setTimeout(() => {
                                    if (scanType === 'cameras') {
                                        window.location.href = '/cameras';
                                    } else {
                                        window.location.href = '/results';
                                    }
                                }, 3000);
                            } else {
                                document.getElementById('statusText').textContent = 'Scan failed!';
                            }
                        }
                    });
                }, 1000);
            })
            .catch(error => {
                document.getElementById('statusText').textContent = 'Error: ' + error;
            });
        });
    </script>
</body>
</html>
            '''
        
        def generate_results_page(self):
            results = get_scan_results()
            results_html = ''
            if results:
                for result in results:
                    # Determine severity class
                    severity_class = ''
                    if result.get('description', '').lower().find('critical') != -1:
                        severity_class = 'critical'
                    elif result.get('description', '').lower().find('high') != -1:
                        severity_class = 'high'
                    elif result.get('description', '').lower().find('medium') != -1:
                        severity_class = 'medium'
                    elif result.get('description', '').lower().find('low') != -1:
                        severity_class = 'low'
                    
                    results_html += f'''
                    <div class="result-item {severity_class}">
                        <h4>{result.get('cve_id', 'Unknown CVE')}</h4>
                        <p><strong>Target:</strong> {result.get('ip', 'Unknown IP')}:{result.get('port', 'Unknown Port')}</p>
                        <p><strong>Service:</strong> {result.get('service', 'Unknown')}</p>
                        <p><strong>Severity:</strong> <span class="severity">{self.get_severity_text(result.get('description', ''))}</span></p>
                        <p><strong>Description:</strong> {result.get('description', 'No description')}</p>
                    </div>
                    '''
            else:
                results_html = '<p>No results found. Run a scan to get started.</p>'
            
            return '''
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Results - Advanced Network Scanner</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        :root {
            --primary: #3498db;
            --secondary: #2c3e50;
            --success: #27ae60;
            --warning: #f39c12;
            --danger: #e74c3c;
            --light: #ecf0f1;
            --dark: #34495e;
            --critical: #e74c3c;
            --high: #f39c12;
            --medium: #f1c40f;
            --low: #2ecc71;
        }
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72, #2a5298);
            color: #333;
            line-height: 1.6;
        }
        .container {
            width: 90%;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background: rgba(255, 255, 255, 0.9);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        h1 {
            color: var(--secondary);
            margin-bottom: 10px;
        }
        .nav {
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 10px;
            margin: 20px 0;
        }
        .nav a {
            display: inline-block;
            padding: 12px 20px;
            background: var(--primary);
            color: white;
            text-decoration: none;
            border-radius: 5px;
            transition: all 0.3s ease;
        }
        .nav a:hover {
            background: #2980b9;
            transform: translateY(-2px);
        }
        .card {
            background: rgba(255, 255, 255, 0.9);
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .stat-box {
            background: var(--light);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-value {
            font-size: 2rem;
            font-weight: bold;
            margin: 10px 0;
        }
        .results {
            margin: 20px 0;
        }
        .result-item {
            padding: 20px;
            background: var(--light);
            margin: 15px 0;
            border-radius: 8px;
            border-left: 5px solid var(--primary);
        }
        .result-item.critical {
            border-left-color: var(--critical);
        }
        .result-item.high {
            border-left-color: var(--high);
        }
        .result-item.medium {
            border-left-color: var(--medium);
        }
        .result-item.low {
            border-left-color: var(--low);
        }
        .severity {
            padding: 3px 8px;
            border-radius: 3px;
            font-weight: bold;
            color: white;
        }
        .severity.critical {
            background: var(--critical);
        }
        .severity.high {
            background: var(--high);
        }
        .severity.medium {
            background: var(--medium);
        }
        .severity.low {
            background: var(--low);
        }
        .filter-controls {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin: 20px 0;
            padding: 15px;
            background: var(--light);
            border-radius: 8px;
        }
        .filter-control {
            flex: 1;
            min-width: 200px;
        }
        .export-options {
            display: flex;
            gap: 10px;
            margin: 20px 0;
        }
        .export-btn {
            padding: 10px 15px;
            background: var(--secondary);
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        .export-btn:hover {
            background: #1a2530;
        }
        @media (max-width: 768px) {
            .nav {
                flex-direction: column;
            }
            .nav a {
                width: 100%;
                text-align: center;
            }
            .summary {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Vulnerability Results</h1>
            <p>Detailed analysis of discovered vulnerabilities</p>
        </header>
        
        <div class="nav">
            <a href="/">Dashboard</a>
            <a href="/scan">Scan Network</a>
            <a href="/results">Vulnerabilities</a>
            <a href="/cameras">Cameras</a>
            <a href="/history">Scan History</a>
            <a href="/settings">Settings</a>
        </div>
        
        <div class="card">
            <h2>📈 Results Summary</h2>
            <div class="summary">
                <div class="stat-box">
                    <div class="stat-value">''' + str(len(results)) + '''</div>
                    <div>Total Vulnerabilities</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">''' + str(len(set(result.get('ip', '') for result in results))) + '''</div>
                    <div>Affected Devices</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">''' + str(len([r for r in results if 'critical' in r.get('description', '').lower()])) + '''</div>
                    <div>Critical Issues</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">''' + str(len([r for r in results if 'high' in r.get('description', '').lower()])) + '''</div>
                    <div>High Priority</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>🔍 Filter & Export</h2>
            <div class="filter-controls">
                <div class="filter-control">
                    <label for="severityFilter">Filter by Severity:</label>
                    <select id="severityFilter" onchange="filterResults()">
                        <option value="all">All Severities</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                    </select>
                </div>
                <div class="filter-control">
                    <label for="ipFilter">Filter by IP:</label>
                    <input type="text" id="ipFilter" placeholder="Enter IP address" oninput="filterResults()">
                </div>
            </div>
            
            <div class="export-options">
                <button class="export-btn" onclick="exportResults('json')">Export JSON</button>
                <button class="export-btn" onclick="exportResults('csv')">Export CSV</button>
                <button class="export-btn" onclick="exportResults('html')">Export HTML</button>
                <button class="export-btn" onclick="printResults()">Print Report</button>
            </div>
        </div>
        
        <div class="card">
            <h2>⚠️ Detailed Results</h2>
            <div class="results" id="resultsContainer">
                ''' + results_html + '''
            </div>
        </div>
    </div>
    
    <script>
        function filterResults() {
            // In a real implementation, this would filter the results
            // For now, we'll just show an alert
            alert('Filtering functionality would be implemented in a full version');
        }
        
        function exportResults(format) {
            alert('Export as ' + format.toUpperCase() + ' would be implemented in a full version');
            // In a real implementation, this would trigger the export
        }
        
        function printResults() {
            window.print();
        }
        
        function getSeverityText(description) {
            if (description.toLowerCase().includes('critical')) return 'Critical';
            if (description.toLowerCase().includes('high')) return 'High';
            if (description.toLowerCase().includes('medium')) return 'Medium';
            if (description.toLowerCase().includes('low')) return 'Low';
            return 'Unknown';
        }
    </script>
</body>
</html>
            '''
        
        def generate_cameras_page(self):
            cameras = get_camera_results()
            cameras_html = ''
            if cameras:
                for camera in cameras:
                    cameras_html += f'''
                    <div class="result-item">
                        <h4>{camera.get('ip', 'Unknown IP')}</h4>
                        <p><strong>Device Type:</strong> {camera.get('device_type', 'Unknown')}</p>
                        <p><strong>Vendor:</strong> {camera.get('vendor', 'Unknown')}</p>
                        <p><strong>Model:</strong> {camera.get('model', 'Unknown')}</p>
                        <p><strong>Open Ports:</strong> {', '.join(map(str, camera.get('ports', [])))}</p>
                    </div>
                    '''
            else:
                cameras_html = '<p>No cameras found. Run a camera detection scan to find devices.</p>'
            
            return '''
<!DOCTYPE html>
<html>
<head>
    <title>Camera Detection - Advanced Network Scanner</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        :root {
            --primary: #3498db;
            --secondary: #2c3e50;
            --success: #27ae60;
            --warning: #f39c12;
            --danger: #e74c3c;
            --light: #ecf0f1;
            --dark: #34495e;
        }
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72, #2a5298);
            color: #333;
            line-height: 1.6;
        }
        .container {
            width: 90%;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background: rgba(255, 255, 255, 0.9);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        h1 {
            color: var(--secondary);
            margin-bottom: 10px;
        }
        .nav {
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 10px;
            margin: 20px 0;
        }
        .nav a {
            display: inline-block;
            padding: 12px 20px;
            background: var(--primary);
            color: white;
            text-decoration: none;
            border-radius: 5px;
            transition: all 0.3s ease;
        }
        .nav a:hover {
            background: #2980b9;
            transform: translateY(-2px);
        }
        .card {
            background: rgba(255, 255, 255, 0.9);
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .stat-box {
            background: var(--light);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-value {
            font-size: 2rem;
            font-weight: bold;
            margin: 10px 0;
        }
        .results {
            margin: 20px 0;
        }
        .result-item {
            padding: 20px;
            background: var(--light);
            margin: 15px 0;
            border-radius: 8px;
            border-left: 5px solid var(--primary);
        }
        .camera-types {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .camera-type {
            background: var(--light);
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }
        .export-options {
            display: flex;
            gap: 10px;
            margin: 20px 0;
        }
        .export-btn {
            padding: 10px 15px;
            background: var(--secondary);
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        .export-btn:hover {
            background: #1a2530;
        }
        .scan-btn {
            background: var(--success);
            color: white;
            padding: 15px 25px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            display: block;
            margin: 20px auto;
            width: 300px;
            text-align: center;
        }
        .scan-btn:hover {
            background: #229954;
        }
        @media (max-width: 768px) {
            .nav {
                flex-direction: column;
            }
            .nav a {
                width: 100%;
                text-align: center;
            }
            .summary {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>📹 Camera Detection</h1>
            <p>Discover IP cameras, DVRs, and NVR systems on your network</p>
        </header>
        
        <div class="nav">
            <a href="/">Dashboard</a>
            <a href="/scan">Scan Network</a>
            <a href="/results">Vulnerabilities</a>
            <a href="/cameras">Cameras</a>
            <a href="/history">Scan History</a>
            <a href="/settings">Settings</a>
        </div>
        
        <div class="card">
            <h2>📈 Camera Summary</h2>
            <div class="summary">
                <div class="stat-box">
                    <div class="stat-value">''' + str(len(cameras)) + '''</div>
                    <div>Total Cameras</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">''' + str(len([c for c in cameras if c.get('device_type', '') == 'IP Camera'])) + '''</div>
                    <div>IP Cameras</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">''' + str(len([c for c in cameras if 'DVR' in c.get('device_type', '') or 'NVR' in c.get('device_type', '')])) + '''</div>
                    <div>DVR/NVR Systems</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">''' + str(len(set(c.get('vendor', 'Unknown') for c in cameras if c.get('vendor', 'Unknown') != 'Unknown'))) + '''</div>
                    <div>Unique Vendors</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>📷 Camera Types</h2>
            <div class="camera-types">
                <div class="camera-type">
                    <h3>IP Cameras</h3>
                    <p>Network-connected cameras with built-in web servers</p>
                </div>
                <div class="camera-type">
                    <h3>DVR Systems</h3>
                    <p>Digital Video Recorders for analog camera systems</p>
                </div>
                <div class="camera-type">
                    <h3>NVR Systems</h3>
                    <p>Network Video Recorders for IP camera systems</p>
                </div>
            </div>
        </div>
        
        <button class="scan-btn" onclick="startCameraScan()">🔍 Scan for Cameras</button>
        
        <div class="card">
            <h2>🔍 Detected Cameras</h2>
            <div class="export-options">
                <button class="export-btn" onclick="exportResults('json')">Export JSON</button>
                <button class="export-btn" onclick="exportResults('csv')">Export CSV</button>
                <button class="export-btn" onclick="exportResults('html')">Export HTML</button>
                <button class="export-btn" onclick="printResults()">Print Report</button>
            </div>
            
            <div class="results" id="camerasContainer">
                ''' + cameras_html + '''
            </div>
        </div>
    </div>
    
    <script>
        function startCameraScan() {
            const network = prompt('Enter network to scan for cameras (e.g., 192.168.1.0/24):', '192.168.1.0/24');
            if (network) {
                if (confirm('Start camera detection on ' + network + '?')) {
                    // Show loading
                    document.getElementById('camerasContainer').innerHTML = '<p>Scanning for cameras... Please wait.</p>';
                    
                    fetch('/api/scan_network', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            network: network,
                            scan_type: 'cameras'
                        })
                    })
                    .then(response => response.json())
                    .then(data => {
                        alert('Camera detection started: ' + data.network);
                        // Poll for status updates
                        const statusInterval = setInterval(() => {
                            fetch('/api/status')
                            .then(response => response.json())
                            .then(status => {
                                if (status.status === 'completed' || status.status === 'error') {
                                    clearInterval(statusInterval);
                                    if (status.status === 'completed') {
                                        // Reload the page to show results
                                        location.reload();
                                    } else {
                                        document.getElementById('camerasContainer').innerHTML = '<p>Error during camera detection.</p>';
                                    }
                                }
                            });
                        }, 1000);
                    })
                    .catch(error => {
                        document.getElementById('camerasContainer').innerHTML = '<p>Error starting camera detection: ' + error + '</p>';
                    });
                }
            }
        }
        
        function exportResults(format) {
            alert('Export as ' + format.toUpperCase() + ' would be implemented in a full version');
            // In a real implementation, this would trigger the export
        }
        
        function printResults() {
            window.print();
        }
    </script>
</body>
</html>
            '''
        
        def get_severity_text(self, description):
            """Get severity text from description"""
            description_lower = description.lower()
            if 'critical' in description_lower:
                return 'Critical'
            elif 'high' in description_lower:
                return 'High'
            elif 'medium' in description_lower:
                return 'Medium'
            elif 'low' in description_lower:
                return 'Low'
            else:
                return 'Unknown'
        
        def generate_history_page(self):
            return '''
<!DOCTYPE html>
<html>
<head>
    <title>Scan History - Advanced Network Scanner</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        :root {
            --primary: #3498db;
            --secondary: #2c3e50;
            --success: #27ae60;
            --warning: #f39c12;
            --danger: #e74c3c;
            --light: #ecf0f1;
            --dark: #34495e;
        }
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72, #2a5298);
            color: #333;
            line-height: 1.6;
        }
        .container {
            width: 90%;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background: rgba(255, 255, 255, 0.9);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        h1 {
            color: var(--secondary);
            margin-bottom: 10px;
        }
        .nav {
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 10px;
            margin: 20px 0;
        }
        .nav a {
            display: inline-block;
            padding: 12px 20px;
            background: var(--primary);
            color: white;
            text-decoration: none;
            border-radius: 5px;
            transition: all 0.3s ease;
        }
        .nav a:hover {
            background: #2980b9;
            transform: translateY(-2px);
        }
        .card {
            background: rgba(255, 255, 255, 0.9);
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
        }
        .history-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        .history-table th, .history-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        .history-table th {
            background: var(--light);
            font-weight: 600;
        }
        .history-table tr:hover {
            background: #f5f5f5;
        }
        .history-table .view-btn {
            padding: 5px 10px;
            background: var(--primary);
            color: white;
            border: none;
            border-radius: 3px;
            cursor: pointer;
        }
        .history-table .view-btn:hover {
            background: #2980b9;
        }
        .stats-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .stat-card {
            background: var(--light);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-value {
            font-size: 2rem;
            font-weight: bold;
            margin: 10px 0;
            color: var(--primary);
        }
        .pagination {
            display: flex;
            justify-content: center;
            gap: 10px;
            margin: 20px 0;
        }
        .page-btn {
            padding: 8px 15px;
            background: var(--light);
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        .page-btn.active {
            background: var(--primary);
            color: white;
        }
        @media (max-width: 768px) {
            .nav {
                flex-direction: column;
            }
            .nav a {
                width: 100%;
                text-align: center;
            }
            .history-table {
                font-size: 0.9rem;
            }
            .history-table th, .history-table td {
                padding: 8px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>📜 Scan History</h1>
            <p>Review previous scan results and reports</p>
        </header>
        
        <div class="nav">
            <a href="/">Dashboard</a>
            <a href="/scan">Scan Network</a>
            <a href="/results">Vulnerabilities</a>
            <a href="/cameras">Cameras</a>
            <a href="/history">Scan History</a>
            <a href="/settings">Settings</a>
        </div>
        
        <div class="card">
            <h2>📊 History Summary</h2>
            <div class="stats-summary">
                <div class="stat-card">
                    <div class="stat-value" id="totalScans">0</div>
                    <div>Total Scans</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="totalVulns">0</div>
                    <div>Total Vulnerabilities</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="avgVulns">0</div>
                    <div>Avg. Per Scan</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="lastScan">Never</div>
                    <div>Last Scan</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>📋 Scan Records</h2>
            <table class="history-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Date & Time</th>
                        <th>Network</th>
                        <th>Type</th>
                        <th>Devices</th>
                        <th>Vulnerabilities</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="historyTableBody">
                    <tr>
                        <td colspan="7" style="text-align: center;">Loading history...</td>
                    </tr>
                </tbody>
            </table>
            
            <div class="pagination">
                <button class="page-btn active">1</button>
                <button class="page-btn">2</button>
                <button class="page-btn">3</button>
                <button class="page-btn">Next →</button>
            </div>
        </div>
    </div>
    
    <script>
        // Load scan history
        function loadScanHistory() {
            fetch('/api/history')
            .then(response => response.json())
            .then(history => {
                const tbody = document.getElementById('historyTableBody');
                tbody.innerHTML = '';
                
                if (history.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="7" style="text-align: center;">No scan history found</td></tr>';
                    return;
                }
                
                // Update summary stats
                document.getElementById('totalScans').textContent = history.length;
                
                // Calculate total vulnerabilities
                let totalVulns = 0;
                history.forEach(scan => {
                    totalVulns += scan.vulnerability_count || 0;
                });
                document.getElementById('totalVulns').textContent = totalVulns;
                
                // Calculate average vulnerabilities per scan
                const avgVulns = history.length > 0 ? Math.round(totalVulns / history.length) : 0;
                document.getElementById('avgVulns').textContent = avgVulns;
                
                // Add rows for each scan
                history.forEach(scan => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${scan.id || 'N/A'}</td>
                        <td>${scan.timestamp ? new Date(scan.timestamp).toLocaleString() : 'Unknown'}</td>
                        <td>${scan.network || 'Unknown'}</td>
                        <td>${scan.scan_type || 'Unknown'}</td>
                        <td>${scan.device_count || 0}</td>
                        <td>${scan.vulnerability_count || 0}</td>
                        <td>
                            <button class="view-btn" onclick="viewScanDetails(${scan.id})">View</button>
                        </td>
                    `;
                    tbody.appendChild(row);
                });
                
                // Update last scan time
                if (history.length > 0) {
                    const lastScan = new Date(history[0].timestamp);
                    document.getElementById('lastScan').textContent = lastScan.toLocaleDateString();
                }
            })
            .catch(error => {
                console.error('Error loading scan history:', error);
                document.getElementById('historyTableBody').innerHTML = '<tr><td colspan="7" style="text-align: center;">Error loading history</td></tr>';
            });
        }
        
        // View scan details
        function viewScanDetails(scanId) {
            alert('Viewing details for scan #' + scanId + ' would be implemented in a full version');
            // In a real implementation, this would show the scan details
        }
        
        // Initialize
        loadScanHistory();
    </script>
</body>
</html>
            '''
        
        def generate_settings_page(self):
            return '''
<!DOCTYPE html>
<html>
<head>
    <title>Settings - Advanced Network Scanner</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        :root {
            --primary: #3498db;
            --secondary: #2c3e50;
            --success: #27ae60;
            --warning: #f39c12;
            --danger: #e74c3c;
            --light: #ecf0f1;
            --dark: #34495e;
        }
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72, #2a5298);
            color: #333;
            line-height: 1.6;
        }
        .container {
            width: 90%;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background: rgba(255, 255, 255, 0.9);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        h1 {
            color: var(--secondary);
            margin-bottom: 10px;
        }
        .nav {
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 10px;
            margin: 20px 0;
        }
        .nav a {
            display: inline-block;
            padding: 12px 20px;
            background: var(--primary);
            color: white;
            text-decoration: none;
            border-radius: 5px;
            transition: all 0.3s ease;
        }
        .nav a:hover {
            background: #2980b9;
            transform: translateY(-2px);
        }
        .card {
            background: rgba(255, 255, 255, 0.9);
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
        }
        .settings-section {
            margin: 20px 0;
            padding: 20px;
            background: var(--light);
            border-radius: 8px;
        }
        .form-group {
            margin: 15px 0;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: 600;
        }
        input, select, textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        button {
            background: var(--primary);
            color: white;
            padding: 12px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 600;
        }
        button:hover {
            background: #2980b9;
        }
        .btn-danger {
            background: var(--danger);
        }
        .btn-danger:hover {
            background: #c0392b;
        }
        .btn-success {
            background: var(--success);
        }
        .btn-success:hover {
            background: #229954;
        }
        .setting-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 0;
            border-bottom: 1px solid #eee;
        }
        .setting-info {
            flex: 1;
        }
        .setting-control {
            width: 200px;
        }
        @media (max-width: 768px) {
            .nav {
                flex-direction: column;
            }
            .nav a {
                width: 100%;
                text-align: center;
            }
            .setting-row {
                flex-direction: column;
                align-items: flex-start;
            }
            .setting-control {
                width: 100%;
                margin-top: 10px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>⚙️ Settings</h1>
            <p>Configure scanner preferences and settings</p>
        </header>
        
        <div class="nav">
            <a href="/">Dashboard</a>
            <a href="/scan">Scan Network</a>
            <a href="/results">Vulnerabilities</a>
            <a href="/cameras">Cameras</a>
            <a href="/history">Scan History</a>
            <a href="/settings">Settings</a>
        </div>
        
        <div class="card">
            <h2>🔧 Scanner Settings</h2>
            
            <div class="settings-section">
                <h3>Network Configuration</h3>
                
                <div class="setting-row">
                    <div class="setting-info">
                        <h4>Default Network</h4>
                        <p>Network to scan when no specific network is provided</p>
                    </div>
                    <div class="setting-control">
                        <input type="text" value="192.168.1.0/24" placeholder="e.g., 192.168.1.0/24">
                    </div>
                </div>
                
                <div class="setting-row">
                    <div class="setting-info">
                        <h4>Max Threads</h4>
                        <p>Maximum number of concurrent scanning threads</p>
                    </div>
                    <div class="setting-control">
                        <input type="number" value="100" min="10" max="500">
                    </div>
                </div>
                
                <div class="setting-row">
                    <div class="setting-info">
                        <h4>Port Scan Timeout</h4>
                        <p>Timeout for port scanning operations (seconds)</p>
                    </div>
                    <div class="setting-control">
                        <input type="number" value="3" min="1" max="30">
                    </div>
                </div>
            </div>
            
            <div class="settings-section">
                <h3>Security Settings</h3>
                
                <div class="setting-row">
                    <div class="setting-info">
                        <h4>Safe Network Check</h4>
                        <p>Prevent scanning of public networks</p>
                    </div>
                    <div class="setting-control">
                        <select>
                            <option value="enabled" selected>Enabled</option>
                            <option value="disabled">Disabled</option>
                        </select>
                    </div>
                </div>
                
                <div class="setting-row">
                    <div class="setting-info">
                        <h4>Port Validation</h4>
                        <p>Validate ports before scanning</p>
                    </div>
                    <div class="setting-control">
                        <select>
                            <option value="enabled" selected>Enabled</option>
                            <option value="disabled">Disabled</option>
                        </select>
                    </div>
                </div>
            </div>
            
            <div class="settings-section">
                <h3>Data Management</h3>
                
                <div class="setting-row">
                    <div class="setting-info">
                        <h4>Persistent Storage</h4>
                        <p>Save scan results to persistent storage</p>
                    </div>
                    <div class="setting-control">
                        <select>
                            <option value="enabled" selected>Enabled</option>
                            <option value="disabled">Disabled</option>
                        </select>
                    </div>
                </div>
                
                <div class="setting-row">
                    <div class="setting-info">
                        <h4>Auto Export</h4>
                        <p>Automatically export results in multiple formats</p>
                    </div>
                    <div class="setting-control">
                        <select>
                            <option value="enabled">Enabled</option>
                            <option value="disabled" selected>Disabled</option>
                        </select>
                    </div>
                </div>
            </div>
            
            <div class="settings-section">
                <h3>System Actions</h3>
                
                <div class="setting-row">
                    <div class="setting-info">
                        <h4>Update CVE Database</h4>
                        <p>Download latest CVE data from NVD</p>
                    </div>
                    <div class="setting-control">
                        <button class="btn-success" onclick="updateCveDatabase()">Update Now</button>
                    </div>
                </div>
                
                <div class="setting-row">
                    <div class="setting-info">
                        <h4>Update Scanner</h4>
                        <p>Update scanner from GitHub repository</p>
                    </div>
                    <div class="setting-control">
                        <button class="btn-success" onclick="updateScanner()">Update Now</button>
                    </div>
                </div>
                
                <div class="setting-row">
                    <div class="setting-info">
                        <h4>Clear Scan History</h4>
                        <p>Delete all stored scan results</p>
                    </div>
                    <div class="setting-control">
                        <button class="btn-danger" onclick="clearHistory()">Clear History</button>
                    </div>
                </div>
            </div>
            
            <div style="text-align: center; margin-top: 30px;">
                <button class="btn-success" style="padding: 15px 30px; font-size: 16px;">Save Settings</button>
            </div>
        </div>
    </div>
    
    <script>
        function updateCveDatabase() {
            alert('CVE database update would be implemented in a full version');
        }
        
        function updateScanner() {
            if (confirm('Update scanner from GitHub? This will fetch the latest changes.')) {
                fetch('/api/update_github', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        alert('Update successful! ' + data.message);
                    } else {
                        alert('Update failed: ' + data.message);
                    }
                })
                .catch(error => {
                    alert('Update error: ' + error);
                });
            }
        }
        
        function clearHistory() {
            if (confirm('Are you sure you want to clear all scan history? This cannot be undone.')) {
                alert('History cleared');
            }
        }
    </script>
</body>
</html>
            '''
        

    # Return the handler class
    return ScannerHandler


def main():
    """Main entry point for the web interface"""
    try:
        from http.server import HTTPServer
        handler_class = simple_web_server()
        if handler_class:
            server = HTTPServer(('localhost', 8080), handler_class)
            print("Web interface started at http://localhost:8080")
            server.serve_forever()
        else:
            print("Failed to start web server")
    except KeyboardInterrupt:
        print("\nWeb server stopped.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()