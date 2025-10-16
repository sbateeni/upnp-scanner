#!/usr/bin/env python3
"""
Web Interface for Advanced Network Scanner
This provides a simple web-based interface alternative to the CLI
"""

import threading
import json
import os
import sys
from typing import List, Dict, Any
from scanner.core import AdvancedNetworkScanner
from utils.security import is_safe_network, validate_port_list
from utils.network_visualizer import print_summary_stats

# Global variables for scan results and status
_scan_results: List[Dict[str, Any]] = []
scan_status = "idle"  # idle, running, completed, error
scan_progress = 0
scanner_thread = None
scanner = None

def get_scan_results():
    """Get current scan results"""
    return _scan_results

def update_scan_results(results):
    """Update scan results"""
    global _scan_results
    _scan_results = results

def simple_web_server():
    """Create a simple HTTP server for the web interface"""
    try:
        from http.server import HTTPServer, BaseHTTPRequestHandler
        from urllib.parse import parse_qs
        import urllib.parse
        
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
                    
                elif self.path == '/api/status':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    
                    status_data = {
                        'status': scan_status,
                        'progress': scan_progress,
                        'results_count': len(get_scan_results())
                    }
                    self.wfile.write(json.dumps(status_data).encode())
                    
                elif self.path == '/api/results':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    
                    self.wfile.write(json.dumps(get_scan_results()).encode())
                    
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
                    
                    # Start scan in background
                    global scanner_thread, scan_status, scan_progress, scanner
                    scan_status = "running"
                    scan_progress = 0
                    
                    if not scanner:
                        scanner = AdvancedNetworkScanner()
                        
                    scanner_thread = threading.Thread(target=self.run_scan, args=(network,))
                    scanner_thread.daemon = True
                    scanner_thread.start()
                    
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'status': 'started', 'network': network}).encode())
            
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
            
            def generate_main_page(self):
                return '''
<!DOCTYPE html>
<html>
<head>
    <title>Advanced Network Scanner</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; text-align: center; }
        .nav { margin: 20px 0; }
        .nav a { display: inline-block; padding: 10px 20px; margin: 5px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; }
        .nav a:hover { background: #2980b9; }
        .status { padding: 15px; background: #ecf0f1; border-radius: 5px; margin: 20px 0; }
        .progress { height: 20px; background: #bdc3c7; border-radius: 10px; margin: 10px 0; }
        .progress-bar { height: 100%; background: #3498db; border-radius: 10px; width: ''' + str(scan_progress) + '''%; }
        .results { margin: 20px 0; }
        .result-item { padding: 10px; background: #f8f9fa; margin: 5px 0; border-left: 4px solid #3498db; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Advanced Network Scanner</h1>
        
        <div class="nav">
            <a href="/">Dashboard</a>
            <a href="/scan">Scan</a>
            <a href="/results">Results</a>
        </div>
        
        <div class="status">
            <h2>System Status</h2>
            <p>Status: <strong>''' + scan_status + '''</strong></p>
            <p>Progress: ''' + str(scan_progress) + '''%</p>
            <div class="progress">
                <div class="progress-bar"></div>
            </div>
            <p>Results Found: ''' + str(len(get_scan_results())) + '''</p>
        </div>
        
        <div class="results">
            <h2>Recent Results</h2>
            ''' + ('<p>No results yet. Run a scan to get started.</p>' if len(get_scan_results()) == 0 else '<p>Found ' + str(len(get_scan_results())) + ' results. Go to Results page for details.</p>') + '''
        </div>
    </div>
</body>
</html>
                '''
            
            def generate_scan_page(self):
                return '''
<!DOCTYPE html>
<html>
<head>
    <title>Scan Network - Advanced Network Scanner</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; text-align: center; }
        .nav { margin: 20px 0; }
        .nav a { display: inline-block; padding: 10px 20px; margin: 5px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; }
        .nav a:hover { background: #2980b9; }
        .form-group { margin: 15px 0; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input, select { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
        button { background: #27ae60; color: white; padding: 12px 20px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        button:hover { background: #229954; }
        .status { padding: 15px; background: #ecf0f1; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Scan Network</h1>
        
        <div class="nav">
            <a href="/">Dashboard</a>
            <a href="/scan">Scan</a>
            <a href="/results">Results</a>
        </div>
        
        <form id="scanForm">
            <div class="form-group">
                <label for="network">Network CIDR:</label>
                <input type="text" id="network" name="network" value="192.168.1.0/24" placeholder="e.g., 192.168.1.0/24">
            </div>
            
            <div class="form-group">
                <label for="scanType">Scan Type:</label>
                <select id="scanType" name="scanType">
                    <option value="full">Full Network Scan</option>
                    <option value="single">Single IP Scan</option>
                    <option value="ports">Port Scan</option>
                </select>
            </div>
            
            <button type="submit">Start Scan</button>
        </form>
        
        <div class="status" id="statusDiv" style="display: none;">
            <h3>Scan Status</h3>
            <p id="statusText">Starting scan...</p>
            <div class="progress">
                <div class="progress-bar" id="progressBar" style="width: 0%"></div>
            </div>
        </div>
    </div>
    
    <script>
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
                                document.getElementById('statusText').textContent = 'Scan completed! Found ' + status.results_count + ' results.';
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
                        results_html += f'''
                        <div class="result-item">
                            <strong>{result.get('ip', 'Unknown IP')}:{result.get('port', 'Unknown Port')}</strong><br>
                            Service: {result.get('service', 'Unknown')}<br>
                            CVE: {result.get('cve_id', 'Unknown')}<br>
                            Description: {result.get('description', 'No description')}
                        </div>
                        '''
                else:
                    results_html = '<p>No results found. Run a scan to get started.</p>'
                
                return '''
<!DOCTYPE html>
<html>
<head>
    <title>Scan Results - Advanced Network Scanner</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; text-align: center; }
        .nav { margin: 20px 0; }
        .nav a { display: inline-block; padding: 10px 20px; margin: 5px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; }
        .nav a:hover { background: #2980b9; }
        .results { margin: 20px 0; }
        .result-item { padding: 15px; background: #f8f9fa; margin: 10px 0; border-left: 4px solid #e74c3c; border-radius: 5px; }
        .summary { padding: 15px; background: #ecf0f1; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>📊 Scan Results</h1>
        
        <div class="nav">
            <a href="/">Dashboard</a>
            <a href="/scan">Scan</a>
            <a href="/results">Results</a>
        </div>
        
        <div class="summary">
            <h3>Summary</h3>
            <p>Total Results: ''' + str(len(results)) + '''</p>
        </div>
        
        <div class="results">
            <h3>Detailed Results</h3>
            ''' + results_html + '''
        </div>
    </div>
</body>
</html>
                '''
        
        server_address = ('localhost', 8080)
        httpd = HTTPServer(server_address, ScannerHandler)
        print("Starting web interface on http://localhost:8080")
        print("Press Ctrl+C to stop the server")
        httpd.serve_forever()
        
    except KeyboardInterrupt:
        print("\nShutting down web server...")
        sys.exit(0)
    except Exception as e:
        print(f"Error starting web server: {e}")
        print("Make sure port 8080 is available")

def main():
    """Main entry point"""
    print("Advanced Network Scanner - Web Interface")
    print("=" * 40)
    print("This will start a simple web server for the scanner interface.")
    print("Open your browser to http://localhost:8080")
    print("Press Ctrl+C to stop the server")
    print()
    
    try:
        simple_web_server()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    main()