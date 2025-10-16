"""Persistent storage utilities for scan results."""

import json
import os
import sqlite3
from datetime import datetime
from typing import List, Dict, Any
import csv

class PersistentStorage:
    """Handle permanent storage of scan results."""
    
    def __init__(self, storage_dir: str = "scan_results"):
        """Initialize storage system."""
        self.storage_dir = storage_dir
        self.db_path = os.path.join(storage_dir, "scan_results.db")
        self.ensure_storage_directory()
        self.init_database()
        
    def ensure_storage_directory(self):
        """Create storage directory if it doesn't exist."""
        if not os.path.exists(self.storage_dir):
            os.makedirs(self.storage_dir)
            print(f"📁 Created storage directory: {self.storage_dir}")
            
    def init_database(self):
        """Initialize SQLite database for scan results."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                network TEXT,
                scan_type TEXT,
                device_count INTEGER,
                vulnerability_count INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                ip TEXT NOT NULL,
                port INTEGER,
                service TEXT,
                cve_id TEXT,
                description TEXT,
                severity TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                ip TEXT NOT NULL,
                hostname TEXT,
                mac_address TEXT,
                vendor TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        ''')
        
        conn.commit()
        conn.close()
        print(f"💾 Initialized database: {self.db_path}")
        
    def save_scan_results(self, results: List[Dict[str, Any]], network: str = "", scan_type: str = "network_scan") -> int:
        """
        Save scan results to persistent storage.
        
        Args:
            results: List of vulnerability dictionaries
            network: Network that was scanned
            scan_type: Type of scan performed
            
        Returns:
            Scan ID in database
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Insert scan record
        timestamp = datetime.now().isoformat()
        vulnerability_count = len(results)
        device_count = len(set(result.get('ip', '') for result in results))
        
        cursor.execute('''
            INSERT INTO scans (timestamp, network, scan_type, device_count, vulnerability_count)
            VALUES (?, ?, ?, ?, ?)
        ''', (timestamp, network, scan_type, device_count, vulnerability_count))
        
        scan_id = cursor.lastrowid
        
        # Insert vulnerabilities
        for result in results:
            cursor.execute('''
                INSERT INTO vulnerabilities (scan_id, ip, port, service, cve_id, description, severity)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                result.get('ip', ''),
                result.get('port', 0),
                result.get('service', ''),
                result.get('cve_id', ''),
                result.get('description', ''),
                self.determine_severity(result.get('description', ''))
            ))
        
        conn.commit()
        conn.close()
        
        print(f"✅ Saved scan #{scan_id} with {vulnerability_count} vulnerabilities to database")
        return int(scan_id) if scan_id is not None else 0
        
    def determine_severity(self, description: str) -> str:
        """Determine severity level based on description."""
        description_lower = description.lower()
        
        if any(keyword in description_lower for keyword in ['rce', 'remote code execution', 'arbitrary code']):
            return 'critical'
        elif any(keyword in description_lower for keyword in ['dos', 'denial of service', 'bypass', 'overflow']):
            return 'high'
        elif any(keyword in description_lower for keyword in ['xss', 'csrf', 'cross-site']):
            return 'medium'
        elif any(keyword in description_lower for keyword in ['information disclosure', 'info leak']):
            return 'low'
        else:
            return 'unknown'
            
    def save_results_to_files(self, results: List[Dict[str, Any]], scan_id: int):
        """
        Save results to various file formats.
        
        Args:
            results: List of vulnerability dictionaries
            scan_id: Scan ID for filename
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"scan_{scan_id}_{timestamp}"
        
        # Save as JSON
        json_path = os.path.join(self.storage_dir, f"{base_filename}.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"📄 Saved JSON results: {json_path}")
        
        # Save as CSV
        csv_path = os.path.join(self.storage_dir, f"{base_filename}.csv")
        if results:
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                # Write header
                writer.writerow(['IP', 'Port', 'Service', 'CVE ID', 'Description', 'Severity'])
                # Write data
                for result in results:
                    writer.writerow([
                        result.get('ip', ''),
                        result.get('port', ''),
                        result.get('service', ''),
                        result.get('cve_id', ''),
                        result.get('description', ''),
                        self.determine_severity(result.get('description', ''))
                    ])
        print(f"📄 Saved CSV results: {csv_path}")
        
        # Save as HTML report
        html_path = os.path.join(self.storage_dir, f"{base_filename}.html")
        self.generate_html_report(results, html_path, scan_id)
        print(f"📄 Saved HTML report: {html_path}")
        
    def generate_html_report(self, results: List[Dict[str, Any]], filepath: str, scan_id: int):
        """Generate HTML report of scan results."""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Scan Report #{scan_id} - Advanced Network Scanner</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; text-align: center; }}
        h2 {{ color: #34495e; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        .summary {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .vulnerability {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .critical {{ border-left: 5px solid #e74c3c; }}
        .high {{ border-left: 5px solid #f39c12; }}
        .medium {{ border-left: 5px solid #f1c40f; }}
        .low {{ border-left: 5px solid #2ecc71; }}
        .stats {{ display: flex; justify-content: space-around; text-align: center; margin: 20px 0; }}
        .stat-box {{ background: #3498db; color: white; padding: 20px; border-radius: 10px; }}
        .stat-number {{ font-size: 2em; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Network Scan Report #{scan_id}</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="summary">
            <h2>📊 Scan Summary</h2>
            <div class="stats">
                <div class="stat-box">
                    <div class="stat-number">{len(results)}</div>
                    <div>Vulnerabilities Found</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{len(set(result.get('ip', '') for result in results))}</div>
                    <div>Devices Scanned</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{len(set(result.get('service', '') for result in results))}</div>
                    <div>Services Detected</div>
                </div>
            </div>
        </div>
        
        <h2>⚠️ Vulnerabilities Found</h2>
        """
        
        # Group by severity
        critical = [r for r in results if self.determine_severity(r.get('description', '')) == 'critical']
        high = [r for r in results if self.determine_severity(r.get('description', '')) == 'high']
        medium = [r for r in results if self.determine_severity(r.get('description', '')) == 'medium']
        low = [r for r in results if self.determine_severity(r.get('description', '')) == 'low']
        
        for vuln in results:
            severity = self.determine_severity(vuln.get('description', ''))
            severity_class = severity if severity in ['critical', 'high', 'medium', 'low'] else 'low'
            
            html_content += f"""
        <div class="vulnerability {severity_class}">
            <h3>{vuln.get('cve_id', 'Unknown CVE')}</h3>
            <p><strong>IP:</strong> {vuln.get('ip', 'Unknown')}:{vuln.get('port', 'Unknown')}</p>
            <p><strong>Service:</strong> {vuln.get('service', 'Unknown')}</p>
            <p><strong>Severity:</strong> {severity.upper()}</p>
            <p><strong>Description:</strong> {vuln.get('description', 'No description')}</p>
        </div>
            """
        
        html_content += """
    </div>
</body>
</html>
        """
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
    def get_scan_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get scan history from database.
        
        Args:
            limit: Number of recent scans to retrieve
            
        Returns:
            List of scan records
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, timestamp, network, scan_type, device_count, vulnerability_count
            FROM scans
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        
        scans = []
        for row in cursor.fetchall():
            scans.append({
                'id': row[0],
                'timestamp': row[1],
                'network': row[2],
                'scan_type': row[3],
                'device_count': row[4],
                'vulnerability_count': row[5]
            })
            
        conn.close()
        return scans
        
    def get_scan_results(self, scan_id: int) -> List[Dict[str, Any]]:
        """
        Get detailed results for a specific scan.
        
        Args:
            scan_id: ID of scan to retrieve
            
        Returns:
            List of vulnerability records
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT ip, port, service, cve_id, description, severity
            FROM vulnerabilities
            WHERE scan_id = ?
        ''', (scan_id,))
        
        vulnerabilities = []
        for row in cursor.fetchall():
            vulnerabilities.append({
                'ip': row[0],
                'port': row[1],
                'service': row[2],
                'cve_id': row[3],
                'description': row[4],
                'severity': row[5]
            })
            
        conn.close()
        return vulnerabilities
        
    def export_scan_to_json(self, scan_id: int, filepath: str):
        """
        Export a specific scan to JSON file.
        
        Args:
            scan_id: ID of scan to export
            filepath: Path to save JSON file
        """
        results = self.get_scan_results(scan_id)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"📤 Exported scan #{scan_id} to: {filepath}")
        
    def get_storage_stats(self) -> Dict[str, Any]:
        """
        Get storage statistics.
        
        Returns:
            Dictionary with storage statistics
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get total scans
        cursor.execute('SELECT COUNT(*) FROM scans')
        total_scans = cursor.fetchone()[0]
        
        # Get total vulnerabilities
        cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
        total_vulnerabilities = cursor.fetchone()[0]
        
        # Get total devices
        cursor.execute('SELECT COUNT(DISTINCT ip) FROM vulnerabilities')
        total_devices = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_scans': total_scans,
            'total_vulnerabilities': total_vulnerabilities,
            'total_devices': total_devices,
            'storage_directory': self.storage_dir,
            'database_path': self.db_path
        }

# Global storage instance
persistent_storage = PersistentStorage()