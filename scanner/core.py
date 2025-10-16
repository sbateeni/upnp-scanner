import ipaddress
import threading
import time
import requests
from datetime import datetime
from threading import Lock
import socket
import struct
from typing import List, Dict, Any, Optional

from config.settings import MAX_THREADS, COMMON_PORTS, RESULTS_FILE, LOG_FILE
from scanner.discovery import discover_with_ws_discovery, discover_with_ssdp, discover_with_mdns
from scanner.port_scanner import is_port_open
from scanner.cve_checker import test_port_based_cve
from scanner.report import setup_logger, save_results
from utils.security import is_safe_network, validate_port_list

# Set up logger
logger = setup_logger()

class AdvancedNetworkScanner:
    """Advanced network scanner with multiple discovery methods and CVE checking."""
    
    def __init__(self):
        self.exploited_devices = []
        self.lock = Lock()
        self.stats = {
            "devices_scanned": 0,
            "ports_scanned": 0,
            "vulnerabilities_found": 0
        }
        self.scan_token = self._generate_scan_token()
        
    def _generate_scan_token(self) -> str:
        """Generate a unique token for this scan session."""
        import hashlib
        import time
        import random
        import os
        
        # Create a unique string based on time and random data
        unique_string = f"{time.time()}_{random.randint(1000, 9999)}_{os.getpid()}"
        
        # Hash it to create a token
        token = hashlib.sha256(unique_string.encode()).hexdigest()[:16]
        
        return token
        
    def get_device_info(self, ip: str) -> dict:
        """Get basic device information via HTTP."""
        info = {
            "ip": ip,
            "port_80_open": False,
            "server": "Unknown",
            "title": "Unknown"
        }
        
        try:
            response = requests.get(f"http://{ip}", timeout=3, verify=False)
            info["port_80_open"] = True
            if "Server" in response.headers:
                info["server"] = response.headers["Server"]
            if "<title>" in response.text:
                start = response.text.find("<title>") + 7
                end = response.text.find("</title>")
                if end > start:
                    info["title"] = response.text[start:end].strip()
        except Exception:
            pass
            
        return info

    def scan_single_host(self, ip: str):
        """Perform a full scan on a single host."""
        if not self.check_private_network(ip):
            return

        contacted = False
        open_ports = []

        # Update stats
        with self.lock:
            self.stats["devices_scanned"] += 1

        # --- Discovery Protocols (UDP) ---
        if discover_with_ws_discovery(ip):
            contacted = True
        if discover_with_ssdp(ip):
            contacted = True
        if discover_with_mdns(ip):
            contacted = True

        # --- HTTP Info Gathering (TCP 80/443) ---
        device_info = self.get_device_info(ip)
        if device_info["port_80_open"]:
            contacted = True

        # --- Extended Port Scanning (TCP) ---
        # Validate ports for safety
        safe_ports = validate_port_list(COMMON_PORTS)
        for port in safe_ports:
            if is_port_open(ip, port):
                open_ports.append(port)
                contacted = True
                # Update stats
                with self.lock:
                    self.stats["ports_scanned"] += 1

        if open_ports:
            logger.info(f"🔓 Open ports on {ip}: {open_ports}")
            # Test for port-based CVEs
            vulnerabilities_found = test_port_based_cve(self.exploited_devices, self.lock, ip, open_ports)
            # Update stats
            with self.lock:
                self.stats["vulnerabilities_found"] += vulnerabilities_found

        # --- CVE Testing (Only if device is contacted) ---
        if contacted:
            logger.info(f"✅ Contacted device at {ip} (Server: {device_info.get('server', 'N/A')})")
        else:
            logger.debug(f"No response from {ip}")

    def scan_network(self, network: str):
        """Scan an entire network subnet."""
        # Safety check
        if not is_safe_network(network):
            logger.error(f"❌ Network {network} is not safe to scan. Only private networks are allowed.")
            return
            
        logger.info(f"🚀 Starting advanced network scan on: {network}")
        net = ipaddress.IPv4Network(network, strict=False)
        threads = []

        for ip in net.hosts():
            while threading.active_count() > MAX_THREADS:
                time.sleep(0.1)

            t = threading.Thread(target=self.scan_single_host, args=(str(ip),), daemon=True)
            t.start()
            threads.append(t)

        for t in threads:
            t.join(timeout=10)

        save_results(self.exploited_devices, RESULTS_FILE)
        logger.info(f"✅ Scan complete. Full log: {LOG_FILE}")
        if self.exploited_devices:
            logger.critical(
                f"🚨 {len(self.exploited_devices)} VULNERABLE DEVICE(S) DETECTED! "
                f"Details saved to: {RESULTS_FILE}"
            )
        # Print stats
        logger.info(f"📊 Scan Statistics: {self.stats['devices_scanned']} devices scanned, "
                   f"{self.stats['ports_scanned']} ports scanned, "
                   f"{self.stats['vulnerabilities_found']} vulnerabilities found")

    def check_private_network(self, ip: str) -> bool:
        """Check if IP is within private network ranges."""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def scan_single_ip(self, ip: str):
        """Scan a single IP address."""
        # Safety check
        if not self.check_private_network(ip):
            logger.error(f"❌ IP {ip} is not in a private network range.")
            return
            
        logger.info(f"🎯 Scanning single IP: {ip}")
        self.scan_single_host(ip)
        save_results(self.exploited_devices, RESULTS_FILE)
        logger.info(f"✅ Scan complete. Full log: {LOG_FILE}")
        if self.exploited_devices:
            logger.critical(
                f"🚨 {len(self.exploited_devices)} VULNERABLE DEVICE(S) DETECTED! "
                f"Details saved to: {RESULTS_FILE}"
            )

    def scan_ports(self, network: str, ports: list):
        """Scan specific TCP ports on a network."""
        # Safety check
        if not is_safe_network(network):
            logger.error(f"❌ Network {network} is not safe to scan. Only private networks are allowed.")
            return
            
        logger.info(f"🔓 Scanning ports {ports} on network: {network}")
        net = ipaddress.IPv4Network(network, strict=False)
        
        # Validate ports for safety
        safe_ports = validate_port_list(ports)
        
        for ip in net.hosts():
            if not self.check_private_network(str(ip)):
                continue
            open_ports = []
            for port in safe_ports:
                if is_port_open(str(ip), port):
                    open_ports.append(port)
                    # Update stats
                    with self.lock:
                        self.stats["ports_scanned"] += 1
            if open_ports:
                logger.info(f"🔓 Open ports on {ip}: {open_ports}")
                # Test for port-based CVEs
                vulnerabilities_found = test_port_based_cve(self.exploited_devices, self.lock, str(ip), open_ports)
                # Update stats
                with self.lock:
                    self.stats["vulnerabilities_found"] += vulnerabilities_found
                
        save_results(self.exploited_devices, RESULTS_FILE)
        logger.info(f"✅ Port scan complete. Full log: {LOG_FILE}")
        if self.exploited_devices:
            logger.critical(
                f"🚨 {len(self.exploited_devices)} VULNERABLE DEVICE(S) DETECTED! "
                f"Details saved to: {RESULTS_FILE}"
            )

    def enhanced_port_scan(self, ip: str, ports: Optional[List[int]] = None) -> Dict[str, Any]:
        """Enhanced port scanning with service detection."""
        if ports is None:
            ports = COMMON_PORTS
            
        # Validate ports for safety
        safe_ports = validate_port_list(ports)
            
        open_ports = []
        service_info = {}
        
        for port in safe_ports:
            if is_port_open(ip, port):
                open_ports.append(port)
                # Try to identify service
                service = self.identify_service(ip, port)
                service_info[port] = service
                
        return {
            "ip": ip,
            "open_ports": open_ports,
            "services": service_info
        }
    
    def identify_service(self, ip: str, port: int) -> str:
        """Basic service identification based on port number."""
        service_map = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            8080: "HTTP-Alt"
        }
        
        return service_map.get(port, f"Unknown Service (Port {port})")

    def network_discovery(self, network: str) -> list:
        """Discover devices on network using multiple methods."""
        # Safety check
        if not is_safe_network(network):
            logger.error(f"❌ Network {network} is not safe to scan. Only private networks are allowed.")
            return []
            
        logger.info(f"🔍 Discovering devices on network: {network}")
        net = ipaddress.IPv4Network(network, strict=False)
        discovered_devices = []
        
        for ip in net.hosts():
            # Check if device responds to any discovery method
            if (discover_with_ws_discovery(str(ip)) or 
                discover_with_ssdp(str(ip)) or 
                discover_with_mdns(str(ip)) or
                is_port_open(str(ip), 80)):
                discovered_devices.append(str(ip))
                logger.info(f"📱 Discovered device: {ip}")
                
        logger.info(f"📊 Discovered {len(discovered_devices)} devices")
        return discovered_devices