import ipaddress
import threading
import time
import requests
from datetime import datetime
from threading import Lock

from config.settings import MAX_THREADS, COMMON_PORTS, RESULTS_FILE, LOG_FILE
from scanner.discovery import discover_with_ws_discovery, discover_with_ssdp, discover_with_mdns
from scanner.port_scanner import is_port_open
from scanner.cve_checker import test_port_based_cve
from scanner.report import setup_logger, save_results

# Set up logger
logger = setup_logger()

class AdvancedNetworkScanner:
    """Advanced network scanner with multiple discovery methods and CVE checking."""
    
    def __init__(self):
        self.exploited_devices = []
        self.lock = Lock()
        
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
        for port in COMMON_PORTS:
            if is_port_open(ip, port):
                open_ports.append(port)
                contacted = True

        if open_ports:
            logger.info(f"🔓 Open ports on {ip}: {open_ports}")
            # Test for port-based CVEs
            test_port_based_cve(self.exploited_devices, self.lock, ip, open_ports)

        # --- CVE Testing (Only if device is contacted) ---
        if contacted:
            logger.info(f"✅ Contacted device at {ip} (Server: {device_info.get('server', 'N/A')})")
        else:
            logger.debug(f"No response from {ip}")

    def scan_network(self, network: str):
        """Scan an entire network subnet."""
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

    def check_private_network(self, ip: str) -> bool:
        """Check if IP is within private network ranges."""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def scan_single_ip(self, ip: str):
        """Scan a single IP address."""
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
        logger.info(f"🔓 Scanning ports {ports} on network: {network}")
        net = ipaddress.IPv4Network(network, strict=False)
        scanner = AdvancedNetworkScanner()
        
        for ip in net.hosts():
            if not scanner.check_private_network(str(ip)):
                continue
            open_ports = []
            for port in ports:
                if is_port_open(str(ip), port):
                    open_ports.append(port)
            if open_ports:
                logger.info(f"🔓 Open ports on {ip}: {open_ports}")
                # Test for port-based CVEs
                test_port_based_cve(scanner.exploited_devices, scanner.lock, str(ip), open_ports)
                
        save_results(scanner.exploited_devices, RESULTS_FILE)
        logger.info(f"✅ Port scan complete. Full log: {LOG_FILE}")
        if scanner.exploited_devices:
            logger.critical(
                f"🚨 {len(scanner.exploited_devices)} VULNERABLE DEVICE(S) DETECTED! "
                f"Details saved to: {RESULTS_FILE}"
            )