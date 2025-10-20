import ipaddress
import threading
import time
import requests
import subprocess
import re
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
from utils.persistent_storage import persistent_storage

# Set up logger
logger = setup_logger()

# Camera-specific ports and signatures
CAMERA_PORTS = [554, 80, 8080, 8000, 37777, 37778, 8001, 9000]
CAMERA_SIGNATURES = [
    "Network Camera", "IP Camera", "DVR", "NVR", " surveillance", 
    "camera server", "rtsp", "onvif", "axis", "hikvision", 
    "dahua", "foscam", "tplink", "netcam"
]

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
        
        # Save to persistent storage with error handling
        try:
            scan_id = persistent_storage.save_scan_results(self.exploited_devices, network, "network_scan")
            persistent_storage.save_results_to_files(self.exploited_devices, scan_id)
        except Exception as e:
            logger.error(f"❌ Error saving to persistent storage: {e}")
        
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

    def scan_multiple_networks(self, networks: List[str]):
        """Scan multiple network subnets."""
        logger.info(f"🔄 Scanning multiple networks: {networks}")
        
        all_results = []
        for network in networks:
            logger.info(f"📡 Scanning network: {network}")
            self.scan_network(network)
            all_results.extend(self.exploited_devices.copy())
            # Clear results for next network
            self.exploited_devices.clear()
        
        # Restore all results
        self.exploited_devices = all_results
        save_results(self.exploited_devices, RESULTS_FILE)
        
        # Save to persistent storage with error handling
        try:
            if networks:
                scan_id = persistent_storage.save_scan_results(self.exploited_devices, ", ".join(networks), "multiple_networks")
                persistent_storage.save_results_to_files(self.exploited_devices, scan_id)
        except Exception as e:
            logger.error(f"❌ Error saving to persistent storage: {e}")
            
        logger.info(f"✅ Multi-network scan complete. Results saved to: {RESULTS_FILE}")

    def scan_with_exclusions(self, network: str, exclude_ips: List[str]):
        """Scan network excluding specific IPs."""
        logger.info(f"🔄 Scanning network {network} excluding IPs: {exclude_ips}")
        
        if not is_safe_network(network):
            logger.error(f"❌ Network {network} is not safe to scan.")
            return
            
        net = ipaddress.IPv4Network(network, strict=False)
        exclude_set = set(exclude_ips)
        threads = []

        for ip in net.hosts():
            # Skip excluded IPs
            if str(ip) in exclude_set:
                logger.debug(f"⏭️  Skipping excluded IP: {ip}")
                continue
                
            while threading.active_count() > MAX_THREADS:
                time.sleep(0.1)

            t = threading.Thread(target=self.scan_single_host, args=(str(ip),), daemon=True)
            t.start()
            threads.append(t)

        for t in threads:
            t.join(timeout=10)

        save_results(self.exploited_devices, RESULTS_FILE)
        
        # Save to persistent storage with error handling
        try:
            scan_id = persistent_storage.save_scan_results(self.exploited_devices, network, "network_with_exclusions")
            persistent_storage.save_results_to_files(self.exploited_devices, scan_id)
        except Exception as e:
            logger.error(f"❌ Error saving to persistent storage: {e}")
        
        logger.info(f"✅ Scan with exclusions complete. Results saved to: {RESULTS_FILE}")

    def discover_surrounding_routers(self) -> List[Dict[str, Any]]:
        """Discover surrounding WiFi routers/networks."""
        routers = []
        logger.info("🔍 Discovering surrounding routers...")
        
        try:
            import platform
            import subprocess
            import re
            
            system = platform.system().lower()
            
            if system == "windows":
                # Windows: Use netsh to discover WiFi networks
                routers = self._discover_windows_wifi()
            elif system in ["linux", "darwin"]:  # Linux or macOS
                # Unix-like systems: Try different approaches
                routers = self._discover_unix_wifi()
            else:
                logger.warning(f"Unsupported platform for router discovery: {system}")
                
        except Exception as e:
            logger.error(f"Error discovering routers: {e}")
            
        return routers
    
    def _discover_windows_wifi(self) -> List[Dict[str, Any]]:
        """Discover WiFi networks on Windows using netsh."""
        routers = []
        try:
            # First check if WiFi is available
            result = subprocess.run([
                "netsh", "wlan", "show", "interfaces"
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and "disconnected" not in result.stdout.lower():
                # Show available networks
                result = subprocess.run([
                    "netsh", "wlan", "show", "networks", "mode=bssid"
                ], capture_output=True, text=True, timeout=15)
                
                if result.returncode == 0:
                    routers = self._parse_windows_wifi_output(result.stdout)
                    
        except subprocess.TimeoutExpired:
            logger.warning("WiFi discovery timed out")
        except Exception as e:
            logger.error(f"Error in Windows WiFi discovery: {e}")
            
        return routers
    
    def _discover_unix_wifi(self) -> List[Dict[str, Any]]:
        """Discover WiFi networks on Unix-like systems."""
        routers = []
        try:
            # Try nmcli (NetworkManager)
            result = subprocess.run([
                "nmcli", "device", "wifi", "list"
            ], capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                routers = self._parse_nmcli_output(result.stdout)
            else:
                # Try iwlist as fallback
                result = subprocess.run([
                    "sudo", "iwlist", "scan"
                ], capture_output=True, text=True, timeout=20)
                
                if result.returncode == 0:
                    routers = self._parse_iwlist_output(result.stdout)
                    
        except subprocess.TimeoutExpired:
            logger.warning("WiFi discovery timed out")
        except Exception as e:
            logger.error(f"Error in Unix WiFi discovery: {e}")
            
        return routers
    
    def _parse_windows_wifi_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Windows netsh WiFi output."""
        routers = []
        current_network = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            # Look for network SSID
            if line.startswith("SSID"):
                if current_network and 'ssid' in current_network:
                    routers.append(current_network)
                    
                current_network = {}
                # Extract SSID (format: "SSID 1 : NetworkName")
                parts = line.split(":", 1)
                if len(parts) > 1:
                    current_network['ssid'] = parts[1].strip()
                    
            # Look for BSSID (MAC address)
            elif line.startswith("BSSID") and current_network:
                parts = line.split(":", 1)
                if len(parts) > 1:
                    current_network['bssid'] = parts[1].strip()
                    
            # Look for signal strength
            elif line.startswith("Signal") and current_network:
                parts = line.split(":", 1)
                if len(parts) > 1:
                    signal = parts[1].strip().replace('%', '')
                    try:
                        # Convert percentage to dBm approximation
                        signal_dbm = int(signal) / 2 - 100
                        current_network['signal'] = f"{signal_dbm:.0f} dBm"
                        current_network['signal_percentage'] = f"{signal}%"
                    except ValueError:
                        current_network['signal'] = signal
                        
            # Look for authentication
            elif line.startswith("Authentication") and current_network:
                parts = line.split(":", 1)
                if len(parts) > 1:
                    current_network['security'] = parts[1].strip()
        
        # Add the last network
        if current_network and 'ssid' in current_network:
            routers.append(current_network)
            
        return routers
    
    def _parse_nmcli_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse nmcli WiFi output."""
        routers = []
        
        lines = output.split('\n')
        if len(lines) > 1:
            # Skip header line
            for line in lines[1:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 8:
                        router = {
                            'ssid': parts[1] if parts[1] != '--' else 'Hidden Network',
                            'bssid': parts[0],
                            'signal': f"{parts[6]} dBm" if parts[6] != '--' else 'Unknown',
                            'security': parts[7] if parts[7] != '--' else 'Open'
                        }
                        routers.append(router)
                        
        return routers
    
    def _parse_iwlist_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse iwlist scan output."""
        routers = []
        current_network = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            if line.startswith("Cell"):
                if current_network:
                    routers.append(current_network)
                current_network = {}
                
            elif "ESSID:" in line:
                match = re.search(r'ESSID:"(.+)"', line)
                if match:
                    current_network['ssid'] = match.group(1)
                    
            elif "Address:" in line:
                match = re.search(r'Address: (.+)', line)
                if match:
                    current_network['bssid'] = match.group(1)
                    
            elif "Quality=" in line:
                match = re.search(r'Quality=(\d+)/(\d+)', line)
                if match:
                    try:
                        quality = int(match.group(1))
                        max_quality = int(match.group(2))
                        percentage = (quality / max_quality) * 100
                        signal_dbm = percentage / 2 - 100
                        current_network['signal'] = f"{signal_dbm:.0f} dBm"
                        current_network['signal_percentage'] = f"{percentage:.0f}%"
                    except:
                        pass
                        
            elif "Encryption key:" in line:
                if "on" in line:
                    current_network['security'] = "Encrypted"
                else:
                    current_network['security'] = "Open"
        
        # Add the last network
        if current_network:
            routers.append(current_network)
            
        return routers

    def scan_ipv6_network(self, network: str):
        """Scan an IPv6 network subnet."""
        try:
            logger.info(f"🔄 Scanning IPv6 network: {network}")
            net = ipaddress.IPv6Network(network, strict=False)
            threads = []

            for ip in net.hosts():
                # Limit IPv6 scans due to address space size
                if threading.active_count() > MAX_THREADS:
                    time.sleep(0.1)

                t = threading.Thread(target=self.scan_single_host, args=(str(ip),), daemon=True)
                t.start()
                threads.append(t)

                # Limit total threads for IPv6 (much larger address space)
                if len(threads) > 1000:
                    break

            for t in threads:
                t.join(timeout=5)

            save_results(self.exploited_devices, RESULTS_FILE)
            
            # Save to persistent storage with error handling
            try:
                scan_id = persistent_storage.save_scan_results(self.exploited_devices, network, "ipv6_network")
                persistent_storage.save_results_to_files(self.exploited_devices, scan_id)
            except Exception as e:
                logger.error(f"❌ Error saving to persistent storage: {e}")
            
            logger.info(f"✅ IPv6 scan complete. Results saved to: {RESULTS_FILE}")
            
        except Exception as e:
            logger.error(f"❌ Error scanning IPv6 network: {e}")

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
        
        # Save to persistent storage with error handling
        try:
            scan_id = persistent_storage.save_scan_results(self.exploited_devices, ip, "single_ip")
            persistent_storage.save_results_to_files(self.exploited_devices, scan_id)
        except Exception as e:
            logger.error(f"❌ Error saving to persistent storage: {e}")
        
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
        
        # Save to persistent storage with error handling
        try:
            scan_id = persistent_storage.save_scan_results(self.exploited_devices, network, "port_scan")
            persistent_storage.save_results_to_files(self.exploited_devices, scan_id)
        except Exception as e:
            logger.error(f"❌ Error saving to persistent storage: {e}")
        
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
            554: "RTSP",  # RTSP - Real Time Streaming Protocol (common for IP cameras)
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            37777: "DVR/NVR",  # Common port for DVR/NVR systems
            37778: "DVR/NVR",  # Another common port for DVR/NVR systems
            5432: "PostgreSQL",
            5900: "VNC",
            8000: "HTTP-Alt",
            8001: "HTTP-Alt",
            8080: "HTTP-Alt",
            9000: "HTTP-Alt"
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

    def vlan_scan(self, base_network: str, vlan_ids: List[int]):
        """Scan VLANs by modifying the base network."""
        logger.info(f"🔄 Scanning VLANs {vlan_ids} on base network {base_network}")
        
        # This is a simplified VLAN scan - in practice, you'd need special network equipment
        # For demonstration, we'll simulate by modifying the network's third octet
        try:
            base_net = ipaddress.IPv4Network(base_network, strict=False)
            base_parts = str(base_net.network_address).split('.')
            
            for vlan_id in vlan_ids:
                # Modify the network to simulate VLAN (e.g., 192.168.1.0/24 -> 192.168.{vlan_id}.0/24)
                modified_parts = base_parts.copy()
                modified_parts[2] = str(vlan_id % 256)  # Keep within valid range
                modified_network = '.'.join(modified_parts) + '/24'
                
                logger.info(f"📡 Scanning VLAN {vlan_id} network: {modified_network}")
                self.scan_network(modified_network)
                
        except Exception as e:
            logger.error(f"❌ Error during VLAN scan: {e}")

    def detect_cameras(self, network: str):
        """Detect cameras on the network including IP cameras, DVRs, NVRs, etc."""
        logger.info(f"📹 Starting camera detection on network: {network}")
        
        if not is_safe_network(network):
            logger.error(f"❌ Network {network} is not safe to scan.")
            return []
            
        net = ipaddress.IPv4Network(network, strict=False)
        camera_devices = []
        threads = []
        
        # Update stats
        with self.lock:
            self.stats["devices_scanned"] = 0
            self.stats["ports_scanned"] = 0
            self.stats["vulnerabilities_found"] = 0
        
        for ip in net.hosts():
            while threading.active_count() > MAX_THREADS:
                time.sleep(0.1)

            t = threading.Thread(target=self._scan_camera_device, args=(str(ip), camera_devices), daemon=True)
            t.start()
            threads.append(t)

        for t in threads:
            t.join(timeout=15)  # Increased timeout for camera detection

        logger.info(f"✅ Camera detection complete. Found {len(camera_devices)} camera devices")
        
        # Save results
        if camera_devices:
            save_results(camera_devices, RESULTS_FILE.replace('.json', '_cameras.json'))
            
            # Save to persistent storage
            try:
                scan_id = persistent_storage.save_scan_results(camera_devices, network, "camera_detection")
                persistent_storage.save_results_to_files(camera_devices, scan_id)
            except Exception as e:
                logger.error(f"❌ Error saving camera results to persistent storage: {e}")
            
            logger.critical(f"📹 {len(camera_devices)} CAMERA DEVICE(S) DETECTED!")
            
        return camera_devices

    def _scan_camera_device(self, ip: str, camera_devices: List[Dict]):
        """Scan a single device for camera services."""
        # Update stats
        with self.lock:
            self.stats["devices_scanned"] += 1
            
        logger.debug(f"🔍 Scanning {ip} for camera services...")
        
        # Check camera-specific ports
        camera_ports_open = []
        for port in CAMERA_PORTS:
            if is_port_open(ip, port):
                camera_ports_open.append(port)
                with self.lock:
                    self.stats["ports_scanned"] += 1
                logger.debug(f"🔓 Camera port {port} open on {ip}")
        
        if not camera_ports_open:
            return  # No camera ports open, skip further checks
            
        # Try to identify camera services
        camera_info = self._identify_camera_service(ip, camera_ports_open)
        
        if camera_info:
            with self.lock:
                camera_devices.append(camera_info)
                self.stats["vulnerabilities_found"] += 1
            logger.info(f"📹 Camera detected: {ip} - {camera_info.get('device_type', 'Unknown')}")

    def _identify_camera_service(self, ip: str, open_ports: List[int]) -> Optional[Dict]:
        """Identify camera service based on open ports and HTTP responses."""
        camera_info = {
            "ip": ip,
            "device_type": "Unknown Camera Device",
            "ports": open_ports,
            "vendor": "Unknown",
            "model": "Unknown",
            "vulnerabilities": []
        }
        
        # Check port 80/HTTP first for device identification
        if 80 in open_ports or 8080 in open_ports or 8000 in open_ports:
            http_port = 80 if 80 in open_ports else (8080 if 8080 in open_ports else 8000)
            try:
                response = requests.get(f"http://{ip}:{http_port}", timeout=5, verify=False)
                content = response.text.lower()
                headers = str(response.headers).lower()
                
                # Check for camera signatures in response
                for signature in CAMERA_SIGNATURES:
                    if signature in content or signature in headers:
                        camera_info["device_type"] = self._determine_camera_type(signature)
                        camera_info["vendor"] = self._extract_vendor(content, headers)
                        camera_info["model"] = self._extract_model(content)
                        break
                        
                # Extract title if available
                if "<title>" in response.text:
                    start = response.text.find("<title>") + 7
                    end = response.text.find("</title>")
                    if end > start:
                        title = response.text[start:end].strip()
                        if not camera_info["model"] or camera_info["model"] == "Unknown":
                            camera_info["model"] = title
            except Exception as e:
                logger.debug(f"❌ HTTP request failed for {ip}:{http_port} - {e}")
        
        # Check RTSP port (554)
        if 554 in open_ports:
            try:
                # Try to connect to RTSP
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((ip, 554))
                if result == 0:
                    # Send RTSP OPTIONS request
                    rtsp_request = f"OPTIONS rtsp://{ip}:554/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
                    sock.send(rtsp_request.encode())
                    response = sock.recv(1024).decode().lower()
                    if "rtsp" in response:
                        if "hikvision" in response:
                            camera_info["vendor"] = "Hikvision"
                            camera_info["device_type"] = "IP Camera"
                        elif "dahua" in response:
                            camera_info["vendor"] = "Dahua"
                            camera_info["device_type"] = "IP Camera"
                        else:
                            camera_info["device_type"] = "RTSP Camera"
                sock.close()
            except Exception as e:
                logger.debug(f"❌ RTSP connection failed for {ip}:554 - {e}")
        
        # Check DVR/NVR ports
        if 37777 in open_ports or 37778 in open_ports:
            camera_info["device_type"] = "DVR/NVR System"
            camera_info["vendor"] = "Generic"
            
        # If we found any camera-related information, return the device info
        if (camera_info["device_type"] != "Unknown Camera Device" or 
            camera_info["vendor"] != "Unknown" or 
            len(open_ports) > 0):
            return camera_info
            
        return None

    def _determine_camera_type(self, signature: str) -> str:
        """Determine camera type based on signature."""
        signature = signature.lower()
        if "dvr" in signature:
            return "DVR System"
        elif "nvr" in signature:
            return "NVR System"
        elif "ip camera" in signature or "network camera" in signature:
            return "IP Camera"
        elif "surveillance" in signature:
            return "Surveillance Camera"
        elif "onvif" in signature:
            return "ONVIF Camera"
        elif "rtsp" in signature:
            return "RTSP Camera"
        else:
            return "Network Camera"

    def _extract_vendor(self, content: str, headers: str) -> str:
        """Extract vendor information from HTTP response."""
        content = content.lower()
        headers = headers.lower()
        
        vendors = {
            "hikvision": ["hikvision", "hik"],
            "dahua": ["dahua"],
            "axis": ["axis"],
            "foscam": ["foscam"],
            "tplink": ["tp-link", "tplink"],
            "dlink": ["d-link", "dlink"],
            "sony": ["sony"],
            "panasonic": ["panasonic"],
            "bosch": ["bosch"]
        }
        
        for vendor, signatures in vendors.items():
            for sig in signatures:
                if sig in content or sig in headers:
                    return vendor.capitalize()
                    
        return "Unknown"

    def _extract_model(self, content: str) -> str:
        """Extract model information from HTTP response."""
        # This is a simplified model extraction
        # In a real implementation, you would have more sophisticated parsing
        return "Unknown"