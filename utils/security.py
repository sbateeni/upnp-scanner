"""Security utilities for safe scanning."""

import ipaddress
import os
import sys
from typing import List, Dict, Any

def is_safe_network(network: str) -> bool:
    """
    Check if a network is safe to scan.
    
    Args:
        network: Network CIDR string
        
    Returns:
        True if safe to scan, False otherwise
    """
    try:
        net = ipaddress.ip_network(network, strict=False)
        
        # Block scanning of localhost/loopback
        if net.network_address.is_loopback:
            return False
            
        # Block scanning of multicast networks
        if net.network_address.is_multicast:
            return False
            
        # Block scanning of reserved networks
        if net.network_address.is_reserved:
            return False
            
        # For IPv6, only allow private address spaces
        if net.version == 6:
            # Allow Unique Local Addresses (ULA) - fc00::/7
            ula_network = ipaddress.IPv6Network('fc00::/7')
            if net.overlaps(ula_network):
                return True
            # Allow Link-Local addresses - fe80::/10
            link_local_network = ipaddress.IPv6Network('fe80::/10')
            if net.overlaps(link_local_network):
                return True
            return False
            
        # For IPv4, only allow private networks (RFC 1918)
        safe_ranges = [
            ipaddress.ip_network('10.0.0.0/8'),      # 10.0.0.0 - 10.255.255.255
            ipaddress.ip_network('172.16.0.0/12'),   # 172.16.0.0 - 172.31.255.255
            ipaddress.ip_network('192.168.0.0/16'),  # 192.168.0.0 - 192.168.255.255
        ]
        
        # Check if network is within safe ranges
        for safe_range in safe_ranges:
            if net.overlaps(safe_range):
                return True
                
        # If we get here, it's not a safe private network
        return False
        
    except Exception:
        # If we can't parse the network, consider it unsafe
        return False

def get_safe_scan_range() -> str:
    """
    Get a safe default scan range based on local IP.
    
    Returns:
        Safe network CIDR string
    """
    try:
        # Get local IP
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        # Convert to network range
        ip_obj = ipaddress.ip_address(local_ip)
        if ip_obj.version == 4:
            # For IPv4, get the /24 network
            network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
            return str(network)
        else:
            # For IPv6, get a smaller range
            return "fc00::/7"  # ULA range for IPv6
    except Exception:
        # Fallback to a common private network
        return "192.168.1.0/24"

def validate_port_list(ports: List[int]) -> List[int]:
    """
    Validate and filter a list of ports for safety.
    
    Args:
        ports: List of port numbers
        
    Returns:
        Filtered list of safe ports
    """
    # Common safe ports for scanning
    safe_ports = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
        993, 995, 1433, 1521, 1883, 3306, 3389, 5000, 5432, 5900, 
        631, 8080, 8443, 9000, 9090, 9100, 9200, 11211, 27017
    ]
    
    # Filter to only safe ports
    filtered_ports = [port for port in ports if port in safe_ports and 1 <= port <= 65535]
    
    # Remove duplicates and sort
    return sorted(list(set(filtered_ports)))

def check_permissions() -> bool:
    """
    Check if the scanner has necessary permissions.
    
    Returns:
        True if permissions are sufficient, False otherwise
    """
    # Check if running as root/admin (needed for some scans)
    if sys.platform.startswith('win'):
        # Windows - check if running as administrator
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    else:
        # Unix-like systems - check if root
        try:
            return os.geteuid() == 0
        except AttributeError:
            # geteuid not available on Windows
            return True

def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent directory traversal.
    
    Args:
        filename: Input filename
        
    Returns:
        Sanitized filename
    """
    # Remove path separators
    filename = filename.replace('/', '_').replace('\\', '_')
    # Remove other potentially dangerous characters
    filename = ''.join(c for c in filename if c.isalnum() or c in '._-')
    # Limit length
    if len(filename) > 255:
        filename = filename[:255]
    return filename

def obfuscate_results(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Obfuscate sensitive information in scan results.
    
    Args:
        results: List of scan results
        
    Returns:
        List of obfuscated results
    """
    obfuscated = []
    
    for result in results:
        obfuscated_result = result.copy()
        
        # Obfuscate IP addresses
        if 'ip' in obfuscated_result:
            ip = obfuscated_result['ip']
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.version == 4:
                    parts = ip.split('.')
                    obfuscated_result['ip'] = f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"
                else:
                    parts = ip.split(':')
                    # For IPv6, obfuscate the last segments
                    if len(parts) > 4:
                        obfuscated_result['ip'] = ':'.join(parts[:4]) + ':xxxx:xxxx:xxxx:xxxx'
                    else:
                        obfuscated_result['ip'] = ':'.join(parts[:-1]) + ':xxxx'
            except Exception:
                obfuscated_result['ip'] = "xxx.xxx.xxx.xxx"
                
        obfuscated.append(obfuscated_result)
        
    return obfuscated

def generate_scan_token() -> str:
    """
    Generate a unique token for this scan session.
    
    Returns:
        Unique scan token
    """
    import hashlib
    import time
    import random
    
    # Create a unique string based on time and random data
    unique_string = f"{time.time()}_{random.randint(1000, 9999)}_{os.getpid()}"
    
    # Hash it to create a token
    token = hashlib.sha256(unique_string.encode()).hexdigest()[:16]
    
    return token

def is_valid_vlan_id(vlan_id: int) -> bool:
    """
    Check if a VLAN ID is valid.
    
    Args:
        vlan_id: VLAN ID to check
        
    Returns:
        True if valid, False otherwise
    """
    return isinstance(vlan_id, int) and 1 <= vlan_id <= 4094

def validate_network_list(networks: List[str]) -> List[str]:
    """
    Validate a list of networks for safety.
    
    Args:
        networks: List of network CIDR strings
        
    Returns:
        Filtered list of safe networks
    """
    safe_networks = []
    
    for network in networks:
        if is_safe_network(network):
            safe_networks.append(network)
        else:
            print(f"⚠️  Skipping unsafe network: {network}")
            
    return safe_networks