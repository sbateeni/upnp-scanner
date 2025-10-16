import ipaddress
import time
import random
from threading import Lock
import socket
import struct

def check_private_network(ip: str) -> bool:
    """Check if IP is within private network ranges."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def validate_environment() -> bool:
    """Validate that scanning is allowed in this environment."""
    # This is a placeholder for environment validation
    # In a real implementation, you might check:
    # - Network permissions
    # - Legal compliance
    # - Configuration files
    return True

class RateLimiter:
    """Simple rate limiter to prevent network flooding."""
    def __init__(self, max_rps=10):
        self.max_rps = max_rps
        self.request_times = []
        self.lock = Lock()

    def rate_limit(self):
        """Enforce rate limiting."""
        with self.lock:
            now = time.time()
            # Remove requests older than 1 second
            self.request_times = [t for t in self.request_times if now - t < 1.0]
            if len(self.request_times) >= self.max_rps:
                sleep_time = 1.0 - (now - self.request_times[0])
                if sleep_time > 0:
                    time.sleep(sleep_time)
            self.request_times.append(now)

class StealthScanner:
    """Scanner with stealth capabilities."""
    def __init__(self, min_delay=0.1, max_delay=1.0):
        self.min_delay = min_delay
        self.max_delay = max_delay

    def random_delay(self):
        """Add a random delay to avoid detection."""
        delay = random.uniform(self.min_delay, self.max_delay)
        time.sleep(delay)

def is_valid_ip(ip: str) -> bool:
    """Check if a string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_network(network: str) -> bool:
    """Check if a string is a valid network CIDR."""
    try:
        ipaddress.ip_network(network, strict=False)
        return True
    except ValueError:
        return False

def get_local_ip() -> str:
    """Get the local IP address of this machine."""
    try:
        # Connect to a remote server to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"

def get_network_range(ip: str, subnet_mask: str = "255.255.255.0") -> str:
    """Get the network range for a given IP and subnet mask."""
    try:
        # Convert subnet mask to CIDR
        mask_parts = subnet_mask.split('.')
        mask_binary = ''.join(format(int(part), '08b') for part in mask_parts)
        cidr = mask_binary.count('1')
        
        network = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
        return str(network)
    except Exception:
        return "192.168.1.0/24"

def format_bytes(bytes_count: int) -> str:
    """Format byte count to human readable format."""
    byte_val = float(bytes_count)
    for unit in ['B', 'KB', 'MB', 'GB']:
        if byte_val < 1024.0:
            return f"{byte_val:.1f} {unit}"
        byte_val /= 1024.0
    return f"{byte_val:.1f} TB"

def calculate_network_stats(network: str) -> dict:
    """Calculate statistics for a network range."""
    try:
        net = ipaddress.IPv4Network(network, strict=False)
        return {
            "network": str(net),
            "netmask": str(net.netmask),
            "hosts_count": net.num_addresses - 2,  # Subtract network and broadcast
            "first_host": str(net[1]),
            "last_host": str(net[-2])
        }
    except Exception:
        return {}

def obfuscate_ip(ip: str) -> str:
    """Obfuscate an IP address for privacy."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 4:
            parts = ip.split('.')
            # Hide the last octet
            return f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"
        else:
            # For IPv6, hide the last part
            parts = ip.split(':')
            return ':'.join(parts[:-1]) + ':xxxx'
    except Exception:
        return "xxx.xxx.xxx.xxx"