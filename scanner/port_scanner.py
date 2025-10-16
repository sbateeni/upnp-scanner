import socket
from config.settings import SCAN_TIMEOUT

def is_port_open(ip: str, port: int) -> bool:
    """Check if a TCP port is open on the specified IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SCAN_TIMEOUT)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False