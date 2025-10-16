import socket
import struct
import time
from config.settings import SCAN_TIMEOUT

def discover_with_ws_discovery(ip: str) -> bool:
    """Discover devices using WS-Discovery protocol (UDP 3702)."""
    try:
        # WS-Discovery multicast address and port
        multicast_group = '239.255.255.250'
        port = 3702
        
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(SCAN_TIMEOUT)
        
        # WS-Discovery probe message
        message = b'<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsd:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsd:Action></soap:Header><soap:Body><wsd:Probe/></soap:Body></soap:Envelope>'
        
        # Send probe directly to the device
        sock.sendto(message, (ip, port))
        
        # Try to receive a response
        try:
            data, _ = sock.recvfrom(1024)
            sock.close()
            return len(data) > 0
        except socket.timeout:
            sock.close()
            return False
            
    except Exception:
        return False

def discover_with_ssdp(ip: str) -> bool:
    """Discover devices using SSDP protocol (UDP 1900)."""
    try:
        # SSDP multicast address and port
        multicast_group = '239.255.255.250'
        port = 1900
        
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(SCAN_TIMEOUT)
        
        # SSDP M-SEARCH message
        message = 'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n'
        
        # Send M-SEARCH directly to the device
        sock.sendto(message.encode(), (ip, port))
        
        # Try to receive a response
        try:
            data, _ = sock.recvfrom(1024)
            sock.close()
            return len(data) > 0
        except socket.timeout:
            sock.close()
            return False
            
    except Exception:
        return False

def discover_with_mdns(ip: str) -> bool:
    """Discover devices using mDNS protocol (UDP 5353)."""
    try:
        # mDNS multicast address and port
        multicast_group = '224.0.0.251'
        port = 5353
        
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(SCAN_TIMEOUT)
        
        # Simple mDNS query (querying for all services)
        # This is a basic DNS query packet
        message = bytearray.fromhex('000000000001000000000000095f7365727669636573075f646e732d7364045f756470056c6f63616c00000c0001')
        
        # Send query directly to the device
        sock.sendto(message, (ip, port))
        
        # Try to receive a response
        try:
            data, _ = sock.recvfrom(1024)
            sock.close()
            return len(data) > 0
        except socket.timeout:
            sock.close()
            return False
            
    except Exception:
        return False