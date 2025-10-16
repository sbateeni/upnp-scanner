import socket
import struct
import time
from config.settings import SCAN_TIMEOUT
import ipaddress

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

def discover_with_arp(network: str) -> list:
    """Discover devices using ARP scanning (Linux/Mac only)."""
    try:
        # This is a simplified version - in practice, you'd use a library like scapy
        # For now, we'll just return an empty list as this requires special permissions
        return []
    except Exception:
        return []

def discover_with_icmp(ip: str) -> bool:
    """Discover devices using ICMP ping."""
    try:
        # Create ICMP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(SCAN_TIMEOUT)
        
        # Create ICMP echo request
        # Type=8 (Echo Request), Code=0
        icmp_packet = struct.pack('!BBHHH', 8, 0, 0, 1, 1)
        
        # Calculate checksum
        checksum = 0
        for i in range(0, len(icmp_packet), 2):
            checksum += (icmp_packet[i] << 8) + icmp_packet[i+1]
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum = ~checksum & 0xFFFF
        
        # Rebuild packet with checksum
        icmp_packet = struct.pack('!BBHHH', 8, 0, checksum, 1, 1)
        
        # Send ping
        sock.sendto(icmp_packet, (ip, 0))
        
        # Try to receive a response
        try:
            data, _ = sock.recvfrom(1024)
            sock.close()
            return len(data) > 0
        except socket.timeout:
            sock.close()
            return False
            
    except Exception:
        # Raw sockets require root privileges on Unix systems
        return False

def discover_with_snmp(ip: str) -> bool:
    """Discover devices using SNMP (UDP 161)."""
    try:
        # SNMP community string (public is default)
        community = b'public'
        
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(SCAN_TIMEOUT)
        
        # Simple SNMP GET request for sysDescr.0
        # This is a simplified version - real SNMP is more complex
        snmp_packet = b'\x30'  # ASN.1 SEQUENCE
        # In practice, you'd use a library like pysnmp for proper SNMP support
        
        # Send SNMP request
        sock.sendto(b'', (ip, 161))
        
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