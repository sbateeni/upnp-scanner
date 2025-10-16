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

def is_udp_port_open(ip: str, port: int) -> bool:
    """Check if a UDP port is open on the specified IP."""
    try:
        # UDP is connectionless, so we send a dummy packet and see if we get a response
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(SCAN_TIMEOUT)
        
        # Send a dummy packet
        sock.sendto(b"dummy", (ip, port))
        
        # Try to receive a response
        try:
            data, _ = sock.recvfrom(1024)
            sock.close()
            return True
        except socket.timeout:
            # No response, but port might still be open
            # UDP scanning is unreliable - we assume open if no error
            sock.close()
            return True
    except Exception:
        return False

def scan_port_range(ip: str, start_port: int, end_port: int, protocol: str = "tcp") -> list:
    """Scan a range of ports on the specified IP."""
    open_ports = []
    
    for port in range(start_port, end_port + 1):
        if protocol.lower() == "tcp":
            if is_port_open(ip, port):
                open_ports.append(port)
        elif protocol.lower() == "udp":
            if is_udp_port_open(ip, port):
                open_ports.append(port)
                
    return open_ports

def service_scan(ip: str, ports: list) -> dict:
    """Perform service detection on open ports."""
    services = {}
    
    # Common service ports and their typical banners
    service_banners = {
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
    
    for port in ports:
        if is_port_open(ip, port):
            # Try to get service banner
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(SCAN_TIMEOUT)
                sock.connect((ip, port))
                
                # Try to read banner
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                
                if "Server:" in banner:
                    start = banner.find("Server:") + 8
                    end = banner.find("\r\n", start)
                    services[port] = banner[start:end].strip()
                else:
                    services[port] = service_banners.get(port, f"Unknown Service (Port {port})")
            except Exception:
                services[port] = service_banners.get(port, f"Unknown Service (Port {port})")
        else:
            services[port] = "Closed"
            
    return services