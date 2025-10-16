"""Network visualization tools for scan results."""

import json
import os
from datetime import datetime
from typing import List, Dict, Optional, Any

def generate_network_map(devices: List[Dict[str, Any]], output_file: Optional[str] = None) -> str:
    """
    Generate a simple text-based network map from scan results.
    
    Args:
        devices: List of discovered devices/vulnerabilities
        output_file: Optional file to save the map to
        
    Returns:
        String representation of the network map
    """
    if not devices:
        map_str = "Network Map\n" + "="*50 + "\n"
        map_str += "No devices discovered.\n"
        return map_str
    
    # Group devices by IP
    ip_devices = {}
    for device in devices:
        ip = device.get('ip', 'unknown')
        if ip not in ip_devices:
            ip_devices[ip] = []
        ip_devices[ip].append(device)
    
    # Generate map
    map_str = "Network Map\n" + "="*50 + "\n"
    map_str += f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    
    for ip, device_list in ip_devices.items():
        map_str += f"IP: {ip}\n"
        map_str += "-"*30 + "\n"
        
        # Group by port
        port_services = {}
        for device in device_list:
            port = device.get('port', 'unknown')
            service = device.get('service', 'unknown')
            cve_id = device.get('cve_id', 'unknown')
            description = device.get('description', 'no description')
            
            if port not in port_services:
                port_services[port] = []
            port_services[port].append((service, cve_id, description))
        
        for port, services in port_services.items():
            map_str += f"  Port {port}:\n"
            for service, cve_id, description in services:
                severity = "🔴" if "critical" in description.lower() or "rce" in description.lower() else "🟡"
                map_str += f"    {severity} {service} - {cve_id}\n"
                map_str += f"      {description}\n"
        map_str += "\n"
    
    # Save to file if requested
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(map_str)
    
    return map_str

def generate_simple_topology(devices: List[Dict[str, Any]]) -> str:
    """
    Generate a simple ASCII topology view of the network.
    
    Args:
        devices: List of discovered devices
        
    Returns:
        ASCII representation of network topology
    """
    if not devices:
        return "Network Topology\n" + "="*30 + "\nNo devices found.\n"
    
    # Group by subnet
    subnets = {}
    for device in devices:
        ip = device.get('ip', 'unknown')
        if '.' in ip:
            subnet = '.'.join(ip.split('.')[:3]) + '.0/24'
            if subnet not in subnets:
                subnets[subnet] = []
            subnets[subnet].append(ip)
    
    # Generate topology
    topology = "Network Topology\n" + "="*30 + "\n"
    
    for i, (subnet, ips) in enumerate(subnets.items()):
        topology += f"Subnet {i+1}: {subnet}\n"
        for j, ip in enumerate(sorted(set(ips))):
            # Add vulnerability indicator
            vuln_indicator = ""
            for device in devices:
                if device.get('ip') == ip and 'cve_id' in device:
                    vuln_indicator = " [🔴VULNERABLE]"
                    break
            topology += f"  ├── {ip}{vuln_indicator}\n"
        topology += "\n"
    
    return topology

def export_to_graphviz(devices: List[Dict[str, Any]], output_file: str) -> bool:
    """
    Export network map to Graphviz format for visualization.
    
    Args:
        devices: List of discovered devices
        output_file: Output .dot file path
        
    Returns:
        True if successful, False otherwise
    """
    try:
        if not devices:
            return False
            
        dot_content = "graph network_map {\n"
        dot_content += "  rankdir=LR;\n"
        dot_content += "  node [shape=box, style=filled, fillcolor=lightblue];\n\n"
        
        # Add nodes and edges
        ip_devices = {}
        for device in devices:
            ip = device.get('ip', 'unknown')
            if ip not in ip_devices:
                ip_devices[ip] = []
            ip_devices[ip].append(device)
        
        # Create nodes
        for ip in ip_devices.keys():
            has_vulns = any('cve_id' in device for device in ip_devices[ip])
            color = "red" if has_vulns else "lightblue"
            dot_content += f'  "{ip}" [fillcolor={color}];\n'
        
        # Create edges (simplified - just showing connections)
        ips = list(ip_devices.keys())
        for i in range(len(ips)-1):
            dot_content += f'  "{ips[i]}" -- "{ips[i+1]}";\n'
        
        dot_content += "}\n"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(dot_content)
            
        return True
    except Exception:
        return False

def print_summary_stats(devices: List[Dict[str, Any]]) -> str:
    """
    Print summary statistics of the scan.
    
    Args:
        devices: List of discovered devices/vulnerabilities
        
    Returns:
        Summary statistics string
    """
    if not devices:
        return "Scan Summary\n" + "="*30 + "\nNo vulnerabilities found.\n"
    
    total_devices = len(set(device.get('ip') for device in devices if 'ip' in device))
    total_vulns = len([device for device in devices if 'cve_id' in device])
    critical_vulns = len([device for device in devices 
                         if 'cve_id' in device and 
                         any(keyword in device.get('description', '').lower() 
                             for keyword in ['rce', 'critical', 'arbitrary code'])])
    
    # Service distribution
    service_count = {}
    for device in devices:
        if 'service' in device:
            service = device['service']
            service_count[service] = service_count.get(service, 0) + 1
    
    summary = "Scan Summary\n" + "="*50 + "\n"
    summary += f"Total Devices Scanned: {total_devices}\n"
    summary += f"Total Vulnerabilities: {total_vulns}\n"
    summary += f"Critical Vulnerabilities: {critical_vulns}\n"
    summary += "\nService Distribution:\n"
    
    for service, count in sorted(service_count.items(), key=lambda x: x[1], reverse=True):
        summary += f"  {service}: {count}\n"
    
    return summary