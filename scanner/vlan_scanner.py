"""VLAN scanning utilities for complex network environments."""

import ipaddress
from typing import List, Dict, Any
from scanner.core import AdvancedNetworkScanner
from utils.security import is_valid_vlan_id

class VLANScanner:
    """Scanner specialized for VLAN environments."""
    
    def __init__(self, base_scanner: AdvancedNetworkScanner):
        self.base_scanner = base_scanner
        self.vlan_results = {}
        
    def scan_vlan_range(self, base_network: str, vlan_start: int, vlan_end: int) -> Dict[int, List[Dict[str, Any]]]:
        """
        Scan a range of VLANs by modifying the base network.
        
        Args:
            base_network: Base network in CIDR notation (e.g., '192.168.0.0/24')
            vlan_start: Starting VLAN ID
            vlan_end: Ending VLAN ID
            
        Returns:
            Dictionary mapping VLAN IDs to scan results
        """
        if not is_valid_vlan_id(vlan_start) or not is_valid_vlan_id(vlan_end):
            raise ValueError("Invalid VLAN ID range")
            
        if vlan_start > vlan_end:
            raise ValueError("VLAN start must be less than or equal to VLAN end")
            
        results = {}
        
        # Parse base network to get the base IP
        try:
            base_net = ipaddress.ip_network(base_network, strict=False)
            base_parts = str(base_net.network_address).split('.')
        except Exception as e:
            raise ValueError(f"Invalid base network: {e}")
            
        # Scan each VLAN in the range
        for vlan_id in range(vlan_start, vlan_end + 1):
            # Modify the network to simulate VLAN
            # For example, 192.168.1.0/24 with VLAN 100 becomes 192.168.100.0/24
            modified_parts = base_parts.copy()
            
            # Use VLAN ID to modify the third octet (with modulo to keep in range)
            modified_parts[2] = str(vlan_id % 256)
            modified_network = '.'.join(modified_parts) + '/24'
            
            print(f"📡 Scanning VLAN {vlan_id} network: {modified_network}")
            
            # Perform scan on this VLAN network
            vlan_scanner = AdvancedNetworkScanner()
            vlan_scanner.scan_network(modified_network)
            
            # Store results
            results[vlan_id] = vlan_scanner.exploited_devices.copy()
            
        self.vlan_results = results
        return results
        
    def scan_specific_vlans(self, base_network: str, vlan_ids: List[int]) -> Dict[int, List[Dict[str, Any]]]:
        """
        Scan specific VLAN IDs.
        
        Args:
            base_network: Base network in CIDR notation
            vlan_ids: List of VLAN IDs to scan
            
        Returns:
            Dictionary mapping VLAN IDs to scan results
        """
        # Validate VLAN IDs
        invalid_vlans = [vlan for vlan in vlan_ids if not is_valid_vlan_id(vlan)]
        if invalid_vlans:
            raise ValueError(f"Invalid VLAN IDs: {invalid_vlans}")
            
        results = {}
        
        # Parse base network
        try:
            base_net = ipaddress.ip_network(base_network, strict=False)
            base_parts = str(base_net.network_address).split('.')
        except Exception as e:
            raise ValueError(f"Invalid base network: {e}")
            
        # Scan each specified VLAN
        for vlan_id in vlan_ids:
            # Modify the network to simulate VLAN
            modified_parts = base_parts.copy()
            modified_parts[2] = str(vlan_id % 256)
            modified_network = '.'.join(modified_parts) + '/24'
            
            print(f"📡 Scanning VLAN {vlan_id} network: {modified_network}")
            
            # Perform scan on this VLAN network
            vlan_scanner = AdvancedNetworkScanner()
            vlan_scanner.scan_network(modified_network)
            
            # Store results
            results[vlan_id] = vlan_scanner.exploited_devices.copy()
            
        self.vlan_results = results
        return results
        
    def get_vlan_summary(self) -> Dict[str, Any]:
        """
        Get a summary of all VLAN scan results.
        
        Returns:
            Summary dictionary with statistics
        """
        if not self.vlan_results:
            return {"error": "No VLAN scan results available"}
            
        total_vlans = len(self.vlan_results)
        total_vulnerabilities = sum(len(devices) for devices in self.vlan_results.values())
        vlan_with_vulns = sum(1 for devices in self.vlan_results.values() if devices)
        
        # Find most vulnerable VLAN
        most_vuln_vlan = None
        max_vulns = 0
        for vlan_id, devices in self.vlan_results.items():
            if len(devices) > max_vulns:
                max_vulns = len(devices)
                most_vuln_vlan = vlan_id
                
        return {
            "total_vlans_scanned": total_vlans,
            "total_vulnerabilities": total_vulnerabilities,
            "vlans_with_vulnerabilities": vlan_with_vulns,
            "most_vulnerable_vlan": most_vuln_vlan,
            "average_vulnerabilities_per_vlan": total_vulnerabilities / total_vlans if total_vlans > 0 else 0
        }
        
    def export_vlan_results(self, filename_prefix: str = "vlan_scan"):
        """
        Export VLAN scan results to multiple formats.
        
        Args:
            filename_prefix: Prefix for output files
        """
        from scanner.report import save_results_csv, save_results_xml, save_results_html
        import json
        
        # Combine all VLAN results
        all_devices = []
        for vlan_id, devices in self.vlan_results.items():
            for device in devices:
                # Add VLAN info to each device
                device_with_vlan = device.copy()
                device_with_vlan['vlan_id'] = vlan_id
                all_devices.append(device_with_vlan)
                
        if not all_devices:
            print("No devices to export")
            return
            
        # Save in multiple formats
        save_results_csv(all_devices, f"{filename_prefix}.csv")
        save_results_xml(all_devices, f"{filename_prefix}.xml")
        save_results_html(all_devices, f"{filename_prefix}.html")
        
        # Save JSON
        with open(f"{filename_prefix}.json", "w", encoding="utf-8") as f:
            json.dump(all_devices, f, indent=4, ensure_ascii=False)
            
        print(f"✅ VLAN scan results exported to {filename_prefix}.*")
        
    def print_vlan_report(self):
        """Print a formatted report of VLAN scan results."""
        if not self.vlan_results:
            print("No VLAN scan results available")
            return
            
        print("\n" + "="*60)
        print("📊 VLAN Scan Report")
        print("="*60)
        
        # Print summary
        summary = self.get_vlan_summary()
        for key, value in summary.items():
            print(f"{key.replace('_', ' ').title()}: {value}")
            
        print("\n" + "-"*60)
        print("VLAN Details:")
        print("-"*60)
        
        # Print details for each VLAN
        for vlan_id, devices in self.vlan_results.items():
            if devices:
                print(f"\nVLAN {vlan_id}: {len(devices)} vulnerabilities")
                for device in devices:
                    print(f"  • {device.get('ip', 'Unknown')}:{device.get('port', 'Unknown')} "
                          f"- {device.get('cve_id', 'Unknown')} ({device.get('service', 'Unknown')})")
            else:
                print(f"\nVLAN {vlan_id}: No vulnerabilities found")