#!/usr/bin/env python3
import sys
import subprocess
import os
import json
import urllib.request
import platform
from typing import List
from scanner.core import AdvancedNetworkScanner
from scanner.vlan_scanner import VLANScanner
from scanner.report import view_report, save_results_csv, save_results_xml, save_results_html
from utils.cve_updater import update_cve_database
from utils.network_visualizer import generate_network_map, generate_simple_topology, print_summary_stats
from utils.cli_ui import EnhancedCLI
from utils.helpers import cleanup_old_logs  # Added import
from config.settings import COMMON_PORTS, RESULTS_FILE, AVAILABLE_PROFILES
from config.profiles import get_profile

# Initialize enhanced CLI
cli = EnhancedCLI()

# Clean up old log files on startup
cleanup_old_logs()

def display_menu():
    """Display the main menu options."""
    cli.print_header("Advanced Network Scanner")
    
    cli.print_menu_item(1, "Scan Full Network (e.g., 192.168.1.0/24)", "🔍")
    cli.print_menu_item(2, "Scan Single IP Address", "🎯")
    cli.print_menu_item(3, "Scan Specific TCP Ports on Network", "🔓")
    cli.print_menu_item(4, "Update CVE Database", "📦")
    cli.print_menu_item(5, "Update Scanner from GitHub", "🔄")
    cli.print_menu_item(6, "Network Discovery", "📊")
    cli.print_menu_item(7, "Visualize Network Map", "🗺️")
    cli.print_menu_item(8, "Scan Multiple Networks", "🔗")
    cli.print_menu_item(9, "Scan with IP Exclusions", "🚫")
    cli.print_menu_item(10, "VLAN Scan", "🌐")
    cli.print_menu_item(11, "Start Web Interface", "🌐")
    cli.print_menu_item(12, "Detect Network Cameras", "📹")
    cli.print_menu_item(13, "View Last Scan Report", "📜")
    cli.print_menu_item(14, "Detect Surrounding Networks", "📡")  # New option
    cli.print_menu_item(15, "Exit", "🚪")  # Updated exit option
    
    print(cli.colorize("="*60, 'cyan'))

def get_user_choice():
    """Get and validate user menu choice."""
    try:
        choice = int(cli.get_user_input("Enter your choice (1-15)"))  # Updated range
        return choice
    except ValueError:
        return -1

def select_scan_profile():
    """Let user select a scanning profile."""
    cli.print_header("Scanning Profiles")
    print("\n📋 Available Scanning Profiles:")
    for i, profile_name in enumerate(AVAILABLE_PROFILES, 1):
        profile = get_profile(profile_name)
        print(f"  {cli.colorize(str(i), 'yellow')}. {profile['name']} - {profile['description']}")
    
    try:
        choice_input = cli.get_user_input(f"Select profile (1-{len(AVAILABLE_PROFILES)})", "1")
        choice = int(choice_input) if choice_input else 1
        if 1 <= choice <= len(AVAILABLE_PROFILES):
            return AVAILABLE_PROFILES[choice - 1]
        else:
            cli.print_status("Invalid choice. Using default profile.", "warning")
            return "default"
    except ValueError:
        cli.print_status("Invalid input. Using default profile.", "warning")
        return "default"

def run_scan_network(scanner):
    """Run a full network scan."""
    # Select profile
    profile_name = select_scan_profile()
    profile = get_profile(profile_name)
    cli.print_status(f"Using profile: {profile['name']} - {profile['description']}", "info")
    
    network = cli.get_user_input("Enter network CIDR (e.g., 192.168.1.0/24)", "192.168.1.0/24")
    
    cli.print_status(f"Starting scan on {network}...", "info")
    cli.animated_wait("Scanning network", 3)
    
    scanner.scan_network(network)
    
    # Save in multiple formats
    base_name = RESULTS_FILE.replace('.json', '')
    save_results_csv(scanner.exploited_devices, f"{base_name}.csv")
    save_results_xml(scanner.exploited_devices, f"{base_name}.xml")
    save_results_html(scanner.exploited_devices, f"{base_name}.html")
    
    # Generate visualization
    network_map = generate_network_map(scanner.exploited_devices, f"{base_name}_map.txt")
    print(network_map)
    
    # Print summary
    summary = print_summary_stats(scanner.exploited_devices)
    print(summary)
    
    # Print scan summary
    cli.print_scan_summary(scanner.exploited_devices)

def run_scan_single_ip(scanner):
    """Scan a single IP address."""
    cli.print_header("Single IP Scan")
    
    ip = cli.get_user_input("Enter IP address to scan (e.g., 192.168.1.100)")
    if ip:
        cli.print_status(f"Scanning IP {ip}...", "info")
        cli.animated_wait("Scanning IP", 2)
        
        scanner.scan_single_ip(ip)
        
        # Save in multiple formats
        base_name = RESULTS_FILE.replace('.json', '')
        save_results_csv(scanner.exploited_devices, f"{base_name}_single.csv")
        save_results_xml(scanner.exploited_devices, f"{base_name}_single.xml")
        save_results_html(scanner.exploited_devices, f"{base_name}_single.html")
        
        # Generate visualization
        network_map = generate_network_map(scanner.exploited_devices, f"{base_name}_single_map.txt")
        print(network_map)
        
        # Print summary
        summary = print_summary_stats(scanner.exploited_devices)
        print(summary)
        
        # Print scan summary
        cli.print_scan_summary(scanner.exploited_devices)
    else:
        cli.print_status("Invalid IP address.", "error")

def run_port_scan(scanner):
    """Scan specific ports on a network."""
    cli.print_header("Port Scan")
    
    network = cli.get_user_input("Enter network CIDR (e.g., 192.168.1.0/24)", "192.168.1.0/24")
    
    ports_input = cli.get_user_input(f"Enter ports to scan (comma-separated, e.g., 22,80,443)", 
                                    ','.join(map(str, COMMON_PORTS[:5])))
    if ports_input:
        try:
            ports = [int(p.strip()) for p in ports_input.split(",")]
        except ValueError:
            cli.print_status("Invalid port format. Using default ports.", "warning")
            ports = COMMON_PORTS[:5]
    else:
        ports = COMMON_PORTS[:5]
    
    cli.print_status(f"Scanning ports {ports} on network {network}...", "info")
    cli.animated_wait("Scanning ports", 3)
    
    scanner.scan_ports(network, ports)
    
    # Save in multiple formats
    base_name = RESULTS_FILE.replace('.json', '')
    save_results_csv(scanner.exploited_devices, f"{base_name}_ports.csv")
    save_results_xml(scanner.exploited_devices, f"{base_name}_ports.xml")
    save_results_html(scanner.exploited_devices, f"{base_name}_ports.html")
    
    # Generate visualization
    network_map = generate_network_map(scanner.exploited_devices, f"{base_name}_ports_map.txt")
    print(network_map)
    
    # Print summary
    summary = print_summary_stats(scanner.exploited_devices)
    print(summary)
    
    # Print scan summary
    cli.print_scan_summary(scanner.exploited_devices)

def run_network_discovery(scanner):
    """Run network discovery."""
    cli.print_header("Network Discovery")
    
    network = cli.get_user_input("Enter network CIDR (e.g., 192.168.1.0/24)", "192.168.1.0/24")
    
    cli.print_status(f"Discovering devices on {network}...", "info")
    cli.animated_wait("Discovering devices", 3)
    
    devices = scanner.network_discovery(network)
    if devices:
        cli.print_status(f"Discovered {len(devices)} devices:", "success")
        cli.print_device_list(devices)
    else:
        cli.print_status("No devices discovered.", "info")

def run_network_visualization(scanner):
    """Generate network visualization."""
    if not scanner.exploited_devices:
        cli.print_status("No scan data available. Run a scan first.", "warning")
        return
    
    cli.print_header("Network Visualization")
    print("1. Text-based Network Map")
    print("2. Simple Topology View")
    print("3. Summary Statistics")
    
    try:
        choice_input = cli.get_user_input("Select visualization type (1-3)", "1")
        choice = int(choice_input) if choice_input else 1
        
        if choice == 1:
            base_name = RESULTS_FILE.replace('.json', '')
            network_map = generate_network_map(scanner.exploited_devices, f"{base_name}_visualization.txt")
            print(network_map)
        elif choice == 2:
            topology = generate_simple_topology(scanner.exploited_devices)
            print(topology)
        elif choice == 3:
            summary = print_summary_stats(scanner.exploited_devices)
            print(summary)
        else:
            cli.print_status("Invalid choice.", "warning")
    except ValueError:
        cli.print_status("Invalid input.", "warning")

def run_multiple_networks_scan(scanner):
    """Scan multiple networks."""
    cli.print_header("Multiple Networks Scan")
    
    networks_input = cli.get_user_input("Enter networks to scan (comma-separated, e.g., 192.168.1.0/24,10.0.0.0/24)")
    if not networks_input:
        cli.print_status("No networks provided.", "warning")
        return
        
    try:
        networks = [net.strip() for net in networks_input.split(",")]
        cli.print_status(f"Scanning {len(networks)} networks...", "info")
        
        # Show progress
        for i, network in enumerate(networks, 1):
            cli.print_progress(i, len(networks), "Networks Scanned")
            scanner.scan_network(network)
        
        # Save in multiple formats
        base_name = RESULTS_FILE.replace('.json', '')
        save_results_csv(scanner.exploited_devices, f"{base_name}_multiple.csv")
        save_results_xml(scanner.exploited_devices, f"{base_name}_multiple.xml")
        save_results_html(scanner.exploited_devices, f"{base_name}_multiple.html")
        
        # Generate visualization
        network_map = generate_network_map(scanner.exploited_devices, f"{base_name}_multiple_map.txt")
        print(network_map)
        
        # Print summary
        summary = print_summary_stats(scanner.exploited_devices)
        print(summary)
        
        # Print scan summary
        cli.print_scan_summary(scanner.exploited_devices)
        
    except Exception as e:
        cli.print_status(f"Error scanning multiple networks: {e}", "error")

def run_exclusion_scan(scanner):
    """Scan network with IP exclusions."""
    cli.print_header("Scan with IP Exclusions")
    
    network = cli.get_user_input("Enter network CIDR (e.g., 192.168.1.0/24)", "192.168.1.0/24")
    
    exclusions_input = cli.get_user_input("Enter IPs to exclude (comma-separated, e.g., 192.168.1.1,192.168.1.254)")
    if exclusions_input:
        try:
            exclude_ips = [ip.strip() for ip in exclusions_input.split(",")]
        except Exception:
            cli.print_status("Invalid IP format. Scanning without exclusions.", "warning")
            exclude_ips = []
    else:
        exclude_ips = []
    
    cli.print_status(f"Scanning network {network} excluding {len(exclude_ips)} IPs...", "info")
    cli.animated_wait("Scanning with exclusions", 3)
    
    scanner.scan_with_exclusions(network, exclude_ips)
    
    # Save in multiple formats
    base_name = RESULTS_FILE.replace('.json', '')
    save_results_csv(scanner.exploited_devices, f"{base_name}_exclusions.csv")
    save_results_xml(scanner.exploited_devices, f"{base_name}_exclusions.xml")
    save_results_html(scanner.exploited_devices, f"{base_name}_exclusions.html")
    
    # Generate visualization
    network_map = generate_network_map(scanner.exploited_devices, f"{base_name}_exclusions_map.txt")
    print(network_map)
    
    # Print summary
    summary = print_summary_stats(scanner.exploited_devices)
    print(summary)
    
    # Print scan summary
    cli.print_scan_summary(scanner.exploited_devices)

def run_vlan_scan(scanner):
    """Scan VLANs."""
    cli.print_header("VLAN Scan")
    
    base_network = cli.get_user_input("Enter base network (e.g., 192.168.0.0/24)", "192.168.0.0/24")
    
    print("\nVLAN Scan Options:")
    print("1. Scan VLAN range")
    print("2. Scan specific VLANs")
    
    try:
        choice_input = cli.get_user_input("Select option (1-2)", "1")
        choice = int(choice_input) if choice_input else 1
        
        vlan_scanner = VLANScanner(scanner)
        
        if choice == 1:
            # Scan VLAN range
            vlan_start = int(cli.get_user_input("Enter start VLAN ID", "100"))
            vlan_end = int(cli.get_user_input("Enter end VLAN ID", "110"))
            
            cli.print_status(f"Scanning VLANs {vlan_start}-{vlan_end}...", "info")
            results = vlan_scanner.scan_vlan_range(base_network, vlan_start, vlan_end)
            
        elif choice == 2:
            # Scan specific VLANs
            vlan_input = cli.get_user_input("Enter VLAN IDs (comma-separated, e.g., 100,101,102)")
            vlan_ids = [int(vlan.strip()) for vlan in vlan_input.split(",")]
            
            cli.print_status(f"Scanning VLANs {vlan_ids}...", "info")
            results = vlan_scanner.scan_specific_vlans(base_network, vlan_ids)
            
        else:
            cli.print_status("Invalid choice.", "warning")
            return
            
        # Print VLAN report
        vlan_scanner.print_vlan_report()
        
        # Export results
        if cli.confirm_action("Export VLAN scan results?"):
            vlan_scanner.export_vlan_results("vlan_scan_results")
            
    except Exception as e:
        cli.print_status(f"Error during VLAN scan: {e}", "error")

def start_web_interface():
    """Start the web interface."""
    cli.print_header("Web Interface")
    cli.print_status("Starting web interface...", "info")
    cli.print_status("Open your browser to http://localhost:8080", "info")
    cli.print_status("Press Ctrl+C to stop the server", "info")
    
    try:
        # Import and run the new web interface
        from web.app import run_app
        run_app()
    except ImportError as e:
        # More detailed error handling to help with Termux issues
        cli.print_status(f"Web interface not available. Import error: {e}", "error")
        cli.print_status("This could be due to:", "warning")
        cli.print_status("1. Flask not installed (but you said it is installed)", "warning")
        cli.print_status("2. Missing web directory structure", "warning")
        cli.print_status("3. Circular import issues", "warning")
        
        # Check if Flask is really installed
        try:
            import flask
            cli.print_status(f"✅ Flask {flask.__version__} is installed", "success")
        except ImportError:
            cli.print_status("❌ Flask is NOT installed", "error")
            cli.print_status("Install with: pip install flask", "info")
            return
            
        # Check if web directory exists
        import os
        web_dir = os.path.join(os.path.dirname(__file__), 'web')
        if os.path.exists(web_dir):
            cli.print_status("✅ web directory exists", "success")
        else:
            cli.print_status("❌ web directory not found", "error")
            return
            
        # Check if app.py exists
        app_file = os.path.join(web_dir, 'app.py')
        if os.path.exists(app_file):
            cli.print_status("✅ web/app.py exists", "success")
        else:
            cli.print_status("❌ web/app.py not found", "error")
            return
            
        cli.print_status("Make sure all required files exist in the web/ directory", "error")
        cli.print_status("Refer to web/README.md for the directory structure", "info")
    except KeyboardInterrupt:
        cli.print_status("Web interface stopped.", "info")
    except Exception as e:
        cli.print_status(f"Error starting web interface: {e}", "error")
        import traceback
        traceback.print_exc()

def run_camera_detection(scanner):
    """Detect network cameras."""
    cli.print_header("Camera Detection")
    
    network = cli.get_user_input("Enter network CIDR (e.g., 192.168.1.0/24)", "192.168.1.0/24")
    
    cli.print_status(f"Detecting cameras on {network}...", "info")
    cli.animated_wait("Detecting cameras", 3)
    
    cameras = scanner.detect_cameras(network)
    
    if cameras:
        cli.print_status(f"Detected {len(cameras)} camera devices:", "success")
        for i, camera in enumerate(cameras, 1):
            print(f"\n{cli.colorize(f'Camera {i}:', 'bold')}")
            print(f"  IP: {camera.get('ip', 'Unknown')}")
            print(f"  Type: {camera.get('device_type', 'Unknown')}")
            print(f"  Vendor: {camera.get('vendor', 'Unknown')}")
            print(f"  Model: {camera.get('model', 'Unknown')}")
            print(f"  Ports: {', '.join(map(str, camera.get('ports', [])))}")
    else:
        cli.print_status("No cameras detected.", "info")

def run_surrounding_networks_detection(scanner):  # New function
    """Detect surrounding networks when connecting to Wi-Fi."""
    cli.print_header("Surrounding Networks Detection")
    
    cli.print_status("Detecting network interfaces and surrounding networks...", "info")
    
    try:
        # Try to get network interfaces - different approach for different platforms
        import platform
        system = platform.system().lower()
        
        if system == "windows":
            # Windows approach
            cli.print_status("Using Windows network detection...", "info")
            try:
                import subprocess
                import re
                
                # Get network interfaces
                result = subprocess.run(["netsh", "interface", "ip", "show", "addresses"], 
                                      capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    interfaces = []
                    current_interface = None
                    
                    for line in lines:
                        if 'Configuration for interface' in line:
                            match = re.search(r'"(.+)"', line)
                            if match:
                                current_interface = match.group(1)
                                interfaces.append(current_interface)
                                print(f"  Interface: {current_interface}")
                        elif 'IP Address' in line and current_interface:
                            match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                            if match:
                                ip = match.group(1)
                                print(f"    IP Address: {ip}")
                        elif 'Subnet Prefix' in line and current_interface:
                            match = re.search(r'(\d+\.\d+\.\d+\.\d+/\d+)', line)
                            if match:
                                subnet = match.group(1)
                                print(f"    Subnet: {subnet}")
                
                # Get routing table to find default gateway
                cli.print_status("\nGetting routing information...", "info")
                result = subprocess.run(["route", "print", "0.0.0.0"], 
                                      capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if '0.0.0.0' in line and 'Active Routes' not in line:
                            parts = line.strip().split()
                            if len(parts) >= 4:
                                destination = parts[0]
                                netmask = parts[1]
                                gateway = parts[2]
                                interface = parts[3]
                                if destination == "0.0.0.0":
                                    cli.print_status(f"Default gateway: {gateway} via interface {interface}", "info")
                                    break
                
                cli.print_status("\nNote: On Windows, you may need to run this as Administrator for full functionality.", "warning")
                
            except Exception as e:
                cli.print_status(f"Error in Windows network detection: {e}", "error")
        else:
            # Unix/Linux/Mac approach using netifaces
            try:
                import netifaces
                interfaces = netifaces.interfaces()
                
                cli.print_status(f"Found {len(interfaces)} network interfaces:", "success")
                
                # Display interfaces
                for i, interface in enumerate(interfaces, 1):
                    print(f"  {i}. {interface}")
                    try:
                        addrs = netifaces.ifaddresses(interface)
                        if netifaces.AF_INET in addrs:
                            for addr in addrs[netifaces.AF_INET]:
                                print(f"     IPv4: {addr.get('addr', 'N/A')}/{addr.get('netmask', 'N/A')}")
                        if netifaces.AF_INET6 in addrs:
                            for addr in addrs[netifaces.AF_INET6]:
                                print(f"     IPv6: {addr.get('addr', 'N/A')}")
                    except Exception as e:
                        print(f"     Error getting details: {e}")
                
                # Try to detect surrounding networks based on current IP
                cli.print_status("\nDetecting surrounding networks...", "info")
                
                # Get the default gateway and network
                try:
                    gateways = netifaces.gateways()
                    if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                        default_gateway = gateways['default'][netifaces.AF_INET]
                        gateway_ip = default_gateway[0]
                        interface_name = default_gateway[1]
                        cli.print_status(f"Default gateway: {gateway_ip} on interface {interface_name}", "info")
                        
                        # Try to determine the network range
                        try:
                            import ipaddress
                            # Get the interface details
                            addrs = netifaces.ifaddresses(interface_name)
                            if netifaces.AF_INET in addrs:
                                for addr in addrs[netifaces.AF_INET]:
                                    ip = addr.get('addr')
                                    netmask = addr.get('netmask')
                                    if ip and netmask:
                                        # Create network object
                                        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                                        cli.print_status(f"Current network: {network}", "success")
                                        
                                        # Suggest scanning the network
                                        if cli.get_user_input(f"Scan this network? (y/n)", "y").lower() == 'y':
                                            cli.print_status(f"Starting scan on {network}...", "info")
                                            cli.animated_wait("Scanning network", 3)
                                            scanner.scan_network(str(network))
                                            
                                            # Save results
                                            base_name = RESULTS_FILE.replace('.json', '')
                                            save_results_csv(scanner.exploited_devices, f"{base_name}_surrounding.csv")
                                            save_results_xml(scanner.exploited_devices, f"{base_name}_surrounding.xml")
                                            save_results_html(scanner.exploited_devices, f"{base_name}_surrounding.html")
                                            
                                            # Print summary
                                            if scanner.exploited_devices:
                                                cli.print_status(f"Found {len(scanner.exploited_devices)} vulnerabilities!", "critical")
                                                summary = print_summary_stats(scanner.exploited_devices)
                                                print(summary)
                                                cli.print_scan_summary(scanner.exploited_devices)
                                            else:
                                                cli.print_status("No vulnerabilities found.", "success")
                        except Exception as e:
                            cli.print_status(f"Error determining network: {e}", "error")
                    else:
                        cli.print_status("No default gateway found.", "warning")
                except Exception as e:
                    cli.print_status(f"Error getting gateways: {e}", "error")
                    
            except ImportError:
                cli.print_status("netifaces module not found.", "warning")
                cli.print_status("You can install it with: pip install netifaces", "info")
                
    except Exception as e:
        cli.print_status(f"Error detecting surrounding networks: {e}", "error")
        
    # Provide manual network entry option
    cli.print_status("\nAs an alternative, you can manually enter a network to scan:", "info")
    network = cli.get_user_input("Enter network CIDR (e.g., 192.168.1.0/24)", "")
    if network:
        try:
            import ipaddress
            # Validate network
            ipaddress.IPv4Network(network, strict=False)
            cli.print_status(f"Starting scan on {network}...", "info")
            cli.animated_wait("Scanning network", 3)
            scanner.scan_network(network)
            
            # Save results
            base_name = RESULTS_FILE.replace('.json', '')
            save_results_csv(scanner.exploited_devices, f"{base_name}_surrounding.csv")
            save_results_xml(scanner.exploited_devices, f"{base_name}_surrounding.xml")
            save_results_html(scanner.exploited_devices, f"{base_name}_surrounding.html")
            
            # Print summary
            if scanner.exploited_devices:
                cli.print_status(f"Found {len(scanner.exploited_devices)} vulnerabilities!", "critical")
                summary = print_summary_stats(scanner.exploited_devices)
                print(summary)
                cli.print_scan_summary(scanner.exploited_devices)
            else:
                cli.print_status("No vulnerabilities found.", "success")
        except Exception as e:
            cli.print_status(f"Error scanning network: {e}", "error")

def update_from_github():
    """Update the scanner from GitHub repository with better Termux compatibility."""
    cli.print_header("Update Scanner")
    
    try:
        cli.print_status("Updating scanner from GitHub...", "info")
        
        # Check if we're in a git repository
        if not os.path.exists(".git"):
            cli.print_status("This directory is not a git repository.", "error")
            cli.print_status("Please clone the repository first using:", "info")
            print("   git clone <repository-url>")
            return
            
        # Detect if we're in Termux
        is_termux = "termux" in platform.platform().lower()
        
        if is_termux:
            cli.print_status("Detected Termux environment. Using compatible update method...", "info")
            # Use a more compatible approach for Termux
            try:
                # First, fetch the latest changes
                cli.print_status("Fetching latest changes...", "info")
                result = subprocess.run(["git", "fetch"], capture_output=True, text=True, timeout=30)
                if result.returncode != 0:
                    cli.print_status(f"Fetch failed: {result.stderr}", "error")
                    return
                    
                # Then merge the changes
                cli.print_status("Merging changes...", "info")
                result = subprocess.run(["git", "merge", "origin/main"], capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    cli.print_status("Update successful!", "success")
                    if result.stdout:
                        print(result.stdout)
                    # Check if requirements.txt was updated
                    if "requirements.txt" in result.stdout:
                        cli.print_status("Requirements may have changed. Installing updates...", "info")
                        try:
                            subprocess.run(["pip", "install", "-r", "requirements.txt"], 
                                         capture_output=True, text=True, timeout=60)
                            cli.print_status("Requirements updated.", "success")
                        except subprocess.TimeoutExpired:
                            cli.print_status("Requirements update timed out. Please run manually: pip install -r requirements.txt", "warning")
                else:
                    cli.print_status("Update failed:", "error")
                    if result.stderr:
                        print(result.stderr)
                        
            except subprocess.TimeoutExpired:
                cli.print_status("Update operation timed out. Please check your network connection.", "error")
            except Exception as e:
                cli.print_status(f"Error during update: {e}", "error")
        else:
            # Standard update method for other environments
            cli.print_status("Using standard update method...", "info")
            
            # Perform git pull
            result = subprocess.run(["git", "pull"], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                cli.print_status("Update successful!", "success")
                print(result.stdout)
                # Check if requirements.txt was updated
                if "requirements.txt" in result.stdout:
                    cli.print_status("Requirements may have changed. Installing updates...", "info")
                    subprocess.run(["pip", "install", "-r", "requirements.txt"], 
                                 capture_output=True, text=True, timeout=60)
                    cli.print_status("Requirements updated.", "success")
            else:
                cli.print_status("Update failed:", "error")
                print(result.stderr)
            
    except FileNotFoundError:
        cli.print_status("Git is not installed or not found in PATH.", "error")
        cli.print_status("Please install Git:", "info")
        print("   Termux: pkg install git")
        print("   Other systems: Install from https://git-scm.com/")
    except subprocess.TimeoutExpired:
        cli.print_status("Update operation timed out. Please check your network connection.", "error")
    except Exception as e:
        cli.print_status(f"Error during update: {e}", "error")

def main():
    """Main entry point for the application."""
    cli.print_banner()
    
    scanner = AdvancedNetworkScanner()
    while True:
        display_menu()
        choice = get_user_choice()

        if choice == 1:
            run_scan_network(scanner)
        elif choice == 2:
            run_scan_single_ip(scanner)
        elif choice == 3:
            run_port_scan(scanner)
        elif choice == 4:
            update_cve_database()
        elif choice == 5:
            update_from_github()
        elif choice == 6:
            run_network_discovery(scanner)
        elif choice == 7:
            run_network_visualization(scanner)
        elif choice == 8:
            run_multiple_networks_scan(scanner)
        elif choice == 9:
            run_exclusion_scan(scanner)
        elif choice == 10:
            run_vlan_scan(scanner)
        elif choice == 11:
            start_web_interface()
        elif choice == 12:
            run_camera_detection(scanner)
        elif choice == 13:
            view_report()
        elif choice == 14:
            run_surrounding_networks_detection(scanner)  # New option
        elif choice == 15:
            cli.print_status("Exiting scanner. Goodbye!", "info")
            break
        else:
            cli.print_status("Invalid choice. Please enter a number between 1 and 15.", "warning")
        
        # Pause before showing menu again
        if choice != 15:
            input(f"\n{cli.colorize('Press Enter to continue...', 'dim')}")

if __name__ == "__main__":
    main()