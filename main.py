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
from config.settings import COMMON_PORTS, RESULTS_FILE, AVAILABLE_PROFILES
from config.profiles import get_profile

# Initialize enhanced CLI
cli = EnhancedCLI()

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
    cli.print_menu_item(12, "View Last Scan Report", "📜")
    cli.print_menu_item(13, "Exit", "🚪")
    
    print(cli.colorize("="*60, 'cyan'))

def get_user_choice():
    """Get and validate user menu choice."""
    try:
        choice = int(cli.get_user_input("Enter your choice (1-13)"))
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
        # Import and run the web interface
        from web_interface import main as web_main
        web_main()
    except ImportError:
        cli.print_status("Web interface not available. Make sure Flask is installed.", "error")
        cli.print_status("Install with: pip install flask", "info")
    except KeyboardInterrupt:
        cli.print_status("Web interface stopped.", "info")
    except Exception as e:
        cli.print_status(f"Error starting web interface: {e}", "error")

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
            view_report()
        elif choice == 13:
            cli.print_status("Exiting scanner. Goodbye!", "info")
            break
        else:
            cli.print_status("Invalid choice. Please enter a number between 1 and 13.", "warning")
        
        # Pause before showing menu again
        if choice != 13:
            input(f"\n{cli.colorize('Press Enter to continue...', 'dim')}")

if __name__ == "__main__":
    main()