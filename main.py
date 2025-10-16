#!/usr/bin/env python3
import sys
import subprocess
import os
import json
import urllib.request
from scanner.core import AdvancedNetworkScanner
from scanner.report import view_report, save_results_csv, save_results_xml, save_results_html
from utils.cve_updater import update_cve_database
from utils.network_visualizer import generate_network_map, generate_simple_topology, print_summary_stats
from config.settings import COMMON_PORTS, RESULTS_FILE, AVAILABLE_PROFILES
from config.profiles import get_profile

def display_menu():
    """Display the main menu options."""
    print("\n" + "="*60)
    print("🛡️  Advanced Network Scanner  🛡️")
    print("="*60)
    print("1. 🔍 Scan Full Network (e.g., 192.168.1.0/24)")
    print("2. 🎯 Scan Single IP Address")
    print("3. 🔓 Scan Specific TCP Ports on Network")
    print("4. 📦 Update CVE Database")
    print("5. 🔄 Update Scanner from GitHub")
    print("6. 📊 Network Discovery")
    print("7. 🗺️  Visualize Network Map")
    print("8. 📜 View Last Scan Report")
    print("9. 🚪 Exit")
    print("="*60)

def get_user_choice():
    """Get and validate user menu choice."""
    try:
        choice = int(input("Enter your choice (1-9): "))
        return choice
    except ValueError:
        return -1

def select_scan_profile():
    """Let user select a scanning profile."""
    print("\n📋 Available Scanning Profiles:")
    for i, profile_name in enumerate(AVAILABLE_PROFILES, 1):
        profile = get_profile(profile_name)
        print(f"  {i}. {profile['name']} - {profile['description']}")
    
    try:
        choice = int(input(f"Select profile (1-{len(AVAILABLE_PROFILES)}) [1]: ") or "1")
        if 1 <= choice <= len(AVAILABLE_PROFILES):
            return AVAILABLE_PROFILES[choice - 1]
        else:
            print("Invalid choice. Using default profile.")
            return "default"
    except ValueError:
        print("Invalid input. Using default profile.")
        return "default"

def run_scan_network(scanner):
    """Run a full network scan."""
    # Select profile
    profile_name = select_scan_profile()
    profile = get_profile(profile_name)
    print(f"Using profile: {profile['name']} - {profile['description']}")
    
    network = input("Enter network CIDR (e.g., 192.168.1.0/24) [default: 192.168.1.0/24]: ").strip()
    if not network:
        network = "192.168.1.0/24"
    
    # Temporarily update scanner settings based on profile
    original_ports = COMMON_PORTS.copy()
    # We'll use the profile ports for this scan
    
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

def run_scan_single_ip(scanner):
    """Scan a single IP address."""
    # Select profile
    profile_name = select_scan_profile()
    profile = get_profile(profile_name)
    print(f"Using profile: {profile['name']} - {profile['description']}")
    
    ip = input("Enter IP address to scan (e.g., 192.168.1.100): ").strip()
    if ip:
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
    else:
        print("❌ Invalid IP address.")

def run_port_scan(scanner):
    """Scan specific ports on a network."""
    network = input("Enter network CIDR (e.g., 192.168.1.0/24) [default: 192.168.1.0/24]: ").strip()
    if not network:
        network = "192.168.1.0/24"
    
    ports_input = input(f"Enter ports to scan (comma-separated, e.g., 22,80,443) [default: {','.join(map(str, COMMON_PORTS[:5]))}]: ").strip()
    if not ports_input:
        ports = COMMON_PORTS[:5]  # Use first 5 common ports as default
    else:
        try:
            ports = [int(p.strip()) for p in ports_input.split(",")]
        except ValueError:
            print("❌ Invalid port format. Using default ports.")
            ports = COMMON_PORTS[:5]
    
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

def run_network_discovery(scanner):
    """Run network discovery."""
    network = input("Enter network CIDR (e.g., 192.168.1.0/24) [default: 192.168.1.0/24]: ").strip()
    if not network:
        network = "192.168.1.0/24"
    
    devices = scanner.network_discovery(network)
    if devices:
        print(f"\n📱 Discovered {len(devices)} devices:")
        for device in devices:
            print(f"  - {device}")
    else:
        print("❌ No devices discovered.")

def run_network_visualization(scanner):
    """Generate network visualization."""
    if not scanner.exploited_devices:
        print("❌ No scan data available. Run a scan first.")
        return
    
    print("\n🗺️  Network Visualization Options:")
    print("1. Text-based Network Map")
    print("2. Simple Topology View")
    print("3. Summary Statistics")
    
    try:
        choice = int(input("Select visualization type (1-3): "))
        
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
            print("Invalid choice.")
    except ValueError:
        print("Invalid input.")

def update_from_github():
    """Update the scanner from GitHub repository."""
    try:
        print("🔄 Updating scanner from GitHub...")
        # Check if we're in a git repository
        if not os.path.exists(".git"):
            print("❌ This directory is not a git repository.")
            print("💡 Please clone the repository first using:")
            print("   git clone <repository-url>")
            return
            
        # Perform git pull
        result = subprocess.run(["git", "pull"], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Update successful!")
            print(result.stdout)
            # Check if requirements.txt was updated
            if "requirements.txt" in result.stdout:
                print("📋 Requirements may have changed. Installing updates...")
                subprocess.run(["pip", "install", "-r", "requirements.txt"], 
                             capture_output=True, text=True)
                print("✅ Requirements updated.")
        else:
            print("❌ Update failed:")
            print(result.stderr)
            
    except FileNotFoundError:
        print("❌ Git is not installed or not found in PATH.")
        print("💡 Please install Git from https://git-scm.com/")
    except Exception as e:
        print(f"❌ Error during update: {e}")

def main():
    """Main entry point for the application."""
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
            view_report()
        elif choice == 9:
            print("👋 Exiting scanner. Goodbye!")
            break
        else:
            print("❌ Invalid choice. Please enter a number between 1 and 9.")

if __name__ == "__main__":
    main()