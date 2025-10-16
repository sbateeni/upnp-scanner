#!/usr/bin/env python3
import sys
import subprocess
import os
import json
import urllib.request
from scanner.core import AdvancedNetworkScanner
from scanner.report import view_report
from utils.cve_updater import update_cve_database
from config.settings import COMMON_PORTS

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
    print("6. 📜 View Last Scan Report")
    print("7. 🚪 Exit")
    print("="*60)

def get_user_choice():
    """Get and validate user menu choice."""
    try:
        choice = int(input("Enter your choice (1-7): "))
        return choice
    except ValueError:
        return -1

def run_scan_network(scanner):
    """Run a full network scan."""
    network = input("Enter network CIDR (e.g., 192.168.1.0/24) [default: 192.168.1.0/24]: ").strip()
    if not network:
        network = "192.168.1.0/24"
    scanner.scan_network(network)

def run_scan_single_ip(scanner):
    """Scan a single IP address."""
    ip = input("Enter IP address to scan (e.g., 192.168.1.100): ").strip()
    if ip:
        scanner.scan_single_ip(ip)
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
            view_report()
        elif choice == 7:
            print("👋 Exiting scanner. Goodbye!")
            break
        else:
            print("❌ Invalid choice. Please enter a number between 1 and 7.")

if __name__ == "__main__":
    main()