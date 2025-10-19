#!/usr/bin/env python3
"""Test script for surrounding networks detection feature."""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from utils.cli_ui import EnhancedCLI
from scanner.core import AdvancedNetworkScanner

def test_network_detection():
    """Test the surrounding networks detection feature."""
    cli = EnhancedCLI()
    scanner = AdvancedNetworkScanner()
    
    cli.print_header("Testing Surrounding Networks Detection")
    cli.print_status("This is a test of the new network detection feature.", "info")
    
    # Import platform to determine OS
    import platform
    system = platform.system().lower()
    
    cli.print_status(f"Detected OS: {system}", "info")
    
    if system == "windows":
        cli.print_status("Running Windows network detection test...", "info")
        try:
            import subprocess
            # Test netsh command
            result = subprocess.run(["netsh", "interface", "ip", "show", "addresses"], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                cli.print_status("Windows network interfaces detected successfully!", "success")
                # Show just first few lines
                lines = result.stdout.split('\n')[:10]
                for line in lines:
                    if line.strip():
                        print(f"  {line}")
            else:
                cli.print_status("Failed to get network interfaces via netsh", "warning")
        except Exception as e:
            cli.print_status(f"Error in Windows network detection: {e}", "error")
    else:
        cli.print_status("Non-Windows system detected. Would use netifaces library.", "info")
        
    cli.print_status("Test completed.", "success")

if __name__ == "__main__":
    test_network_detection()