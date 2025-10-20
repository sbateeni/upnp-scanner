#!/usr/bin/env python3
"""
Test script for router discovery functionality
"""

import sys
import os

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    print("Testing router discovery functionality...")
    
    # Import the scanner
    from scanner.core import AdvancedNetworkScanner
    
    # Create scanner instance
    scanner = AdvancedNetworkScanner()
    
    # Test router discovery
    print("Discovering surrounding routers...")
    routers = scanner.discover_surrounding_routers()
    
    print(f"Found {len(routers)} routers/networks:")
    for i, router in enumerate(routers, 1):
        print(f"\nNetwork {i}:")
        print(f"  SSID: {router.get('ssid', 'Unknown')}")
        print(f"  BSSID: {router.get('bssid', 'Unknown')}")
        print(f"  Signal: {router.get('signal', 'Unknown')}")
        print(f"  Security: {router.get('security', 'Unknown')}")
        
    print("\n✅ Router discovery test completed!")
    
except Exception as e:
    print(f"❌ Error during router discovery test: {e}")
    import traceback
    traceback.print_exc()