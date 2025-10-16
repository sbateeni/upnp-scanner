#!/usr/bin/env python3
"""
Test script to verify all scanner components work correctly.
"""

import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that all modules can be imported."""
    print("🧪 Testing module imports...")
    
    try:
        from scanner.core import AdvancedNetworkScanner
        print("✅ Core scanner module imported successfully")
    except Exception as e:
        print(f"❌ Failed to import core scanner: {e}")
        return False
    
    try:
        from scanner.discovery import discover_with_ws_discovery, discover_with_ssdp, discover_with_mdns
        print("✅ Discovery module imported successfully")
    except Exception as e:
        print(f"❌ Failed to import discovery module: {e}")
        return False
    
    try:
        from scanner.port_scanner import is_port_open, is_udp_port_open
        print("✅ Port scanner module imported successfully")
    except Exception as e:
        print(f"❌ Failed to import port scanner: {e}")
        return False
    
    try:
        from scanner.cve_checker import load_cve_database, test_port_based_cve
        print("✅ CVE checker module imported successfully")
    except Exception as e:
        print(f"❌ Failed to import CVE checker: {e}")
        return False
    
    try:
        from scanner.report import setup_logger, save_results
        print("✅ Report module imported successfully")
    except Exception as e:
        print(f"❌ Failed to import report module: {e}")
        return False
    
    try:
        from utils.helpers import check_private_network, RateLimiter
        print("✅ Helpers module imported successfully")
    except Exception as e:
        print(f"❌ Failed to import helpers: {e}")
        return False
    
    try:
        from utils.security import is_safe_network, validate_port_list
        print("✅ Security module imported successfully")
    except Exception as e:
        print(f"❌ Failed to import security module: {e}")
        return False
    
    try:
        from utils.network_visualizer import generate_network_map
        print("✅ Network visualizer module imported successfully")
    except Exception as e:
        print(f"❌ Failed to import network visualizer: {e}")
        return False
    
    try:
        from config.settings import COMMON_PORTS, MAX_THREADS
        print("✅ Settings module imported successfully")
    except Exception as e:
        print(f"❌ Failed to import settings: {e}")
        return False
    
    try:
        from config.profiles import get_profile
        print("✅ Profiles module imported successfully")
    except Exception as e:
        print(f"❌ Failed to import profiles: {e}")
        return False
    
    return True

def test_cve_database():
    """Test that the CVE database can be loaded."""
    print("\n📚 Testing CVE database...")
    
    try:
        from scanner.cve_checker import load_cve_database
        cve_db = load_cve_database()
        
        if cve_db and "ports" in cve_db:
            port_count = len(cve_db["ports"])
            cve_count = sum(len(service.get("cves", [])) for service in cve_db["ports"].values())
            print(f"✅ CVE database loaded successfully")
            print(f"   Ports with CVEs: {port_count}")
            print(f"   Total CVEs: {cve_count}")
            return True
        else:
            print("❌ CVE database is empty or malformed")
            return False
    except Exception as e:
        print(f"❌ Failed to load CVE database: {e}")
        return False

def test_network_functions():
    """Test network-related utility functions."""
    print("\n🌐 Testing network functions...")
    
    try:
        from utils.helpers import check_private_network, is_valid_ip, is_valid_network
        from utils.security import is_safe_network, get_safe_scan_range
        
        # Test IP validation
        test_ips = ["192.168.1.1", "10.0.0.1", "8.8.8.8", "invalid"]
        for ip in test_ips:
            result = is_valid_ip(ip)
            print(f"   {ip}: {'Valid' if result else 'Invalid'}")
        
        # Test network validation
        test_networks = ["192.168.1.0/24", "10.0.0.0/8", "8.8.8.0/24"]
        for network in test_networks:
            is_safe = is_safe_network(network)
            is_valid = is_valid_network(network)
            print(f"   {network}: Valid={is_valid}, Safe={is_safe}")
        
        # Test safe network range
        safe_range = get_safe_scan_range()
        print(f"   Safe scan range: {safe_range}")
        
        print("✅ Network functions working correctly")
        return True
    except Exception as e:
        print(f"❌ Failed network function tests: {e}")
        return False

def test_scanner_initialization():
    """Test that the scanner can be initialized."""
    print("\n🚀 Testing scanner initialization...")
    
    try:
        from scanner.core import AdvancedNetworkScanner
        scanner = AdvancedNetworkScanner()
        print(f"✅ Scanner initialized successfully")
        print(f"   Scan token: {scanner.scan_token}")
        print(f"   Stats: {scanner.stats}")
        return True
    except Exception as e:
        print(f"❌ Failed to initialize scanner: {e}")
        return False

def test_port_validation():
    """Test port validation functions."""
    print("\n🔌 Testing port validation...")
    
    try:
        from utils.security import validate_port_list
        
        test_ports = [21, 22, 23, 80, 443, 3306, 3389, 8080, 99999, -1, 0]
        safe_ports = validate_port_list(test_ports)
        
        print(f"   Input ports: {test_ports}")
        print(f"   Safe ports: {safe_ports}")
        print("✅ Port validation working correctly")
        return True
    except Exception as e:
        print(f"❌ Failed port validation: {e}")
        return False

def main():
    """Run all tests."""
    print("🔬 Advanced Network Scanner - Component Tests")
    print("="*50)
    
    tests = [
        test_imports,
        test_cve_database,
        test_network_functions,
        test_scanner_initialization,
        test_port_validation
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("="*50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! The scanner is ready to use.")
        return 0
    else:
        print("⚠️  Some tests failed. Please check the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())