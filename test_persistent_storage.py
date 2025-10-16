#!/usr/bin/env python3
"""
Test script for persistent storage functionality
"""

from utils.persistent_storage import PersistentStorage
import os

def test_persistent_storage():
    """Test the persistent storage functionality"""
    print("Testing Persistent Storage...")
    
    # Initialize storage
    storage = PersistentStorage()
    
    # Test data
    test_results = [
        {
            "ip": "192.168.1.100",
            "port": 80,
            "service": "HTTP",
            "cve_id": "CVE-2023-12345",
            "description": "Remote Code Execution vulnerability in web server"
        },
        {
            "ip": "192.168.1.101",
            "port": 22,
            "service": "SSH",
            "cve_id": "CVE-2023-54321",
            "description": "Weak authentication mechanism"
        }
    ]
    
    # Test saving scan results
    print("Saving test scan results...")
    scan_id = storage.save_scan_results(test_results, "192.168.1.0/24", "test_scan")
    print(f"Saved scan with ID: {scan_id}")
    
    # Test saving to files
    print("Saving results to files...")
    storage.save_results_to_files(test_results, scan_id)
    
    # Test retrieving scan history
    print("Retrieving scan history...")
    history = storage.get_scan_history()
    print(f"Found {len(history)} scans in history")
    
    # Test retrieving scan results
    print("Retrieving scan results...")
    results = storage.get_scan_results(scan_id)
    print(f"Retrieved {len(results)} results for scan #{scan_id}")
    
    # Test storage stats
    print("Getting storage statistics...")
    stats = storage.get_storage_stats()
    print(f"Storage stats: {stats}")
    
    print("Test completed successfully!")

if __name__ == "__main__":
    test_persistent_storage()