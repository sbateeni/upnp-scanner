#!/usr/bin/env python3
"""Test script for camera detection feature"""

from scanner.core import AdvancedNetworkScanner

def test_camera_detection():
    """Test that camera detection methods exist"""
    scanner = AdvancedNetworkScanner()
    
    # Check if camera detection method exists
    has_detect_method = hasattr(scanner, 'detect_cameras')
    print(f"Camera detection method available: {has_detect_method}")
    
    # Check if camera ports constant exists
    try:
        from scanner.core import CAMERA_PORTS
        print(f"CAMERA_PORTS constant available: {len(CAMERA_PORTS)} ports defined")
        print(f"Sample ports: {CAMERA_PORTS[:5]}")
    except ImportError:
        print("CAMERA_PORTS constant not found")
    
    # Check if camera signatures constant exists
    try:
        from scanner.core import CAMERA_SIGNATURES
        print(f"CAMERA_SIGNATURES constant available: {len(CAMERA_SIGNATURES)} signatures defined")
        print(f"Sample signatures: {CAMERA_SIGNATURES[:5]}")
    except ImportError:
        print("CAMERA_SIGNATURES constant not found")

if __name__ == "__main__":
    test_camera_detection()