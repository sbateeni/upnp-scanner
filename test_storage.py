#!/usr/bin/env python3
"""
Simple test for storage functionality
"""

import os
import sys

# Add the current directory to the path so we can import modules
sys.path.insert(0, '.')

def test_directory_creation():
    """Test directory creation"""
    print("Testing directory creation...")
    try:
        os.makedirs('scan_results', exist_ok=True)
        print("✅ Directory creation successful")
        return True
    except Exception as e:
        print(f"❌ Directory creation failed: {e}")
        return False

def test_import():
    """Test importing the persistent storage module"""
    print("Testing import of persistent storage module...")
    try:
        from utils.persistent_storage import PersistentStorage
        print("✅ Import successful")
        return True
    except Exception as e:
        print(f"❌ Import failed: {e}")
        return False

def test_storage_initialization():
    """Test storage initialization"""
    print("Testing storage initialization...")
    try:
        from utils.persistent_storage import PersistentStorage
        storage = PersistentStorage()
        print(f"✅ Storage initialized. Directory: {storage.storage_dir}")
        print(f"✅ Database path: {storage.db_path}")
        return True
    except Exception as e:
        print(f"❌ Storage initialization failed: {e}")
        return False

if __name__ == "__main__":
    print("Running storage tests...")
    print("=" * 40)
    
    test1 = test_directory_creation()
    test2 = test_import()
    test3 = test_storage_initialization()
    
    print("=" * 40)
    if test1 and test2 and test3:
        print("🎉 All tests passed!")
    else:
        print("❌ Some tests failed.")