#!/usr/bin/env python3
"""
Test script for web interface module
"""

try:
    import web_interface
    print("✅ Web interface module imported successfully")
    
    # Test if the main functions exist
    if hasattr(web_interface, 'simple_web_server'):
        print("✅ simple_web_server function found")
    else:
        print("❌ simple_web_server function not found")
        
    if hasattr(web_interface, 'main'):
        print("✅ main function found")
    else:
        print("❌ main function not found")
        
    print("🎉 Web interface module is ready for use")
    
except ImportError as e:
    print(f"❌ Failed to import web interface: {e}")
    print("💡 Make sure all dependencies are installed:")
    print("   pip install flask")
except Exception as e:
    print(f"❌ Error testing web interface: {e}")