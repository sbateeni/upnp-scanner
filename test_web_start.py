#!/usr/bin/env python3
"""
Test script to start the web interface
"""

try:
    from web_interface import main
    print("Starting web interface...")
    main()
except Exception as e:
    print(f"Error starting web interface: {e}")
    import traceback
    traceback.print_exc()