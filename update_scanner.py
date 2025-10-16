#!/usr/bin/env python3
"""
Scanner Update Script
This script updates the scanner from GitHub and updates the CVE database
"""

import subprocess
import sys
import os

def update_from_github():
    """Update the scanner from GitHub repository"""
    print("🔄 Updating scanner from GitHub...")
    
    try:
        # Perform git pull
        result = subprocess.run(['git', 'pull'], 
                              capture_output=True, text=True, cwd=os.getcwd())
        
        if result.returncode == 0:
            print("✅ GitHub update successful!")
            print(result.stdout)
            
            # Check if requirements.txt was updated
            if 'requirements.txt' in result.stdout:
                print("📋 Requirements may have changed. Installing updates...")
                subprocess.run(['pip', 'install', '-r', 'requirements.txt'], 
                             capture_output=True, text=True, cwd=os.getcwd())
                print("✅ Requirements updated.")
            return True
        else:
            print("❌ GitHub update failed:")
            print(result.stderr)
            return False
            
    except FileNotFoundError:
        print("❌ Git is not installed or not found in PATH.")
        print("💡 Please install Git from https://git-scm.com/")
        return False
    except Exception as e:
        print(f"❌ Error during GitHub update: {e}")
        return False

def update_cve_database():
    """Update the CVE database"""
    print("🔄 Updating CVE database...")
    
    try:
        # Import the CVE updater
        from utils.cve_updater import update_cve_database as update_cve
        
        if update_cve():
            print("✅ CVE database update completed.")
            return True
        else:
            print("❌ CVE database update failed.")
            return False
            
    except Exception as e:
        print(f"❌ Error updating CVE database: {e}")
        return False

def main():
    """Main update function"""
    print("🛡️  Advanced Network Scanner - Update Tool")
    print("="*50)
    
    # Update from GitHub
    github_success = update_from_github()
    
    # Update CVE database
    cve_success = update_cve_database()
    
    # Summary
    print("\n" + "="*50)
    print("📊 Update Summary:")
    print(f"   GitHub Update: {'✅ Success' if github_success else '❌ Failed'}")
    print(f"   CVE Database:  {'✅ Success' if cve_success else '❌ Failed'}")
    
    if github_success and cve_success:
        print("\n🎉 All updates completed successfully!")
        return 0
    else:
        print("\n⚠️  Some updates failed. Please check the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())