#!/usr/bin/env python3
"""
Scanner Update Script
This script updates the scanner from GitHub and updates the CVE database
"""

import subprocess
import sys
import os
import platform

def update_from_github():
    """Update the scanner from GitHub repository with better Termux compatibility."""
    print("🔄 Updating scanner from GitHub...")
    
    try:
        # Check if we're in a git repository
        if not os.path.exists(".git"):
            print("❌ This directory is not a git repository.")
            print("💡 Please clone the repository first using:")
            print("   git clone <repository-url>")
            return False
            
        # Detect if we're in Termux
        is_termux = "termux" in platform.platform().lower()
        
        if is_termux:
            print("📱 Detected Termux environment. Using compatible update method...")
            # Use a more compatible approach for Termux
            try:
                # First, fetch the latest changes
                print("📥 Fetching latest changes...")
                result = subprocess.run(["git", "fetch"], capture_output=True, text=True, timeout=30)
                if result.returncode != 0:
                    print(f"❌ Fetch failed: {result.stderr}")
                    return False
                    
                # Then merge the changes
                print("📥 Merging changes...")
                result = subprocess.run(["git", "merge", "origin/main"], capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    print("✅ GitHub update successful!")
                    if result.stdout:
                        print(result.stdout)
                    # Check if requirements.txt was updated
                    if "requirements.txt" in result.stdout:
                        print("📋 Requirements may have changed. Installing updates...")
                        try:
                            subprocess.run(["pip", "install", "-r", "requirements.txt"], 
                                         capture_output=True, text=True, timeout=60)
                            print("✅ Requirements updated.")
                        except subprocess.TimeoutExpired:
                            print("⚠️  Requirements update timed out. Please run manually: pip install -r requirements.txt")
                    return True
                else:
                    print("❌ Update failed:")
                    if result.stderr:
                        print(result.stderr)
                    return False
                        
            except subprocess.TimeoutExpired:
                print("❌ Update operation timed out. Please check your network connection.")
                return False
            except Exception as e:
                print(f"❌ Error during update: {e}")
                return False
        else:
            # Standard update method for other environments
            print("💻 Using standard update method...")
            
            # Perform git pull
            result = subprocess.run(["git", "pull"], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                print("✅ GitHub update successful!")
                print(result.stdout)
                
                # Check if requirements.txt was updated
                if "requirements.txt" in result.stdout:
                    print("📋 Requirements may have changed. Installing updates...")
                    subprocess.run(["pip", "install", "-r", "requirements.txt"], 
                                 capture_output=True, text=True, timeout=60)
                    print("✅ Requirements updated.")
                return True
            else:
                print("❌ GitHub update failed:")
                print(result.stderr)
                return False
            
    except FileNotFoundError:
        print("❌ Git is not installed or not found in PATH.")
        print("💡 Please install Git:")
        print("   Termux: pkg install git")
        print("   Other systems: Install from https://git-scm.com/")
        return False
    except subprocess.TimeoutExpired:
        print("❌ Update operation timed out. Please check your network connection.")
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