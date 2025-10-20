#!/bin/bash
# Termux Update Script for Advanced Network Scanner

echo "🔄 Advanced Network Scanner - Termux Update"
echo "=========================================="

# Check if we're in the right directory
if [ ! -f "main.py" ]; then
    echo "❌ Please run this script from the scanner directory"
    exit 1
fi

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo "📦 Installing git..."
    pkg install git -y
fi

# Check if pip is installed
if ! command -v pip &> /dev/null; then
    echo "📦 Installing pip..."
    pkg install python-pip -y
fi

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    echo "❌ This directory is not a git repository."
    echo "💡 Please clone the repository first using:"
    echo "   git clone <repository-url>"
    exit 1
fi

echo "📥 Fetching latest changes..."
git fetch origin main

echo "📥 Merging changes..."
git merge origin/main

# Check if merge was successful
if [ $? -eq 0 ]; then
    echo "✅ GitHub update successful!"
    
    # Check if requirements.txt was updated
    if [ -f "requirements.txt" ]; then
        echo "📋 Updating Python requirements..."
        pip install -r requirements.txt
        if [ $? -eq 0 ]; then
            echo "✅ Requirements updated successfully!"
        else
            echo "⚠️  Failed to update requirements. Please run manually: pip install -r requirements.txt"
        fi
    fi
else
    echo "❌ Update failed. Please check for conflicts and resolve them manually."
    echo "💡 You can try:"
    echo "   git status"
    echo "   git diff"
    echo "   Manually resolve conflicts and then run: git add . && git commit"
fi

echo "✅ Update completed!"
echo "💡 To run the scanner: python main.py"