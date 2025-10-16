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

echo "📥 Fetching latest changes..."
git fetch

echo "📥 Merging changes..."
git merge origin/main

# Check if requirements.txt was updated
if [ -f "requirements.txt" ]; then
    echo "📋 Updating Python requirements..."
    pip install -r requirements.txt
fi

echo "✅ Update completed!"
echo "💡 To run the scanner: python main.py"