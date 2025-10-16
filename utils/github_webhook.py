#!/usr/bin/env python3
"""
GitHub Webhook Handler for automatic updates
This script can be used to automatically update the scanner when changes are pushed to GitHub
"""

import subprocess
import os
import json
import hashlib
import hmac
from http.server import HTTPServer, BaseHTTPRequestHandler

# Secret token for webhook verification (should be set in environment variables)
WEBHOOK_SECRET = os.environ.get('GITHUB_WEBHOOK_SECRET', 'your_secret_here')

class GitHubWebhookHandler(BaseHTTPRequestHandler):
    """Handle GitHub webhook requests"""
    
    def do_POST(self):
        """Handle POST requests from GitHub"""
        # Get the request headers
        content_length = int(self.headers['Content-Length'])
        signature = self.headers.get('X-Hub-Signature-256')
        
        # Read the request body
        post_data = self.rfile.read(content_length)
        
        # Verify the signature if secret is provided
        if WEBHOOK_SECRET != 'your_secret_here':
            if not self.verify_signature(post_data, signature):
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b'Unauthorized')
                return
        
        # Parse the JSON payload
        try:
            payload = json.loads(post_data.decode('utf-8'))
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'Invalid JSON')
            return
        
        # Check if this is a push event
        if self.headers.get('X-GitHub-Event') == 'push':
            self.handle_push_event(payload)
        else:
            print(f"Received {self.headers.get('X-GitHub-Event')} event")
        
        # Send response
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')
    
    def verify_signature(self, payload, signature):
        """Verify the webhook signature"""
        if not signature:
            return False
            
        expected_signature = 'sha256=' + hmac.new(
            WEBHOOK_SECRET.encode('utf-8'),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(expected_signature, signature)
    
    def handle_push_event(self, payload):
        """Handle push events"""
        print("🔄 Received push event from GitHub")
        
        # Get repository information
        repo_name = payload.get('repository', {}).get('name', 'Unknown')
        branch = payload.get('ref', 'Unknown').replace('refs/heads/', '')
        
        print(f"📦 Repository: {repo_name}")
        print(f"🌿 Branch: {branch}")
        
        # Only update if this is the main branch
        if branch in ['main', 'master']:
            print("🔄 Updating scanner from GitHub...")
            
            try:
                # Perform git pull
                result = subprocess.run(['git', 'pull'], 
                                      capture_output=True, text=True, cwd=os.getcwd())
                
                if result.returncode == 0:
                    print("✅ Update successful!")
                    print(result.stdout)
                    
                    # Check if requirements.txt was updated
                    if 'requirements.txt' in result.stdout:
                        print("📋 Requirements may have changed. Installing updates...")
                        subprocess.run(['pip', 'install', '-r', 'requirements.txt'], 
                                     capture_output=True, text=True, cwd=os.getcwd())
                        print("✅ Requirements updated.")
                        
                else:
                    print("❌ Update failed:")
                    print(result.stderr)
                    
            except Exception as e:
                print(f"❌ Error during update: {e}")
        else:
            print(f"ℹ️  Skipping update for branch {branch}")

def run_webhook_server(port=8000):
    """Run the webhook server"""
    server_address = ('', port)
    httpd = HTTPServer(server_address, GitHubWebhookHandler)
    print(f"🚀 GitHub webhook server running on port {port}")
    print("💡 Set up your GitHub webhook to point to this server")
    print("📝 Payload URL: http://your-server:{port}/webhook")
    print("🔐 Don't forget to set the WEBHOOK_SECRET environment variable")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Shutting down webhook server...")
        httpd.server_close()

if __name__ == '__main__':
    run_webhook_server()