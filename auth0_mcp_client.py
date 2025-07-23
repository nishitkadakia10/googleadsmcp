#!/usr/bin/env python3
"""
Auth0 MCP Client Wrapper - Handles authentication before connecting to MCP
"""

import os
import sys
import json
import asyncio
import webbrowser
from urllib.parse import urlencode
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

class Auth0Client:
    def __init__(self):
        self.domain = os.environ.get('AUTH0_DOMAIN')
        self.client_id = os.environ.get('AUTH0_CLIENT_ID')
        self.client_secret = os.environ.get('AUTH0_CLIENT_SECRET')
        self.api_identifier = os.environ.get('AUTH0_API_IDENTIFIER')
        self.redirect_uri = 'http://localhost:8080/callback'
        self.token = None
        
    def get_auth_url(self):
        """Generate Auth0 authorization URL"""
        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': 'openid profile email',
            'audience': self.api_identifier
        }
        return f"https://{self.domain}/authorize?" + urlencode(params)
    
    def exchange_code_for_token(self, code):
        """Exchange authorization code for access token"""
        token_url = f"https://{self.domain}/oauth/token"
        
        data = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': self.redirect_uri
        }
        
        response = requests.post(token_url, json=data)
        if response.status_code == 200:
            token_data = response.json()
            self.token = token_data['access_token']
            return self.token
        else:
            raise Exception(f"Failed to get token: {response.text}")
    
    def authenticate(self):
        """Perform OAuth flow"""
        auth_code = None
        
        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                nonlocal auth_code
                if self.path.startswith('/callback?code='):
                    auth_code = self.path.split('code=')[1].split('&')[0]
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b'''
                        <html>
                        <body>
                        <h1>Authentication Successful!</h1>
                        <p>You can close this window and return to your terminal.</p>
                        <script>window.close();</script>
                        </body>
                        </html>
                    ''')
                else:
                    self.send_response(404)
                    self.end_headers()
            
            def log_message(self, format, *args):
                pass  # Suppress logs
        
        # Start local server
        server = HTTPServer(('localhost', 8080), CallbackHandler)
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        
        # Open browser
        auth_url = self.get_auth_url()
        print(f"Opening browser for authentication...")
        webbrowser.open(auth_url)
        
        # Wait for callback
        print("Waiting for authentication...")
        while auth_code is None:
            threading.Event().wait(0.1)
        
        server.shutdown()
        
        # Exchange code for token
        token = self.exchange_code_for_token(auth_code)
        print("Authentication successful!")
        return token

def main():
    """Main entry point for authenticated MCP client"""
    # Check if we have a saved token
    token_file = os.path.expanduser('~/.mcp_auth0_token')
    
    auth_client = Auth0Client()
    
    # Try to load existing token
    if os.path.exists(token_file):
        try:
            with open(token_file, 'r') as f:
                token_data = json.load(f)
                auth_client.token = token_data.get('access_token')
                print("Using saved authentication token")
        except:
            pass
    
    # If no valid token, authenticate
    if not auth_client.token:
        auth_client.authenticate()
        
        # Save token
        with open(token_file, 'w') as f:
            json.dump({'access_token': auth_client.token}, f)
    
    # Now connect to MCP with auth header
    mcp_url = os.environ.get('MCP_SERVER_URL', 'https://your-railway-app.up.railway.app/sse')
    
    # Pass the token to the MCP connection
    # This would be used by the stdio-to-sse bridge with auth headers
    os.environ['MCP_AUTH_HEADER'] = f"Bearer {auth_client.token}"
    
    # Execute the MCP client with authentication
    import subprocess
    subprocess.run([
        'npx', '-y', 'mcp-remote', mcp_url,
        '--header', f"Authorization: Bearer {auth_client.token}"
    ])

if __name__ == "__main__":
    main()
