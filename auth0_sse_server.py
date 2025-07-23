#!/usr/bin/env python3
"""
Auth0-Protected SSE MCP Server Compatible with Claude Desktop
This version handles authentication in a way that works with Claude Desktop's remote MCP feature
"""

import os
import sys
import logging
import asyncio
import uuid
import json
import hashlib
import hmac
import secrets  # Add this import
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime, timezone, timedelta
from functools import wraps
import secrets

from starlette.applications import Starlette
from starlette.responses import JSONResponse, StreamingResponse, HTMLResponse, RedirectResponse, Response
from starlette.routing import Route
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.exceptions import HTTPException
from mcp.server.sse import SseServerTransport
import jwt
from jwt import PyJWKClient

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from google_ads_server import mcp, setup_credentials_file

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Auth0 Configuration
AUTH0_DOMAIN = os.environ.get('AUTH0_DOMAIN', '')
AUTH0_CLIENT_ID = os.environ.get('AUTH0_CLIENT_ID', '')
AUTH0_CLIENT_SECRET = os.environ.get('AUTH0_CLIENT_SECRET', '')
AUTH0_API_IDENTIFIER = os.environ.get('AUTH0_API_IDENTIFIER', '')
AUTH0_ALGORITHMS = ['RS256']

# Server Configuration
RAILWAY_URL = os.environ.get('RAILWAY_STATIC_URL', '')
if RAILWAY_URL and not RAILWAY_URL.startswith('http'):
    SERVER_URL = f"https://{RAILWAY_URL}"
else:
    SERVER_URL = RAILWAY_URL or 'http://localhost:8000'

# API Key Configuration for initial auth
API_KEY_SECRET = os.environ.get('API_KEY_SECRET', secrets.token_urlsafe(32))

# In-memory stores
auth_sessions = {}
api_keys = {}  # Maps API keys to user info
pending_auth_sessions = {}

class Auth0Handler:
    """Handles Auth0 OAuth flow"""
    
    def __init__(self):
        if AUTH0_DOMAIN:
            self.jwks_client = PyJWKClient(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    
    def get_auth_url(self, state: str) -> str:
        """Generate Auth0 authorization URL"""
        redirect_uri = f"{SERVER_URL}/callback"
        
        auth_params = {
            'response_type': 'code',
            'client_id': AUTH0_CLIENT_ID,
            'redirect_uri': redirect_uri,
            'scope': 'openid profile email',
            'audience': AUTH0_API_IDENTIFIER,
            'state': state
        }
        
        from urllib.parse import urlencode
        return f"https://{AUTH0_DOMAIN}/authorize?" + urlencode(auth_params)
    
    def exchange_code_for_token(self, code: str) -> Dict[str, Any]:
        """Exchange authorization code for tokens"""
        import requests
        
        token_url = f"https://{AUTH0_DOMAIN}/oauth/token"
        redirect_uri = f"{SERVER_URL}/callback"
        
        data = {
            'grant_type': 'authorization_code',
            'client_id': AUTH0_CLIENT_ID,
            'client_secret': AUTH0_CLIENT_SECRET,
            'code': code,
            'redirect_uri': redirect_uri
        }
        
        response = requests.post(token_url, json=data)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to get token: {response.text}")
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify and decode JWT token"""
        signing_key = self.jwks_client.get_signing_key_from_jwt(token)
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=AUTH0_ALGORITHMS,
            audience=AUTH0_API_IDENTIFIER,
            issuer=f'https://{AUTH0_DOMAIN}/'
        )
        return payload

auth0_handler = Auth0Handler() if AUTH0_DOMAIN else None

# Create SSE transport
sse = SseServerTransport("/sse")

def generate_api_key(user_info: Dict[str, Any]) -> str:
    """Generate a secure API key for a user"""
    # Create a unique key based on user ID and timestamp
    key_data = f"{user_info['sub']}:{datetime.now().timestamp()}:{secrets.token_urlsafe(16)}"
    api_key = hashlib.sha256(key_data.encode()).hexdigest()
    
    # Store the API key with user info
    api_keys[api_key] = {
        'user': user_info,
        'created_at': datetime.now(timezone.utc).isoformat()
    }
    
    return api_key

def verify_api_key(api_key: str) -> Optional[Dict[str, Any]]:
    """Verify an API key and return user info"""
    if api_key in api_keys:
        key_info = api_keys[api_key]
        # Check if key is still valid (7 days expiry)
        created_at = datetime.fromisoformat(key_info['created_at'])
        if datetime.now(timezone.utc) - created_at < timedelta(days=7):
            return key_info['user']
        else:
            # Key expired, remove it
            del api_keys[api_key]
    return None

async def health(request):
    """Health check endpoint"""
    return JSONResponse({
        "status": "healthy",
        "service": "auth0-mcp-server",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "auth_enabled": bool(AUTH0_DOMAIN)
    })

async def handle_sse(request: Request):
    """Handle SSE connections with API key authentication"""
    # Check for API key in query params (Claude Desktop sends auth this way)
    api_key = request.query_params.get('api_key')
    
    # Also check Authorization header as fallback
    auth_header = request.headers.get('authorization', '')
    if auth_header.startswith('Bearer '):
        api_key = api_header[7:]
    
    # Verify API key
    if api_key:
        user_info = verify_api_key(api_key)
        if user_info:
            logger.info(f"SSE connection established for user: {user_info.get('email')}")
            
            # Add user context to MCP
            if hasattr(mcp, '_user_context'):
                mcp._user_context = user_info
            
            # Establish SSE connection
            async with sse.connect_sse(
                request.scope,
                request.receive,
                request._send
            ) as streams:
                await mcp._mcp_server.run(
                    streams[0],
                    streams[1],
                    mcp._mcp_server.create_initialization_options()
                )
            return
    
    # No valid API key, return 401
    return JSONResponse(
        {"error": "Authentication required. Please visit /auth to get an API key."},
        status_code=401
    )

async def handle_messages(request: Request):
    """Handle POST messages with authentication check"""
    # Check for API key
    api_key = request.query_params.get('api_key')
    auth_header = request.headers.get('authorization', '')
    if auth_header.startswith('Bearer '):
        api_key = auth_header[7:]
    
    if api_key and verify_api_key(api_key):
        await sse.handle_post_message(
            request.scope,
            request.receive,
            request._send
        )
    else:
        return JSONResponse(
            {"error": "Authentication required"},
            status_code=401
        )

async def handle_auth(request: Request):
    """Initiate authentication flow"""
    state = secrets.token_urlsafe(32)
    
    # Store state for callback
    pending_auth_sessions[state] = {
        'created_at': datetime.now(timezone.utc).isoformat()
    }
    
    auth_url = auth0_handler.get_auth_url(state)
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Authenticate for Google Ads MCP</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
                background: #f5f5f5;
            }}
            .auth-container {{
                background: white;
                padding: 40px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                text-align: center;
                max-width: 500px;
            }}
            h1 {{
                color: #333;
                margin-bottom: 10px;
            }}
            p {{
                color: #666;
                margin-bottom: 30px;
                line-height: 1.6;
            }}
            .auth-button {{
                background: #5c6bc0;
                color: white;
                border: none;
                padding: 12px 30px;
                border-radius: 5px;
                font-size: 16px;
                cursor: pointer;
                text-decoration: none;
                display: inline-block;
            }}
            .auth-button:hover {{
                background: #4a5ab5;
            }}
            .info-box {{
                background: #f0f4ff;
                padding: 20px;
                border-radius: 5px;
                margin-top: 30px;
                text-align: left;
            }}
            .info-box h3 {{
                margin-top: 0;
                color: #5c6bc0;
            }}
            .info-box ol {{
                margin: 10px 0;
                padding-left: 20px;
            }}
            .info-box li {{
                margin: 5px 0;
            }}
        </style>
    </head>
    <body>
        <div class="auth-container">
            <h1>🔐 Google Ads MCP Authentication</h1>
            <p>To use the Google Ads MCP server with Claude Desktop, you need to authenticate and get an API key.</p>
            <a href="{auth_url}" class="auth-button">Sign in with Auth0</a>
            
            <div class="info-box">
                <h3>What happens next?</h3>
                <ol>
                    <li>You'll be redirected to Auth0 to sign in</li>
                    <li>After successful authentication, you'll receive an API key</li>
                    <li>Copy the API key and your personal MCP URL</li>
                    <li>Add the URL to Claude Desktop</li>
                </ol>
            </div>
        </div>
    </body>
    </html>
    """
    
    return HTMLResponse(html_content)

async def handle_callback(request: Request):
    """Handle Auth0 callback and generate API key"""
    code = request.query_params.get('code')
    state = request.query_params.get('state')
    error = request.query_params.get('error')
    
    if error:
        return HTMLResponse(f"<h1>Authentication Error</h1><p>{error}</p>")
    
    if not code or not state:
        return HTMLResponse("<h1>Error</h1><p>Missing code or state</p>")
    
    # Verify state
    if state not in pending_auth_sessions:
        return HTMLResponse("<h1>Error</h1><p>Invalid state parameter</p>")
    
    pending_auth_sessions.pop(state)
    
    try:
        # Exchange code for token
        token_data = auth0_handler.exchange_code_for_token(code)
        access_token = token_data['access_token']
        
        # Verify and decode token
        user_info = auth0_handler.verify_token(access_token)
        
        # Generate API key for this user
        api_key = generate_api_key(user_info)
        
        # Generate the MCP URL with API key
        mcp_url = f"{SERVER_URL}/sse?api_key={api_key}"
        
        logger.info(f"Generated API key for user: {user_info.get('email')} ({user_info.get('sub')})")
        
        # Return success page with API key
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authentication Successful - Google Ads MCP</title>
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    min-height: 100vh;
                    margin: 0;
                    background: #f5f5f5;
                    padding: 20px;
                }}
                .success-container {{
                    background: white;
                    padding: 40px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    max-width: 700px;
                    width: 100%;
                }}
                h1 {{
                    color: #4caf50;
                    margin-bottom: 20px;
                }}
                .user-info {{
                    background: #f0f8f0;
                    padding: 15px;
                    border-radius: 5px;
                    margin-bottom: 30px;
                }}
                .api-key-section {{
                    background: #f5f5f5;
                    padding: 20px;
                    border-radius: 5px;
                    margin: 20px 0;
                }}
                .url-box {{
                    background: #ffffff;
                    border: 2px solid #5c6bc0;
                    padding: 15px;
                    border-radius: 5px;
                    font-family: monospace;
                    font-size: 14px;
                    word-break: break-all;
                    margin: 10px 0;
                }}
                .copy-button {{
                    background: #5c6bc0;
                    color: white;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 5px;
                    cursor: pointer;
                    font-size: 14px;
                }}
                .copy-button:hover {{
                    background: #4a5ab5;
                }}
                .instructions {{
                    background: #e8eaf6;
                    padding: 20px;
                    border-radius: 5px;
                    margin-top: 30px;
                }}
                .instructions h3 {{
                    margin-top: 0;
                    color: #5c6bc0;
                }}
                .warning {{
                    background: #fff3cd;
                    border: 1px solid #ffeeba;
                    padding: 15px;
                    border-radius: 5px;
                    margin-top: 20px;
                    color: #856404;
                }}
            </style>
        </head>
        <body>
            <div class="success-container">
                <h1>✅ Authentication Successful!</h1>
                
                <div class="user-info">
                    <strong>Logged in as:</strong> {user_info.get('email', 'Unknown')}<br>
                    <strong>User ID:</strong> {user_info.get('sub', 'Unknown')}
                </div>
                
                <div class="api-key-section">
                    <h2>Your Personal MCP URL</h2>
                    <p>Copy this URL and add it to Claude Desktop:</p>
                    <div class="url-box" id="mcp-url">{mcp_url}</div>
                    <button class="copy-button" onclick="copyUrl()">Copy URL</button>
                </div>
                
                <div class="instructions">
                    <h3>How to add to Claude Desktop:</h3>
                    <ol>
                        <li>Open Claude Desktop</li>
                        <li>Go to Settings → Developer → Edit Config</li>
                        <li>Click "Add MCP Server"</li>
                        <li>Enter:
                            <ul>
                                <li><strong>Name:</strong> Google Ads MCP</li>
                                <li><strong>URL:</strong> <em>Paste the URL you copied above</em></li>
                            </ul>
                        </li>
                        <li>Save and restart Claude Desktop</li>
                    </ol>
                </div>
                
                <div class="warning">
                    <strong>⚠️ Important:</strong> Keep this URL private! It contains your personal API key. 
                    This key will expire in 7 days for security reasons. You can always return to 
                    <a href="/auth">{SERVER_URL}/auth</a> to get a new one.
                </div>
            </div>
            
            <script>
                function copyUrl() {{
                    const urlText = document.getElementById('mcp-url').textContent;
                    navigator.clipboard.writeText(urlText).then(() => {{
                        const button = document.querySelector('.copy-button');
                        button.textContent = 'Copied!';
                        setTimeout(() => {{
                            button.textContent = 'Copy URL';
                        }}, 2000);
                    }});
                }}
            </script>
        </body>
        </html>
        """
        
        return HTMLResponse(html_content)
        
    except Exception as e:
        logger.error(f"Auth callback error: {str(e)}")
        return HTMLResponse(f"<h1>Authentication Error</h1><p>{str(e)}</p>")

async def handle_revoke(request: Request):
    """Revoke an API key"""
    api_key = request.query_params.get('api_key')
    
    if api_key and api_key in api_keys:
        user = api_keys[api_key]['user']
        del api_keys[api_key]
        logger.info(f"API key revoked for user: {user.get('email')}")
        return JSONResponse({"status": "revoked"})
    
    return JSONResponse({"error": "Invalid API key"}, status_code=404)

# Cleanup old sessions periodically
async def cleanup_sessions():
    """Remove expired API keys and pending sessions"""
    while True:
        await asyncio.sleep(3600)  # Run every hour
        
        now = datetime.now(timezone.utc)
        
        # Cleanup expired API keys (older than 7 days)
        expired_keys = []
        for api_key, key_info in api_keys.items():
            created_at = datetime.fromisoformat(key_info['created_at'])
            if now - created_at > timedelta(days=7):
                expired_keys.append(api_key)
        
        for api_key in expired_keys:
            logger.info(f"Removing expired API key for user: {api_keys[api_key]['user'].get('email')}")
            del api_keys[api_key]
        
        # Cleanup pending auth sessions older than 10 minutes
        expired_pending = []
        for state, info in pending_auth_sessions.items():
            created_at = datetime.fromisoformat(info['created_at'])
            if now - created_at > timedelta(minutes=10):
                expired_pending.append(state)
        
        for state in expired_pending:
            del pending_auth_sessions[state]

# Create Starlette app
app = Starlette(
    routes=[
        Route("/", health),  # Root returns health check
        Route("/health", health),
        Route("/sse", handle_sse),
        Route("/messages", handle_messages, methods=["POST"]),
        Route("/auth", handle_auth),
        Route("/callback", handle_callback),
        Route("/revoke", handle_revoke, methods=["POST"]),
    ],
    middleware=[
        Middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"]
        )
    ],
    on_startup=[lambda: asyncio.create_task(cleanup_sessions())]
)

if __name__ == "__main__":
    # Setup credentials if needed
    if os.environ.get("RAILWAY_ENVIRONMENT") or os.environ.get("GOOGLE_ADS_CREDENTIALS_BASE64"):
        setup_credentials_file()
    
    # Get port from Railway
    port = int(os.environ.get("PORT", 8000))
    
    logger.info(f"Starting Auth0-protected SSE MCP server on port {port}")
    logger.info(f"Server URL: {SERVER_URL}")
    logger.info(f"Auth0 Domain: {AUTH0_DOMAIN}")
    logger.info(f"Authentication URL: {SERVER_URL}/auth")
    
    # Run with uvicorn
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=port)
