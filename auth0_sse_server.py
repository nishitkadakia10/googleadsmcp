#!/usr/bin/env python3
"""
Auth0-Protected SSE MCP Server with Browser-Based Authentication Flow
This server implements a user-friendly authentication flow for Claude Desktop
"""

import os
import sys
import logging
import asyncio
import uuid
import json
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime, timezone, timedelta
from functools import wraps
import secrets

from starlette.applications import Starlette
from starlette.responses import JSONResponse, StreamingResponse, HTMLResponse, RedirectResponse
from starlette.routing import Route
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
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
SESSION_SECRET = os.environ.get('SESSION_SECRET', secrets.token_urlsafe(32))

# In-memory session store (use Redis in production)
auth_sessions = {}
pending_auth_sessions = {}

class Auth0Handler:
    """Handles Auth0 OAuth flow"""
    
    def __init__(self):
        self.jwks_client = PyJWKClient(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    
    def get_auth_url(self, state: str, session_id: str) -> str:
        """Generate Auth0 authorization URL"""
        redirect_uri = f"{SERVER_URL}/callback"
        
        auth_params = {
            'response_type': 'code',
            'client_id': AUTH0_CLIENT_ID,
            'redirect_uri': redirect_uri,
            'scope': 'openid profile email',
            'audience': AUTH0_API_IDENTIFIER,
            'state': state,
            'prompt': 'login'  # Force login screen
        }
        
        # Store session info for callback
        pending_auth_sessions[state] = {
            'session_id': session_id,
            'created_at': datetime.now(timezone.utc).isoformat()
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

auth0_handler = Auth0Handler()

# Create SSE transport
sse = SseServerTransport("/sse")

# HTML Templates
AUTH_REQUIRED_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Required - Google Ads MCP</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: #f5f5f5;
        }
        .auth-container {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 400px;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
        }
        p {
            color: #666;
            margin-bottom: 30px;
        }
        .auth-button {
            background: #5c6bc0;
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }
        .auth-button:hover {
            background: #4a5ab5;
        }
        .session-info {
            margin-top: 20px;
            padding: 10px;
            background: #f0f0f0;
            border-radius: 5px;
            font-family: monospace;
            font-size: 12px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="auth-container">
        <h1>🔐 Authentication Required</h1>
        <p>To access the Google Ads MCP Server, you need to authenticate with your company account.</p>
        <a href="{auth_url}" class="auth-button">Sign in with Auth0</a>
        <div class="session-info">Session ID: {session_id}</div>
    </div>
</body>
</html>
"""

AUTH_SUCCESS_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Successful - Google Ads MCP</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: #f5f5f5;
        }
        .success-container {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 500px;
        }
        h1 {
            color: #4caf50;
            margin-bottom: 20px;
        }
        p {
            color: #666;
            margin-bottom: 20px;
            line-height: 1.6;
        }
        .close-button {
            background: #4caf50;
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
        }
        .close-button:hover {
            background: #45a049;
        }
        .user-info {
            margin: 20px 0;
            padding: 15px;
            background: #f0f8f0;
            border-radius: 5px;
            text-align: left;
        }
        .user-info strong {
            color: #333;
        }
    </style>
</head>
<body>
    <div class="success-container">
        <h1>✅ Authentication Successful!</h1>
        <div class="user-info">
            <strong>Logged in as:</strong> {email}<br>
            <strong>User ID:</strong> {user_id}
        </div>
        <p>You can now return to Claude Desktop. Your MCP connection has been authenticated and is ready to use.</p>
        <p><small>This window will close automatically in 5 seconds...</small></p>
        <button class="close-button" onclick="window.close()">Close Window</button>
    </div>
    <script>
        setTimeout(() => window.close(), 5000);
    </script>
</body>
</html>
"""

AUTH_ERROR_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Error - Google Ads MCP</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: #f5f5f5;
        }
        .error-container {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 500px;
        }
        h1 {
            color: #f44336;
            margin-bottom: 20px;
        }
        p {
            color: #666;
            margin-bottom: 20px;
        }
        .error-details {
            background: #fff0f0;
            padding: 15px;
            border-radius: 5px;
            color: #d32f2f;
            margin-bottom: 20px;
            font-family: monospace;
            font-size: 14px;
        }
        .retry-button {
            background: #f44336;
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }
        .retry-button:hover {
            background: #d32f2f;
        }
    </style>
</head>
<body>
    <div class="error-container">
        <h1>❌ Authentication Failed</h1>
        <p>We couldn't authenticate your account. Please try again.</p>
        <div class="error-details">{error}</div>
        <a href="/" class="retry-button">Try Again</a>
    </div>
</body>
</html>
"""

async def health(request):
    """Health check endpoint"""
    return JSONResponse({
        "status": "healthy",
        "service": "auth0-mcp-server",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "auth_enabled": bool(AUTH0_DOMAIN)
    })

async def handle_sse(request: Request):
    """Handle SSE connections with authentication"""
    session_id = request.cookies.get('mcp_session_id')
    
    # Check if user has valid session
    if session_id and session_id in auth_sessions:
        session = auth_sessions[session_id]
        
        # Check if session is still valid (24 hour expiry)
        created_at = datetime.fromisoformat(session['created_at'])
        if datetime.now(timezone.utc) - created_at > timedelta(hours=24):
            del auth_sessions[session_id]
            session_id = None
    
    # If no valid session, trigger auth flow
    if not session_id or session_id not in auth_sessions:
        # Generate new session ID
        new_session_id = str(uuid.uuid4())
        state = secrets.token_urlsafe(32)
        
        # Get auth URL
        auth_url = auth0_handler.get_auth_url(state, new_session_id)
        
        # Return HTML that triggers auth flow
        html_content = AUTH_REQUIRED_HTML.format(
            auth_url=auth_url,
            session_id=new_session_id
        )
        
        response = HTMLResponse(html_content)
        response.set_cookie(
            'mcp_session_id',
            new_session_id,
            max_age=86400,  # 24 hours
            httponly=True,
            samesite='lax'
        )
        return response
    
    # User is authenticated, establish SSE connection
    session = auth_sessions[session_id]
    user = session['user']
    logger.info(f"SSE connection established for user: {user.get('email')}")
    
    # Add user context to MCP
    if hasattr(mcp, '_user_context'):
        mcp._user_context = user
    
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

async def handle_messages(request: Request):
    """Handle POST messages with authentication check"""
    session_id = request.cookies.get('mcp_session_id')
    
    if not session_id or session_id not in auth_sessions:
        return JSONResponse(
            {"error": "Authentication required"},
            status_code=401
        )
    
    # User is authenticated
    session = auth_sessions[session_id]
    user = session['user']
    
    await sse.handle_post_message(
        request.scope,
        request.receive,
        request._send
    )

async def handle_callback(request: Request):
    """Handle Auth0 callback"""
    code = request.query_params.get('code')
    state = request.query_params.get('state')
    error = request.query_params.get('error')
    
    if error:
        return HTMLResponse(AUTH_ERROR_HTML.format(error=error))
    
    if not code or not state:
        return HTMLResponse(AUTH_ERROR_HTML.format(error="Missing code or state"))
    
    # Verify state and get session info
    if state not in pending_auth_sessions:
        return HTMLResponse(AUTH_ERROR_HTML.format(error="Invalid state parameter"))
    
    session_info = pending_auth_sessions.pop(state)
    session_id = session_info['session_id']
    
    try:
        # Exchange code for token
        token_data = auth0_handler.exchange_code_for_token(code)
        access_token = token_data['access_token']
        
        # Verify and decode token
        user_info = auth0_handler.verify_token(access_token)
        
        # Store authenticated session
        auth_sessions[session_id] = {
            'user': user_info,
            'access_token': access_token,
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        
        # Log successful authentication
        logger.info(f"User authenticated: {user_info.get('email')} ({user_info.get('sub')})")
        
        # Return success page
        html_content = AUTH_SUCCESS_HTML.format(
            email=user_info.get('email', 'Unknown'),
            user_id=user_info.get('sub', 'Unknown')
        )
        
        response = HTMLResponse(html_content)
        response.set_cookie(
            'mcp_session_id',
            session_id,
            max_age=86400,  # 24 hours
            httponly=True,
            samesite='lax'
        )
        return response
        
    except Exception as e:
        logger.error(f"Auth callback error: {str(e)}")
        return HTMLResponse(AUTH_ERROR_HTML.format(error=str(e)))

async def handle_logout(request: Request):
    """Handle logout"""
    session_id = request.cookies.get('mcp_session_id')
    
    if session_id and session_id in auth_sessions:
        user = auth_sessions[session_id]['user']
        logger.info(f"User logged out: {user.get('email')}")
        del auth_sessions[session_id]
    
    response = RedirectResponse(url='/')
    response.delete_cookie('mcp_session_id')
    return response

async def handle_status(request: Request):
    """Check authentication status"""
    session_id = request.cookies.get('mcp_session_id')
    
    if session_id and session_id in auth_sessions:
        session = auth_sessions[session_id]
        return JSONResponse({
            "authenticated": True,
            "user": {
                "email": session['user'].get('email'),
                "sub": session['user'].get('sub')
            }
        })
    
    return JSONResponse({"authenticated": False})

# Cleanup old sessions periodically
async def cleanup_sessions():
    """Remove expired sessions"""
    while True:
        await asyncio.sleep(3600)  # Run every hour
        
        now = datetime.now(timezone.utc)
        expired = []
        
        for session_id, session in auth_sessions.items():
            created_at = datetime.fromisoformat(session['created_at'])
            if now - created_at > timedelta(hours=24):
                expired.append(session_id)
        
        for session_id in expired:
            logger.info(f"Removing expired session: {session_id}")
            del auth_sessions[session_id]
        
        # Also cleanup pending auth sessions older than 10 minutes
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
        Route("/", handle_sse),  # Main SSE endpoint
        Route("/health", health),
        Route("/sse", handle_sse),
        Route("/messages", handle_messages, methods=["POST"]),
        Route("/callback", handle_callback),
        Route("/logout", handle_logout),
        Route("/status", handle_status),
    ],
    middleware=[
        Middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"]
        ),
        Middleware(
            SessionMiddleware,
            secret_key=SESSION_SECRET
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
    
    # Run with uvicorn
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=port)
