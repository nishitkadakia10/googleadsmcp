#!/usr/bin/env python3
"""
Google Ads MCP Server with Auth0 OAuth Authentication
For deployment on Railway with Claude Desktop
"""

import os
import sys
import logging
import asyncio
import secrets
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode, parse_qs
from typing import Dict, Set, Optional

from starlette.applications import Starlette
from starlette.responses import JSONResponse, HTMLResponse, Response, RedirectResponse
from starlette.routing import Route
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from mcp.server.sse import SseServerTransport
import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from google_ads_server import mcp, setup_credentials_file

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Server Configuration
RAILWAY_URL = os.environ.get('RAILWAY_STATIC_URL', '')
if RAILWAY_URL and not RAILWAY_URL.startswith('http'):
    SERVER_URL = f"https://{RAILWAY_URL}"
else:
    SERVER_URL = RAILWAY_URL or 'http://localhost:8000'

# Auth0 Configuration
AUTH0_DOMAIN = os.environ.get('AUTH0_DOMAIN', '')  # e.g., 'your-tenant.auth0.com'
AUTH0_CLIENT_ID = os.environ.get('AUTH0_CLIENT_ID', '')
AUTH0_CLIENT_SECRET = os.environ.get('AUTH0_CLIENT_SECRET', '')
AUTH0_AUDIENCE = os.environ.get('AUTH0_AUDIENCE', f'{SERVER_URL}/api')

# Session configuration
SESSION_SECRET_KEY = os.environ.get('SESSION_SECRET_KEY', secrets.token_urlsafe(32))

# In-memory storage for active sessions (in production, use Redis or similar)
active_sessions: Dict[str, dict] = {}

# Create SSE transport
sse = SseServerTransport("/sse")

def validate_auth0_config():
    """Validate Auth0 configuration on startup"""
    if not all([AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET]):
        logger.error("Missing Auth0 configuration!")
        logger.error("Required environment variables:")
        logger.error("  AUTH0_DOMAIN: Your Auth0 domain (e.g., 'your-tenant.auth0.com')")
        logger.error("  AUTH0_CLIENT_ID: Your Auth0 application Client ID")
        logger.error("  AUTH0_CLIENT_SECRET: Your Auth0 application Client Secret")
        return False
    return True

async def get_auth0_jwks():
    """Fetch Auth0 JWKS for token validation"""
    async with httpx.AsyncClient() as client:
        response = await client.get(f"https://{AUTH0_DOMAIN}/.well-known/jwks.json")
        return response.json()

def verify_auth0_token(token: str) -> Optional[dict]:
    """Verify Auth0 JWT token"""
    try:
        # For simplicity, decode without verification in this example
        # In production, properly verify with JWKS
        unverified_header = jwt.get_unverified_header(token)
        
        # Decode and verify token
        payload = jwt.decode(
            token,
            options={"verify_signature": False},  # In production, verify with JWKS
            audience=AUTH0_AUDIENCE,
            issuer=f"https://{AUTH0_DOMAIN}/"
        )
        return payload
    except Exception as e:
        logger.error(f"Token verification failed: {e}")
        return None

async def health(request: Request):
    """Health check endpoint"""
    return JSONResponse({
        "status": "healthy",
        "service": "google-ads-mcp",
        "auth": "oauth",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

async def oauth_status(request: Request):
    """OAuth status endpoint for Claude Desktop"""
    # Check if we have a valid session
    session_token = request.cookies.get('mcp_session')
    authenticated = session_token and session_token in active_sessions
    
    return JSONResponse({
        "authenticated": authenticated,
        "expires_at": active_sessions[session_token]['expires_at'].isoformat() if authenticated else None
    })

async def oauth_authorize(request: Request):
    """OAuth authorization endpoint - redirects to Auth0"""
    if not validate_auth0_config():
        return JSONResponse({"error": "OAuth not configured"}, status_code=500)
    
    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)
    
    # Store state in session (in production, use proper session storage)
    request.session['oauth_state'] = state
    
    # Build Auth0 authorization URL
    params = {
        'response_type': 'code',
        'client_id': AUTH0_CLIENT_ID,
        'redirect_uri': f"{SERVER_URL}/oauth/callback",
        'scope': 'openid profile email',
        'state': state,
        'audience': AUTH0_AUDIENCE
    }
    
    auth_url = f"https://{AUTH0_DOMAIN}/authorize?{urlencode(params)}"
    
    return RedirectResponse(url=auth_url)

async def oauth_callback(request: Request):
    """OAuth callback endpoint - handles Auth0 response"""
    # Get code and state from query params
    code = request.query_params.get('code')
    state = request.query_params.get('state')
    error = request.query_params.get('error')
    
    if error:
        return HTMLResponse(f"""
            <html>
            <body>
                <h1>Authentication Error</h1>
                <p>{error}: {request.query_params.get('error_description', '')}</p>
                <p><a href="/">Try again</a></p>
            </body>
            </html>
        """)
    
    # Verify state
    stored_state = request.session.get('oauth_state')
    if not state or state != stored_state:
        return JSONResponse({"error": "Invalid state"}, status_code=400)
    
    if not code:
        return JSONResponse({"error": "No authorization code"}, status_code=400)
    
    # Exchange code for tokens
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            f"https://{AUTH0_DOMAIN}/oauth/token",
            data={
                'grant_type': 'authorization_code',
                'client_id': AUTH0_CLIENT_ID,
                'client_secret': AUTH0_CLIENT_SECRET,
                'code': code,
                'redirect_uri': f"{SERVER_URL}/oauth/callback"
            }
        )
        
        if token_response.status_code != 200:
            return JSONResponse(
                {"error": "Token exchange failed", "details": token_response.text}, 
                status_code=400
            )
        
        tokens = token_response.json()
    
    # Verify the ID token
    id_token = tokens.get('id_token')
    if not id_token:
        return JSONResponse({"error": "No ID token received"}, status_code=400)
    
    # Decode token to get user info
    user_info = verify_auth0_token(id_token)
    if not user_info:
        return JSONResponse({"error": "Invalid token"}, status_code=400)
    
    # Create session
    session_id = secrets.token_urlsafe(32)
    active_sessions[session_id] = {
        'user': user_info,
        'access_token': tokens.get('access_token'),
        'expires_at': datetime.now(timezone.utc) + timedelta(hours=24)
    }
    
    # Create response with session cookie
    response = HTMLResponse("""
        <html>
        <head>
            <title>Authentication Successful</title>
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
                .success {
                    background: white;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    text-align: center;
                }
                .success h1 { color: #4CAF50; }
            </style>
        </head>
        <body>
            <div class="success">
                <h1>✅ Authentication Successful!</h1>
                <p>You can now close this window and return to Claude Desktop.</p>
                <p>Your session will remain active for 24 hours.</p>
            </div>
        </body>
        </html>
    """)
    
    response.set_cookie(
        'mcp_session',
        session_id,
        httponly=True,
        secure=True,
        samesite='lax',
        max_age=86400  # 24 hours
    )
    
    return response

async def handle_sse(request: Request):
    """Handle SSE connections with OAuth authentication"""
    # Check for session cookie
    session_token = request.cookies.get('mcp_session')
    
    # Also check for bearer token in case Claude sends it
    auth_header = request.headers.get('authorization', '')
    if auth_header.startswith('Bearer '):
        bearer_token = auth_header[7:]
        # Verify the bearer token
        token_info = verify_auth0_token(bearer_token)
        if not token_info:
            return JSONResponse({"error": "Invalid token"}, status_code=401)
    elif session_token and session_token in active_sessions:
        # Check session validity
        session = active_sessions[session_token]
        if datetime.now(timezone.utc) > session['expires_at']:
            del active_sessions[session_token]
            return JSONResponse({"error": "Session expired"}, status_code=401)
    else:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    
    # Handle SSE connection
    logger.info(f"SSE connection established")
    
    # For POST requests with session_id, handle message
    if request.method == "POST" and request.query_params.get('session_id'):
        await sse.handle_post_message(
            request.scope,
            request.receive,
            request._send
        )
        return Response(status_code=200)
    
    # Handle SSE connection using the MCP SSE transport
    try:
        # Return a streaming response that handles the SSE connection
        async def sse_stream():
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
        
        # Create the task but don't await it here
        task = asyncio.create_task(sse_stream())
        
        # Return immediately with a valid response
        return Response(
            status_code=200,
            headers={
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
            }
        )
        
    except Exception as e:
        logger.error(f"Error in SSE handler: {str(e)}")
        return JSONResponse({"error": str(e)}, status_code=500)

async def manifest(request: Request):
    """MCP manifest endpoint for Claude to discover server capabilities."""
    return JSONResponse({
        "name": "Google Ads MCP",
        "description": "Access Google Ads data and analytics",
        "version": "1.0.0",
        "protocol_version": "1.0",
        "auth": {
            "type": "oauth2",
            "oauth2": {
                "authorize_url": f"{SERVER_URL}/oauth/authorize",
                "token_url": f"{SERVER_URL}/oauth/token",
                "client_id": AUTH0_CLIENT_ID,
                "scope": "openid profile email"
            }
        },
        "capabilities": {
            "tools": True,
            "resources": False,
            "prompts": False
        }
    })

async def instructions(request: Request):
    """Instructions page"""
    if not validate_auth0_config():
        return HTMLResponse("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Google Ads MCP Server - Configuration Error</title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    max-width: 800px;
                    margin: 50px auto;
                    padding: 20px;
                }
                .error {
                    background: #f8d7da;
                    border: 1px solid #f5c6cb;
                    color: #721c24;
                    padding: 20px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                }
                code {
                    background: #f4f4f4;
                    padding: 2px 5px;
                    border-radius: 3px;
                    font-family: monospace;
                }
            </style>
        </head>
        <body>
            <h1>⚠️ Configuration Error</h1>
            <div class="error">
                <strong>Auth0 not configured!</strong><br><br>
                This server requires Auth0 to be configured. Set these environment variables:<br><br>
                <code>AUTH0_DOMAIN</code> - Your Auth0 domain (e.g., 'your-tenant.auth0.com')<br>
                <code>AUTH0_CLIENT_ID</code> - Your Auth0 application Client ID<br>
                <code>AUTH0_CLIENT_SECRET</code> - Your Auth0 application Client Secret<br><br>
                Please configure the server properly before use.
            </div>
        </body>
        </html>
        """)
    
    # Check if user is authenticated
    session_token = request.cookies.get('mcp_session')
    authenticated = session_token and session_token in active_sessions
    
    auth_status = "✅ Authenticated" if authenticated else "❌ Not authenticated"
    auth_button = '<a href="/oauth/authorize" style="display: inline-block; background: #0066cc; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Login with Auth0</a>' if not authenticated else '<p>You are logged in!</p>'
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Google Ads MCP Server</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                max-width: 800px;
                margin: 50px auto;
                padding: 20px;
                line-height: 1.6;
            }}
            .status {{
                background: #d4edda;
                border: 1px solid #c3e6cb;
                padding: 15px;
                border-radius: 5px;
                margin-bottom: 30px;
            }}
            code {{
                background: #f4f4f4;
                padding: 2px 5px;
                border-radius: 3px;
                font-family: monospace;
            }}
            .url-box {{
                background: #f8f9fa;
                border: 1px solid #dee2e6;
                padding: 15px;
                border-radius: 5px;
                margin: 20px 0;
                word-break: break-all;
                font-family: monospace;
            }}
        </style>
    </head>
    <body>
        <h1>🚀 Google Ads MCP Server with OAuth</h1>
        
        <div class="status">
            <strong>Status:</strong> ✅ Running<br>
            <strong>Authentication:</strong> {auth_status}<br>
            <strong>Auth Provider:</strong> Auth0<br>
            <strong>Endpoint:</strong> <code>{SERVER_URL}</code>
        </div>
        
        {auth_button}
        
        <h2>Claude Desktop Setup</h2>
        <ol>
            <li>First authenticate by clicking the login button above</li>
            <li>Open Claude Desktop</li>
            <li>Go to Settings → Developer → Edit Config</li>
            <li>Add this server configuration:</li>
        </ol>
        
        <div class="url-box">
{{
  "mcpServers": {{
    "google-ads": {{
      "uri": "{SERVER_URL}/sse",
      "auth": {{
        "type": "oauth",
        "authorize_url": "{SERVER_URL}/oauth/authorize",
        "pkce": false,
        "polling": {{
          "interval": 5000,
          "status_url": "{SERVER_URL}/oauth/status"
        }}
      }}
    }}
  }}
}}
        </div>
        
        <h2>Available Tools</h2>
        <ul>
            <li>List Google Ads accounts</li>
            <li>Get campaign performance</li>
            <li>Analyze ad performance</li>
            <li>Run custom GAQL queries</li>
            <li>Manage image assets</li>
        </ul>
        
        <hr>
        <p><a href="/health">Health Check</a> | <a href="/oauth/status">Auth Status</a></p>
    </body>
    </html>
    """
    return HTMLResponse(html)

# Create a custom SSE endpoint that handles OAuth
class OAuthSSEEndpoint:
    def __init__(self, sse_transport):
        self.sse = sse_transport

    async def __call__(self, scope, receive, send):
        # Get cookies from headers
        headers = dict(scope.get('headers', []))
        cookie_header = headers.get(b'cookie', b'').decode()
        
        # Parse cookies
        cookies = {}
        if cookie_header:
            for cookie in cookie_header.split(';'):
                if '=' in cookie:
                    key, value = cookie.strip().split('=', 1)
                    cookies[key] = value
        
        # Check for session
        session_token = cookies.get('mcp_session')
        authenticated = False
        
        if session_token and session_token in active_sessions:
            session = active_sessions[session_token]
            if datetime.now(timezone.utc) <= session['expires_at']:
                authenticated = True
        
        if not authenticated:
            await send({
                'type': 'http.response.start',
                'status': 401,
                'headers': [[b'content-type', b'application/json']],
            })
            await send({
                'type': 'http.response.body',
                'body': b'{"error": "Authentication required"}',
            })
            return
        
        # Handle different methods
        method = scope.get('method', 'GET')
        
        if method == 'HEAD':
            await send({
                'type': 'http.response.start',
                'status': 200,
                'headers': [],
            })
            await send({
                'type': 'http.response.body',
                'body': b'',
            })
            return
        
        # Handle SSE connection
        logger.info(f"Authenticated SSE connection established")
        
        # Extract query parameters
        query_string = scope.get('query_string', b'').decode()
        query_params = {}
        if query_string:
            for param in query_string.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    query_params[key] = value
        
        if method == "POST" and query_params.get('session_id'):
            await self.sse.handle_post_message(scope, receive, send)
        else:
            async with self.sse.connect_sse(scope, receive, send) as streams:
                await mcp._mcp_server.run(
                    streams[0],
                    streams[1],
                    mcp._mcp_server.create_initialization_options()
                )

# Create SSE endpoint instance
sse_endpoint = OAuthSSEEndpoint(sse)

# Create Starlette app with session middleware
app = Starlette(
    routes=[
        Route("/", instructions),
        Route("/health", health),
        Route("/manifest", manifest),  # Add manifest endpoint
        Route("/oauth/authorize", oauth_authorize),
        Route("/oauth/callback", oauth_callback),
        Route("/oauth/status", oauth_status),
        Route("/sse", endpoint=sse_endpoint, methods=["GET", "POST", "HEAD"]),
    ],
    middleware=[
        Middleware(SessionMiddleware, secret_key=SESSION_SECRET_KEY),
        Middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_methods=["*"],
            allow_headers=["*"],
            allow_credentials=True
        )
    ]
)

if __name__ == "__main__":
    # Setup credentials if needed
    if os.environ.get("RAILWAY_ENVIRONMENT") or os.environ.get("GOOGLE_ADS_CREDENTIALS_BASE64"):
        setup_credentials_file()
    
    # Get port from environment
    port = int(os.environ.get("PORT", 8000))
    
    logger.info(f"Starting Google Ads MCP Server with OAuth on port {port}")
    logger.info(f"Server URL: {SERVER_URL}")
    
    # Validate Auth0 configuration
    if not validate_auth0_config():
        logger.error("Please configure Auth0 environment variables before starting!")
    else:
        logger.info(f"Auth0 Domain: {AUTH0_DOMAIN}")
        logger.info("OAuth authentication enabled")
    
    # Check Google Ads configuration
    if not os.environ.get("GOOGLE_ADS_DEVELOPER_TOKEN"):
        logger.warning("GOOGLE_ADS_DEVELOPER_TOKEN not set - Google Ads tools may not work properly")
    
    # Start server
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=port)
