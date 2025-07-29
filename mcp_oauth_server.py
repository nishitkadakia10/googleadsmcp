#!/usr/bin/env python3
"""
Google Ads MCP Server with OAuth 2.0 Authorization
Following MCP Authorization Specification
"""

import os
import sys
import logging
import asyncio
import json
import secrets
import hashlib
import base64
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Set
from pathlib import Path

from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.exceptions import HTTPException
import jwt
from mcp.server.sse import SseServerTransport

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

# OAuth Configuration
AUTHORIZATION_SERVER_URL = os.environ.get('AUTHORIZATION_SERVER_URL', SERVER_URL)
CLIENT_ID = os.environ.get('OAUTH_CLIENT_ID', 'google-ads-mcp-client')
CLIENT_SECRET = os.environ.get('OAUTH_CLIENT_SECRET', secrets.token_urlsafe(32))
JWT_SECRET = os.environ.get('JWT_SECRET', secrets.token_urlsafe(32))

# User Management (in production, use a database)
AUTHORIZED_USERS = set(os.environ.get('AUTHORIZED_USERS', '').split(',')) if os.environ.get('AUTHORIZED_USERS') else set()
# Token storage (in production, use Redis or similar)
authorization_codes: Dict[str, Dict] = {}
access_tokens: Dict[str, Dict] = {}
refresh_tokens: Dict[str, Dict] = {}
revoked_tokens: Set[str] = set()

# Create SSE transport
sse = SseServerTransport("/mcp")

# ===== OAuth 2.0 Authorization Server Endpoints =====

async def oauth_metadata(request: Request):
    """OAuth 2.0 Authorization Server Metadata (RFC 8414)"""
    return JSONResponse({
        "issuer": AUTHORIZATION_SERVER_URL,
        "authorization_endpoint": f"{AUTHORIZATION_SERVER_URL}/oauth/authorize",
        "token_endpoint": f"{AUTHORIZATION_SERVER_URL}/oauth/token",
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["google_ads:read", "google_ads:write"],
        "service_documentation": f"{SERVER_URL}/docs"
    })

async def protected_resource_metadata(request: Request):
    """OAuth 2.0 Protected Resource Metadata (RFC 9728)"""
    return JSONResponse({
        "resource": SERVER_URL,
        "authorization_servers": [AUTHORIZATION_SERVER_URL],
        "scopes_supported": ["google_ads:read", "google_ads:write"],
        "bearer_methods_supported": ["header"]
    })

async def authorize(request: Request):
    """OAuth 2.0 Authorization Endpoint"""
    # Extract parameters
    client_id = request.query_params.get('client_id')
    redirect_uri = request.query_params.get('redirect_uri')
    response_type = request.query_params.get('response_type')
    state = request.query_params.get('state')
    code_challenge = request.query_params.get('code_challenge')
    code_challenge_method = request.query_params.get('code_challenge_method', 'S256')
    resource = request.query_params.get('resource')
    
    # Validate parameters
    if response_type != 'code':
        return JSONResponse({"error": "unsupported_response_type"}, status_code=400)
    
    if not code_challenge:
        return JSONResponse({"error": "invalid_request", "error_description": "PKCE required"}, status_code=400)
    
    # In production, show a login page here
    # For now, we'll auto-approve if user is in AUTHORIZED_USERS
    username = request.query_params.get('username', 'default_user')
    
    if AUTHORIZED_USERS and username not in AUTHORIZED_USERS:
        return JSONResponse({"error": "access_denied"}, status_code=403)
    
    # Generate authorization code
    code = secrets.token_urlsafe(32)
    authorization_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "username": username,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "resource": resource,
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10),
        "scopes": ["google_ads:read"]
    }
    
    # Redirect back to client
    redirect_url = f"{redirect_uri}?code={code}&state={state}"
    return Response(status_code=302, headers={"Location": redirect_url})

async def token_endpoint(request: Request):
    """OAuth 2.0 Token Endpoint"""
    form_data = await request.form()
    grant_type = form_data.get('grant_type')
    
    # Client authentication
    client_id = form_data.get('client_id')
    client_secret = form_data.get('client_secret')
    
    # In production, validate client credentials against database
    # For now, accept the configured client
    if client_id != CLIENT_ID or client_secret != CLIENT_SECRET:
        return JSONResponse(
            {"error": "invalid_client"},
            status_code=401,
            headers={"WWW-Authenticate": "Basic"}
        )
    
    if grant_type == 'authorization_code':
        return await handle_authorization_code_grant(form_data)
    elif grant_type == 'refresh_token':
        return await handle_refresh_token_grant(form_data)
    else:
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

async def handle_authorization_code_grant(form_data):
    """Handle authorization code grant type"""
    code = form_data.get('code')
    code_verifier = form_data.get('code_verifier')
    redirect_uri = form_data.get('redirect_uri')
    resource = form_data.get('resource')
    
    if not code or code not in authorization_codes:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    
    auth_code_data = authorization_codes[code]
    
    # Check expiration
    if datetime.now(timezone.utc) > auth_code_data['expires_at']:
        del authorization_codes[code]
        return JSONResponse({"error": "invalid_grant", "error_description": "Code expired"}, status_code=400)
    
    # Validate PKCE
    if auth_code_data['code_challenge_method'] == 'S256':
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip('=')
        
        if challenge != auth_code_data['code_challenge']:
            return JSONResponse({"error": "invalid_grant", "error_description": "Invalid PKCE"}, status_code=400)
    
    # Validate redirect_uri
    if redirect_uri != auth_code_data['redirect_uri']:
        return JSONResponse({"error": "invalid_grant", "error_description": "Redirect URI mismatch"}, status_code=400)
    
    # Validate resource parameter (RFC 8707)
    if resource and resource != auth_code_data.get('resource'):
        return JSONResponse({"error": "invalid_target"}, status_code=400)
    
    # Generate tokens
    access_token = jwt.encode({
        "sub": auth_code_data['username'],
        "aud": resource or SERVER_URL,
        "scope": " ".join(auth_code_data['scopes']),
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        "iat": datetime.now(timezone.utc),
        "jti": secrets.token_urlsafe(16)
    }, JWT_SECRET, algorithm="HS256")
    
    refresh_token = secrets.token_urlsafe(32)
    
    # Store tokens
    access_tokens[access_token] = {
        "username": auth_code_data['username'],
        "scopes": auth_code_data['scopes'],
        "resource": resource or SERVER_URL
    }
    
    refresh_tokens[refresh_token] = {
        "username": auth_code_data['username'],
        "scopes": auth_code_data['scopes'],
        "resource": resource or SERVER_URL,
        "created_at": datetime.now(timezone.utc)
    }
    
    # Clean up authorization code
    del authorization_codes[code]
    
    return JSONResponse({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": refresh_token,
        "scope": " ".join(auth_code_data['scopes'])
    })

async def handle_refresh_token_grant(form_data):
    """Handle refresh token grant"""
    refresh_token = form_data.get('refresh_token')
    
    if not refresh_token or refresh_token not in refresh_tokens:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    
    token_data = refresh_tokens[refresh_token]
    
    # Check if user is still authorized
    if AUTHORIZED_USERS and token_data['username'] not in AUTHORIZED_USERS:
        del refresh_tokens[refresh_token]
        return JSONResponse({"error": "invalid_grant", "error_description": "User no longer authorized"}, status_code=400)
    
    # Generate new access token
    access_token = jwt.encode({
        "sub": token_data['username'],
        "aud": token_data['resource'],
        "scope": " ".join(token_data['scopes']),
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        "iat": datetime.now(timezone.utc),
        "jti": secrets.token_urlsafe(16)
    }, JWT_SECRET, algorithm="HS256")
    
    access_tokens[access_token] = {
        "username": token_data['username'],
        "scopes": token_data['scopes'],
        "resource": token_data['resource']
    }
    
    return JSONResponse({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": " ".join(token_data['scopes'])
    })

# ===== Token Management Endpoints =====

async def revoke_token(request: Request):
    """Revoke a user's access tokens"""
    # This would typically require admin authentication
    data = await request.json()
    username = data.get('username')
    
    if not username:
        return JSONResponse({"error": "username required"}, status_code=400)
    
    # Find and revoke all tokens for this user
    revoked_count = 0
    
    # Revoke access tokens
    tokens_to_revoke = []
    for token, token_data in access_tokens.items():
        if token_data['username'] == username:
            tokens_to_revoke.append(token)
            revoked_tokens.add(token)
            revoked_count += 1
    
    for token in tokens_to_revoke:
        del access_tokens[token]
    
    # Revoke refresh tokens
    refresh_to_revoke = []
    for token, token_data in refresh_tokens.items():
        if token_data['username'] == username:
            refresh_to_revoke.append(token)
            revoked_count += 1
    
    for token in refresh_to_revoke:
        del refresh_tokens[token]
    
    return JSONResponse({
        "message": f"Revoked {revoked_count} tokens for user {username}"
    })

# ===== MCP SSE Endpoint with OAuth Protection =====

def validate_bearer_token(authorization_header: Optional[str]) -> Optional[Dict]:
    """Validate Bearer token from Authorization header"""
    if not authorization_header or not authorization_header.startswith('Bearer '):
        return None
    
    token = authorization_header[7:]  # Remove "Bearer " prefix
    
    # Check if token is revoked
    if token in revoked_tokens:
        return None
    
    try:
        # Decode and validate JWT
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        
        # Check expiration (jwt.decode handles this by default)
        # Check audience
        if payload.get('aud') != SERVER_URL:
            logger.warning(f"Token audience mismatch: {payload.get('aud')} != {SERVER_URL}")
            return None
        
        # Check if token exists in our storage
        if token not in access_tokens:
            return None
        
        token_data = access_tokens[token]
        
        # Check if user is still authorized
        if AUTHORIZED_USERS and token_data['username'] not in AUTHORIZED_USERS:
            return None
        
        return token_data
        
    except jwt.ExpiredSignatureError:
        logger.info("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {e}")
        return None

class AuthenticatedSSEEndpoint:
    def __init__(self, sse_transport):
        self.sse = sse_transport

    async def __call__(self, scope, receive, send):
        # Extract headers
        headers = dict(scope.get('headers', []))
        authorization = headers.get(b'authorization', b'').decode()
        
        # Validate token
        token_data = validate_bearer_token(authorization)
        
        if not token_data:
            # Return 401 with WWW-Authenticate header
            await send({
                'type': 'http.response.start',
                'status': 401,
                'headers': [
                    [b'content-type', b'application/json'],
                    [b'www-authenticate', f'Bearer realm="{SERVER_URL}", resource_metadata="{SERVER_URL}/.well-known/oauth-protected-resource"'.encode()]
                ],
            })
            await send({
                'type': 'http.response.body',
                'body': b'{"error": "unauthorized"}',
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
        
        # Log authenticated connection
        logger.info(f"Authenticated SSE connection for user: {token_data['username']}")
        
        # Handle SSE connection
        if method == "POST":
            await self.sse.handle_post_message(scope, receive, send)
        else:
            async with self.sse.connect_sse(scope, receive, send) as streams:
                await mcp._mcp_server.run(
                    streams[0],
                    streams[1],
                    mcp._mcp_server.create_initialization_options()
                )

# Create authenticated SSE endpoint
authenticated_sse = AuthenticatedSSEEndpoint(sse)

# ===== Additional Endpoints =====

async def health(request: Request):
    """Health check endpoint"""
    return JSONResponse({
        "status": "healthy",
        "service": "google-ads-mcp",
        "authorization": "oauth2",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

async def home(request: Request):
    """Home page with setup instructions"""
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Google Ads MCP Server - OAuth Protected</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                max-width: 800px;
                margin: 50px auto;
                padding: 20px;
                line-height: 1.6;
            }}
            .config {{
                background: #f8f9fa;
                border: 1px solid #dee2e6;
                padding: 15px;
                border-radius: 5px;
                margin: 20px 0;
                font-family: monospace;
            }}
            code {{
                background: #f4f4f4;
                padding: 2px 5px;
                border-radius: 3px;
            }}
        </style>
    </head>
    <body>
        <h1>🔐 Google Ads MCP Server (OAuth Protected)</h1>
        
        <h2>Server Information</h2>
        <ul>
            <li><strong>MCP Endpoint:</strong> <code>{SERVER_URL}/mcp</code></li>
            <li><strong>Authorization Required:</strong> Yes (OAuth 2.0)</li>
            <li><strong>Client ID:</strong> <code>{CLIENT_ID}</code></li>
        </ul>
        
        <h2>Claude Desktop Configuration</h2>
        <p>Add this to your Claude Desktop config:</p>
        
        <div class="config">
{{
  "mcpServers": {{
    "google-ads": {{
      "url": "{SERVER_URL}/mcp",
      "auth": {{
        "type": "oauth2",
        "client_id": "{CLIENT_ID}",
        "client_secret": "{CLIENT_SECRET}",
        "authorization_endpoint": "{AUTHORIZATION_SERVER_URL}/oauth/authorize",
        "token_endpoint": "{AUTHORIZATION_SERVER_URL}/oauth/token",
        "pkce": true,
        "scopes": ["google_ads:read"]
      }}
    }}
  }}
}}
        </div>
        
        <h2>Metadata Endpoints</h2>
        <ul>
            <li><a href="/.well-known/oauth-authorization-server">Authorization Server Metadata</a></li>
            <li><a href="/.well-known/oauth-protected-resource">Protected Resource Metadata</a></li>
            <li><a href="/health">Health Check</a></li>
        </ul>
        
        <h2>User Management</h2>
        <p>Currently authorized users: {len(AUTHORIZED_USERS) if AUTHORIZED_USERS else "All users allowed"}</p>
    </body>
    </html>
    """
    return Response(content=html, media_type="text/html")

# Create Starlette app
app = Starlette(
    routes=[
        Route("/", home),
        Route("/health", health),
        Route("/.well-known/oauth-authorization-server", oauth_metadata),
        Route("/.well-known/oauth-protected-resource", protected_resource_metadata),
        Route("/oauth/authorize", authorize),
        Route("/oauth/token", token_endpoint, methods=["POST"]),
        Route("/admin/revoke", revoke_token, methods=["POST"]),
        Route("/mcp", endpoint=authenticated_sse, methods=["GET", "POST", "HEAD"]),
    ],
    middleware=[
        Middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_methods=["*"],
            allow_headers=["*"]
        )
    ]
)

if __name__ == "__main__":
    # Setup credentials if needed
    if os.environ.get("RAILWAY_ENVIRONMENT") or os.environ.get("GOOGLE_ADS_CREDENTIALS_BASE64"):
        setup_credentials_file()
    
    # Get port from environment
    port = int(os.environ.get("PORT", 8000))
    
    logger.info(f"Starting OAuth-Protected Google Ads MCP Server on port {port}")
    logger.info(f"Server URL: {SERVER_URL}")
    logger.info(f"Authorized users: {AUTHORIZED_USERS if AUTHORIZED_USERS else 'All users'}")
    
    # Start server
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=port)
