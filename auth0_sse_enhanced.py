#!/usr/bin/env python3
"""
Production-ready Auth0-protected SSE MCP Server
"""

import os
import sys
import logging
import asyncio
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime, timezone

from starlette.applications import Starlette
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Route
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
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
AUTH0_API_IDENTIFIER = os.environ.get('AUTH0_API_IDENTIFIER', '')
AUTH0_ALGORITHMS = ['RS256']

class AuthMiddleware:
    """Middleware to validate Auth0 JWT tokens"""
    
    def __init__(self, app):
        self.app = app
        self.jwks_client = PyJWKClient(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
        
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope["headers"])
            
            # Skip auth for health check
            if scope["path"] == "/health":
                await self.app(scope, receive, send)
                return
            
            # Extract authorization header
            auth_header = headers.get(b"authorization", b"").decode()
            
            if not auth_header.startswith("Bearer "):
                response = JSONResponse(
                    {"error": "Missing or invalid authorization header"},
                    status_code=401
                )
                await response(scope, receive, send)
                return
            
            token = auth_header[7:]  # Remove "Bearer " prefix
            
            try:
                # Verify JWT
                signing_key = self.jwks_client.get_signing_key_from_jwt(token)
                payload = jwt.decode(
                    token,
                    signing_key.key,
                    algorithms=AUTH0_ALGORITHMS,
                    audience=AUTH0_API_IDENTIFIER,
                    issuer=f'https://{AUTH0_DOMAIN}/'
                )
                
                # Add user info to scope
                scope["user"] = payload
                
                # Log authenticated access
                logger.info(f"Authenticated access from user: {payload.get('sub')}")
                
            except jwt.ExpiredSignatureError:
                response = JSONResponse(
                    {"error": "Token expired"},
                    status_code=401
                )
                await response(scope, receive, send)
                return
            except Exception as e:
                logger.error(f"Auth error: {str(e)}")
                response = JSONResponse(
                    {"error": "Invalid token"},
                    status_code=401
                )
                await response(scope, receive, send)
                return
        
        await self.app(scope, receive, send)

# Create SSE transport
sse = SseServerTransport("/sse")

async def health(request):
    """Health check endpoint"""
    return JSONResponse({
        "status": "healthy",
        "service": "auth0-mcp-server",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

async def handle_sse(request):
    """Handle SSE connections with Auth0 protection"""
    # User info is already validated by middleware
    user = request.scope.get("user", {})
    logger.info(f"SSE connection established for user: {user.get('sub')}")
    
    # Create a modified MCP server with user context
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

async def handle_messages(request):
    """Handle POST messages with Auth0 protection"""
    user = request.scope.get("user", {})
    await sse.handle_post_message(
        request.scope, 
        request.receive, 
        request._send
    )

# Create Starlette app with middleware
middleware = [
    Middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]),
    Middleware(AuthMiddleware) if AUTH0_DOMAIN else None
]

# Remove None middleware
middleware = [m for m in middleware if m is not None]

app = Starlette(
    routes=[
        Route("/health", health),
        Route("/sse", handle_sse),
        Route("/messages", handle_messages, methods=["POST"]),
    ],
    middleware=middleware
)

if __name__ == "__main__":
    # Setup credentials if needed
    if os.environ.get("RAILWAY_ENVIRONMENT") or os.environ.get("GOOGLE_ADS_CREDENTIALS_BASE64"):
        setup_credentials_file()
    
    # Get port from Railway
    port = int(os.environ.get("PORT", 8000))
    
    logger.info(f"Starting Auth0-protected SSE MCP server on port {port}")
    
    # Run with uvicorn
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=port)
