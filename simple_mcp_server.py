#!/usr/bin/env python3
"""
Simple Google Ads MCP Server with API Key Authentication
Perfect for public deployment where each user runs their own instance
"""

import os
import sys
import logging
from pathlib import Path
from datetime import datetime, timezone

from starlette.applications import Starlette
from starlette.responses import JSONResponse, HTMLResponse, Response
from starlette.routing import Route
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
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

# API Keys Configuration
# Option 1: Single API key (simplest)
SINGLE_API_KEY = os.environ.get('MCP_API_KEY', '')

# Option 2: Multiple API keys (comma-separated)
MULTIPLE_API_KEYS = os.environ.get('MCP_API_KEYS', '')

# Parse API keys
if MULTIPLE_API_KEYS:
    # Multiple keys: "key1,key2,key3"
    API_KEYS = set(k.strip() for k in MULTIPLE_API_KEYS.split(',') if k.strip())
elif SINGLE_API_KEY:
    # Single key for backwards compatibility
    API_KEYS = {SINGLE_API_KEY}
else:
    API_KEYS = set()

# Create SSE transport
sse = SseServerTransport("/sse")

async def health(request: Request):
    """Health check endpoint"""
    return JSONResponse({
        "status": "healthy",
        "service": "google-ads-mcp",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

async def handle_sse(request: Request):
    """Handle SSE connections with API key authentication"""
    
    # Handle HEAD requests (Claude uses these to check the endpoint)
    if request.method == "HEAD":
        # Just return 200 OK for HEAD requests with valid API key
        provided_key = request.query_params.get('api_key', '')
        if provided_key and provided_key in API_KEYS:
            return Response(status_code=200)
        else:
            return Response(status_code=401)
    
    # For POST requests with session_id, we need to handle them specially
    if request.method == "POST" and request.query_params.get('session_id'):
        # This is a message for an existing SSE session
        # The session was already authenticated during the initial GET request
        await sse.handle_post_message(
            request.scope,
            request.receive,
            request._send
        )
        return  # Important: return after handling POST
    
    # For initial connections (GET requests or POST without session_id), require API key
    if not API_KEYS:
        logger.error("No API keys configured - server is not properly secured!")
        return JSONResponse(
            {"error": "Server configuration error: No API keys set"},
            status_code=500
        )
    
    # Check for API key in query params or header
    provided_key = request.query_params.get('api_key', '')
    if not provided_key:
        auth_header = request.headers.get('authorization', '')
        if auth_header.startswith('Bearer '):
            provided_key = auth_header[7:]
    
    # Verify API key
    if not provided_key:
        logger.warning(f"Missing API key from {request.client.host}")
        return JSONResponse(
            {"error": "API key required. Add ?api_key=YOUR_KEY to the URL"},
            status_code=401
        )
    
    if provided_key not in API_KEYS:
        logger.warning(f"Invalid API key attempt from {request.client.host}")
        return JSONResponse(
            {"error": "Invalid API key"},
            status_code=401
        )
    
    # Valid API key - establish SSE connection
    logger.info(f"SSE connection established from {request.client.host}")
    
    # Handle GET requests (normal SSE connection)
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
    """Handle POST messages with authentication"""
    # API key is REQUIRED
    if not API_KEYS:
        return JSONResponse(
            {"error": "Server configuration error: No API keys set"},
            status_code=500
        )
    
    provided_key = request.query_params.get('api_key', '')
    if not provided_key:
        auth_header = request.headers.get('authorization', '')
        if auth_header.startswith('Bearer '):
            provided_key = auth_header[7:]
    
    if not provided_key or provided_key not in API_KEYS:
        return JSONResponse({"error": "Invalid API key"}, status_code=401)
    
    await sse.handle_post_message(
        request.scope,
        request.receive,
        request._send
    )

async def instructions(request: Request):
    """Simple instructions page"""
    if not API_KEYS:
        # Show warning if no API keys are configured
        html = """
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
                <strong>No API keys configured!</strong><br><br>
                This server requires API keys to be set. Use one of these environment variables:<br><br>
                <code>MCP_API_KEY</code> - For a single API key<br>
                <code>MCP_API_KEYS</code> - For multiple API keys (comma-separated)<br><br>
                Please configure the server properly before use.
            </div>
        </body>
        </html>
        """
        return HTMLResponse(html)
    
    # Normal instructions when API key is set
    example_url = f"{SERVER_URL}/sse?api_key=YOUR_API_KEY"
    
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
        <h1>🚀 Google Ads MCP Server</h1>
        
        <div class="status">
            <strong>Status:</strong> ✅ Running<br>
            <strong>API Key Required:</strong> Yes<br>
            <strong>Endpoint:</strong> <code>{SERVER_URL}</code>
        </div>
        
        <h2>Claude Desktop Setup</h2>
        <ol>
            <li>Open Claude Desktop</li>
            <li>Go to Settings → Developer → Edit Config</li>
            <li>Click "Add MCP Server"</li>
            <li>Enter:
                <ul>
                    <li><strong>Name:</strong> Google Ads MCP</li>
                    <li><strong>URL:</strong> (see below)</li>
                </ul>
            </li>
            <li>Save and restart Claude Desktop</li>
        </ol>
        
        <h3>Your MCP URL:</h3>
        <div class="url-box">{example_url}</div>
        
        <h2>Available Tools</h2>
        <ul>
            <li>List Google Ads accounts</li>
            <li>Get campaign performance</li>
            <li>Analyze ad performance</li>
            <li>Run custom GAQL queries</li>
            <li>Manage image assets</li>
        </ul>
        
        <hr>
        <p><a href="/health">Health Check</a> | <a href="https://github.com/yourusername/mcp-google-ads">GitHub</a></p>
    </body>
    </html>
    """
    return HTMLResponse(html)

async def oauth_not_required(request: Request):
    """Tell Claude that OAuth is not required for this server"""
    return JSONResponse({
        "error": "OAuth not required. Use API key authentication.",
        "authentication_method": "api_key"
    }, status_code=404)

# Create Starlette app
app = Starlette(
    routes=[
        Route("/", instructions),
        Route("/health", health),
        Route("/sse", handle_sse, methods=["GET", "POST", "HEAD"]),  # Allow HEAD requests too
        Route("/messages", handle_messages, methods=["POST"]),
        Route("/.well-known/oauth-protected-resource/{path:path}", oauth_not_required),
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
    
    logger.info(f"Starting Google Ads MCP Server on port {port}")
    logger.info(f"Server URL: {SERVER_URL}")
    
    if not API_KEYS:
        logger.error("WARNING: No API keys configured!")
        logger.error("Set MCP_API_KEY (single key) or MCP_API_KEYS (comma-separated) environment variable")
        logger.error("Server will reject all requests until API keys are configured")
    else:
        logger.info(f"API Key Protection: Enabled ({len(API_KEYS)} keys loaded)")
    
    # Start server
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=port)
