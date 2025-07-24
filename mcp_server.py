#!/usr/bin/env python3
"""
Production-Ready Google Ads MCP Server with API Key Authentication
Secure, scalable, and easy to manage
"""

import os
import sys
import logging
import json
import hashlib
import asyncio
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
import hmac

from starlette.applications import Starlette
from starlette.responses import JSONResponse, HTMLResponse, PlainTextResponse
from starlette.routing import Route
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.exceptions import HTTPException
from mcp.server.sse import SseServerTransport

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from google_ads_server import mcp, setup_credentials_file

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Server Configuration
RAILWAY_URL = os.environ.get('RAILWAY_STATIC_URL', '')
if RAILWAY_URL and not RAILWAY_URL.startswith('http'):
    SERVER_URL = f"https://{RAILWAY_URL}"
else:
    SERVER_URL = RAILWAY_URL or 'http://localhost:8000'

# Security Configuration
ADMIN_SECRET = os.environ.get('MCP_ADMIN_SECRET', '')
RATE_LIMIT_REQUESTS = int(os.environ.get('MCP_RATE_LIMIT_REQUESTS', '100'))
RATE_LIMIT_WINDOW = int(os.environ.get('MCP_RATE_LIMIT_WINDOW', '3600'))  # 1 hour

# API Key Management
class APIKeyManager:
    """Manages API keys and user authentication"""
    
    def __init__(self):
        self.keys = self._load_keys_from_env()
        self.rate_limits = {}  # Track request counts per key
        logger.info(f"Loaded {len(self.keys)} API keys")
    
    def _load_keys_from_env(self) -> Dict[str, Dict[str, Any]]:
        """Load API keys from environment variables"""
        keys = {}
        
        # Load individual user keys
        for key, value in os.environ.items():
            if key.startswith("MCP_USER_"):
                username = key.replace("MCP_USER_", "").lower()
                # Parse JSON value for additional metadata
                try:
                    if value.startswith('{'):
                        user_data = json.loads(value)
                        api_key = user_data.get('key')
                        keys[api_key] = {
                            "username": username,
                            "email": user_data.get('email', ''),
                            "role": user_data.get('role', 'user'),
                            "created": user_data.get('created', datetime.now(timezone.utc).isoformat()),
                            "expires": user_data.get('expires', None)
                        }
                    else:
                        # Simple key format for backwards compatibility
                        keys[value] = {
                            "username": username,
                            "email": f"{username}@company.com",
                            "role": "user",
                            "created": datetime.now(timezone.utc).isoformat(),
                            "expires": None
                        }
                except json.JSONDecodeError:
                    logger.error(f"Invalid JSON for user {username}")
                    continue
        
        # Load bulk keys from a single environment variable
        bulk_keys = os.environ.get('MCP_API_KEYS_JSON', '')
        if bulk_keys:
            try:
                bulk_data = json.loads(bulk_keys)
                for api_key, user_info in bulk_data.items():
                    keys[api_key] = user_info
            except json.JSONDecodeError:
                logger.error("Invalid JSON in MCP_API_KEYS_JSON")
        
        return keys
    
    def verify_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Verify an API key and return user info"""
        if not api_key:
            return None
        
        user_info = self.keys.get(api_key)
        if not user_info:
            return None
        
        # Check expiration
        if user_info.get('expires'):
            expires_at = datetime.fromisoformat(user_info['expires'])
            if datetime.now(timezone.utc) > expires_at:
                logger.warning(f"Expired API key for user: {user_info['username']}")
                return None
        
        return user_info
    
    def check_rate_limit(self, api_key: str) -> bool:
        """Check if API key has exceeded rate limit"""
        now = datetime.now(timezone.utc)
        window_start = now.timestamp() - RATE_LIMIT_WINDOW
        
        if api_key not in self.rate_limits:
            self.rate_limits[api_key] = []
        
        # Clean old requests
        self.rate_limits[api_key] = [
            ts for ts in self.rate_limits[api_key] 
            if ts > window_start
        ]
        
        # Check limit
        if len(self.rate_limits[api_key]) >= RATE_LIMIT_REQUESTS:
            return False
        
        # Add current request
        self.rate_limits[api_key].append(now.timestamp())
        return True
    
    def get_all_users(self) -> List[Dict[str, Any]]:
        """Get all users (for admin panel)"""
        users = []
        for api_key, user_info in self.keys.items():
            users.append({
                "username": user_info['username'],
                "email": user_info.get('email', ''),
                "role": user_info.get('role', 'user'),
                "created": user_info.get('created', ''),
                "expires": user_info.get('expires', ''),
                "api_key_preview": f"{api_key[:12]}..." if len(api_key) > 12 else api_key
            })
        return sorted(users, key=lambda x: x['username'])

# Initialize API key manager
api_key_manager = APIKeyManager()

# Create SSE transport
sse = SseServerTransport("/sse")

# Middleware for request logging
async def log_request(request: Request, call_next):
    """Log all requests for audit trail"""
    start_time = datetime.now(timezone.utc)
    
    # Get API key from request
    api_key = request.query_params.get('api_key', '')
    if not api_key:
        auth_header = request.headers.get('authorization', '')
        if auth_header.startswith('Bearer '):
            api_key = auth_header[7:]
    
    # Log request
    logger.info(f"Request: {request.method} {request.url.path} from {request.client.host}")
    
    response = await call_next(request)
    
    # Log response
    duration = (datetime.now(timezone.utc) - start_time).total_seconds()
    logger.info(f"Response: {response.status_code} in {duration:.2f}s")
    
    return response

# Route handlers
async def health(request: Request):
    """Health check endpoint"""
    return JSONResponse({
        "status": "healthy",
        "service": "google-ads-mcp",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0",
        "users_loaded": len(api_key_manager.keys)
    })

async def handle_sse(request: Request):
    """Handle SSE connections with API key authentication"""
    # Extract API key
    api_key = request.query_params.get('api_key', '').strip()
    if not api_key:
        auth_header = request.headers.get('authorization', '')
        if auth_header.startswith('Bearer '):
            api_key = auth_header[7:].strip()
    
    # Verify API key
    if not api_key:
        logger.warning(f"Missing API key from {request.client.host}")
        return JSONResponse(
            {"error": "Missing API key. Add ?api_key=YOUR_KEY to the URL"},
            status_code=401,
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    user_info = api_key_manager.verify_key(api_key)
    if not user_info:
        logger.warning(f"Invalid API key attempt from {request.client.host}: {api_key[:10]}...")
        return JSONResponse(
            {"error": "Invalid or expired API key"},
            status_code=401,
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    # Check rate limit
    if not api_key_manager.check_rate_limit(api_key):
        logger.warning(f"Rate limit exceeded for user: {user_info['username']}")
        return JSONResponse(
            {"error": "Rate limit exceeded. Please try again later."},
            status_code=429,
            headers={"Retry-After": str(RATE_LIMIT_WINDOW)}
        )
    
    # Log successful authentication
    logger.info(f"SSE connection established for user: {user_info['username']} ({user_info.get('email', 'N/A')})")
    
    # Add user context to MCP
    if hasattr(mcp, '_user_context'):
        mcp._user_context = {
            "username": user_info['username'],
            "email": user_info.get('email', ''),
            "role": user_info.get('role', 'user')
        }
    
    # Establish SSE connection
    try:
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
    except Exception as e:
        logger.error(f"SSE error for user {user_info['username']}: {str(e)}")
        raise

async def handle_messages(request: Request):
    """Handle POST messages with authentication"""
    # Extract and verify API key
    api_key = request.query_params.get('api_key', '').strip()
    if not api_key:
        auth_header = request.headers.get('authorization', '')
        if auth_header.startswith('Bearer '):
            api_key = auth_header[7:].strip()
    
    if not api_key or not api_key_manager.verify_key(api_key):
        return JSONResponse(
            {"error": "Authentication required"},
            status_code=401
        )
    
    # Check rate limit
    if not api_key_manager.check_rate_limit(api_key):
        return JSONResponse(
            {"error": "Rate limit exceeded"},
            status_code=429
        )
    
    # Handle the message
    await sse.handle_post_message(
        request.scope,
        request.receive,
        request._send
    )

async def instructions(request: Request):
    """Public instructions page"""
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Google Ads MCP Server</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            * {{ box-sizing: border-box; }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 900px;
                margin: 0 auto;
                padding: 20px;
                background: #f5f5f5;
            }}
            .container {{
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }}
            h1 {{
                color: #2c3e50;
                border-bottom: 3px solid #3498db;
                padding-bottom: 10px;
                margin-bottom: 30px;
            }}
            h2 {{
                color: #34495e;
                margin-top: 30px;
            }}
            .status {{
                background: #d4edda;
                border: 1px solid #c3e6cb;
                border-radius: 5px;
                padding: 15px;
                margin-bottom: 30px;
            }}
            .warning {{
                background: #fff3cd;
                border: 1px solid #ffeeba;
                border-radius: 5px;
                padding: 15px;
                margin: 20px 0;
            }}
            code {{
                background: #f8f9fa;
                padding: 2px 6px;
                border-radius: 3px;
                font-family: 'Consolas', 'Monaco', monospace;
            }}
            .url-box {{
                background: #f8f9fa;
                border: 2px solid #dee2e6;
                border-radius: 5px;
                padding: 15px;
                margin: 20px 0;
                font-family: monospace;
                word-break: break-all;
            }}
            ol, ul {{
                line-height: 2;
            }}
            .footer {{
                margin-top: 50px;
                padding-top: 20px;
                border-top: 1px solid #dee2e6;
                text-align: center;
                color: #6c757d;
                font-size: 0.9em;
            }}
            a {{
                color: #3498db;
                text-decoration: none;
            }}
            a:hover {{
                text-decoration: underline;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🚀 Google Ads MCP Server</h1>
            
            <div class="status">
                <strong>✅ Server Status:</strong> Online<br>
                <strong>🔐 Authentication:</strong> API Key Required<br>
                <strong>📍 Endpoint:</strong> {SERVER_URL}
            </div>
            
            <h2>Getting Started</h2>
            
            <ol>
                <li><strong>Get your API key</strong> from your administrator</li>
                <li><strong>Open Claude Desktop</strong></li>
                <li>Navigate to <strong>Settings → Developer → Edit Config</strong></li>
                <li>Click <strong>"Add MCP Server"</strong></li>
                <li>Configure with:
                    <ul>
                        <li><strong>Name:</strong> <code>Google Ads MCP</code></li>
                        <li><strong>URL:</strong> Your personal MCP URL (see below)</li>
                    </ul>
                </li>
                <li>Save and restart Claude Desktop</li>
            </ol>
            
            <h2>Your MCP URL Format</h2>
            <div class="url-box">
                {SERVER_URL}/sse?api_key=YOUR_API_KEY_HERE
            </div>
            <p>Replace <code>YOUR_API_KEY_HERE</code> with your actual API key.</p>
            
            <h2>Available Tools</h2>
            <p>Once connected, you can ask Claude to:</p>
            <ul>
                <li>📊 List all Google Ads accounts</li>
                <li>📈 Analyze campaign performance</li>
                <li>💰 Get cost and conversion metrics</li>
                <li>🎯 Review ad performance</li>
                <li>🔍 Run custom GAQL queries</li>
                <li>🖼️ Manage image assets</li>
                <li>📝 Export ad creatives</li>
            </ul>
            
            <div class="warning">
                <strong>⚠️ Security Notice:</strong> Keep your API key confidential. Never share it publicly or commit it to version control.
            </div>
            
            <h2>Troubleshooting</h2>
            <ul>
                <li><strong>Authentication Error:</strong> Verify your API key is correct and not expired</li>
                <li><strong>Connection Failed:</strong> Check that Claude Desktop is properly restarted</li>
                <li><strong>Rate Limit:</strong> You're limited to {RATE_LIMIT_REQUESTS} requests per hour</li>
                <li><strong>No Tools Available:</strong> Ensure the MCP server shows as "Connected"</li>
            </ul>
            
            <h2>Need Help?</h2>
            <p>Contact your administrator if you:</p>
            <ul>
                <li>Need a new API key</li>
                <li>Forgot your API key</li>
                <li>Experience persistent connection issues</li>
            </ul>
            
            <div class="footer">
                <p>Google Ads MCP Server v1.0.0 | <a href="/health">API Status</a></p>
            </div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(html)

async def admin_panel(request: Request):
    """Admin panel for user management"""
    # Verify admin authentication
    auth_header = request.headers.get('authorization', '')
    if not auth_header.startswith('Bearer ') or auth_header[7:] != ADMIN_SECRET:
        return PlainTextResponse(
            "Unauthorized",
            status_code=401,
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    users = api_key_manager.get_all_users()
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>MCP Admin Panel</title>
        <meta charset="utf-8">
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                margin: 0;
                padding: 20px;
                background: #f5f5f5;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }}
            h1 {{
                margin-top: 0;
                color: #2c3e50;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
            }}
            th, td {{
                text-align: left;
                padding: 12px;
                border-bottom: 1px solid #ddd;
            }}
            th {{
                background: #34495e;
                color: white;
                font-weight: 600;
            }}
            tr:hover {{
                background: #f8f9fa;
            }}
            .stats {{
                display: flex;
                gap: 20px;
                margin-bottom: 30px;
            }}
            .stat-box {{
                flex: 1;
                background: #ecf0f1;
                padding: 20px;
                border-radius: 5px;
                text-align: center;
            }}
            .stat-number {{
                font-size: 2em;
                font-weight: bold;
                color: #3498db;
            }}
            .role {{
                display: inline-block;
                padding: 3px 8px;
                border-radius: 3px;
                font-size: 0.85em;
                background: #3498db;
                color: white;
            }}
            .role.admin {{
                background: #e74c3c;
            }}
            .expires {{
                color: #e74c3c;
                font-weight: 600;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 MCP Admin Panel</h1>
            
            <div class="stats">
                <div class="stat-box">
                    <div class="stat-number">{len(users)}</div>
                    <div>Total Users</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{len([u for u in users if u['role'] == 'admin'])}</div>
                    <div>Admins</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{RATE_LIMIT_REQUESTS}/hr</div>
                    <div>Rate Limit</div>
                </div>
            </div>
            
            <h2>Active Users</h2>
            <table>
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>API Key</th>
                        <th>Created</th>
                        <th>Expires</th>
                    </tr>
                </thead>
                <tbody>
    """
    
    for user in users:
        role_class = "admin" if user['role'] == 'admin' else ""
        expires = user['expires'] if user['expires'] else "Never"
        expires_class = "expires" if user['expires'] else ""
        
        html += f"""
                    <tr>
                        <td><strong>{user['username']}</strong></td>
                        <td>{user['email']}</td>
                        <td><span class="role {role_class}">{user['role']}</span></td>
                        <td><code>{user['api_key_preview']}</code></td>
                        <td>{user['created'][:10] if user['created'] else 'N/A'}</td>
                        <td class="{expires_class}">{expires}</td>
                    </tr>
        """
    
    html += """
                </tbody>
            </table>
            
            <div style="margin-top: 40px; padding: 20px; background: #f8f9fa; border-radius: 5px;">
                <h3>Managing Users</h3>
                <p>To add or remove users, update the Railway environment variables:</p>
                <ul>
                    <li><strong>Simple format:</strong> <code>MCP_USER_JOHN=sk_john_abc123...</code></li>
                    <li><strong>JSON format:</strong> <code>MCP_USER_JOHN={"key":"sk_john_abc123","email":"john@company.com","role":"user"}</code></li>
                    <li><strong>Bulk format:</strong> Use <code>MCP_API_KEYS_JSON</code> with a JSON object</li>
                </ul>
            </div>
        </div>
    </body>
    </html>
    """
    
    return HTMLResponse(html)

# Create Starlette app with middleware
app = Starlette(
    routes=[
        Route("/", instructions),
        Route("/health", health),
        Route("/sse", handle_sse),
        Route("/messages", handle_messages, methods=["POST"]),
        Route("/admin", admin_panel),
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
            TrustedHostMiddleware,
            allowed_hosts=["*"]  # Configure this for production
        ),
    ],
    on_startup=[lambda: logger.info("Server starting up...")],
    on_shutdown=[lambda: logger.info("Server shutting down...")]
)

# Add request logging middleware
app.add_middleware(log_request)

if __name__ == "__main__":
    # Setup credentials if needed
    if os.environ.get("RAILWAY_ENVIRONMENT") or os.environ.get("GOOGLE_ADS_CREDENTIALS_BASE64"):
        setup_credentials_file()
    
    # Get port from environment
    port = int(os.environ.get("PORT", 8000))
    
    # Log startup information
    logger.info("="*50)
    logger.info("Google Ads MCP Server Starting")
    logger.info(f"Server URL: {SERVER_URL}")
    logger.info(f"Port: {port}")
    logger.info(f"Users loaded: {len(api_key_manager.keys)}")
    logger.info(f"Admin panel: {'Enabled' if ADMIN_SECRET else 'Disabled'}")
    logger.info(f"Rate limit: {RATE_LIMIT_REQUESTS} requests per {RATE_LIMIT_WINDOW} seconds")
    logger.info("="*50)
    
    # Start server
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info",
        access_log=True
    )
