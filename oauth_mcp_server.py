"""
Google Ads MCP Server for Railway - GitHub Deploy Version
No local setup required!
"""

import os
import json
import base64
import secrets
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import tempfile
import atexit

from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.responses import JSONResponse, RedirectResponse
import uvicorn
import jwt

# Google Ads related imports
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from google.oauth2 import service_account
from google.auth.transport.requests import Request as GoogleRequest
from google.auth.exceptions import RefreshError
import requests

# MCP
from mcp.server.fastmcp import FastMCP

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Google Ads MCP Server")

# Initialize MCP
mcp = FastMCP(
    "google-ads-server",
    dependencies=["google-auth-oauthlib", "google-auth", "requests"]
)

# Configuration
CLAUDE_CLIENT_ID = os.environ.get("CLAUDE_CLIENT_ID")
CLAUDE_CLIENT_SECRET = os.environ.get("CLAUDE_CLIENT_SECRET")
JWT_SECRET = os.environ.get("JWT_SECRET", "default-secret-please-change")
API_VERSION = "v18"

# Google Ads Configuration
GOOGLE_ADS_CREDENTIALS_BASE64 = os.environ.get("GOOGLE_ADS_CREDENTIALS_BASE64")
GOOGLE_ADS_DEVELOPER_TOKEN = os.environ.get("GOOGLE_ADS_DEVELOPER_TOKEN")
GOOGLE_ADS_LOGIN_CUSTOMER_ID = os.environ.get("GOOGLE_ADS_LOGIN_CUSTOMER_ID", "")
GOOGLE_ADS_AUTH_TYPE = os.environ.get("GOOGLE_ADS_AUTH_TYPE", "oauth")

# Decode credentials if base64 provided
TEMP_CREDENTIALS_FILE = None
GOOGLE_ADS_CREDENTIALS_PATH = None

if GOOGLE_ADS_CREDENTIALS_BASE64:
    try:
        credentials_json = base64.b64decode(GOOGLE_ADS_CREDENTIALS_BASE64).decode('utf-8')
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp_file:
            tmp_file.write(credentials_json)
            TEMP_CREDENTIALS_FILE = tmp_file.name
            GOOGLE_ADS_CREDENTIALS_PATH = tmp_file.name
        logger.info("Decoded credentials from base64")
    except Exception as e:
        logger.error(f"Error decoding credentials: {e}")

# Cleanup temp file on exit
def cleanup_temp_file():
    if TEMP_CREDENTIALS_FILE and os.path.exists(TEMP_CREDENTIALS_FILE):
        os.remove(TEMP_CREDENTIALS_FILE)

atexit.register(cleanup_temp_file)

# Simple storage
auth_codes = {}
tokens = {}

# Google Ads helper functions
def format_customer_id(customer_id: str) -> str:
    """Format customer ID to 10 digits without dashes."""
    customer_id = str(customer_id)
    customer_id = customer_id.replace('\"', '').replace('"', '')
    customer_id = ''.join(char for char in customer_id if char.isdigit())
    return customer_id.zfill(10)

def get_google_credentials():
    """Get Google Ads credentials."""
    if not GOOGLE_ADS_CREDENTIALS_PATH:
        raise ValueError("No credentials configured")
    
    if GOOGLE_ADS_AUTH_TYPE == "service_account":
        return service_account.Credentials.from_service_account_file(
            GOOGLE_ADS_CREDENTIALS_PATH,
            scopes=['https://www.googleapis.com/auth/adwords']
        )
    else:
        # For OAuth, we'll use the stored token
        # In production, you'd implement proper OAuth flow
        creds = Credentials.from_authorized_user_file(
            GOOGLE_ADS_CREDENTIALS_PATH,
            ['https://www.googleapis.com/auth/adwords']
        )
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(GoogleRequest())
        return creds

def get_google_headers(creds):
    """Get headers for Google Ads API."""
    if not creds.valid:
        if hasattr(creds, 'refresh'):
            creds.refresh(GoogleRequest())
    
    return {
        'Authorization': f'Bearer {creds.token}',
        'developer-token': GOOGLE_ADS_DEVELOPER_TOKEN,
        'content-type': 'application/json',
        'login-customer-id': format_customer_id(GOOGLE_ADS_LOGIN_CUSTOMER_ID) if GOOGLE_ADS_LOGIN_CUSTOMER_ID else None
    }

# ===== OAuth Endpoints =====

@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata():
    """OAuth metadata endpoint."""
    base_url = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost")
    if not base_url.startswith("http"):
        base_url = f"https://{base_url}"
    
    return {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/authorize",
        "token_endpoint": f"{base_url}/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"]
    }

@app.get("/authorize")
async def authorize(
    client_id: str,
    redirect_uri: str,
    response_type: str,
    state: str,
    code_challenge: str,
    code_challenge_method: str = "S256"
):
    """OAuth authorization endpoint."""
    if client_id != CLAUDE_CLIENT_ID:
        raise HTTPException(status_code=400, detail="Invalid client")
    
    code = secrets.token_urlsafe(32)
    auth_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "expires": datetime.utcnow() + timedelta(minutes=5)
    }
    
    return RedirectResponse(f"{redirect_uri}?code={code}&state={state}")

@app.post("/token")
async def token(request: Request):
    """Token endpoint."""
    form = await request.form()
    
    client_id = form.get("client_id")
    client_secret = form.get("client_secret")
    
    if client_id != CLAUDE_CLIENT_ID or client_secret != CLAUDE_CLIENT_SECRET:
        raise HTTPException(status_code=401, detail="Invalid client")
    
    if form.get("grant_type") == "authorization_code":
        code = form.get("code")
        
        if code not in auth_codes:
            raise HTTPException(status_code=400, detail="Invalid code")
        
        auth_codes.pop(code)
        
        access_token = jwt.encode(
            {"sub": "user", "exp": datetime.utcnow() + timedelta(hours=24)},
            JWT_SECRET,
            algorithm="HS256"
        )
        
        tokens[access_token] = {"client_id": client_id}
        
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 86400
        }
    
    raise HTTPException(status_code=400, detail="Unsupported grant type")

# ===== MCP Endpoints =====

def verify_token(auth_header: Optional[str]) -> bool:
    """Verify authorization token."""
    if not auth_header or not auth_header.startswith("Bearer "):
        return False
    
    token = auth_header.split(" ")[1]
    try:
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return token in tokens
    except:
        return False

@app.post("/mcp/v1/messages")
async def mcp_endpoint(request: Request, authorization: Optional[str] = Header(None)):
    """MCP protocol endpoint."""
    if not verify_token(authorization):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    message = await request.json()
    method = message.get("method")
    params = message.get("params", {})
    
    if method == "initialize":
        return {
            "protocolVersion": "2024-10-07",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "google-ads-server", "version": "1.0.0"}
        }
    
    elif method == "tools/list":
        return {
            "tools": [
                {
                    "name": "list_accounts",
                    "description": "List all accessible Google Ads accounts",
                    "inputSchema": {"type": "object", "properties": {}}
                },
                {
                    "name": "get_campaign_performance",
                    "description": "Get campaign performance metrics",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "customer_id": {"type": "string"},
                            "days": {"type": "integer", "default": 30}
                        },
                        "required": ["customer_id"]
                    }
                }
            ]
        }
    
    elif method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        
        try:
            if tool_name == "list_accounts":
                result = await list_accounts()
            elif tool_name == "get_campaign_performance":
                result = await get_campaign_performance(
                    arguments.get("customer_id"),
                    arguments.get("days", 30)
                )
            else:
                raise HTTPException(status_code=404, detail=f"Unknown tool: {tool_name}")
            
            return {"content": [{"type": "text", "text": str(result)}]}
        except Exception as e:
            logger.error(f"Tool error: {str(e)}")
            return {"content": [{"type": "text", "text": f"Error: {str(e)}"}], "isError": True}
    
    else:
        raise HTTPException(status_code=400, detail=f"Unknown method: {method}")

# ===== Google Ads Tools =====

async def list_accounts() -> str:
    """List Google Ads accounts."""
    try:
        creds = get_google_credentials()
        headers = get_google_headers(creds)
        
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers:listAccessibleCustomers"
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            return f"Error: {response.text}"
        
        customers = response.json()
        if not customers.get('resourceNames'):
            return "No accounts found"
        
        result = ["Accessible Google Ads Accounts:"]
        for resource in customers['resourceNames']:
            customer_id = resource.split('/')[-1]
            result.append(f"Account ID: {format_customer_id(customer_id)}")
        
        return "\n".join(result)
    except Exception as e:
        return f"Error listing accounts: {str(e)}"

async def get_campaign_performance(customer_id: str, days: int = 30) -> str:
    """Get campaign performance."""
    try:
        creds = get_google_credentials()
        headers = get_google_headers(creds)
        
        formatted_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_id}/googleAds:search"
        
        query = f"""
            SELECT campaign.id, campaign.name, campaign.status,
                   metrics.impressions, metrics.clicks, metrics.cost_micros
            FROM campaign
            WHERE segments.date DURING LAST_{days}_DAYS
            ORDER BY metrics.cost_micros DESC
            LIMIT 10
        """
        
        response = requests.post(url, headers=headers, json={"query": query})
        
        if response.status_code != 200:
            return f"Error: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No campaign data found"
        
        output = [f"Campaign Performance (Last {days} days):"]
        output.append("-" * 50)
        
        for result in results['results']:
            campaign = result.get('campaign', {})
            metrics = result.get('metrics', {})
            
            output.append(f"Campaign: {campaign.get('name', 'N/A')}")
            output.append(f"Status: {campaign.get('status', 'N/A')}")
            output.append(f"Impressions: {metrics.get('impressions', 0)}")
            output.append(f"Clicks: {metrics.get('clicks', 0)}")
            output.append(f"Cost: ${metrics.get('costMicros', 0) / 1000000:.2f}")
            output.append("-" * 50)
        
        return "\n".join(output)
    except Exception as e:
        return f"Error getting campaign data: {str(e)}"

# ===== Utility Endpoints =====

@app.get("/")
async def root():
    """Root endpoint with info."""
    base_url = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost")
    if not base_url.startswith("http"):
        base_url = f"https://{base_url}"
    
    return {
        "name": "Google Ads MCP Server",
        "status": "running",
        "instructions": {
            "1": "Add this URL to Claude as a custom connector",
            "2": f"URL: {base_url}",
            "3": f"Client ID: {CLAUDE_CLIENT_ID or 'NOT_SET'}",
            "4": "Client Secret: Check your environment variables"
        }
    }

@app.get("/health")
async def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
