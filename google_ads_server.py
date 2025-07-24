from typing import Any, Dict, List, Optional, Union
from pydantic import Field
import os
import json
import requests
from datetime import datetime, timedelta

from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from google.oauth2 import service_account
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
import logging
import base64
import tempfile

# MCP
from mcp.server.fastmcp import FastMCP

def setup_credentials_file():
    """
    Setup credentials file from environment variable for Railway deployment.
    """
    # Check if we have base64 encoded credentials in environment
    creds_base64 = os.environ.get("GOOGLE_ADS_CREDENTIALS_BASE64")
    
    if creds_base64:
        try:
            # Decode the credentials
            creds_json = base64.b64decode(creds_base64).decode('utf-8')
            
            # Write to a temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                f.write(creds_json)
                temp_path = f.name
            
            # Update the environment variable to point to the temp file
            os.environ["GOOGLE_ADS_CREDENTIALS_PATH"] = temp_path
            
            # Use print instead of logger if logger not available yet
            print(f"Credentials file created at: {temp_path}")
            return temp_path
        except Exception as e:
            print(f"Failed to decode credentials: {str(e)}")
            raise
    
    return None

# Call this function before any other setup
if os.environ.get("RAILWAY_ENVIRONMENT") or os.environ.get("GOOGLE_ADS_CREDENTIALS_BASE64"):
    setup_credentials_file()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('google_ads_server')

# Create MCP instance without host/port for SSE transport
mcp = FastMCP(
    "google-ads-server",
    dependencies=[
        "google-auth-oauthlib",
        "google-auth",
        "requests",
        "python-dotenv"
    ]
)

# Constants and configuration
SCOPES = ['https://www.googleapis.com/auth/adwords']
API_VERSION = "v19"  # Google Ads API version

# Load environment variables
try:
    from dotenv import load_dotenv
    # Load from .env file if it exists
    load_dotenv()
    logger.info("Environment variables loaded from .env file")
except ImportError:
    logger.warning("python-dotenv not installed, skipping .env file loading")

# Get credentials from environment variables
GOOGLE_ADS_CREDENTIALS_PATH = os.environ.get("GOOGLE_ADS_CREDENTIALS_PATH")
GOOGLE_ADS_DEVELOPER_TOKEN = os.environ.get("GOOGLE_ADS_DEVELOPER_TOKEN")
GOOGLE_ADS_LOGIN_CUSTOMER_ID = os.environ.get("GOOGLE_ADS_LOGIN_CUSTOMER_ID", "")
GOOGLE_ADS_AUTH_TYPE = os.environ.get("GOOGLE_ADS_AUTH_TYPE", "oauth")  # oauth or service_account

def format_customer_id(customer_id: str) -> str:
    """Format customer ID to ensure it's 10 digits without dashes."""
    # Convert to string if passed as integer or another type
    customer_id = str(customer_id)
    
    # Remove any quotes surrounding the customer_id (both escaped and unescaped)
    customer_id = customer_id.replace('\"', '').replace('"', '')
    
    # Remove any non-digit characters (including dashes, braces, etc.)
    customer_id = ''.join(char for char in customer_id if char.isdigit())
    
    # Ensure it's 10 digits with leading zeros if needed
    return customer_id.zfill(10)

def get_credentials():
    """
    Get and refresh OAuth credentials or service account credentials based on the auth type.
    
    This function supports two authentication methods:
    1. OAuth 2.0 (User Authentication) - For individual users or desktop applications
    2. Service Account (Server-to-Server Authentication) - For automated systems

    Returns:
        Valid credentials object to use with Google Ads API
    """
    if not GOOGLE_ADS_CREDENTIALS_PATH:
        raise ValueError("GOOGLE_ADS_CREDENTIALS_PATH environment variable not set")
    
    auth_type = GOOGLE_ADS_AUTH_TYPE.lower()
    logger.info(f"Using authentication type: {auth_type}")
    
    # Service Account authentication
    if auth_type == "service_account":
        try:
            return get_service_account_credentials()
        except Exception as e:
            logger.error(f"Error with service account authentication: {str(e)}")
            raise
    
    # OAuth 2.0 authentication (default)
    return get_oauth_credentials()

def get_service_account_credentials():
    """Get credentials using a service account key file."""
    logger.info(f"Loading service account credentials from {GOOGLE_ADS_CREDENTIALS_PATH}")
    
    if not os.path.exists(GOOGLE_ADS_CREDENTIALS_PATH):
        raise FileNotFoundError(f"Service account key file not found at {GOOGLE_ADS_CREDENTIALS_PATH}")
    
    try:
        credentials = service_account.Credentials.from_service_account_file(
            GOOGLE_ADS_CREDENTIALS_PATH, 
            scopes=SCOPES
        )
        
        # Check if impersonation is required
        impersonation_email = os.environ.get("GOOGLE_ADS_IMPERSONATION_EMAIL")
        if impersonation_email:
            logger.info(f"Impersonating user: {impersonation_email}")
            credentials = credentials.with_subject(impersonation_email)
            
        return credentials
        
    except Exception as e:
        logger.error(f"Error loading service account credentials: {str(e)}")
        raise

def get_oauth_credentials():
    """Get and refresh OAuth user credentials."""
    creds = None
    client_config = None
    
    # Path to store the refreshed token
    token_path = GOOGLE_ADS_CREDENTIALS_PATH
    if os.path.exists(token_path) and not os.path.basename(token_path).endswith('.json'):
        # If it's not explicitly a .json file, append a default name
        token_dir = os.path.dirname(token_path)
        token_path = os.path.join(token_dir, 'google_ads_token.json')
    
    # Check if token file exists and load credentials
    if os.path.exists(token_path):
        try:
            logger.info(f"Loading OAuth credentials from {token_path}")
            with open(token_path, 'r') as f:
                creds_data = json.load(f)
                # Check if this is a client config or saved credentials
                if "installed" in creds_data or "web" in creds_data:
                    client_config = creds_data
                    logger.info("Found OAuth client configuration")
                else:
                    logger.info("Found existing OAuth token")
                    creds = Credentials.from_authorized_user_info(creds_data, SCOPES)
        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON in token file: {token_path}")
            creds = None
        except Exception as e:
            logger.warning(f"Error loading credentials: {str(e)}")
            creds = None
    
    # If credentials don't exist or are invalid, get new ones
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                logger.info("Refreshing expired token")
                creds.refresh(Request())
                logger.info("Token successfully refreshed")
            except RefreshError as e:
                logger.warning(f"Error refreshing token: {str(e)}, will try to get new token")
                creds = None
            except Exception as e:
                logger.error(f"Unexpected error refreshing token: {str(e)}")
                raise
        
        # If we need new credentials
        if not creds:
            # If no client_config is defined yet, create one from environment variables
            if not client_config:
                logger.info("Creating OAuth client config from environment variables")
                client_id = os.environ.get("GOOGLE_ADS_CLIENT_ID")
                client_secret = os.environ.get("GOOGLE_ADS_CLIENT_SECRET")
                
                if not client_id or not client_secret:
                    raise ValueError("GOOGLE_ADS_CLIENT_ID and GOOGLE_ADS_CLIENT_SECRET must be set if no client config file exists")
                
                client_config = {
                    "installed": {
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                        "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob", "http://localhost"]
                    }
                }
            
            # Run the OAuth flow
            logger.info("Starting OAuth authentication flow")
            flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
            creds = flow.run_local_server(port=0)
            logger.info("OAuth flow completed successfully")
        
        # Save the refreshed/new credentials
        try:
            logger.info(f"Saving credentials to {token_path}")
            # Ensure directory exists
            os.makedirs(os.path.dirname(token_path), exist_ok=True)
            with open(token_path, 'w') as f:
                f.write(creds.to_json())
        except Exception as e:
            logger.warning(f"Could not save credentials: {str(e)}")
    
    return creds

def get_headers(creds):
    """Get headers for Google Ads API requests."""
    if not GOOGLE_ADS_DEVELOPER_TOKEN:
        raise ValueError("GOOGLE_ADS_DEVELOPER_TOKEN environment variable not set")
    
    # Handle different credential types
    if isinstance(creds, service_account.Credentials):
        # For service account, we need to get a new bearer token
        auth_req = Request()
        creds.refresh(auth_req)
        token = creds.token
    else:
        # For OAuth credentials, check if token needs refresh
        if not creds.valid:
            if creds.expired and creds.refresh_token:
                try:
                    logger.info("Refreshing expired OAuth token in get_headers")
                    creds.refresh(Request())
                    logger.info("Token successfully refreshed in get_headers")
                except RefreshError as e:
                    logger.error(f"Error refreshing token in get_headers: {str(e)}")
                    raise ValueError(f"Failed to refresh OAuth token: {str(e)}")
                except Exception as e:
                    logger.error(f"Unexpected error refreshing token in get_headers: {str(e)}")
                    raise
            else:
                raise ValueError("OAuth credentials are invalid and cannot be refreshed")
        
        token = creds.token
        
    headers = {
        'Authorization': f'Bearer {token}',
        'developer-token': GOOGLE_ADS_DEVELOPER_TOKEN,
        'content-type': 'application/json'
    }
    
    if GOOGLE_ADS_LOGIN_CUSTOMER_ID:
        headers['login-customer-id'] = format_customer_id(GOOGLE_ADS_LOGIN_CUSTOMER_ID)
    
    return headers

# All the @mcp.tool() decorated functions remain exactly the same
# I'm not including them here to save space, but they should all be kept as-is

@mcp.tool()
async def list_accounts() -> str:
    """
    Lists all accessible Google Ads accounts.
    
    This is typically the first command you should run to identify which accounts 
    you have access to. The returned account IDs can be used in subsequent commands.
    
    Returns:
        A formatted list of all Google Ads accounts accessible with your credentials
    """
    try:
        creds = get_credentials()
        headers = get_headers(creds)
        
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers:listAccessibleCustomers"
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            return f"Error accessing accounts: {response.text}"
        
        customers = response.json()
        if not customers.get('resourceNames'):
            return "No accessible accounts found."
        
        # Format the results
        result_lines = ["Accessible Google Ads Accounts:"]
        result_lines.append("-" * 50)
        
        for resource_name in customers['resourceNames']:
            customer_id = resource_name.split('/')[-1]
            formatted_id = format_customer_id(customer_id)
            result_lines.append(f"Account ID: {formatted_id}")
        
        return "\n".join(result_lines)
    
    except Exception as e:
        return f"Error listing accounts: {str(e)}"

# Include all other @mcp.tool() decorated functions here...
# (I'm omitting them to save space, but they should all be included)

# Remove the if __name__ == "__main__" block entirely
# The MCP server should not be run directly from this file
