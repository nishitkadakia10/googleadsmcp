#!/usr/bin/env python3
"""
Google Ads MCP Server: Provides Google Ads API tools via MCP protocol.

Production-ready: structured with CLI, logging, and error handling.
Supports both stdio (DEV) and SSE (PROD) transports based on ENV variable.
Supports service account authentication via base64 encoded JSON in environment variables.
"""

import os
import sys
import json
import base64
import requests
import argparse
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union

from google.oauth2.credentials import Credentials
from google.oauth2 import service_account
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from google_auth_oauthlib.flow import InstalledAppFlow

# MCP
from fastmcp import FastMCP
from dotenv import load_dotenv
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response

load_dotenv()

# --- Constants ---
API_VERSION = "v19"  # Google Ads API version
SCOPES = ['https://www.googleapis.com/auth/adwords']

# Environment variables
GOOGLE_ADS_DEVELOPER_TOKEN = os.environ.get("GOOGLE_ADS_DEVELOPER_TOKEN")
GOOGLE_ADS_LOGIN_CUSTOMER_ID = os.environ.get("GOOGLE_ADS_LOGIN_CUSTOMER_ID", "")
GOOGLE_ADS_AUTH_TYPE = os.environ.get("GOOGLE_ADS_AUTH_TYPE", "service_account")
GOOGLE_ADS_SERVICE_ACCOUNT_BASE64 = os.environ.get("GOOGLE_ADS_SERVICE_ACCOUNT_BASE64")
GOOGLE_ADS_CREDENTIALS_PATH = os.environ.get("GOOGLE_ADS_CREDENTIALS_PATH")

def setup_logging():
    """
    Configure logging using LOG_LEVEL environment variable with default INFO.
    """
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s"
    )

def parse_args():
    """
    Parse CLI arguments for MCP server host and port.
    Only used in DEV mode.
    """
    parser = argparse.ArgumentParser(description="Run the Google Ads MCP server")
    parser.add_argument(
        "--host", "-H",
        default=os.getenv("MCP_HOST", "0.0.0.0"),
        help="Host interface to bind the MCP server"
    )
    parser.add_argument(
        "--port", "-P",
        type=int,
        default=int(os.getenv("MCP_PORT", "8000")),
        help="Port to bind the MCP server"
    )
    return parser.parse_args()

def add_sse_post_handler(mcp: FastMCP):
    """
    Add POST handler for /sse endpoint to handle client probes and prevent 405 errors.
    """
    @mcp.custom_route("/sse", methods=["POST"])
    async def sse_post_probe(request: StarletteRequest) -> Response:
        """Handle POST requests to /sse endpoint for client probing"""
        logging.info("Received POST probe to /sse endpoint")
        # Return 204 No Content to indicate successful probe
        return Response(status_code=204)
    
    logging.info("Added POST /sse handler to prevent 405 errors from client probes")

# --- Helper Functions ---

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
    1. Service Account via base64 encoded JSON (Recommended for Railway)
    2. Service Account via file path (Local development)
    3. OAuth 2.0 (User Authentication) - For individual users
    
    Returns:
        Valid credentials object to use with Google Ads API
    """
    auth_type = GOOGLE_ADS_AUTH_TYPE.lower()
    logging.info(f"Using authentication type: {auth_type}")
    
    # Service Account authentication
    if auth_type == "service_account":
        try:
            return get_service_account_credentials()
        except Exception as e:
            logging.error(f"Error with service account authentication: {str(e)}")
            raise
    
    # OAuth 2.0 authentication (fallback)
    return get_oauth_credentials()

def get_service_account_credentials():
    """Get credentials using a service account key (base64 or file)."""
    
    # First try base64 encoded service account (preferred for Railway)
    if GOOGLE_ADS_SERVICE_ACCOUNT_BASE64:
        logging.info("Loading service account credentials from base64 environment variable")
        try:
            # Decode the base64 service account JSON
            service_account_json = base64.b64decode(GOOGLE_ADS_SERVICE_ACCOUNT_BASE64).decode('utf-8')
            service_account_info = json.loads(service_account_json)
            
            credentials = service_account.Credentials.from_service_account_info(
                service_account_info, 
                scopes=SCOPES
            )
            
            # Check if impersonation is required
            impersonation_email = os.environ.get("GOOGLE_ADS_IMPERSONATION_EMAIL")
            if impersonation_email:
                logging.info(f"Impersonating user: {impersonation_email}")
                credentials = credentials.with_subject(impersonation_email)
                
            return credentials
            
        except Exception as e:
            logging.error(f"Error loading service account from base64: {str(e)}")
            raise
    
    # Fallback to file path (for local development)
    elif GOOGLE_ADS_CREDENTIALS_PATH:
        logging.info(f"Loading service account credentials from file: {GOOGLE_ADS_CREDENTIALS_PATH}")
        
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
                logging.info(f"Impersonating user: {impersonation_email}")
                credentials = credentials.with_subject(impersonation_email)
                
            return credentials
            
        except Exception as e:
            logging.error(f"Error loading service account from file: {str(e)}")
            raise
    
    else:
        raise ValueError("Either GOOGLE_ADS_SERVICE_ACCOUNT_BASE64 or GOOGLE_ADS_CREDENTIALS_PATH must be set for service account authentication")

def get_oauth_credentials():
    """Get and refresh OAuth user credentials."""
    # This is for local development - not recommended for Railway deployment
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
        logging.info(f"Loading OAuth credentials from {token_path}")
        with open(token_path, 'r') as f:
            creds_data = json.load(f)
            creds = Credentials.from_authorized_user_info(creds_data, SCOPES)
    
    # If credentials don't exist or are invalid, get new ones
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                logging.info("Refreshing expired token")
                creds.refresh(Request())
                logging.info("Token successfully refreshed")
            except RefreshError as e:
                logging.warning(f"Error refreshing token: {str(e)}, will try to get new token")
                creds = None
        
        # If we need new credentials, this won't work in Railway environment
        if not creds:
            raise ValueError("OAuth flow not supported in production environment. Use service account authentication.")
    
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
                    logging.info("Refreshing expired OAuth token in get_headers")
                    creds.refresh(Request())
                    logging.info("Token successfully refreshed in get_headers")
                except RefreshError as e:
                    logging.error(f"Error refreshing token in get_headers: {str(e)}")
                    raise ValueError(f"Failed to refresh OAuth token: {str(e)}")
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

# --- Tool Registration ---
def register_tools(mcp: FastMCP):
    """Register all Google Ads API tools with the MCP server."""
    
    @mcp.tool()
    def health_check() -> Dict:
        """Health check tool for the Google Ads MCP server."""
        import time
        return {
            "status": "healthy",
            "service": "google-ads-mcp-server",
            "developer_token_configured": bool(GOOGLE_ADS_DEVELOPER_TOKEN),
            "auth_type": GOOGLE_ADS_AUTH_TYPE,
            "service_account_configured": bool(GOOGLE_ADS_SERVICE_ACCOUNT_BASE64 or GOOGLE_ADS_CREDENTIALS_PATH),
            "timestamp": time.time(),
        }
    
    @mcp.tool()
    def list_accounts() -> str:
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
    
    @mcp.tool()
    def execute_gaql_query(
        customer_id: str,
        query: str
    ) -> str:
        """
        Execute a custom GAQL (Google Ads Query Language) query.
        
        This tool allows you to run any valid GAQL query against the Google Ads API.
        
        Args:
            customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
            query: The GAQL query to execute (must follow GAQL syntax)
            
        Returns:
            Formatted query results or error message
            
        Example:
            customer_id: "1234567890"
            query: "SELECT campaign.id, campaign.name FROM campaign LIMIT 10"
        """
        try:
            creds = get_credentials()
            headers = get_headers(creds)
            
            formatted_customer_id = format_customer_id(customer_id)
            url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
            
            payload = {"query": query}
            response = requests.post(url, headers=headers, json=payload)
            
            if response.status_code != 200:
                return f"Error executing query: {response.text}"
            
            results = response.json()
            if not results.get('results'):
                return "No results found for the query."
            
            # Format the results as a table
            result_lines = [f"Query Results for Account {formatted_customer_id}:"]
            result_lines.append("-" * 80)
            
            # Get field names from the first result
            fields = []
            first_result = results['results'][0]
            for key in first_result:
                if isinstance(first_result[key], dict):
                    for subkey in first_result[key]:
                        fields.append(f"{key}.{subkey}")
                else:
                    fields.append(key)
            
            # Add header
            result_lines.append(" | ".join(fields))
            result_lines.append("-" * 80)
            
            # Add data rows
            for result in results['results']:
                row_data = []
                for field in fields:
                    if "." in field:
                        parent, child = field.split(".")
                        value = str(result.get(parent, {}).get(child, ""))
                    else:
                        value = str(result.get(field, ""))
                    row_data.append(value)
                result_lines.append(" | ".join(row_data))
            
            return "\n".join(result_lines)
        
        except Exception as e:
            return f"Error executing GAQL query: {str(e)}"
    
    @mcp.tool()
    def get_campaign_performance(
        customer_id: str,
        days: int = 30
    ) -> str:
        """
        Get campaign performance metrics for the specified time period.
        
        RECOMMENDED WORKFLOW:
        1. First run list_accounts() to get available account IDs
        2. Then run get_account_currency() to see what currency the account uses
        3. Finally run this command to get campaign performance
        
        Args:
            customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
            days: Number of days to look back (default: 30)
            
        Returns:
            Formatted table of campaign performance data
            
        Note:
            Cost values are in micros (millionths) of the account currency
            (e.g., 1000000 = 1 USD in a USD account)
            
        Example:
            customer_id: "1234567890"
            days: 14
        """
        query = f"""
            SELECT
                campaign.id,
                campaign.name,
                campaign.status,
                metrics.impressions,
                metrics.clicks,
                metrics.cost_micros,
                metrics.conversions,
                metrics.average_cpc
            FROM campaign
            WHERE segments.date DURING LAST_{days}_DAYS
            ORDER BY metrics.cost_micros DESC
            LIMIT 50
        """
        
        return execute_gaql_query(customer_id, query)
    
    @mcp.tool()
    def get_account_currency(
        customer_id: str
    ) -> str:
        """
        Retrieve the default currency code used by the Google Ads account.
        
        IMPORTANT: Run this first before analyzing cost data to understand which currency
        the account uses. Cost values are always displayed in the account's currency.
        
        Args:
            customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
        
        Returns:
            The account's default currency code (e.g., 'USD', 'EUR', 'GBP')
            
        Example:
            customer_id: "1234567890"
        """
        query = """
            SELECT
                customer.id,
                customer.currency_code
            FROM customer
            LIMIT 1
        """
        
        try:
            creds = get_credentials()
            headers = get_headers(creds)
            
            formatted_customer_id = format_customer_id(customer_id)
            url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
            
            payload = {"query": query}
            response = requests.post(url, headers=headers, json=payload)
            
            if response.status_code != 200:
                return f"Error retrieving account currency: {response.text}"
            
            results = response.json()
            if not results.get('results'):
                return "No account information found for this customer ID."
            
            # Extract the currency code from the results
            customer = results['results'][0].get('customer', {})
            currency_code = customer.get('currencyCode', 'Not specified')
            
            return f"Account {formatted_customer_id} uses currency: {currency_code}"
        
        except Exception as e:
            logging.error(f"Error retrieving account currency: {str(e)}")
            return f"Error retrieving account currency: {str(e)}"
    
    @mcp.tool()
    def run_gaql(
        customer_id: str,
        query: str,
        format: str = "table"
    ) -> str:
        """
        Execute any arbitrary GAQL (Google Ads Query Language) query with custom formatting options.
        
        This is the most powerful tool for custom Google Ads data queries.
        
        Args:
            customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
            query: The GAQL query to execute (any valid GAQL query)
            format: Output format ("table", "json", or "csv")
        
        Returns:
            Query results in the requested format
        
        EXAMPLE QUERIES:
        
        1. Basic campaign metrics:
            SELECT 
              campaign.name, 
              metrics.clicks, 
              metrics.impressions,
              metrics.cost_micros
            FROM campaign 
            WHERE segments.date DURING LAST_7_DAYS
        
        2. Ad group performance:
            SELECT 
              ad_group.name, 
              metrics.conversions, 
              metrics.cost_micros,
              campaign.name
            FROM ad_group 
            WHERE metrics.clicks > 100
        
        3. Keyword analysis:
            SELECT 
              keyword.text, 
              metrics.average_position, 
              metrics.ctr
            FROM keyword_view 
            ORDER BY metrics.impressions DESC
            
        Note:
            Cost values are in micros (millionths) of the account currency
            (e.g., 1000000 = 1 USD in a USD account)
        """
        try:
            creds = get_credentials()
            headers = get_headers(creds)
            
            formatted_customer_id = format_customer_id(customer_id)
            url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
            
            payload = {"query": query}
            response = requests.post(url, headers=headers, json=payload)
            
            if response.status_code != 200:
                return f"Error executing query: {response.text}"
            
            results = response.json()
            if not results.get('results'):
                return "No results found for the query."
            
            if format.lower() == "json":
                return json.dumps(results, indent=2)
            
            elif format.lower() == "csv":
                # Get field names from the first result
                fields = []
                first_result = results['results'][0]
                for key, value in first_result.items():
                    if isinstance(value, dict):
                        for subkey in value:
                            fields.append(f"{key}.{subkey}")
                    else:
                        fields.append(key)
                
                # Create CSV string
                csv_lines = [",".join(fields)]
                for result in results['results']:
                    row_data = []
                    for field in fields:
                        if "." in field:
                            parent, child = field.split(".")
                            value = str(result.get(parent, {}).get(child, "")).replace(",", ";")
                        else:
                            value = str(result.get(field, "")).replace(",", ";")
                        row_data.append(value)
                    csv_lines.append(",".join(row_data))
                
                return "\n".join(csv_lines)
            
            else:  # default table format
                result_lines = [f"Query Results for Account {formatted_customer_id}:"]
                result_lines.append("-" * 100)
                
                # Get field names and maximum widths
                fields = []
                field_widths = {}
                first_result = results['results'][0]
                
                for key, value in first_result.items():
                    if isinstance(value, dict):
                        for subkey in value:
                            field = f"{key}.{subkey}"
                            fields.append(field)
                            field_widths[field] = len(field)
                    else:
                        fields.append(key)
                        field_widths[key] = len(key)
                
                # Calculate maximum field widths
                for result in results['results']:
                    for field in fields:
                        if "." in field:
                            parent, child = field.split(".")
                            value = str(result.get(parent, {}).get(child, ""))
                        else:
                            value = str(result.get(field, ""))
                        field_widths[field] = max(field_widths[field], len(value))
                
                # Create formatted header
                header = " | ".join(f"{field:{field_widths[field]}}" for field in fields)
                result_lines.append(header)
                result_lines.append("-" * len(header))
                
                # Add data rows
                for result in results['results']:
                    row_data = []
                    for field in fields:
                        if "." in field:
                            parent, child = field.split(".")
                            value = str(result.get(parent, {}).get(child, ""))
                        else:
                            value = str(result.get(field, ""))
                        row_data.append(f"{value:{field_widths[field]}}")
                    result_lines.append(" | ".join(row_data))
                
                return "\n".join(result_lines)
        
        except Exception as e:
            return f"Error executing GAQL query: {str(e)}"

    logging.info("Registered Google Ads API tools")


def main():
    """Main function to run the Google Ads MCP server."""
    load_dotenv()
    setup_logging()
    
    # Check required environment variables
    if not GOOGLE_ADS_DEVELOPER_TOKEN:
        logging.error("Error: GOOGLE_ADS_DEVELOPER_TOKEN not configured")
        sys.exit(1)
    
    if not (GOOGLE_ADS_SERVICE_ACCOUNT_BASE64 or GOOGLE_ADS_CREDENTIALS_PATH):
        logging.error("Error: Either GOOGLE_ADS_SERVICE_ACCOUNT_BASE64 or GOOGLE_ADS_CREDENTIALS_PATH must be configured")
        sys.exit(1)
    
    # Get environment mode
    env = os.getenv("ENV", "DEV").upper()
    
    # Parse CLI args only in DEV mode
    if env == "DEV":
        args = parse_args()
        host = args.host
        port = args.port
        transport = "stdio"
    else:  # PROD mode
        # Railway provides MCP_PORT environment variable, fallback to 8000
        port = int(os.getenv("MCP_PORT", "8000"))
        host = "0.0.0.0"
        transport = "sse"

    # Create MCP server with better error handling
    try:
        mcp = FastMCP("Google Ads MCP Server")
        
        # Register tools
        register_tools(mcp)
        
        # Add POST handler for SSE endpoint (only for PROD mode)
        if transport == "sse":
            add_sse_post_handler(mcp)

        logging.info("Environment: %s", env)
        logging.info("Transport: %s", transport)
        logging.info("✅ Google Ads API credentials configured")
        logging.info("🚀 Starting Google Ads MCP Server on %s:%s", host, port)
        
        if transport == "stdio":
            logging.info("Starting Google Ads MCP server with stdio transport")
            try:
                mcp.run(transport="stdio")
            except Exception as e:
                logging.exception("Google Ads MCP server terminated unexpectedly: %s", e)
        else:  # SSE transport with POST probe handler
            logging.info("Starting Google Ads MCP server with SSE transport (with POST probe support)")
            try:
                mcp.run(transport="sse", host=host, port=port)
            except Exception as e:
                logging.exception("Google Ads MCP server terminated unexpectedly: %s", e)
                
    except Exception as e:
        logging.exception("Failed to initialize Google Ads MCP server: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main() 
