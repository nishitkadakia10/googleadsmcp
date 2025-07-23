#!/usr/bin/env python3
"""
SSE-enabled Google Ads MCP Server for Railway deployment
"""

import os
import sys
import logging
from pathlib import Path

# Add the parent directory to Python path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Import the MCP server and tools
from google_ads_server import (
    mcp, 
    list_accounts, 
    execute_gaql_query,
    get_campaign_performance,
    get_ad_performance,
    run_gaql,
    get_ad_creatives,
    get_account_currency,
    get_image_assets,
    download_image_asset,
    get_asset_usage,
    analyze_image_assets,
    list_resources
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('sse_server')

if __name__ == "__main__":
    # Get port from Railway
    port = int(os.environ.get("PORT", 8000))
    
    # Force SSE transport for Railway
    logger.info(f"Starting SSE MCP server on port {port}")
    
    # Update server settings for Railway
    mcp.settings.host = "0.0.0.0"  # Bind to all interfaces (required by Railway)
    mcp.settings.port = port
    
    # Start with SSE transport
    try:
        logger.info("Starting MCP server with SSE transport...")
        mcp.run(transport="sse")
    except Exception as e:
        logger.error(f"Failed to start SSE server: {e}")
        sys.exit(1)
