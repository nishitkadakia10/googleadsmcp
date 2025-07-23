#!/usr/bin/env python3
"""
Auth0-Protected SSE MCP Server for Google Ads
"""

import os
import sys
import logging
import json
from pathlib import Path
from functools import wraps
from typing import Optional, Dict, Any

# Auth0 and JWT imports
import jwt
from jwt import PyJWKClient
import requests
from flask import Flask, request, Response, jsonify
from flask_cors import CORS

# Add the parent directory to Python path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Import the MCP server
from google_ads_server import mcp, setup_credentials_file

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('auth0_mcp_server')

# Auth0 Configuration
AUTH0_DOMAIN = os.environ.get('AUTH0_DOMAIN', '')
AUTH0_API_IDENTIFIER = os.environ.get('AUTH0_API_IDENTIFIER', '')
AUTH0_ALGORITHMS = ['RS256']

# Initialize Flask app for Auth0 handling
app = Flask(__name__)
CORS(app)

# JWT validation
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

def get_token_auth_header():
    """Extract the Access Token from the Authorization Header"""
    auth = request.headers.get('Authorization', None)
    if not auth:
        raise AuthError({
            'code': 'authorization_header_missing',
            'description': 'Authorization header is expected.'
        }, 401)

    parts = auth.split()
    if parts[0].lower() != 'bearer':
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must start with "Bearer".'
        }, 401)

    elif len(parts) == 1:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Token not found.'
        }, 401)

    elif len(parts) > 2:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must be bearer token.'
        }, 401)

    token = parts[1]
    return token

def verify_jwt(token):
    """Verify and decode the JWT token"""
    if not AUTH0_DOMAIN or not AUTH0_API_IDENTIFIER:
        logger.error("Auth0 configuration missing")
        raise AuthError({
            'code': 'configuration_error',
            'description': 'Auth0 configuration is missing.'
        }, 500)
    
    try:
        # Get the public key from Auth0
        jwks_url = f'https://{AUTH0_DOMAIN}/.well-known/jwks.json'
        jwks_client = PyJWKClient(jwks_url)
        
        # Get the signing key from the token
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        
        # Decode and verify the token
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=AUTH0_ALGORITHMS,
            audience=AUTH0_API_IDENTIFIER,
            issuer=f'https://{AUTH0_DOMAIN}/'
        )
        
        return payload
        
    except jwt.ExpiredSignatureError:
        raise AuthError({
            'code': 'token_expired',
            'description': 'Token has expired.'
        }, 401)
    except jwt.InvalidTokenError:
        raise AuthError({
            'code': 'invalid_token',
            'description': 'Token is invalid.'
        }, 401)
    except Exception as e:
        logger.error(f"Token verification error: {str(e)}")
        raise AuthError({
            'code': 'invalid_token',
            'description': 'Unable to verify token.'
        }, 401)

def requires_auth(f):
    """Decorator to check valid JWT tokens"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            token = get_token_auth_header()
            payload = verify_jwt(token)
            # Store user info in request context
            request.current_user = payload
            return f(*args, **kwargs)
        except AuthError as e:
            return jsonify(e.error), e.status_code
    return decorated

# Health check endpoint (no auth required)
@app.route('/health')
def health():
    return jsonify({"status": "healthy", "service": "auth0-protected-mcp"})

# Auth validation endpoint
@app.route('/auth/validate', methods=['POST'])
@requires_auth
def validate_auth():
    """Validate Auth0 token and return user info"""
    return jsonify({
        "status": "authenticated",
        "user": request.current_user
    })

# Protected SSE endpoint
@app.route('/sse')
@requires_auth
def sse_endpoint():
    """SSE endpoint protected by Auth0"""
    logger.info(f"Authenticated SSE connection from user: {request.current_user.get('sub')}")
    
    # Here we need to proxy to the actual MCP SSE server
    # This is a simplified version - in production you'd want proper SSE proxying
    def generate():
        # Start the MCP server in SSE mode
        import subprocess
        import threading
        
        # Pass the authenticated user info to the MCP server
        env = os.environ.copy()
        env['MCP_USER_ID'] = request.current_user.get('sub')
        env['MCP_USER_EMAIL'] = request.current_user.get('email', '')
        
        # Run the MCP server
        process = subprocess.Popen(
            ['python', 'sse_server.py'],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Stream the output
        while True:
            line = process.stdout.readline()
            if line:
                yield f"data: {line}\n\n"
            else:
                break
    
    return Response(generate(), mimetype="text/event-stream")

# Error handlers
@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404

if __name__ == "__main__":
    # Setup credentials if needed
    if os.environ.get("RAILWAY_ENVIRONMENT") or os.environ.get("GOOGLE_ADS_CREDENTIALS_BASE64"):
        setup_credentials_file()
    
    # Get port from Railway
    port = int(os.environ.get("PORT", 8000))
    
    logger.info(f"Starting Auth0-protected MCP server on port {port}")
    
    # Run Flask app
    app.run(host='0.0.0.0', port=port, debug=False)
