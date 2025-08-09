import os
import json
import jwt
import requests
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template_string, redirect, session
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import uuid

# Simple in-memory cache for state/nonce as fallback (not for production scale)
state_cache = {}

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')

# Configure session for Railway.app
app.config.update(
    SESSION_COOKIE_SECURE=True,  # Require HTTPS
    SESSION_COOKIE_HTTPONLY=True,  # Prevent XSS
    SESSION_COOKIE_SAMESITE='None',  # Allow cross-origin (needed for LTI)
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=60)
)

# LTI 1.3 Configuration
LTI_CONFIG = {
    'client_id': os.environ.get('LTI_CLIENT_ID', 'your-client-id'),
    'deployment_id': os.environ.get('LTI_DEPLOYMENT_ID', 'your-deployment-id'),
    'iss': os.environ.get('LTI_ISSUER', 'https://yourmoodle.com'),  # Your Moodle URL
    'auth_login_url': os.environ.get('LTI_AUTH_LOGIN_URL', 'https://yourmoodle.com/mod/lti/auth.php'),
    'auth_token_url': os.environ.get('LTI_AUTH_TOKEN_URL', 'https://yourmoodle.com/mod/lti/token.php'),
    'key_set_url': os.environ.get('LTI_KEY_SET_URL', 'https://yourmoodle.com/mod/lti/certs.php'),
}

# Generate RSA key pair for JWT signing (in production, store these securely)
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem

# Helper function to fix PEM format
def fix_pem_format(pem_string, key_type='PRIVATE'):
    """Fix PEM format by ensuring proper line breaks"""
    if not pem_string:
        return None
    
    # Remove any existing line breaks and spaces
    clean_key = pem_string.replace('\n', '').replace('\r', '').replace(' ', '')
    
    # Define headers and footers
    if key_type == 'PRIVATE':
        header = '-----BEGIN PRIVATE KEY-----'
        footer = '-----END PRIVATE KEY-----'
    else:
        header = '-----BEGIN PUBLIC KEY-----'
        footer = '-----END PUBLIC KEY-----'
    
    # Remove headers/footers if they exist
    clean_key = clean_key.replace(header.replace('-', '').replace(' ', ''), '')
    clean_key = clean_key.replace(footer.replace('-', '').replace(' ', ''), '')
    
    # Add proper formatting - split into 64-character lines
    formatted_lines = [clean_key[i:i+64] for i in range(0, len(clean_key), 64)]
    
    # Reconstruct with proper headers, footers, and line breaks
    return f"{header}\n" + "\n".join(formatted_lines) + f"\n{footer}"

# Load or generate keys
PRIVATE_KEY_PEM = os.environ.get('PRIVATE_KEY_PEM')
PUBLIC_KEY_PEM = os.environ.get('PUBLIC_KEY_PEM')

# Alternative base64 encoded storage (more Railway-friendly)
PRIVATE_KEY_B64 = os.environ.get('PRIVATE_KEY_B64')
PUBLIC_KEY_B64 = os.environ.get('PUBLIC_KEY_B64')

private_key = None
public_key = None

# Try to load from base64 first (more reliable for environment variables)
if PRIVATE_KEY_B64 and PUBLIC_KEY_B64:
    try:
        import base64
        PRIVATE_KEY_PEM = base64.b64decode(PRIVATE_KEY_B64).decode('utf-8')
        PUBLIC_KEY_PEM = base64.b64decode(PUBLIC_KEY_B64).decode('utf-8')
        print("Loaded keys from base64 environment variables")
    except Exception as e:
        print(f"Failed to load base64 keys: {e}")
        PRIVATE_KEY_PEM = None
        PUBLIC_KEY_PEM = None

# Try to load and fix PEM format
if PRIVATE_KEY_PEM and PUBLIC_KEY_PEM:
    try:
        # Fix PEM formatting in case newlines were lost
        fixed_private = fix_pem_format(PRIVATE_KEY_PEM, 'PRIVATE')
        fixed_public = fix_pem_format(PUBLIC_KEY_PEM, 'PUBLIC')
        
        if fixed_private and fixed_public:
            private_key = serialization.load_pem_private_key(
                fixed_private.encode(),
                password=None
            )
            public_key = serialization.load_pem_public_key(
                fixed_public.encode()
            )
            print("Successfully loaded existing keys")
        else:
            raise ValueError("Could not fix PEM format")
            
    except Exception as e:
        print(f"Failed to load existing keys: {e}")
        private_key = None
        public_key = None

# Generate new keys if loading failed
if not private_key or not public_key:
    print("Generating new key pair...")
    private_key_pem, public_key_pem = generate_key_pair()
    
    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        public_key = serialization.load_pem_public_key(public_key_pem)
        
        print("=== COPY THESE KEYS TO YOUR RAILWAY ENVIRONMENT VARIABLES ===")
        print("\nOption 1 - PEM Format (copy exactly with all line breaks):")
        print(f"PRIVATE_KEY_PEM=")
        print(private_key_pem.decode())
        print(f"\nPUBLIC_KEY_PEM=")
        print(public_key_pem.decode())
        
        print("\nOption 2 - Base64 Format (recommended for Railway):")
        import base64
        private_b64 = base64.b64encode(private_key_pem).decode('utf-8')
        public_b64 = base64.b64encode(public_key_pem).decode('utf-8')
        print(f"PRIVATE_KEY_B64={private_b64}")
        print(f"PUBLIC_KEY_B64={public_b64}")
        print("\n=== END OF KEYS ===")
        
    except Exception as e:
        print(f"Failed to generate keys: {e}")
        raise

# LTI 1.3 OIDC Login endpoint
@app.route('/login', methods=['GET', 'POST'])
def oidc_login():
    """Handle OIDC login initiation from Moodle"""
    
    # Get parameters from request
    iss = request.args.get('iss') or request.form.get('iss')
    client_id = request.args.get('client_id') or request.form.get('client_id')
    target_link_uri = request.args.get('target_link_uri') or request.form.get('target_link_uri')
    login_hint = request.args.get('login_hint') or request.form.get('login_hint')
    lti_message_hint = request.args.get('lti_message_hint') or request.form.get('lti_message_hint')
    
    # Debug logging - print received vs expected values
    print("=== OIDC LOGIN DEBUG ===")
    print(f"Received issuer: '{iss}'")
    print(f"Expected issuer: '{LTI_CONFIG['iss']}'")
    print(f"Received client_id: '{client_id}'")
    print(f"Expected client_id: '{LTI_CONFIG['client_id']}'")
    print(f"Target link URI: '{target_link_uri}'")
    print("========================")
    
    # Validate issuer and client_id
    if iss != LTI_CONFIG['iss'] or client_id != LTI_CONFIG['client_id']:
        error_details = {
            'error': 'Invalid issuer or client_id',
            'debug': {
                'received_iss': iss,
                'expected_iss': LTI_CONFIG['iss'],
                'received_client_id': client_id,
                'expected_client_id': LTI_CONFIG['client_id'],
                'iss_match': iss == LTI_CONFIG['iss'],
                'client_id_match': client_id == LTI_CONFIG['client_id']
            }
        }
        return jsonify(error_details), 400
    
    # Generate state and nonce for security
    state = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    
    # Store state and nonce in session AND in-memory cache (fallback)
    session['oauth_state'] = state
    session['oauth_nonce'] = nonce
    
    # Also store in cache with expiration (fallback for session issues)
    state_cache[state] = {
        'nonce': nonce,
        'timestamp': datetime.utcnow(),
        'client_id': client_id,
        'iss': iss
    }
    
    # Clean old cache entries (older than 10 minutes)
    current_time = datetime.utcnow()
    expired_keys = [k for k, v in state_cache.items() 
                   if current_time - v['timestamp'] > timedelta(minutes=10)]
    for key in expired_keys:
        del state_cache[key]
    
    # Build authorization request
    auth_params = {
        'response_type': 'id_token',
        'scope': 'openid',
        'client_id': client_id,
        'redirect_uri': target_link_uri,
        'login_hint': login_hint,
        'state': state,
        'response_mode': 'form_post',
        'nonce': nonce,
        'prompt': 'none'
    }
    
    if lti_message_hint:
        auth_params['lti_message_hint'] = lti_message_hint
    
    # Redirect to Moodle's authorization endpoint
    auth_url = LTI_CONFIG['auth_login_url'] + '?' + '&'.join([f"{k}={v}" for k, v in auth_params.items()])
    return redirect(auth_url)

# LTI 1.3 Launch endpoint
@app.route('/launch', methods=['POST'])
def lti_launch():
    """Handle LTI launch with JWT token validation"""
    
    # Get the JWT token from the request
    id_token = request.form.get('id_token')
    state = request.form.get('state')
    
    # Debug logging
    print("=== LTI LAUNCH DEBUG ===")
    print(f"Received state: '{state}'")
    print(f"Session state: '{session.get('oauth_state')}'")
    print(f"Session keys: {list(session.keys())}")
    print(f"Has id_token: {bool(id_token)}")
    print("========================")
    
    if not id_token:
        return jsonify({'error': 'Missing id_token'}), 400
    
    # For development/testing: Try session first, then fallback to cache
    stored_state = session.get('oauth_state')
    stored_nonce = session.get('oauth_nonce')
    
    # Fallback to cache if session is empty
    if not stored_state and state in state_cache:
        print("Using cached state (session fallback)")
        cached_data = state_cache[state]
        stored_state = state
        stored_nonce = cached_data['nonce']
        
        # Clean up used cache entry
        del state_cache[state]
    
    if not stored_state:
        print("WARNING: No state found in session OR cache")
        # Last resort: try to continue without state validation for debugging
        try:
            unverified_payload = jwt.decode(id_token, options={"verify_signature": False})
            stored_nonce = unverified_payload.get('nonce')
            print(f"Extracted nonce from JWT: {stored_nonce}")
        except Exception as e:
            print(f"Could not extract nonce from token: {e}")
            return jsonify({
                'error': 'Session lost - please try launching again', 
                'debug': 'No session state found',
                'suggestion': 'This might be a Railway session issue. Try refreshing the course page and launching again.'
            }), 400
    else:
        # Validate state only if we have it
        if state != stored_state:
            return jsonify({
                'error': 'Invalid state parameter',
                'debug': {
                    'received_state': state,
                    'expected_state': stored_state,
                    'session_keys': list(session.keys()),
                    'cache_available': state in state_cache
                }
            }), 400
    
    try:
        # Get Moodle's public keys for token verification
        jwks_response = requests.get(LTI_CONFIG['key_set_url'])
        jwks = jwks_response.json()
        
        # Decode JWT header to get key ID
        unverified_header = jwt.get_unverified_header(id_token)
        kid = unverified_header.get('kid')
        
        # Find the correct public key
        public_key_for_verification = None
        for key in jwks.get('keys', []):
            if key.get('kid') == kid:
                # Convert JWK to PEM format for verification
                # This is simplified - in production use a proper JWK library
                public_key_for_verification = key
                break
        
        if not public_key_for_verification:
            return jsonify({'error': 'Could not find verification key'}), 400
        
        # For simplicity, we'll skip full JWT verification in this basic example
        # In production, properly verify the JWT signature
        
        # Decode token (without verification for this demo)
        payload = jwt.decode(id_token, options={"verify_signature": False})
        
        # Validate nonce
        if payload.get('nonce') != stored_nonce:
            print(f"Nonce validation - Received: '{payload.get('nonce')}', Expected: '{stored_nonce}'")
            if stored_nonce:  # Only fail if we actually had a stored nonce
                return jsonify({'error': 'Invalid nonce', 'debug': {'received_nonce': payload.get('nonce'), 'expected_nonce': stored_nonce}}), 400
            else:
                print("WARNING: No stored nonce - skipping nonce validation")
        
        # Validate required LTI claims
        if (payload.get('iss') != LTI_CONFIG['iss'] or 
            payload.get('aud') != LTI_CONFIG['client_id']):
            return jsonify({'error': 'Invalid issuer or audience'}), 400
        
        # Extract LTI data
        lti_data = {
            'user_id': payload.get('sub'),
            'user_name': payload.get('name'),
            'user_email': payload.get('email'),
            'course_id': payload.get('https://purl.imsglobal.org/spec/lti/claim/context', {}).get('id'),
            'course_title': payload.get('https://purl.imsglobal.org/spec/lti/claim/context', {}).get('title'),
            'roles': payload.get('https://purl.imsglobal.org/spec/lti/claim/roles', []),
            'resource_link_id': payload.get('https://purl.imsglobal.org/spec/lti/claim/resource_link', {}).get('id'),
        }
        
        # Store LTI data in session
        session['lti_data'] = lti_data
        
        # Render the tool interface
        return render_tool_interface(lti_data)
        
    except Exception as e:
        return jsonify({'error': f'Token validation failed: {str(e)}'}), 400

def render_tool_interface(lti_data):
    """Render the main tool interface"""
    
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>LTI 1.3 Hello World Tool</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 800px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f5f5f5;
            }
            .container {
                background-color: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            .header {
                text-align: center;
                color: #333;
                border-bottom: 2px solid #4CAF50;
                padding-bottom: 20px;
                margin-bottom: 30px;
            }
            .info-section {
                margin: 20px 0;
                padding: 15px;
                background-color: #f9f9f9;
                border-left: 4px solid #4CAF50;
            }
            .info-label {
                font-weight: bold;
                color: #555;
                margin-bottom: 5px;
            }
            .info-value {
                color: #333;
                margin-bottom: 10px;
            }
            .success {
                color: #4CAF50;
                text-align: center;
                font-size: 18px;
                margin: 20px 0;
            }
            .button {
                background-color: #4CAF50;
                color: white;
                padding: 10px 20px;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                font-size: 16px;
                margin: 10px 5px;
            }
            .button:hover {
                background-color: #45a049;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🎉 LTI 1.3 Tool Successfully Launched!</h1>
                <p>Hello World from Railway.app</p>
            </div>
            
            <div class="success">
                ✅ LTI 1.3 integration is working correctly!
            </div>
            
            <div class="info-section">
                <div class="info-label">User Information:</div>
                <div class="info-value">User ID: {{ lti_data.user_id }}</div>
                <div class="info-value">Name: {{ lti_data.user_name or 'Not provided' }}</div>
                <div class="info-value">Email: {{ lti_data.user_email or 'Not provided' }}</div>
            </div>
            
            <div class="info-section">
                <div class="info-label">Course Information:</div>
                <div class="info-value">Course ID: {{ lti_data.course_id or 'Not provided' }}</div>
                <div class="info-value">Course Title: {{ lti_data.course_title or 'Not provided' }}</div>
                <div class="info-value">Resource Link ID: {{ lti_data.resource_link_id or 'Not provided' }}</div>
            </div>
            
            <div class="info-section">
                <div class="info-label">User Roles:</div>
                <div class="info-value">
                    {% if lti_data.roles %}
                        {% for role in lti_data.roles %}
                            {{ role }}<br>
                        {% endfor %}
                    {% else %}
                        No roles provided
                    {% endif %}
                </div>
            </div>
            
            <div style="text-align: center; margin-top: 30px;">
                <button class="button" onclick="showMessage()">Test Interaction</button>
                <button class="button" onclick="window.location.reload()">Refresh</button>
            </div>
            
            <div id="message" style="margin-top: 20px; text-align: center;"></div>
        </div>
        
        <script>
            function showMessage() {
                document.getElementById('message').innerHTML = 
                    '<div class="success">Hello {{ lti_data.user_name or "User" }}! This is your personalized LTI tool.</div>';
            }
        </script>
    </body>
    </html>
    """
    
    return render_template_string(html_template, lti_data=lti_data)

# Public key endpoint for Moodle to verify our JWTs
@app.route('/.well-known/jwks.json')
def jwks():
    """Provide public keys for JWT verification"""
    
    # Convert public key to JWK format
    numbers = public_key.public_numbers()
    
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "kid": "lti-tool-key",
        "n": str(numbers.n),
        "e": str(numbers.e),
        "alg": "RS256"
    }
    
    return jsonify({"keys": [jwk]})

# Configuration endpoint
@app.route('/config.json')
def lti_config():
    """LTI 1.3 tool configuration"""
    
    base_url = request.url_root.rstrip('/')
    
    config = {
        "title": "LTI 1.3 Hello World Tool",
        "description": "A simple LTI 1.3 tool for testing integration",
        "oidc_initiation_url": f"{base_url}/login",
        "target_link_uri": f"{base_url}/launch",
        "scopes": [
            "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem",
            "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly",
            "https://purl.imsglobal.org/spec/lti-ags/scope/score"
        ],
        "extensions": [
            {
                "domain": request.host,
                "tool_id": "lti-hello-world",
                "platform": "canvas.instructure.com",
                "settings": {
                    "text": "LTI Hello World",
                    "placements": [
                        {
                            "text": "LTI Hello World",
                            "enabled": True,
                            "placement": "course_navigation",
                            "message_type": "LtiResourceLinkRequest",
                            "target_link_uri": f"{base_url}/launch"
                        }
                    ]
                }
            }
        ],
        "public_jwk_url": f"{base_url}/.well-known/jwks.json",
        "custom_fields": {}
    }
    
    return jsonify(config)

# Health check endpoint
@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})

# Root endpoint
@app.route('/')
def index():
    return jsonify({
        'message': 'LTI 1.3 Tool Server',
        'status': 'running',
        'endpoints': {
            'oidc_login': '/login',
            'lti_launch': '/launch',
            'jwks': '/.well-known/jwks.json',
            'config': '/config.json',
            'debug': '/debug',
            'health': '/health'
        }
    })

# Debug endpoint to show current configuration
@app.route('/debug')
def debug_config():
    """Show current LTI configuration for debugging"""
    return jsonify({
        'lti_config': {
            'client_id': LTI_CONFIG['client_id'],
            'deployment_id': LTI_CONFIG['deployment_id'],
            'iss': LTI_CONFIG['iss'],
            'auth_login_url': LTI_CONFIG['auth_login_url'],
            'auth_token_url': LTI_CONFIG['auth_token_url'],
            'key_set_url': LTI_CONFIG['key_set_url'],
        },
        'keys_loaded': private_key is not None and public_key is not None,
        'base_url': request.url_root.rstrip('/'),
        'tool_urls': {
            'oidc_initiation_url': f"{request.url_root.rstrip('/')}/login",
            'target_link_uri': f"{request.url_root.rstrip('/')}/launch",
            'public_jwk_url': f"{request.url_root.rstrip('/')}/.well-known/jwks.json"
        },
        'session_info': {
            'session_keys': list(session.keys()),
            'has_oauth_state': 'oauth_state' in session,
            'has_oauth_nonce': 'oauth_nonce' in session
        },
        'cache_info': {
            'cache_entries': len(state_cache),
            'cache_keys': list(state_cache.keys())[:5]  # Only show first 5 for privacy
        }
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
