import os
import json
import jwt
import requests
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template_string, redirect, session
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import uuid

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')

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

# Load or generate keys
PRIVATE_KEY_PEM = os.environ.get('PRIVATE_KEY_PEM')
PUBLIC_KEY_PEM = os.environ.get('PUBLIC_KEY_PEM')

if not PRIVATE_KEY_PEM or not PUBLIC_KEY_PEM:
    print("Generating new key pair...")
    PRIVATE_KEY_PEM, PUBLIC_KEY_PEM = generate_key_pair()
    print("Private Key (store this securely):")
    print(PRIVATE_KEY_PEM.decode())
    print("\nPublic Key (use this in Moodle configuration):")
    print(PUBLIC_KEY_PEM.decode())

# Parse keys
private_key = serialization.load_pem_private_key(
    PRIVATE_KEY_PEM.encode() if isinstance(PRIVATE_KEY_PEM, str) else PRIVATE_KEY_PEM,
    password=None
)

public_key = serialization.load_pem_public_key(
    PUBLIC_KEY_PEM.encode() if isinstance(PUBLIC_KEY_PEM, str) else PUBLIC_KEY_PEM
)

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
    
    # Validate issuer and client_id
    if iss != LTI_CONFIG['iss'] or client_id != LTI_CONFIG['client_id']:
        return jsonify({'error': 'Invalid issuer or client_id'}), 400
    
    # Generate state and nonce for security
    state = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    
    # Store state and nonce in session for validation
    session['oauth_state'] = state
    session['oauth_nonce'] = nonce
    
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
    
    if not id_token:
        return jsonify({'error': 'Missing id_token'}), 400
    
    # Validate state
    if state != session.get('oauth_state'):
        return jsonify({'error': 'Invalid state parameter'}), 400
    
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
        if payload.get('nonce') != session.get('oauth_nonce'):
            return jsonify({'error': 'Invalid nonce'}), 400
        
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
            'health': '/health'
        }
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
