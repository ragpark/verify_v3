import os
import json
import jwt
import requests
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template_string, redirect, session, flash, url_for
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import uuid
import mimetypes

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

# Moodle API Configuration
MOODLE_CONFIG = {
    'url': os.environ.get('MOODLE_URL', LTI_CONFIG['iss']),
    'token': os.environ.get('MOODLE_API_TOKEN', ''),  # Moodle web service token
    'service': os.environ.get('MOODLE_SERVICE', 'moodle_mobile_app')  # Web service name
}

print(f"=== STARTUP INFO ===")
print(f"LTI_CONFIG: {LTI_CONFIG}")
print(f"MOODLE_CONFIG: {MOODLE_CONFIG}")
print(f"API Token configured: {bool(MOODLE_CONFIG['token'])}")

# Root route - test basic routing
@app.route('/')
def index():
    return jsonify({
        'message': 'LTI Tool Server - Debugging Version',
        'status': 'running',
        'timestamp': datetime.utcnow().isoformat(),
        'routes': [str(rule) for rule in app.url_map.iter_rules()]
    })

# Simple test route
@app.route('/test')
def test():
    return jsonify({
        'message': 'Test route working!',
        'timestamp': datetime.utcnow().isoformat()
    })

# Test route with parameter
@app.route('/test_param/<param_id>')
def test_param(param_id):
    return jsonify({
        'message': f'Parameter route working with ID: {param_id}',
        'query_params': dict(request.args),
        'timestamp': datetime.utcnow().isoformat()
    })

# File endpoint - simplified
@app.route('/get_user_files/<user_id>')
def get_user_files_simple(user_id):
    course_id = request.args.get('course_id', 'unknown')
    
    print(f"=== GET_USER_FILES CALLED ===")
    print(f"User ID: {user_id}")
    print(f"Course ID: {course_id}")
    print(f"Request URL: {request.url}")
    print(f"Request method: {request.method}")
    print(f"Request args: {dict(request.args)}")
    
    # Return simple response for now
    return jsonify({
        'success': True,
        'message': 'File endpoint reached successfully!',
        'user_id': user_id,
        'course_id': course_id,
        'timestamp': datetime.utcnow().isoformat(),
        'moodle_configured': bool(MOODLE_CONFIG['token'])
    })

# Moodle API test
@app.route('/test_moodle_api')
def test_moodle_api():
    if not MOODLE_CONFIG['token']:
        return jsonify({
            'success': False,
            'error': 'No API token configured'
        })
    
    # Simple API test
    url = f"{MOODLE_CONFIG['url']}/webservice/rest/server.php"
    data = {
        'wstoken': MOODLE_CONFIG['token'],
        'wsfunction': 'core_webservice_get_site_info',
        'moodlewsrestformat': 'json'
    }
    
    try:
        response = requests.post(url, data=data, timeout=30)
        result = response.json()
        
        return jsonify({
            'success': True,
            'moodle_url': MOODLE_CONFIG['url'],
            'response': result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

# Health check
@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat()
    })

# Debug route listing
@app.route('/debug_routes')
def debug_routes():
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append({
            'rule': str(rule),
            'endpoint': rule.endpoint,
            'methods': list(rule.methods)
        })
    
    return jsonify({
        'total_routes': len(routes),
        'routes': routes
    })

if __name__ == '__main__':
    print("=== STARTING SIMPLIFIED SERVER ===")
    print("Registered routes:")
    for rule in app.url_map.iter_rules():
        print(f"  {rule.rule} -> {rule.endpoint} {list(rule.methods)}")
    print("=== SERVER READY ===")
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
