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
        'message': 'LTI Tool Server - Enhanced Debugging Version',
        'status': 'running',
        'timestamp': datetime.utcnow().isoformat(),
        'moodle_configured': bool(MOODLE_CONFIG['token']),
        'endpoints': {
            'get_user_files': '/get_user_files/<user_id>',
            'copy_files': '/copy_moodle_files',
            'upload_files': '/upload_files', 
            'download_file': '/download_file/<file_id>',
            'delete_file': '/delete_file/<file_id>',
            'lti_launch': '/launch',
            'test_session': '/test_session',
            'debug_routes': '/debug_routes'
        },
        'total_routes': len(list(app.url_map.iter_rules())),
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

# File management endpoints - adding back gradually
@app.route('/get_user_files/<user_id>')
def get_user_files_endpoint(user_id):
    """Get files for a specific user from Moodle - Enhanced Version"""
    
    print(f"=== GET_USER_FILES ENDPOINT CALLED ===")
    print(f"User ID: {user_id}")
    print(f"Course ID: {request.args.get('course_id')}")
    print(f"Session keys: {list(session.keys())}")
    print(f"Request method: {request.method}")
    print(f"Request URL: {request.url}")
    
    course_id = request.args.get('course_id')
    
    # Check if we have session data (without failing if we don't)
    lti_data = session.get('lti_data')
    if lti_data:
        print(f"LTI data found in session")
        user_roles = lti_data.get('roles', [])
        print(f"User roles: {user_roles}")
    else:
        print("No LTI data in session - continuing anyway for testing")
    
    # For now, return mock data
    mock_files = [
        {
            'id': 'file_1',
            'name': 'sample_document.pdf',
            'size': 1024000,
            'type': 'private',
            'mimetype': 'application/pdf'
        },
        {
            'id': 'file_2', 
            'name': 'course_image.jpg',
            'size': 512000,
            'type': 'course',
            'mimetype': 'image/jpeg'
        }
    ]
    
    return jsonify({
        'success': True,
        'files': mock_files,
        'user_id': user_id,
        'course_id': course_id,
        'file_count': len(mock_files),
        'session_available': lti_data is not None,
        'moodle_configured': bool(MOODLE_CONFIG['token'])
    })

# Add more file endpoints
@app.route('/copy_moodle_files', methods=['POST'])
def copy_moodle_files():
    """Copy selected files from Moodle - Mock Version"""
    
    print("=== COPY_MOODLE_FILES ENDPOINT CALLED ===")
    
    try:
        data = request.json or {}
        print(f"Request data: {data}")
        
        return jsonify({
            'success': True,
            'copied_count': len(data.get('file_ids', [])),
            'message': 'Mock copy operation completed'
        })
        
    except Exception as e:
        print(f"Error in copy_moodle_files: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/upload_files', methods=['POST'])
def upload_files():
    """Handle file uploads - Mock Version"""
    
    print("=== UPLOAD_FILES ENDPOINT CALLED ===")
    
    try:
        # Check form data
        learner_id = request.form.get('learner_id')
        course_id = request.form.get('course_id')
        files = request.files.getlist('files')
        
        print(f"Upload request: learner={learner_id}, course={course_id}, files={len(files)}")
        
        return jsonify({
            'success': True,
            'uploaded_count': len(files),
            'message': 'Mock upload operation completed'
        })
        
    except Exception as e:
        print(f"Error in upload_files: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/download_file/<file_id>')
def download_file(file_id):
    """Download a file - Mock Version"""
    
    print(f"=== DOWNLOAD_FILE ENDPOINT CALLED: {file_id} ===")
    
    return jsonify({
        'message': f'Mock download for file {file_id}',
        'file_id': file_id
    })

@app.route('/delete_file/<file_id>', methods=['DELETE'])
def delete_file(file_id):
    """Delete a file - Mock Version"""
    
    print(f"=== DELETE_FILE ENDPOINT CALLED: {file_id} ===")
    
    return jsonify({
        'success': True,
        'message': f'Mock delete for file {file_id}',
        'file_id': file_id
    })

# Simple LTI launch for testing
@app.route('/launch', methods=['POST'])
def lti_launch_simple():
    """Simple LTI launch for testing"""
    
    print("=== LTI LAUNCH CALLED ===")
    
    # Store some mock LTI data in session
    session['lti_data'] = {
        'user_id': 'test_user',
        'user_name': 'Test User',
        'course_id': '2',
        'course_title': 'Test Course',
        'roles': ['http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor']
    }
    
    return jsonify({
        'success': True,
        'message': 'Mock LTI launch completed',
        'lti_data': session['lti_data']
    })

# Test session endpoint
@app.route('/test_session')
def test_session():
    """Test session storage"""
    
    # Set some test data
    session['test_key'] = 'test_value'
    session['timestamp'] = datetime.utcnow().isoformat()
    
    return jsonify({
        'session_data': dict(session),
        'session_id': session.get('_id', 'no_id')
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
