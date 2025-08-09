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

# File storage configuration
UPLOAD_FOLDER = '/tmp/lti_files'  # Railway.app temp storage
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB

# Create upload directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# In-memory storage for file metadata (use database in production)
file_storage = {}

# Add RSA key generation - with error handling
def generate_key_pair():
    """Generate RSA key pair for JWT signing"""
    try:
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
    except Exception as e:
        print(f"ERROR in generate_key_pair: {e}")
        raise

# Helper function to fix PEM format
def fix_pem_format(pem_string, key_type='PRIVATE'):
    """Fix PEM format by ensuring proper line breaks"""
    if not pem_string:
        return None
    
    try:
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
    except Exception as e:
        print(f"ERROR in fix_pem_format: {e}")
        return None

# Load or generate keys - with comprehensive error handling
print("=== LOADING RSA KEYS ===")

PRIVATE_KEY_PEM = os.environ.get('PRIVATE_KEY_PEM')
PUBLIC_KEY_PEM = os.environ.get('PUBLIC_KEY_PEM')
PRIVATE_KEY_B64 = os.environ.get('PRIVATE_KEY_B64')
PUBLIC_KEY_B64 = os.environ.get('PUBLIC_KEY_B64')

private_key = None
public_key = None

try:
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

except Exception as e:
    print(f"CRITICAL ERROR in key loading: {e}")
    import traceback
    traceback.print_exc()
    # Don't crash the app, but flag the issue
    private_key = None
    public_key = None

print(f"Keys loaded successfully: {private_key is not None and public_key is not None}")

# Test if keys work
if private_key and public_key:
    try:
        # Test signing
        test_data = b"test"
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        
        signature = private_key.sign(test_data, padding.PKCS1v15(), hashes.SHA256())
        public_key.verify(signature, test_data, padding.PKCS1v15(), hashes.SHA256())
        print("Key pair validation successful")
    except Exception as e:
        print(f"Key pair validation failed: {e}")

print("=== KEY LOADING COMPLETE ===")

app.config.update(
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    MAX_CONTENT_LENGTH=MAX_FILE_SIZE
)

print(f"=== STARTUP INFO ===")
print(f"LTI_CONFIG: {LTI_CONFIG}")
print(f"MOODLE_CONFIG: {MOODLE_CONFIG}")
print(f"API Token configured: {bool(MOODLE_CONFIG['token'])}")
print(f"Keys loaded: {private_key is not None and public_key is not None}")
print(f"Upload folder: {UPLOAD_FOLDER}")
print(f"File storage initialized: {len(file_storage)} files")

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

# Helper functions - adding back gradually
def is_admin_user(roles):
    """Check if user has admin/instructor privileges"""
    admin_roles = [
        'http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor',
        'http://purl.imsglobal.org/vocab/lis/v2/membership#ContentDeveloper',
        'http://purl.imsglobal.org/vocab/lis/v2/system/person#Administrator',
        'Instructor',
        'Teacher',
        'Admin'
    ]
    return any(role in admin_roles for role in (roles or []))

# File management endpoints - adding back authentication
@app.route('/get_user_files/<user_id>')
def get_user_files_endpoint(user_id):
    """Get files for a specific user from Moodle - With Auth"""
    
    print(f"=== GET_USER_FILES ENDPOINT CALLED ===")
    print(f"User ID: {user_id}")
    print(f"Course ID: {request.args.get('course_id')}")
    print(f"Session keys: {list(session.keys())}")
    
    # Check if user has admin privileges - with better error handling
    lti_data = session.get('lti_data')
    if not lti_data:
        print("No LTI data in session")
        return jsonify({
            'success': False, 
            'error': 'Not authorized - no LTI session data',
            'help': 'Try launching the tool from Moodle first',
            'debug': {
                'session_keys': list(session.keys()),
                'has_lti_data': False
            }
        }), 403
    
    user_roles = lti_data.get('roles', [])
    print(f"User roles: {user_roles}")
    
    if not is_admin_user(user_roles):
        print("User is not admin")
        return jsonify({
            'success': False, 
            'error': 'Admin privileges required',
            'debug': {
                'user_roles': user_roles,
                'admin_check': False
            }
        }), 403
    
    course_id = request.args.get('course_id')
    
    # Check if API is configured
    if not MOODLE_CONFIG['token']:
        print("Moodle API not configured")
        return jsonify({
            'success': False,
            'error': 'Moodle API not configured',
            'help': 'Set MOODLE_API_TOKEN environment variable',
            'debug': {
                'token_configured': False
            }
        })
    
    # Return mock data for now (we'll add real API calls later)
    mock_files = [
        {
            'id': 'private_file1',
            'name': 'student_essay.pdf',
            'size': 1024000,
            'type': 'private',
            'mimetype': 'application/pdf',
            'url': 'https://example.com/file1'
        },
        {
            'id': 'course_file2', 
            'name': 'lecture_slides.pptx',
            'size': 2048000,
            'type': 'course',
            'mimetype': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'url': 'https://example.com/file2'
        }
    ]
    
    print(f"Returning {len(mock_files)} mock files")
    return jsonify({
        'success': True,
        'files': mock_files,
        'user_id': user_id,
        'course_id': course_id,
        'file_count': len(mock_files),
        'debug': {
            'auth_passed': True,
            'admin_user': True,
            'api_configured': bool(MOODLE_CONFIG['token'])
        }
    })

# Test route to set up proper LTI session
@app.route('/setup_session')
def setup_session():
    """Set up a proper LTI session for testing"""
    
    session['lti_data'] = {
        'user_id': 'test_admin',
        'user_name': 'Test Administrator', 
        'user_email': 'admin@test.com',
        'course_id': '2',
        'course_title': 'Test Course',
        'roles': ['http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor'],
        'resource_link_id': 'test_link'
    }
    
    return jsonify({
        'success': True,
        'message': 'LTI session data set up',
        'lti_data': session['lti_data']
    })

# Test route to clear session
@app.route('/clear_session')
def clear_session():
    """Clear the session for testing"""
    session.clear()
    
    return jsonify({
        'success': True,
        'message': 'Session cleared',
        'session_data': dict(session)
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
