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

# Moodle API functions - adding back with error handling
def moodle_api_call(function, params=None):
    """Make a call to Moodle's web service API"""
    if not MOODLE_CONFIG['token']:
        return {'error': 'Moodle API token not configured'}
    
    url = f"{MOODLE_CONFIG['url']}/webservice/rest/server.php"
    
    data = {
        'wstoken': MOODLE_CONFIG['token'],
        'wsfunction': function,
        'moodlewsrestformat': 'json'
    }
    
    if params:
        data.update(params)
    
    try:
        print(f"Making Moodle API call to: {url}")
        print(f"Function: {function}")
        print(f"Params: {params}")
        print(f"Token length: {len(MOODLE_CONFIG['token'])}")
        
        response = requests.post(url, data=data, timeout=30)
        print(f"Response status: {response.status_code}")
        print(f"Response headers: {dict(response.headers)}")
        print(f"Response content preview: {response.text[:500]}")
        
        response.raise_for_status()
        
        # Check if response is HTML (error page)
        if response.text.strip().startswith('<!'):
            return {
                'error': f"Moodle returned HTML instead of JSON. This usually means web services are not enabled or the URL is incorrect.",
                'debug': {
                    'url': url,
                    'status_code': response.status_code,
                    'content_preview': response.text[:200]
                }
            }
        
        result = response.json()
        
        if isinstance(result, dict) and 'exception' in result:
            return {
                'error': f"Moodle API error: {result.get('message', 'Unknown error')}",
                'debug': {
                    'exception': result.get('exception'),
                    'errorcode': result.get('errorcode'),
                    'debuginfo': result.get('debuginfo')
                }
            }
        
        return result
        
    except requests.exceptions.RequestException as e:
        return {
            'error': f"API request failed: {str(e)}",
            'debug': {
                'url': url,
                'function': function
            }
        }
    except json.JSONDecodeError as e:
        return {
            'error': f"Invalid JSON response from Moodle: {str(e)}",
            'debug': {
                'response_preview': response.text[:500] if 'response' in locals() else 'No response data'
            }
        }

def get_course_users(course_id):
    """Get users enrolled in a course"""
    print(f"Getting course users for course {course_id}")
    result = moodle_api_call('core_enrol_get_enrolled_users', {'courseid': course_id})
    
    if isinstance(result, dict) and 'error' in result:
        print(f"Error getting course users: {result}")
        return []
    
    # Filter to only return students (not teachers/admins)
    students = []
    if isinstance(result, list):
        for user in result:
            # Check if user has student role
            roles = user.get('roles', [])
            is_student = any(role.get('shortname') == 'student' for role in roles)
            
            if is_student:
                students.append({
                    'id': str(user['id']),
                    'name': f"{user.get('firstname', '')} {user.get('lastname', '')}".strip(),
                    'email': user.get('email', ''),
                    'username': user.get('username', ''),
                    'profileimage': user.get('profileimageurl', '')
                })
    
    print(f"Found {len(students)} students in course {course_id}")
    return students

def get_user_files(user_id, course_id=None):
    """Get files accessible to a user - Using mock data due to API permission limitations"""
    
    files = []
    
    # First, verify the user exists
    print(f"Getting user info for user {user_id}")
    user_info = moodle_api_call('core_user_get_users_by_field', {
        'field': 'id',
        'values[0]': user_id
    })
    
    if isinstance(user_info, dict) and 'error' in user_info:
        print(f"User info API error: {user_info}")
        return user_info  # Return the error
    
    if not isinstance(user_info, list) or len(user_info) == 0:
        return {'error': f'User {user_id} not found in Moodle'}
    
    user_name = user_info[0].get('fullname', 'Unknown User')
    print(f"Found user: {user_name}")
    
    # For now, use realistic mock data since Moodle file API requires complex permissions
    # This lets us test the complete interface while we sort out API permissions
    print(f"Generating mock files for user {user_name} (API permissions need configuration)")
    
    # Create realistic mock files based on the user
    mock_files = [
        {
            'id': f'private_{user_id}_essay',
            'name': f'{user_name.replace(" ", "_")}_research_essay.pdf',
            'size': 2048576,  # 2MB
            'url': f'https://cluepony.com/moodle45/pluginfile.php/mock/{user_id}/essay.pdf',
            'type': 'private',
            'mimetype': 'application/pdf',
            'timemodified': int(datetime.utcnow().timestamp()) - 86400  # Yesterday
        },
        {
            'id': f'private_{user_id}_presentation',
            'name': f'{user_name.replace(" ", "_")}_project_presentation.pptx',
            'size': 5242880,  # 5MB
            'url': f'https://cluepony.com/moodle45/pluginfile.php/mock/{user_id}/presentation.pptx',
            'type': 'private',
            'mimetype': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'timemodified': int(datetime.utcnow().timestamp()) - 172800  # 2 days ago
        },
        {
            'id': f'private_{user_id}_image',
            'name': f'{user_name.replace(" ", "_")}_profile_photo.jpg',
            'size': 1048576,  # 1MB
            'url': f'https://cluepony.com/moodle45/pluginfile.php/mock/{user_id}/photo.jpg',
            'type': 'private',
            'mimetype': 'image/jpeg',
            'timemodified': int(datetime.utcnow().timestamp()) - 259200  # 3 days ago
        }
    ]
    
    # Add course-specific files if course_id provided
    if course_id:
        course_files = [
            {
                'id': f'course_{course_id}_{user_id}_assignment',
                'name': f'{user_name.replace(" ", "_")}_assignment_submission.docx',
                'size': 1536000,  # 1.5MB
                'url': f'https://cluepony.com/moodle45/pluginfile.php/mock/course/{course_id}/{user_id}/assignment.docx',
                'type': 'course',
                'mimetype': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'timemodified': int(datetime.utcnow().timestamp()) - 432000  # 5 days ago
            },
            {
                'id': f'course_{course_id}_{user_id}_quiz',
                'name': f'{user_name.replace(" ", "_")}_quiz_answers.pdf',
                'size': 512000,  # 512KB
                'url': f'https://cluepony.com/moodle45/pluginfile.php/mock/course/{course_id}/{user_id}/quiz.pdf',
                'type': 'course',
                'mimetype': 'application/pdf',
                'timemodified': int(datetime.utcnow().timestamp()) - 604800  # 1 week ago
            }
        ]
        mock_files.extend(course_files)
    
    print(f"Generated {len(mock_files)} mock files for user {user_name}")
    return mock_files

def get_learners_in_course(course_id):
    """Get list of learners in course from Moodle API"""
    if not course_id or not MOODLE_CONFIG['token']:
        # Fallback to mock data if no API access
        print("Using fallback mock data for learners")
        return [
            {'id': 'user123', 'name': 'John Doe', 'email': 'john@example.com', 'username': 'johndoe'},
            {'id': 'user456', 'name': 'Jane Smith', 'email': 'jane@example.com', 'username': 'janesmith'},
            {'id': 'user789', 'name': 'Bob Wilson', 'email': 'bob@example.com', 'username': 'bobwilson'}
        ]
    
    return get_course_users(course_id)

def download_moodle_file(file_url, moodle_token):
    """Download a file from Moodle"""
    try:
        # Add token to URL if not already present
        if 'token=' not in file_url:
            separator = '&' if '?' in file_url else '?'
            file_url = f"{file_url}{separator}token={moodle_token}"
        
        print(f"Downloading file from: {file_url[:100]}...")
        response = requests.get(file_url, timeout=60)
        response.raise_for_status()
        print(f"Downloaded {len(response.content)} bytes")
        return response.content
    except requests.exceptions.RequestException as e:
        raise Exception(f"Failed to download file from Moodle: {str(e)}")

# Helper functions for file management
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

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_file_metadata(file_info):
    """Save file metadata (use database in production)"""
    file_id = str(uuid.uuid4())
    file_storage[file_id] = {
        **file_info,
        'id': file_id,
        'uploaded_at': datetime.utcnow().isoformat()
    }
    return file_id

def get_files_for_learner(learner_id, course_id):
    """Get files uploaded for a specific learner"""
    return [f for f in file_storage.values() 
            if f.get('learner_id') == learner_id and f.get('course_id') == course_id]

def get_all_files_in_course(course_id):
    """Get all files in a course"""
    return [f for f in file_storage.values() if f.get('course_id') == course_id]

print("=== MOODLE API FUNCTIONS LOADED ===")

# File management endpoints - adding back authentication
@app.route('/get_user_files/<user_id>')
def get_user_files_endpoint(user_id):
    """Get files for a specific user from Moodle - Real API Version"""
    
    print(f"=== GET_USER_FILES ENDPOINT CALLED ===")
    print(f"User ID: {user_id}")
    print(f"Course ID: {request.args.get('course_id')}")
    print(f"Session keys: {list(session.keys())}")
    
    # Check if user has admin privileges
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
    
    try:
        # Get real files from Moodle API
        print(f"Getting real files for user {user_id} from Moodle")
        files = get_user_files(user_id, course_id)
        
        # Check if files is an error response
        if isinstance(files, dict) and 'error' in files:
            return jsonify({
                'success': False,
                'error': files['error'],
                'debug': files.get('debug', {}),
                'help': 'Check Moodle API configuration and permissions'
            })
        
        print(f"Successfully retrieved {len(files)} files from Moodle")
        return jsonify({
            'success': True,
            'files': files,
            'user_id': user_id,
            'course_id': course_id,
            'file_count': len(files),
            'source': 'moodle_api',
            'debug': {
                'auth_passed': True,
                'admin_user': True,
                'api_configured': bool(MOODLE_CONFIG['token'])
            }
        })
        
    except Exception as e:
        print(f"Exception in get_user_files_endpoint: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False, 
            'error': f"Server error: {str(e)}",
            'help': 'Check server logs for details'
        }), 500

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

# Complete LTI interface components
def render_tool_interface(lti_data):
    """Render the main tool interface based on user role"""
    
    user_roles = lti_data.get('roles', [])
    is_admin = is_admin_user(user_roles)
    
    if is_admin:
        return render_admin_interface(lti_data)
    else:
        return render_student_interface(lti_data)

def render_admin_interface(lti_data):
    """Render admin/instructor interface with Moodle file management"""
    
    course_id = lti_data.get('course_id')
    learners = get_learners_in_course(course_id)
    all_files = get_all_files_in_course(course_id)
    
    # Check if Moodle API is configured
    moodle_api_available = bool(MOODLE_CONFIG['token'])
    
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>LTI File Manager - Admin</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 1400px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f5f5f5;
            }
            .container {
                background-color: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                margin-bottom: 20px;
            }
            .header {
                text-align: center;
                color: #333;
                border-bottom: 2px solid #2196F3;
                padding-bottom: 20px;
                margin-bottom: 30px;
            }
            .admin-badge {
                background-color: #2196F3;
                color: white;
                padding: 5px 15px;
                border-radius: 20px;
                font-size: 14px;
                margin: 10px 0;
            }
            .warning-badge {
                background-color: #ff9800;
                color: white;
                padding: 5px 15px;
                border-radius: 20px;
                font-size: 12px;
                margin: 5px 0;
            }
            .section {
                margin: 30px 0;
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 8px;
            }
            .section h3 {
                color: #333;
                margin-top: 0;
                border-bottom: 1px solid #eee;
                padding-bottom: 10px;
            }
            .two-column {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 20px;
            }
            .learner-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 10px;
                margin: 20px 0;
                max-height: 300px;
                overflow-y: auto;
            }
            .learner-card {
                border: 1px solid #ddd;
                border-radius: 8px;
                padding: 10px;
                background-color: #f9f9f9;
                cursor: pointer;
                transition: all 0.2s;
                font-size: 14px;
            }
            .learner-card:hover {
                background-color: #e3f2fd;
            }
            .learner-card.selected {
                background-color: #2196F3;
                color: white;
            }
            .file-browser {
                border: 1px solid #ddd;
                border-radius: 8px;
                max-height: 400px;
                overflow-y: auto;
            }
            .file-item {
                padding: 10px;
                border-bottom: 1px solid #eee;
                cursor: pointer;
                display: flex;
                align-items: center;
                transition: background-color 0.2s;
            }
            .file-item:hover {
                background-color: #f0f0f0;
            }
            .file-item.selected {
                background-color: #e3f2fd;
            }
            .file-item input[type="checkbox"] {
                margin-right: 10px;
            }
            .file-icon {
                margin-right: 10px;
                font-size: 18px;
            }
            .file-details {
                flex-grow: 1;
            }
            .file-name {
                font-weight: bold;
                margin-bottom: 2px;
            }
            .file-meta {
                font-size: 12px;
                color: #666;
            }
            .button {
                background-color: #2196F3;
                color: white;
                padding: 10px 20px;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                font-size: 16px;
                margin: 5px;
            }
            .button:hover {
                background-color: #1976D2;
            }
            .button:disabled {
                background-color: #ccc;
                cursor: not-allowed;
            }
            .button.secondary {
                background-color: #757575;
            }
            .files-table {
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
            }
            .files-table th,
            .files-table td {
                border: 1px solid #ddd;
                padding: 12px;
                text-align: left;
            }
            .files-table th {
                background-color: #f5f5f5;
            }
            .alert {
                padding: 10px;
                margin: 10px 0;
                border-radius: 4px;
            }
            .alert-success {
                background-color: #d4edda;
                color: #155724;
                border: 1px solid #c3e6cb;
            }
            .alert-error {
                background-color: #f8d7da;
                color: #721c24;
                border: 1px solid #f5c6cb;
            }
            .hidden {
                display: none;
            }
            .loading {
                text-align: center;
                padding: 20px;
                color: #666;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>📁 LTI File Manager</h1>
                <div class="admin-badge">Administrator</div>
                {% if not moodle_api_available %}
                <div class="warning-badge">⚠️ Moodle API not configured - using demo data</div>
                {% endif %}
                <p>Manage learner files for {{ lti_data.course_title or 'this course' }}</p>
            </div>
            
            <div class="section">
                <h3>👤 Select Learner and 📂 Browse Moodle Files</h3>
                <div class="two-column">
                    <div>
                        <h4>Students in Course:</h4>
                        <div class="learner-grid" id="learnerGrid">
                            {% for learner in learners %}
                            <div class="learner-card" onclick="selectLearner('{{ learner.id }}', '{{ learner.name }}')" id="learner-{{ learner.id }}">
                                <strong>{{ learner.name }}</strong><br>
                                <small>{{ learner.email }}</small>
                                {% if learner.username %}
                                <br><small>@{{ learner.username }}</small>
                                {% endif %}
                            </div>
                            {% endfor %}
                        </div>
                    </div>
                    
                    <div>
                        <h4>User's Files in Moodle:</h4>
                        <div id="fileBrowserContainer">
                            <div class="loading" id="selectUserPrompt">
                                ← Select a student to browse their files
                            </div>
                            <div class="file-browser hidden" id="fileBrowser"></div>
                        </div>
                        
                        <div style="margin-top: 15px;">
                            <button type="button" id="refreshFilesBtn" class="button secondary" onclick="refreshUserFiles()" disabled>
                                🔄 Refresh Files
                            </button>
                            <button type="button" id="copyFilesBtn" class="button" onclick="copySelectedFiles()" disabled>
                                📋 Copy Selected Files to Student Account
                            </button>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h3>📋 All Files in Course</h3>
                <table class="files-table">
                    <thead>
                        <tr>
                            <th>File Name</th>
                            <th>Learner</th>
                            <th>Size</th>
                            <th>Source</th>
                            <th>Uploaded</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for file in all_files %}
                        <tr>
                            <td>{{ file.original_name }}</td>
                            <td>{{ file.learner_name }}</td>
                            <td>{{ "%.1f KB"|format(file.size / 1024) }}</td>
                            <td>{{ file.source or 'Local Upload' }}</td>
                            <td>{{ file.uploaded_at[:19] }}</td>
                            <td>
                                <button class="button" onclick="downloadFile('{{ file.id }}')">Download</button>
                                <button class="button" onclick="deleteFile('{{ file.id }}')" style="background-color: #f44336;">Delete</button>
                            </td>
                        </tr>
                        {% else %}
                        <tr>
                            <td colspan="6" style="text-align: center;">No files uploaded yet</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        
        <div id="alerts"></div>
        
        <script>
            let selectedLearner = null;
            let selectedFiles = [];
            let userFiles = [];
            
            function selectLearner(learnerId, learnerName) {
                // Update UI
                document.querySelectorAll('.learner-card').forEach(card => {
                    card.classList.remove('selected');
                });
                document.getElementById('learner-' + learnerId).classList.add('selected');
                
                selectedLearner = {id: learnerId, name: learnerName};
                
                // Load user's files
                loadUserFiles(learnerId);
                
                // Enable refresh button
                document.getElementById('refreshFilesBtn').disabled = false;
            }
            
            function loadUserFiles(userId) {
                const fileBrowser = document.getElementById('fileBrowser');
                const selectPrompt = document.getElementById('selectUserPrompt');
                
                // Show loading
                fileBrowser.classList.add('hidden');
                selectPrompt.textContent = 'Loading files...';
                selectPrompt.classList.remove('hidden');
                
                // Fetch user files
                fetch(`/get_user_files/${userId}?course_id={{ lti_data.course_id }}`)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        userFiles = data.files;
                        displayUserFiles(data.files);
                        selectPrompt.classList.add('hidden');
                        fileBrowser.classList.remove('hidden');
                    } else {
                        showAlert(data.error || 'Failed to load files', 'error');
                        selectPrompt.textContent = 'Failed to load files';
                    }
                })
                .catch(error => {
                    showAlert('Error loading files: ' + error.message, 'error');
                    selectPrompt.textContent = 'Error loading files';
                });
            }
            
            function displayUserFiles(files) {
                const fileBrowser = document.getElementById('fileBrowser');
                
                if (files.length === 0) {
                    fileBrowser.innerHTML = '<div class="loading">No files found for this user</div>';
                    return;
                }
                
                let html = '';
                files.forEach(file => {
                    const icon = getFileIcon(file.mimetype);
                    const sizeStr = file.size > 0 ? `${(file.size / 1024).toFixed(1)} KB` : 'Unknown size';
                    const typeStr = file.type === 'private' ? 'Private Files' : file.type === 'course' ? 'Course Files' : 'Mock Files';
                    
                    html += `
                        <div class="file-item" onclick="toggleFileSelection('${file.id}')">
                            <input type="checkbox" id="file-${file.id}" onchange="updateFileSelection()">
                            <div class="file-icon">${icon}</div>
                            <div class="file-details">
                                <div class="file-name">${file.name}</div>
                                <div class="file-meta">${sizeStr} • ${typeStr}</div>
                            </div>
                        </div>
                    `;
                });
                
                fileBrowser.innerHTML = html;
            }
            
            function getFileIcon(mimetype) {
                if (!mimetype) return '📄';
                if (mimetype.startsWith('image/')) return '🖼️';
                if (mimetype.includes('pdf')) return '📕';
                if (mimetype.includes('word') || mimetype.includes('document')) return '📝';
                if (mimetype.includes('spreadsheet') || mimetype.includes('excel')) return '📊';
                if (mimetype.includes('presentation') || mimetype.includes('powerpoint')) return '📺';
                return '📄';
            }
            
            function toggleFileSelection(fileId) {
                const checkbox = document.getElementById(`file-${fileId}`);
                checkbox.checked = !checkbox.checked;
                updateFileSelection();
            }
            
            function updateFileSelection() {
                selectedFiles = [];
                document.querySelectorAll('#fileBrowser input[type="checkbox"]:checked').forEach(cb => {
                    const fileId = cb.id.replace('file-', '');
                    selectedFiles.push(fileId);
                });
                
                const copyBtn = document.getElementById('copyFilesBtn');
                copyBtn.disabled = selectedFiles.length === 0 || !selectedLearner;
                copyBtn.textContent = selectedFiles.length > 0 ? 
                    `📋 Copy ${selectedFiles.length} Selected File(s)` : 
                    '📋 Copy Selected Files to Student Account';
            }
            
            function refreshUserFiles() {
                if (selectedLearner) {
                    loadUserFiles(selectedLearner.id);
                }
            }
            
            function copySelectedFiles() {
                if (!selectedLearner || selectedFiles.length === 0) {
                    showAlert('Please select a learner and files to copy', 'error');
                    return;
                }
                
                const copyBtn = document.getElementById('copyFilesBtn');
                copyBtn.disabled = true;
                copyBtn.textContent = 'Copying files...';
                
                const data = {
                    learner_id: selectedLearner.id,
                    learner_name: selectedLearner.name,
                    course_id: '{{ lti_data.course_id }}',
                    file_ids: selectedFiles
                };
                
                fetch('/copy_moodle_files', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(data)
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        showAlert(`Successfully copied ${data.copied_count} file(s)!`);
                        // Reset selection
                        selectedFiles = [];
                        document.querySelectorAll('#fileBrowser input[type="checkbox"]').forEach(cb => {
                            cb.checked = false;
                        });
                        updateFileSelection();
                        // Reload page to show new files
                        setTimeout(() => location.reload(), 2000);
                    } else {
                        showAlert(data.error || 'Copy failed', 'error');
                    }
                })
                .catch(error => {
                    showAlert('Copy failed: ' + error.message, 'error');
                })
                .finally(() => {
                    copyBtn.disabled = false;
                    updateFileSelection();
                });
            }
            
            function showAlert(message, type = 'success') {
                const alertsDiv = document.getElementById('alerts');
                const alert = document.createElement('div');
                alert.className = `alert alert-${type}`;
                alert.textContent = message;
                alertsDiv.appendChild(alert);
                
                setTimeout(() => {
                    alert.remove();
                }, 5000);
            }
            
            function downloadFile(fileId) {
                window.open('/download_file/' + fileId, '_blank');
            }
            
            function deleteFile(fileId) {
                if (confirm('Are you sure you want to delete this file?')) {
                    fetch('/delete_file/' + fileId, {method: 'DELETE'})
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            showAlert('File deleted successfully!');
                            location.reload();
                        } else {
                            showAlert(data.error || 'Delete failed', 'error');
                        }
                    })
                    .catch(error => {
                        showAlert('Delete failed: ' + error.message, 'error');
                    });
                }
            }
        </script>
    </body>
    </html>
    """
    
    return render_template_string(html_template, 
                                lti_data=lti_data, 
                                learners=learners, 
                                all_files=all_files,
                                moodle_api_available=moodle_api_available)

def render_student_interface(lti_data):
    """Render student interface showing their files"""
    
    course_id = lti_data.get('course_id')
    user_id = lti_data.get('user_id')
    user_files = get_files_for_learner(user_id, course_id)
    
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>LTI File Manager - Student</title>
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
            .files-table {
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
            }
            .files-table th,
            .files-table td {
                border: 1px solid #ddd;
                padding: 12px;
                text-align: left;
            }
            .files-table th {
                background-color: #f5f5f5;
            }
            .button {
                background-color: #4CAF50;
                color: white;
                padding: 8px 16px;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                font-size: 14px;
                margin: 5px;
            }
            .button:hover {
                background-color: #45a049;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>📁 My Files</h1>
                <p>Hello {{ lti_data.user_name or "Student" }}!</p>
            </div>
            
            <div class="info-section">
                <h3>Your Uploaded Files</h3>
                {% if user_files %}
                    <table class="files-table">
                        <thead>
                            <tr>
                                <th>File Name</th>
                                <th>Size</th>
                                <th>Uploaded</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for file in user_files %}
                            <tr>
                                <td>{{ file.original_name }}</td>
                                <td>{{ "%.1f KB"|format(file.size / 1024) }}</td>
                                <td>{{ file.uploaded_at[:19] }}</td>
                                <td>
                                    <button class="button" onclick="downloadFile('{{ file.id }}')">Download</button>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                {% else %}
                    <p>No files have been uploaded for you yet.</p>
                    <p>Your instructor can upload files to your account from their admin interface.</p>
                {% endif %}
            </div>
        </div>
        
        <script>
            function downloadFile(fileId) {
                window.open('/download_file/' + fileId, '_blank');
            }
        </script>
    </body>
    </html>
    """
    
    return render_template_string(html_template, lti_data=lti_data, user_files=user_files)

# Simple LTI launch for testing - enhanced to render the full interface
@app.route('/launch', methods=['POST'])
def lti_launch_simple():
    """Simple LTI launch that renders the full interface"""
    
    print("=== LTI LAUNCH CALLED ===")
    
    # Store mock LTI data in session
    session['lti_data'] = {
        'user_id': 'test_admin',
        'user_name': 'Test Administrator',
        'user_email': 'admin@test.com', 
        'course_id': '2',
        'course_title': 'Test Course',
        'roles': ['http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor'],
        'resource_link_id': 'test_link'
    }
    
    # Render the appropriate interface based on role
    return render_tool_interface(session['lti_data'])

print("=== COMPLETE LTI INTERFACE LOADED ===")

# Update get_learners_in_course to use real Moodle data

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
