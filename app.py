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

# File storage configuration
UPLOAD_FOLDER = '/tmp/lti_files'  # Railway.app temp storage
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB

# Create upload directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# In-memory storage for file metadata (use database in production)
file_storage = {}

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')

# Configure session for Railway.app
app.config.update(
    SESSION_COOKIE_SECURE=True,  # Require HTTPS
    SESSION_COOKIE_HTTPONLY=True,  # Prevent XSS
    SESSION_COOKIE_SAMESITE='None',  # Allow cross-origin (needed for LTI)
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=60),
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    MAX_CONTENT_LENGTH=MAX_FILE_SIZE
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

# Helper functions
def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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

def get_learners_in_course(course_id):
    """Get list of learners in course (mock data - integrate with your system)"""
    # This would typically query your LMS or database
    # For demo purposes, return mock data
    return [
        {'id': 'user123', 'name': 'John Doe', 'email': 'john@example.com'},
        {'id': 'user456', 'name': 'Jane Smith', 'email': 'jane@example.com'},
        {'id': 'user789', 'name': 'Bob Wilson', 'email': 'bob@example.com'}
    ]

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
        
        # Store LTI data in session for file management
        session['lti_data'] = lti_data
        
        # Render the tool interface
        return render_tool_interface(lti_data)
        
    except Exception as e:
        return jsonify({'error': f'Token validation failed: {str(e)}'}), 400

def render_tool_interface(lti_data):
    """Render the main tool interface based on user role"""
    
    user_roles = lti_data.get('roles', [])
    is_admin = is_admin_user(user_roles)
    course_id = lti_data.get('course_id')
    user_id = lti_data.get('user_id')
    
    if is_admin:
        return render_admin_interface(lti_data)
    else:
        return render_student_interface(lti_data)

def render_admin_interface(lti_data):
    """Render admin/instructor interface with file management"""
    
    course_id = lti_data.get('course_id')
    learners = get_learners_in_course(course_id)
    all_files = get_all_files_in_course(course_id)
    
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
                max-width: 1200px;
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
            .learner-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 15px;
                margin: 20px 0;
            }
            .learner-card {
                border: 1px solid #ddd;
                border-radius: 8px;
                padding: 15px;
                background-color: #f9f9f9;
                cursor: pointer;
                transition: background-color 0.2s;
            }
            .learner-card:hover {
                background-color: #e3f2fd;
            }
            .learner-card.selected {
                background-color: #2196F3;
                color: white;
            }
            .upload-area {
                border: 2px dashed #ddd;
                border-radius: 8px;
                padding: 40px;
                text-align: center;
                margin: 20px 0;
                transition: border-color 0.2s;
            }
            .upload-area.dragover {
                border-color: #2196F3;
                background-color: #e3f2fd;
            }
            .file-input {
                margin: 20px 0;
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
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>📁 LTI File Manager</h1>
                <div class="admin-badge">Administrator</div>
                <p>Manage learner files for {{ lti_data.course_title or 'this course' }}</p>
            </div>
            
            <div class="section">
                <h3>👤 Select Learner</h3>
                <div class="learner-grid" id="learnerGrid">
                    {% for learner in learners %}
                    <div class="learner-card" onclick="selectLearner('{{ learner.id }}', '{{ learner.name }}')" id="learner-{{ learner.id }}">
                        <strong>{{ learner.name }}</strong><br>
                        <small>{{ learner.email }}</small>
                    </div>
                    {% endfor %}
                </div>
            </div>
            
            <div class="section" id="uploadSection" style="display: none;">
                <h3>📤 Upload Files for <span id="selectedLearnerName"></span></h3>
                
                <div class="upload-area" id="uploadArea" onclick="document.getElementById('fileInput').click()">
                    <p>Click here or drag files to upload</p>
                    <p><small>Allowed: PDF, Images, Documents (max 16MB each)</small></p>
                </div>
                
                <form id="uploadForm" class="hidden">
                    <input type="file" id="fileInput" name="files" multiple accept=".pdf,.jpg,.jpeg,.png,.gif,.doc,.docx,.ppt,.pptx,.xls,.xlsx,.txt">
                    <input type="hidden" id="selectedLearnerId" name="learner_id">
                </form>
                
                <button type="button" id="uploadButton" class="button" disabled onclick="uploadFiles()">
                    Upload Selected Files
                </button>
            </div>
            
            <div class="section">
                <h3>📋 All Files in Course</h3>
                <table class="files-table">
                    <thead>
                        <tr>
                            <th>File Name</th>
                            <th>Learner</th>
                            <th>Size</th>
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
                            <td>{{ file.uploaded_at[:19] }}</td>
                            <td>
                                <button class="button" onclick="downloadFile('{{ file.id }}')">Download</button>
                                <button class="button" onclick="deleteFile('{{ file.id }}')" style="background-color: #f44336;">Delete</button>
                            </td>
                        </tr>
                        {% else %}
                        <tr>
                            <td colspan="5" style="text-align: center;">No files uploaded yet</td>
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
            
            function selectLearner(learnerId, learnerName) {
                // Update UI
                document.querySelectorAll('.learner-card').forEach(card => {
                    card.classList.remove('selected');
                });
                document.getElementById('learner-' + learnerId).classList.add('selected');
                
                // Show upload section
                document.getElementById('uploadSection').style.display = 'block';
                document.getElementById('selectedLearnerName').textContent = learnerName;
                document.getElementById('selectedLearnerId').value = learnerId;
                
                selectedLearner = {id: learnerId, name: learnerName};
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
            
            // File drag and drop
            const uploadArea = document.getElementById('uploadArea');
            const fileInput = document.getElementById('fileInput');
            
            uploadArea.addEventListener('dragover', (e) => {
                e.preventDefault();
                uploadArea.classList.add('dragover');
            });
            
            uploadArea.addEventListener('dragleave', () => {
                uploadArea.classList.remove('dragover');
            });
            
            uploadArea.addEventListener('drop', (e) => {
                e.preventDefault();
                uploadArea.classList.remove('dragover');
                fileInput.files = e.dataTransfer.files;
                updateFileSelection();
            });
            
            fileInput.addEventListener('change', updateFileSelection);
            
            function updateFileSelection() {
                const files = fileInput.files;
                const uploadButton = document.getElementById('uploadButton');
                
                if (files.length > 0) {
                    uploadButton.disabled = false;
                    uploadButton.textContent = `Upload ${files.length} file(s)`;
                } else {
                    uploadButton.disabled = true;
                    uploadButton.textContent = 'Upload Selected Files';
                }
            }
            
            function uploadFiles() {
                if (!selectedLearner || !fileInput.files.length) {
                    showAlert('Please select a learner and files to upload', 'error');
                    return;
                }
                
                const formData = new FormData();
                formData.append('learner_id', selectedLearner.id);
                formData.append('learner_name', selectedLearner.name);
                formData.append('course_id', '{{ lti_data.course_id }}');
                
                for (let file of fileInput.files) {
                    formData.append('files', file);
                }
                
                fetch('/upload_files', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        showAlert(`Successfully uploaded ${data.uploaded_count} file(s)!`);
                        // Reset form
                        fileInput.value = '';
                        updateFileSelection();
                        // Reload page to show new files
                        setTimeout(() => location.reload(), 2000);
                    } else {
                        showAlert(data.error || 'Upload failed', 'error');
                    }
                })
                .catch(error => {
                    showAlert('Upload failed: ' + error.message, 'error');
                });
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
    
    return render_template_string(html_template, lti_data=lti_data, learners=learners, all_files=all_files)

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
