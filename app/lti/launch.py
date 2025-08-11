"""OIDC login and LTI launch endpoints."""
from __future__ import annotations

import os
import secrets
from datetime import datetime, timedelta
from urllib.parse import urlencode, urlparse

import jwt
import requests
from flask import (
    Blueprint,
    abort,
    current_app,
    jsonify,
    redirect,
    request,
    session,
    url_for,
    render_template,
    render_template_string,
)

from .. import db
from ..models import Deployment, Nonce, Platform, State

# Use consistent blueprint name throughout
bp = Blueprint("lti", __name__)
LTI_DEBUG = os.getenv("LTI_DEBUG", "0") == "1"


def _fail(reason: str, code: int = 400):
    """Log and return error response."""
    current_app.logger.error("LTI LAUNCH FAIL: %s", reason)
    if LTI_DEBUG:
        return jsonify({"error": reason}), code
    return jsonify({"error": "Launch failed", "debug": "Check logs"}), code


@bp.route("/lti/login/", methods=["GET", "POST"], strict_slashes=False)
@bp.route("/lti/login", methods=["GET", "POST"], strict_slashes=False)
def login():
    """Initiate OIDC login flow."""
    # IMMEDIATE DEBUG - Print to console AND log
    print("=" * 50)
    print("LTI LOGIN ENDPOINT HIT!")
    print(f"Method: {request.method}")
    print(f"URL: {request.url}")
    print(f"Remote addr: {request.remote_addr}")
    print(f"User agent: {request.headers.get('User-Agent', 'NONE')}")
    print(f"Args: {dict(request.args)}")
    print(f"Form: {dict(request.form)}")
    print("=" * 50)
    
    # Debug: Log all incoming parameters
    current_app.logger.info(f"LOGIN ENDPOINT HIT - Method: {request.method}")
    current_app.logger.info(f"Login request args: {dict(request.args)}")
    current_app.logger.info(f"Login request form: {dict(request.form)}")
    current_app.logger.info(f"Login request headers: {dict(request.headers)}")
    
    iss = request.values.get("iss")
    target_link_uri = request.values.get("target_link_uri")
    client_id = request.values.get("client_id")
    login_hint = request.values.get("login_hint")
    
    current_app.logger.info(f"Parsed parameters - iss: {iss}, target_link_uri: {target_link_uri}, client_id: {client_id}")
    
    if not iss or not target_link_uri:
        return _fail(f"missing required parameters: iss={iss}, target_link_uri={target_link_uri}. Received params: {dict(request.values)}")

    platform = Platform.query.filter_by(issuer=iss).first()
    if not platform:
        return _fail(f"unknown platform: {iss}")

    # Generate secure state and nonce values
    state_val = secrets.token_urlsafe(32)
    nonce_val = secrets.token_urlsafe(32)
    expires = datetime.utcnow() + current_app.config.get("STATE_EXPIRATION", timedelta(minutes=5))
    
    # Store state and nonce in database
    db.session.add(State(value=state_val, redirect_after=target_link_uri, expires_at=expires))
    db.session.add(Nonce(value=nonce_val, expires_at=expires))
    db.session.commit()

    # Build OIDC authorization request parameters
    params = {
        "scope": "openid",
        "response_type": "id_token",
        "response_mode": "form_post",
        "client_id": platform.client_id,
        "redirect_uri": url_for("lti.lti_launch", _external=True),
        "state": state_val,
        "nonce": nonce_val,
    }
    if login_hint:
        params["login_hint"] = login_hint
    
    # Optional lti_message_hint support
    if request.values.get("lti_message_hint"):
        params["lti_message_hint"] = request.values["lti_message_hint"]

    auth_url = f"{platform.auth_login_url}?{urlencode(params)}"
    current_app.logger.info(f"Redirecting to platform auth URL: {auth_url}")
    
    return redirect(auth_url)


@bp.route("/lti/launch/", methods=["POST", "GET"], strict_slashes=False)
@bp.route("/lti/launch", methods=["POST", "GET"], strict_slashes=False)
def lti_launch():
    """Handle LTI launch after OIDC authentication."""
    # Debug: Log all incoming parameters
    print("=" * 50)
    print("LTI LAUNCH ENDPOINT HIT!")
    print(f"Method: {request.method}")
    print(f"URL: {request.url}")
    print(f"Args: {dict(request.args)}")
    print(f"Form: {dict(request.form)}")
    print("=" * 50)
    
    current_app.logger.info(f"Launch request method: {request.method}")
    current_app.logger.info(f"Launch request args: {dict(request.args)}")
    current_app.logger.info(f"Launch request form: {dict(request.form)}")
    
    # Accept POST (normal) and GET (in case a proxy rewrote it)
    id_token = request.form.get("id_token") or request.args.get("id_token")
    state_value = request.form.get("state") or request.args.get("state")

    if not id_token or not state_value:
        return _fail(
            f"missing id_token or state (method={request.method}, "
            f"content_type={request.headers.get('Content-Type')}, "
            f"args={list(request.args.keys())}, form={list(request.form.keys())})"
        )

    # Validate and consume state
    state_row = State.query.filter_by(value=state_value).first()
    if not state_row:
        return _fail("invalid state: not found in database")
    
    if state_row.expires_at < datetime.utcnow():
        db.session.delete(state_row)
        db.session.commit()
        return _fail("invalid state: expired")
    
    redirect_after = state_row.redirect_after
    db.session.delete(state_row)
    db.session.commit()

    # Peek at unverified JWT to get iss/aud/nonce
    try:
        unverified = jwt.decode(id_token, options={"verify_signature": False})
        current_app.logger.info(f"Unverified JWT claims: {unverified}")
    except Exception as e:
        return _fail(f"jwt decode (unverified) failed: {e}")
    
    iss = unverified.get("iss")
    aud = unverified.get("aud")
    nonce_value = unverified.get("nonce")
    
    if not iss:
        return _fail("missing iss claim in id_token")
    
    if not nonce_value:
        return _fail("missing nonce claim in id_token")

    # Find platform by issuer
    platform = Platform.query.filter_by(issuer=iss).first()
    if not platform:
        return _fail(f"unknown platform issuer: {iss}")
    
    # Validate audience
    acceptable_aud = aud if isinstance(aud, list) else [aud] if aud else []
    if platform.client_id not in acceptable_aud:
        return _fail(f"audience mismatch: token aud={acceptable_aud}, expected {platform.client_id}")

    # Verify JWT signature using platform's JWKS
    try:
        current_app.logger.info(f"Fetching JWKS from: {platform.jwks_uri}")
        jwk_client = jwt.PyJWKClient(platform.jwks_uri)
        signing_key = jwk_client.get_signing_key_from_jwt(id_token)
        
        # Decode and verify the JWT
        data = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256", "RS384", "RS512"],  # Support multiple algorithms
            audience=platform.client_id,
            issuer=platform.issuer,
        )
        current_app.logger.info(f"JWT verification successful, claims: {data}")
    except Exception as e:
        return _fail(f"jwt signature verification failed: {e}")

    # Validate and consume nonce
    nonce_row = Nonce.query.filter_by(value=nonce_value).first()
    if not nonce_row:
        return _fail("invalid nonce: not found in database")
    
    if nonce_row.expires_at < datetime.utcnow():
        db.session.delete(nonce_row)
        db.session.commit()
        return _fail("invalid nonce: expired")
    
    db.session.delete(nonce_row)
    db.session.commit()

    # Store deployment information (idempotent)
    dep_id = data.get("https://purl.imsglobal.org/spec/lti/claim/deployment_id")
    if dep_id:
        existing_deployment = Deployment.query.filter_by(
            platform_id=platform.id, 
            deployment_id=dep_id
        ).first()
        
        if not existing_deployment:
            new_deployment = Deployment(platform_id=platform.id, deployment_id=dep_id)
            db.session.add(new_deployment)
            db.session.commit()
            current_app.logger.info(f"Created new deployment: {dep_id} for platform: {platform.issuer}")

    # Store session information for later use
    session['platform_id'] = platform.id
    session['platform_issuer'] = platform.issuer
    session['deployment_id'] = dep_id
    session['user_id'] = data.get("sub")
    session['user_name'] = data.get("name", "Unknown User")
    session['user_email'] = data.get("email")
    context_info = data.get("https://purl.imsglobal.org/spec/lti/claim/context", {})
    session['context_id'] = context_info.get("id")
    session['context_title'] = context_info.get("title")
    session['roles'] = data.get("https://purl.imsglobal.org/spec/lti/claim/roles", [])
    session['return_url'] = data.get("https://purl.imsglobal.org/spec/lti/claim/launch_presentation", {}).get("return_url")
    
    # Handle message type specific logic
    message_type = data.get("https://purl.imsglobal.org/spec/lti/claim/message_type")
    current_app.logger.info(f"Message type: {message_type}")
    
    if message_type == "LtiDeepLinkingRequest":
        # Deep Linking: capture return URL and settings
        deep_linking_settings = data.get("https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings", {})
        
        if deep_linking_settings.get("deep_link_return_url"):
            session["deep_link_return_url"] = deep_linking_settings["deep_link_return_url"]
        
        # Store other deep linking settings that might be needed
        session["deep_linking_settings"] = deep_linking_settings
        
        current_app.logger.info("Deep linking request received")
        
        # Redirect to deep linking selection UI
        return redirect(url_for("lti.deep_link"))
    
    elif message_type == "LtiResourceLinkRequest":
        # Regular resource link launch
        current_app.logger.info("Resource link request received")
        current_app.logger.info(
            f"Successful LTI launch for user: {data.get('sub')} from platform: {iss}"
        )

        # Redirect to the originally requested resource if available, avoiding loops
        if redirect_after:
            path = urlparse(redirect_after).path
            launch_path = url_for("lti.lti_launch")
            login_path = url_for("lti.login")
            if path not in {launch_path, login_path}:
                return redirect(redirect_after)
        return redirect(url_for("lti.lti_success"))


    # Log successful launch for non-resource link requests
    current_app.logger.info(
        f"Successful LTI launch for user: {data.get('sub')} from platform: {iss}"
    )

    # For other message types, return JSON
    return jsonify({
        "launch": "success",
        "message_type": message_type,
        "user_id": data.get("sub"),
        "platform": iss,
        "user_name": data.get("name"),
        "context": data.get("https://purl.imsglobal.org/spec/lti/claim/context", {}).get("title"),
        "return_url": data.get("https://purl.imsglobal.org/spec/lti/claim/launch_presentation", {}).get("return_url"),
    })


@bp.route("/lti/deep_link/", methods=["GET", "POST"], strict_slashes=False)
@bp.route("/lti/deep_link", methods=["GET", "POST"], strict_slashes=False)
def deep_link():
    """Deep link selection UI - teachers choose resources here."""
    if request.method == "GET":
        # Return a simple selection interface
        # In a real app, this would be an HTML form or API for selecting content
        return jsonify({
            "deep_link": "selection_ui_ready",
            "available_resources": [
                {"id": "file_manager", "title": "File Manager", "description": "Access uploaded files"},
                {"id": "upload_tool", "title": "Upload Tool", "description": "Upload new files"}
            ]
        })
    
    # POST: Handle selection and return to LMS
    selected_resource = request.json.get("selected_resource") if request.is_json else request.form.get("selected_resource")
    
    if not selected_resource:
        return jsonify({"error": "No resource selected"}), 200
    
    # Redirect to the return endpoint with the selection
    session["selected_resource"] = selected_resource
    return redirect(url_for("lti.deep_link_return"))


@bp.route("/lti/deep_link/return/", methods=["GET", "POST"], strict_slashes=False)
@bp.route("/lti/deep_link/return", methods=["GET", "POST"], strict_slashes=False)
def deep_link_return():
    """POST a DeepLinkingResponse JWT back to the LMS."""
    deep_link_return_url = session.get("deep_link_return_url") or current_app.config.get("DEEP_LINK_RETURN_URL")
    
    if not deep_link_return_url:
        return _fail("missing deep link return URL")

    platform_id = session.get('platform_id')
    platform = Platform.query.get(platform_id) if platform_id else None

    # Get the selected resource (in a real app, this would come from the selection UI)
    selected_resource = session.get("selected_resource", "file_manager")

    # Create content items based on selection
    content_items = []
    if selected_resource == "file_manager":
        content_items = [{
            "type": "ltiResourceLink",
            "title": "File Manager",
            "text": "Access and manage uploaded files",
            "url": url_for("files.file_browser", _external=True),  # Adjust based on your routes
            "icon": {
                "url": url_for("static", filename="icons/file-manager.png", _external=True),
                "width": 64,
                "height": 64
            }
        }]

    if not platform:
        try:
            requests.post(deep_link_return_url, data={}, timeout=10)
            return jsonify({"deep_link_response": "sent_successfully"})
        except requests.RequestException as exc:
            current_app.logger.error("Failed posting DeepLinkingResponse: %s", exc)
            return _fail(f"failed to post deep link response: {exc}")

    # Create the deep linking response JWT
    now = datetime.utcnow()
    payload = {
        "iss": platform.client_id,  # Tool is the issuer for the response
        "aud": platform.issuer,     # Platform is the audience
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "iat": int(now.timestamp()),
        "nonce": secrets.token_urlsafe(16),
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiDeepLinkingResponse",
        "https://purl.imsglobal.org/spec/lti-dl/claim/content_items": content_items,
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": session.get('deployment_id')
    }

    # Sign the JWT with your tool's private key
    try:
        private_key = current_app.config.get('TOOL_PRIVATE_KEY')
        if not private_key:
            return _fail("Tool private key not configured")

        # Sign the JWT with your private key
        jwt_token = jwt.encode(payload, private_key, algorithm="RS256")

        current_app.logger.info("Deep linking JWT signed successfully")

        # Post the response back to the LMS
        response_data = {"JWT": jwt_token}
        resp = requests.post(deep_link_return_url, data=response_data, timeout=10)
        resp.raise_for_status()

        current_app.logger.info(f"Deep linking response sent successfully to {deep_link_return_url}")

        # Clean up session
        session.pop("deep_link_return_url", None)
        session.pop("deep_linking_settings", None)
        session.pop("selected_resource", None)

        return jsonify({"deep_link_response": "sent_successfully"})

    except requests.RequestException as exc:
        current_app.logger.error("Failed posting DeepLinkingResponse: %s", exc)
        return _fail(f"failed to post deep link response: {exc}")
    except Exception as exc:
        current_app.logger.error("Error creating DeepLinkingResponse: %s", exc)
        return _fail(f"error creating deep link response: {exc}")


# DEBUG ENDPOINTS
@bp.route("/lti/debug/config", methods=["GET"])
def debug_config():
    """Debug endpoint to show tool configuration."""
    config = {
        "login_url": url_for("lti.login", _external=True),
        "launch_url": url_for("lti.lti_launch", _external=True),
        "deep_link_url": url_for("lti.deep_link", _external=True),
        "jwks_url": "/.well-known/jwks.json",  # Standard location
        "base_url": request.host_url,
        "debug_mode": LTI_DEBUG,
        "registered_platforms": []
    }
    
    # Add platform information if available
    try:
        platforms = Platform.query.all()
        for platform in platforms:
            config["registered_platforms"].append({
                "issuer": platform.issuer,
                "client_id": platform.client_id,
                "auth_login_url": platform.auth_login_url,
                "jwks_uri": platform.jwks_uri
            })
    except Exception as e:
        config["platform_error"] = str(e)
    
    return jsonify(config)


@bp.route("/lti/debug/test-login", methods=["GET", "POST"])
def debug_test_login():
    """Test endpoint to simulate a login request."""
    if request.method == "GET":
        # Show a form to test login manually
        return f"""
        <html>
        <body>
        <h2>Test LTI Login</h2>
        <form method="POST" action="{url_for('lti.login')}">
            <p>iss (Platform Issuer): <input name="iss" value="https://your-moodle-site.com" style="width: 400px;"></p>
            <p>target_link_uri: <input name="target_link_uri" value="{url_for('lti.lti_launch', _external=True)}" style="width: 400px;"></p>
            <p>client_id: <input name="client_id" value="your-client-id" style="width: 400px;"></p>
            <p>login_hint: <input name="login_hint" value="test-user" style="width: 400px;"></p>
            <p><input type="submit" value="Test Login"></p>
        </form>
        
        <h3>Current Configuration:</h3>
        <pre>{jsonify(debug_config().get_json()).data.decode()}</pre>
        </body>
        </html>
        """
    else:
        return redirect(url_for('lti.login'), code=307)  # Forward POST data


@bp.route("/lti/simulate-moodle", methods=["GET", "POST"])
def simulate_moodle():
    """Simulate what Moodle should send to login endpoint."""
    if request.method == "GET":
        return f"""
        <html>
        <body>
        <h2>Simulate Moodle LTI Login</h2>
        <p>This simulates what Moodle should send to your login endpoint:</p>
        
        <form method="POST" action="{url_for('lti.login')}">
            <p><strong>Required Parameters:</strong></p>
            <p>iss: <input name="iss" value="https://cluepony.com/moodle45" style="width: 400px;"></p>
            <p>target_link_uri: <input name="target_link_uri" value="{url_for('lti.lti_launch', _external=True)}" style="width: 400px;"></p>
            <p>login_hint: <input name="login_hint" value="123456" style="width: 400px;"></p>
            <p>client_id: <input name="client_id" value="WCAQnJ91bvOQ8D3" style="width: 400px;"></p>
            <p><input type="submit" value="Test Moodle Login Flow"></p>
        </form>
        
        <h3>What should happen:</h3>
        <ol>
        <li>You click "Test Moodle Login Flow"</li>
        <li>You should see console output with "===== LTI LOGIN ENDPOINT HIT!"</li>
        <li>You should either get an error about unknown platform OR a redirect to platform auth URL</li>
        </ol>
        </body>
        </html>
        """
    else:
        return "This should be handled by the login endpoint"


@bp.route("/lti/debug/platforms", methods=["GET"])
def debug_platforms():
    """Debug endpoint to show registered platforms."""
    try:
        platforms = Platform.query.all()
        platform_list = []
        for platform in platforms:
            platform_list.append({
                "id": platform.id,
                "issuer": platform.issuer,
                "client_id": platform.client_id,
                "auth_login_url": platform.auth_login_url,
                "jwks_uri": platform.jwks_uri,
                "deployments": [{"id": d.id, "deployment_id": d.deployment_id} for d in platform.deployments]
            })
        return jsonify({"platforms": platform_list})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route("/lti/debug/manual-register", methods=["GET", "POST"])
def manual_register():
    """Manually register the Moodle platform for testing."""
    if request.method == "GET":
        return f"""
        <html>
        <body>
        <h2>Manual Platform Registration</h2>
        <p>Based on your Moodle login data, register the platform:</p>
        
        <form method="POST">
            <p>Issuer: <input name="issuer" value="https://cluepony.com/moodle45" style="width: 400px;" required></p>
            <p>Client ID: <input name="client_id" value="WCAQnJ91bvOQ8D3" style="width: 400px;" required></p>
            <p>Auth Login URL: <input name="auth_login_url" value="https://cluepony.com/moodle45/mod/lti/auth.php" style="width: 400px;" required></p>
            <p>JWKS URI: <input name="jwks_uri" value="https://cluepony.com/moodle45/mod/lti/certs.php" style="width: 400px;" required></p>
            <p><input type="submit" value="Register Platform"></p>
        </form>
        </body>
        </html>
        """
    else:
        # Manual registration
        try:
            platform = Platform(
                issuer=request.form.get("issuer"),
                client_id=request.form.get("client_id"),
                auth_login_url=request.form.get("auth_login_url"),
                jwks_uri=request.form.get("jwks_uri")
            )
            db.session.add(platform)
            db.session.commit()
            
            return jsonify({
                "success": True,
                "message": "Platform registered successfully",
                "platform": {
                    "issuer": platform.issuer,
                    "client_id": platform.client_id,
                    "auth_login_url": platform.auth_login_url,
                    "jwks_uri": platform.jwks_uri
                }
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500


# Health check endpoint for debugging
@bp.route("/lti/health", methods=["GET"])
def health():
    """Basic health check for LTI endpoints."""
    return jsonify({
        "status": "healthy",
        "endpoints": {
            "login": url_for("lti.login", _external=True),
            "launch": url_for("lti.lti_launch", _external=True),
            "deep_link": url_for("lti.deep_link", _external=True)
        },
        "debug_mode": LTI_DEBUG,
        "timestamp": datetime.utcnow().isoformat()
    })


@bp.route("/lti/test", methods=["GET", "POST"])
def test_endpoint():
    """Simple test endpoint to verify server is reachable."""
    print("TEST ENDPOINT HIT!")
    response_data = {
        "message": "LTI endpoints are working!",
        "method": request.method,
        "url": request.url,
        "args": dict(request.args),
        "form": dict(request.form),
        "headers": dict(request.headers),
        "timestamp": datetime.utcnow().isoformat()
    }
    print(f"Response data: {response_data}")
    return jsonify(response_data)


@bp.route("/lti/success", methods=["GET"])
def lti_success():
    """LTI launch success landing page."""
    user_name = session.get("user_name", "User")
    platform = session.get("platform_issuer", "Unknown Platform")
    roles = session.get("roles", [])
    admin = any(r.split("#")[-1] in {"Instructor", "Administrator"} for r in roles)
    context_title = session.get("context_title", "Course")
    html = """
    <html>
    <head>
      <title>LTI Launch Successful</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { background: white; padding: 30px; border-radius: 8px; max-width: 600px; margin: 0 auto; }
        .card { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 4px; }
        .actions { display: flex; gap: 10px; }
        .actions a { flex: 1; text-align: center; padding: 10px; background: #007bff; color: #fff; text-decoration: none; border-radius: 4px; }
      </style>
    </head>
    <body>
      <div class="container">
        <h2>LTI Launch Successful</h2>
        <p>Welcome <strong>{{user_name}}</strong> to <strong>{{context_title}}</strong> from {{platform}}</p>

        <div class="card actions">
          <a href="{{ url_for('files.file_browser') }}">File Browser</a>
          {% if admin %}
          <a href="{{ url_for('lti.student_files') }}">Student Files</a>
          {% endif %}
        </div>

        <div class="card">
          <strong>Session Info:</strong><br>
          Platform: {{session.platform_issuer}}<br>
          User ID: {{session.user_id}}<br>
          Deployment: {{session.deployment_id}}<br>
          Roles: {{roles}}
        </div>
      </div>
    </body>
    </html>
    """
    return render_template_string(
        html,
        user_name=user_name,
        platform=platform,
        roles=roles,
        admin=admin,
        context_title=context_title,
    )


def _fetch_moodle_students_and_files():
    """Return a list of student users and their files from Moodle."""
    base_url = current_app.config.get("MOODLE_BASE_URL") or os.getenv("MOODLE_BASE_URL")
    token = current_app.config.get("MOODLE_TOKEN") or os.getenv("MOODLE_TOKEN")
    course_id = current_app.config.get("MOODLE_COURSE_ID") or os.getenv("MOODLE_COURSE_ID")
    if not base_url or not token or not course_id:
        current_app.logger.warning("Missing Moodle configuration; unable to fetch students")
        return []

    params = {
        "wstoken": token,
        "wsfunction": "core_enrol_get_enrolled_users",
        "courseid": course_id,
        "moodlewsrestformat": "json",
    }
    try:
        resp = requests.get(f"{base_url}/webservice/rest/server.php", params=params, timeout=10)
        resp.raise_for_status()
        users = resp.json()
    except Exception as err:  # pragma: no cover - network errors
        current_app.logger.error(f"Failed to fetch Moodle users: {err}")
        return []

    students = []
    for user in users:
        roles = [r.get("shortname") for r in user.get("roles", [])]
        if "student" not in roles:
            continue

        file_params = {
            "wstoken": token,
            "wsfunction": "core_files_get_user_files",
            "userid": user.get("id"),
            "moodlewsrestformat": "json",
        }
        files = []
        try:
            f_resp = requests.get(
                f"{base_url}/webservice/rest/server.php", params=file_params, timeout=10
            )
            f_resp.raise_for_status()
            for f in f_resp.json().get("files", []):

                if f.get("isdir"):
                    continue
                url = f.get("fileurl")
                if url:
                    # Append token so admin can download directly
                    files.append(
                        {
                            "filename": f.get("filename"),
                            "url": f"{url}?token={token}",
                        }
                    )

        except Exception as err:  # pragma: no cover
            current_app.logger.error(
                f"Failed to fetch files for user {user.get('id')}: {err}"
            )

        students.append({"fullname": user.get("fullname"), "files": files})

    return students


@bp.route("/lti/student_files", methods=["GET", "POST"])
def student_files():
    """Display Moodle students and allow uploading their files to local storage."""
    uploaded = None
    if request.method == "POST":
        selected = request.form.getlist("files")
        upload_dir = current_app.config.get("UPLOAD_FOLDER", "/tmp/lti_files")
        os.makedirs(upload_dir, exist_ok=True)
        uploaded = 0
        for file_url in selected:
            try:
                resp = requests.get(file_url, timeout=10)
                resp.raise_for_status()
                filename = file_url.rsplit("/", 1)[-1].split("?")[0]

                with open(os.path.join(upload_dir, filename), "wb") as handle:
                    handle.write(resp.content)
                uploaded += 1
            except Exception as err:  # pragma: no cover
                current_app.logger.error(f"Failed to download {file_url}: {err}")

    students = _fetch_moodle_students_and_files()
    return render_template("student_files.html", students=students, uploaded=uploaded)
