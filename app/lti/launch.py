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
        payload = {
            "sub": session["user_id"],
            "roles": session.get("roles", []),
            "platform_id": session.get("platform_id"),
            "platform_issuer": session.get("platform_issuer"),
            "deployment_id": session.get("deployment_id"),
            "context_id": session.get("context_id"),
            "context_title": session.get("context_title"),
            "exp": int((datetime.utcnow() + timedelta(minutes=15)).timestamp()),
        }
        ltik = jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")
        return redirect(url_for("lti.lti_success", ltik=ltik))


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
    ltik = request.args.get("ltik")
    html = """
    <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SV Assistant - Connected</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #1e293b 0%, #334155 50%, #475569 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            line-height: 1.6;
        }

        .container {
            background: white;
            border-radius: 16px;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.15);
            max-width: 500px;
            width: 100%;
            overflow: hidden;
            animation: slideUp 0.8s ease-out;
            border: 1px solid #e2e8f0;
        }

        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(40px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .header {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            padding: 40px 30px;
            text-align: center;
            color: white;
            position: relative;
        }

        .header h1 {
            font-size: 28px;
            font-weight: 600;
            margin-bottom: 8px;
            letter-spacing: -0.5px;
        }

        .header .subtitle {
            font-size: 16px;
            opacity: 0.8;
            color: #94a3b8;
            font-weight: 400;
        }

        .content {
            padding: 40px 30px;
        }

        .welcome-card {
            background: #f8fafc;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 30px;
            border-left: 4px solid #6366f1;
            position: relative;
        }

        .welcome-text {
            font-size: 18px;
            color: #1e293b;
            margin-bottom: 8px;
            font-weight: 500;
        }

        .welcome-details {
            font-size: 15px;
            color: #64748b;
            line-height: 1.5;
        }

        .user-name {
            color: #6366f1;
            font-weight: 600;
        }

        .context-title {
            color: #059669;
            font-weight: 600;
        }

        .platform {
            color: #7c3aed;
            font-weight: 500;
        }

        .actions {
            display: flex;
            flex-direction: column;
            gap: 16px;
        }

        .action-btn {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            padding: 18px 24px;
            background: #6366f1;
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 500;
            font-size: 16px;
            transition: all 0.2s ease;
            position: relative;
            border: 1px solid transparent;
        }

        .action-btn:hover {
            background: #4f46e5;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3);
        }

        .action-btn.admin {
            background: #dc2626;
        }

        .action-btn.admin:hover {
            background: #b91c1c;
            box-shadow: 0 4px 12px rgba(220, 38, 38, 0.3);
        }

        .btn-icon {
            width: 20px;
            height: 20px;
            background: currentColor;
            mask-repeat: no-repeat;
            mask-position: center;
            mask-size: contain;
        }

        .btn-icon.files {
            mask-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='currentColor'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z' /%3E%3C/svg%3E");
        }

        .btn-icon.admin {
            mask-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='currentColor'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4' /%3E%3C/svg%3E");
        }

        .status-indicator {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: #ecfdf5;
            color: #059669;
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 500;
            margin-bottom: 20px;
            border: 1px solid #d1fae5;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            background: #059669;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% { 
                opacity: 1;
                transform: scale(1);
            }
            50% { 
                opacity: 0.5;
                transform: scale(1.1);
            }
            100% { 
                opacity: 1;
                transform: scale(1);
            }
        }

        @media (max-width: 480px) {
            body {
                padding: 15px;
            }

            .header {
                padding: 30px 20px;
            }

            .header h1 {
                font-size: 24px;
            }

            .content {
                padding: 30px 20px;
            }

            .welcome-card {
                padding: 20px;
            }

            .action-btn {
                padding: 16px 20px;
                font-size: 15px;
            }
        }

        @media (min-width: 481px) {
            .actions {
                flex-direction: row;
            }

            .action-btn {
                flex: 1;
            }
        }

        /* Accessibility improvements */
        .action-btn:focus {
            outline: 2px solid #6366f1;
            outline-offset: 2px;
        }

        .action-btn.admin:focus {
            outline-color: #dc2626;
        }

        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
            }
        }

        /* Dark mode support */
        @media (prefers-color-scheme: dark) {
            .container {
                background: #1e293b;
                border-color: #374151;
            }

            .welcome-card {
                background: #334155;
            }

            .welcome-text {
                color: #f1f5f9;
            }

            .welcome-details {
                color: #94a3b8;
            }

            .status-indicator {
                background: #064e3b;
                border-color: #065f46;
                color: #6ee7b7;
            }

            .status-dot {
                background: #6ee7b7;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>SV Assistant</h1>
            <div class="subtitle">Successfully Connected</div>
        </div>
        
        <div class="content">
            <div class="status-indicator">
                <div class="status-dot"></div>
                Connected & Ready
            </div>

            <div class="welcome-card">
                <div class="welcome-text">Welcome back</div>
                <div class="welcome-details">
                    Hello <span class="user-name">{{user_name}}</span>, you're now connected to 
                    <span class="context-title">{{context_title}}</span> via <span class="platform">{{platform}}</span>
                </div>
            </div>

            <div class="actions">
                <a href="{{ url_for('files.file_browser') }}?ltik={{ ltik }}" class="action-btn">
                    <div class="btn-icon files"></div>
                    Learner Files
                </a>
                {% if admin %}
                <a href="{{ url_for('lti.student_files') }}?ltik={{ ltik }}" class="action-btn admin">
                    <div class="btn-icon admin"></div>
                    IV Files
                </a>
                {% endif %}
            </div>
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
        ltik=ltik,
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
    upload_dir = current_app.config.get("UPLOAD_FOLDER", "/tmp/lti_files")
    if request.method == "POST":
        selected = request.form.getlist("files")
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

    uploaded_files = []
    if os.path.isdir(upload_dir):
        uploaded_files = sorted(os.listdir(upload_dir))

    students = _fetch_moodle_students_and_files()
    return render_template(
        "student_files.html",
        students=students,
        uploaded=uploaded,
        uploaded_files=uploaded_files,
    )
