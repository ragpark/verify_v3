"""OIDC login and LTI launch endpoints."""
from __future__ import annotations

import os
import secrets
from datetime import datetime
from urllib.parse import urlencode

import jwt
import requests
from flask import Blueprint, abort, current_app, jsonify, redirect, request, session, url_for

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


@bp.route("/lti/login", methods=["GET", "POST"], strict_slashes=False)
def login():
    """Initiate OIDC login flow."""
    iss = request.values.get("iss")
    target_link_uri = request.values.get("target_link_uri")
    
    if not iss or not target_link_uri:
        return _fail("missing required parameters: iss or target_link_uri")

    platform = Platform.query.filter_by(issuer=iss).first()
    if not platform:
        return _fail(f"unknown platform: {iss}")

    # Generate secure state and nonce values
    state_val = secrets.token_urlsafe(32)
    nonce_val = secrets.token_urlsafe(32)
    expires = datetime.utcnow() + current_app.config.get("STATE_EXPIRATION", datetime.timedelta(minutes=5))
    
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
        "login_hint": request.values.get("login_hint", ""),
        "state": state_val,
        "nonce": nonce_val,
    }
    
    # Optional lti_message_hint support
    if request.values.get("lti_message_hint"):
        params["lti_message_hint"] = request.values["lti_message_hint"]

    auth_url = f"{platform.auth_login_url}?{urlencode(params)}"
    current_app.logger.info(f"Redirecting to platform auth URL: {auth_url}")
    
    return redirect(auth_url)


@bp.route("/lti/launch", methods=["POST", "GET"], strict_slashes=False)
@bp.route("/lti/launch/", methods=["POST", "GET"], strict_slashes=False)
def lti_launch():
    """Handle LTI launch after OIDC authentication."""
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
    
    # Handle message type specific logic
    message_type = data.get("https://purl.imsglobal.org/spec/lti/claim/message_type")
    
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
    
    # Log successful launch
    current_app.logger.info(f"Successful LTI launch for user: {data.get('sub')} from platform: {iss}")
    
    # Redirect to the original target or return success
    if redirect_after:
        return redirect(redirect_after)
    
    return jsonify({
        "launch": "success",
        "message_type": message_type,
        "user_id": data.get("sub"),
        "platform": iss
    })


@bp.route("/lti/deep_link", methods=["GET", "POST"], strict_slashes=False)
@bp.route("/lti/deep_link/", methods=["GET", "POST"], strict_slashes=False)
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
        return _fail("No resource selected")
    
    # Redirect to the return endpoint with the selection
    session["selected_resource"] = selected_resource
    return redirect(url_for("lti.deep_link_return"))


@bp.route("/lti/deep_link/return", methods=["GET", "POST"], strict_slashes=False)
@bp.route("/lti/deep_link/return/", methods=["GET", "POST"], strict_slashes=False)
def deep_link_return():
    """POST a DeepLinkingResponse JWT back to the LMS."""
    deep_link_return_url = session.get("deep_link_return_url") or current_app.config.get("DEEP_LINK_RETURN_URL")
    
    if not deep_link_return_url:
        return _fail("missing deep link return URL")

    platform_id = session.get('platform_id')
    if not platform_id:
        return _fail("missing platform information in session")
    
    platform = Platform.query.get(platform_id)
    if not platform:
        return _fail("platform not found")

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
    
    # Create the deep linking response JWT
    now = datetime.utcnow()
    payload = {
        "iss": platform.client_id,  # Tool is the issuer for the response
        "aud": platform.issuer,     # Platform is the audience
        "exp": int((now + datetime.timedelta(minutes=5)).timestamp()),
        "iat": int(now.timestamp()),
        "nonce": secrets.token_urlsafe(16),
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiDeepLinkingResponse",
        "https://purl.imsglobal.org/spec/lti-dl/claim/content_items": content_items,
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": session.get('deployment_id')
    }
    
    # TODO: You need to implement proper JWT signing here
    # This requires your tool's private key for signing
    # For now, this will fail - you need to add proper key management
    try:
        # You need to get your tool's private key here
        # private_key = get_tool_private_key()  # Implement this function
        # jwt_token = jwt.encode(payload, private_key, algorithm="RS256")
        
        # Temporary placeholder - REPLACE WITH PROPER SIGNING
        jwt_token = "PLACEHOLDER_JWT_NEEDS_PROPER_SIGNING"
        
        current_app.logger.warning("Using placeholder JWT - implement proper signing!")
        
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
        "debug_mode": LTI_DEBUG
    })
