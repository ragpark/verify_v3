"""OIDC login and LTI launch endpoints."""
from __future__ import annotations

import secrets
from datetime import datetime
from urllib.parse import urlencode

import jwt
import requests
from flask import Blueprint, abort, current_app, jsonify, redirect, request, session, url_for

from .. import db
from ..models import Deployment, Nonce, Platform, State

@bp.route("/lti/login", methods=["GET", "POST"], strict_slashes=False)
def login():
    """Initiate OIDC login flow."""
    from urllib.parse import urlencode
    iss = request.values.get("iss")
    target_link_uri = request.values.get("target_link_uri")
    if not iss or not target_link_uri:
        abort(400, "missing parameters")

    platform = Platform.query.filter_by(issuer=iss).first()
    if not platform:
        abort(400, "unknown platform")

    state_val = secrets.token_urlsafe(16)
    nonce_val = secrets.token_urlsafe(16)
    expires = datetime.utcnow() + current_app.config["STATE_EXPIRATION"]
    db.session.add(State(value=state_val, redirect_after=target_link_uri, expires_at=expires))
    db.session.add(Nonce(value=nonce_val, expires_at=expires))
    db.session.commit()

    params = {
        "scope": "openid",
        "response_type": "id_token",
        "response_mode": "form_post",
        "client_id": platform.client_id,
        "redirect_uri": url_for("launch.lti_launch", _external=True),
        "login_hint": request.values.get("login_hint", ""),
        "state": state_val,
        "nonce": nonce_val,
    }
    # Optional lti_message_hint support
    if request.values.get("lti_message_hint"):
        params["lti_message_hint"] = request.values["lti_message_hint"]

    return redirect(f"{platform.auth_login_url}?{urlencode(params)}")


# app/lti/launch.py
import os
from datetime import datetime
from flask import Blueprint, request, abort, current_app, jsonify, redirect, session
import jwt
from .. import db
from ..models import State, Nonce, Platform, Deployment

bp = Blueprint("lti", __name__)
LTI_DEBUG = os.getenv("LTI_DEBUG", "0") == "1"

def _fail(reason: str, code: int = 400):
    current_app.logger.warning("LTI LAUNCH FAIL: %s", reason)
    if LTI_DEBUG:
        return jsonify({"error": reason}), code
    abort(code, reason)

@bp.route("/lti/launch", methods=["POST", "GET"], strict_slashes=False)
@bp.route("/lti/launch/", methods=["POST", "GET"], strict_slashes=False)
def lti_launch():
    # Accept POST (normal) and GET (in case a proxy rewrote it)
    id_token = request.form.get("id_token") or request.args.get("id_token")
    state_value = request.form.get("state") or request.args.get("state")

    if not id_token or not state_value:
        return _fail(
            f"missing id_token or state (method={request.method}, ct={request.headers.get('Content-Type')}, "
            f"args={list(request.args.keys())}, form={list(request.form.keys())})"
        )

    # Validate and consume state
    state_row = State.query.filter_by(value=state_value).first()
    if not state_row:
        return _fail("invalid state: not found")
    if state_row.expires_at < datetime.utcnow():
        db.session.delete(state_row); db.session.commit()
        return _fail("invalid state: expired")
    redirect_after = state_row.redirect_after
    db.session.delete(state_row); db.session.commit()

    # Peek unverified for iss/aud/nonce
    try:
        unverified = jwt.decode(id_token, options={"verify_signature": False})
    except Exception as e:
        return _fail(f"jwt decode (unverified) failed: {e}")
    iss = unverified.get("iss")
    aud = unverified.get("aud")
    nonce_value = unverified.get("nonce")
    if not iss:
        return _fail("missing iss in id_token")

    platform = Platform.query.filter_by(issuer=iss).first()
    if not platform:
        return _fail(f"unknown platform: {iss}")
    acceptable_aud = aud if isinstance(aud, list) else [aud]
    if platform.client_id not in acceptable_aud:
        return _fail(f"aud mismatch: token aud={acceptable_aud}, expected {platform.client_id}")

    # Verify signature
    try:
        jwk_client = jwt.PyJWKClient(platform.jwks_uri)
        signing_key = jwk_client.get_signing_key_from_jwt(id_token)
        data = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=platform.client_id,
            issuer=platform.issuer,
        )
    except Exception as e:
        return _fail(f"jwt verify failed: {e}")

    # Validate and consume nonce
    nonce_row = Nonce.query.filter_by(value=nonce_value).first()
    if not nonce_row:
        return _fail("invalid nonce: not found")
    if nonce_row.expires_at < datetime.utcnow():
        db.session.delete(nonce_row); db.session.commit()
        return _fail("invalid nonce: expired")
    db.session.delete(nonce_row); db.session.commit()

    # Persist deployment (idempotent)
    dep_id = data.get("https://purl.imsglobal.org/spec/lti/claim/deployment_id")
    if dep_id:
        if not Deployment.query.filter_by(platform_id=platform.id, deployment_id=dep_id).first():
            db.session.add(Deployment(platform_id=platform.id, deployment_id=dep_id)); db.session.commit()

    # Deep Linking: capture return URL
    if data.get("https://purl.imsglobal.org/spec/lti/claim/message_type") == "LtiDeepLinkingRequest":
        settings = data.get("https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings", {})
        if settings.get("deep_link_return_url"):
            session["deep_link_return_url"] = settings["deep_link_return_url"]

    if redirect_after:
        return redirect(redirect_after)
    return jsonify({"launch": "ok"})

@bp.route("/lti/deep_link", methods=["GET", "POST"], strict_slashes=False)
@bp.route("/lti/deep_link/", methods=["GET", "POST"], strict_slashes=False)
def deep_link():
    """Simple placeholder for deep link selection UI."""
    return jsonify({"deep_link": "ready"})


@bp.route("/lti/deep_link/return", methods=["GET", "POST"], strict_slashes=False)
@bp.route("/lti/deep_link/return/", methods=["GET", "POST"], strict_slashes=False)
def deep_link_return():
    """POST a DeepLinkingResponse to the stored return URL."""
    deep_link_return_url = session.get("deep_link_return_url") or current_app.config.get(
        "DEEP_LINK_RETURN_URL"
    )
    if not deep_link_return_url:
        abort(400, "missing deep link return URL")

    try:
        resp = requests.post(deep_link_return_url, data={"JWT": "placeholder"}, timeout=10)
        resp.raise_for_status()
    except Exception as exc:  # pragma: no cover - network failure
        current_app.logger.error("Failed posting DeepLinkingResponse: %s", exc)
        abort(400, "failed to post deep link response")

    return jsonify({"deep_link_response": "sent"})
