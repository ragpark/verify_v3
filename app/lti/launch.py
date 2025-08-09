"""OIDC login and LTI launch endpoints."""
from __future__ import annotations

import secrets
from datetime import datetime
from urllib.parse import urlencode

import jwt
from flask import Blueprint, abort, current_app, jsonify, redirect, request, url_for

from .. import db
from ..models import Deployment, Nonce, Platform, State

bp = Blueprint("launch", __name__)


@bp.get("/lti/login")
def login():
    """Initiate OIDC login flow."""
    iss = request.args.get("iss")
    target_link_uri = request.args.get("target_link_uri")
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
        "client_id": platform.client_id,
        "redirect_uri": url_for("launch.lti_launch", _external=True),
        "login_hint": request.args.get("login_hint", ""),
        "state": state_val,
        "nonce": nonce_val,
    }
    # Optional lti_message_hint support
    if request.args.get("lti_message_hint"):
        params["lti_message_hint"] = request.args["lti_message_hint"]

    return redirect(f"{platform.auth_login_url}?{urlencode(params)}")


@bp.post("/lti/launch")
def lti_launch():
    """Handle an LTI launch by verifying the id_token."""
    id_token = request.form.get("id_token")
    state_val = request.form.get("state")
    if not id_token or not state_val:
        abort(400, "missing id_token or state")

    # Validate state
    state = State.query.filter_by(value=state_val).first()
    if not state or state.expires_at < datetime.utcnow():
        abort(400, "invalid state")
    db.session.delete(state)
    db.session.commit()

    unverified = jwt.decode(id_token, options={"verify_signature": False})
    iss = unverified.get("iss")
    aud = unverified.get("aud")
    nonce_val = unverified.get("nonce")
    if not iss:
        abort(400, "missing iss")

    platform = Platform.query.filter_by(issuer=iss).first()
    if not platform:
        abort(400, "unknown platform")
    if platform.client_id not in (aud if isinstance(aud, list) else [aud]):
        abort(400, "aud mismatch")

    # Fetch and verify signature
    jwk_client = jwt.PyJWKClient(platform.jwks_uri)
    signing_key = jwk_client.get_signing_key_from_jwt(id_token)
    data = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=platform.client_id,
        issuer=platform.issuer,
    )

    # Validate nonce
    nonce = Nonce.query.filter_by(value=nonce_val).first()
    if not nonce or nonce.expires_at < datetime.utcnow():
        abort(400, "invalid nonce")
    db.session.delete(nonce)
    db.session.commit()

    deployment_id = data.get("https://purl.imsglobal.org/spec/lti/claim/deployment_id")
    if deployment_id:
        exists = Deployment.query.filter_by(platform_id=platform.id, deployment_id=deployment_id).first()
        if not exists:
            db.session.add(Deployment(platform_id=platform.id, deployment_id=deployment_id))
            db.session.commit()

    return jsonify({"launch": "ok"})
