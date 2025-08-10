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

bp = Blueprint("launch", __name__)


@bp.route("/lti/login", methods=["GET", "POST"])
def login():
    """Initiate OIDC login flow."""
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


@bp.route("/lti/launch", methods=["GET", "POST"])
def lti_launch():
    """Handle an LTI launch by verifying the id_token."""
    id_token = request.values.get("id_token")
    state_val = request.values.get("state")
    if not id_token or not state_val:
        abort(400, "missing id_token or state")

    # Validate state
    state = State.query.filter_by(value=state_val).first()
    if not state or state.expires_at < datetime.utcnow():
        abort(400, "invalid state")
    redirect_after = state.redirect_after
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

    message_type = data.get("https://purl.imsglobal.org/spec/lti/claim/message_type")
    if message_type == "LtiDeepLinkingRequest":
        settings = data.get(
            "https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings",
            {},
        )
        deep_link_return_url = settings.get("deep_link_return_url")
        if deep_link_return_url:
            session["deep_link_return_url"] = deep_link_return_url

    if redirect_after:
        return redirect(redirect_after)

    return jsonify({"launch": "ok"})



@bp.route("/lti/deep_link", methods=["GET", "POST"])
def deep_link():
    """Simple placeholder for deep link selection UI."""
    return jsonify({"deep_link": "ready"})


@bp.route("/lti/deep_link/return", methods=["GET", "POST"])
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
