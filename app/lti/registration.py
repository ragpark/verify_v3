"""Dynamic registration and tool configuration endpoints."""
from __future__ import annotations

import secrets
from datetime import datetime
from urllib.parse import urlparse

import requests
from flask import (
    Blueprint,
    abort,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from .. import db
from ..config import Config
from ..models import Platform, State

bp = Blueprint("registration", __name__)


def _tool_configuration() -> dict:
    """Return the static tool configuration metadata."""
    cfg: Config = current_app.config  # type: ignore
    base_url = cfg["APP_BASE_URL"]
    deep_link_return = cfg.get("DEEP_LINK_RETURN_URL", f"{base_url}/lti/deep_link/return")

    return {
        "application_type": "web",
        "response_types": ["id_token"],
        "grant_types": ["client_credentials"],
        "initiate_login_uri": f"{base_url}/lti/login",
        "redirect_uris": [f"{base_url}/lti/launch", deep_link_return],
        "jwks_uri": f"{base_url}/.well-known/jwks.json",
        "logo_uri": f"{base_url}/static/logo.png",
        "contacts": [cfg.get("TOOL_CONTACT_EMAIL")],
        "client_name": cfg.get("TOOL_TITLE", "Verify"),
        "https://purl.imsglobal.org/spec/lti-tool-configuration": {
            "claims": [
                "https://purl.imsglobal.org/spec/lti/claim/deployment_id",
            ],
            "messages": [
                {
                    "type": "LtiResourceLinkRequest",
                    "target_link_uri": f"{base_url}/lti/launch",
                },
                {
                    "type": "LtiDeepLinkingRequest",
                    "target_link_uri": f"{base_url}/lti/deep_link",
                },
            ],
        },
    }


@bp.get("/.well-known/tool-configuration")
def tool_configuration():
    """Expose tool configuration metadata for dynamic registration."""
    return jsonify(_tool_configuration())


@bp.get("/lti/dynamic-registration")
def dynamic_registration():
    """Display registration URL or handle incoming LMS call."""
    openid_config = request.args.get("openid_configuration")
    registration_token = request.args.get("registration_token")

    if openid_config and registration_token:
        # LMS initiated call; create state and redirect to callback
        state_value = secrets.token_urlsafe(16)
        expires_at = datetime.utcnow() + current_app.config["STATE_EXPIRATION"]
        state = State(value=state_value, expires_at=expires_at)
        db.session.add(state)
        db.session.commit()

        return redirect(
            url_for(
                "registration.dynamic_registration_callback",
                openid_configuration=openid_config,
                registration_token=registration_token,
                state=state_value,
            )
        )

    # Human admin view – display the URL to copy
    registration_url = url_for("registration.dynamic_registration", _external=True)
    return render_template("admin/registration.html", registration_url=registration_url)


@bp.get("/lti/dynamic-registration/callback")
def dynamic_registration_callback():
    """Handle the dynamic registration flow."""
    openid_config = request.args.get("openid_configuration")
    registration_token = request.args.get("registration_token")
    state_value = request.args.get("state")

    if not all([openid_config, registration_token, state_value]):
        abort(400, "missing required parameters")

    # Validate state
    state = State.query.filter_by(value=state_value).first()
    if not state or state.expires_at < datetime.utcnow():
        abort(400, "invalid state")
    db.session.delete(state)
    db.session.commit()

    # Fetch openid configuration
    try:
        resp = requests.get(openid_config, timeout=10)
        resp.raise_for_status()
        oidc = resp.json()
    except Exception as exc:  # pragma: no cover - network failure
        current_app.logger.error("Failed fetching openid configuration: %s", exc)
        abort(400, "failed to fetch openid configuration")

    issuer = oidc.get("issuer")
    registration_endpoint = oidc.get("registration_endpoint")
    authorization_endpoint = oidc.get("authorization_endpoint")
    token_endpoint = oidc.get("token_endpoint")
    jwks_uri = oidc.get("jwks_uri")

    if not (issuer and registration_endpoint and authorization_endpoint and token_endpoint and jwks_uri):
        abort(400, "invalid openid configuration")

    # Assemble registration payload
    payload = _tool_configuration()
    # Add domain for some LMSs
    payload["https://purl.imsglobal.org/spec/lti-tool-configuration"]["domain"] = urlparse(
        current_app.config["APP_BASE_URL"]
    ).netloc

    headers = {"Authorization": f"Bearer {registration_token}"}
    try:
        reg_resp = requests.post(registration_endpoint, json=payload, headers=headers, timeout=10)
        reg_resp.raise_for_status()
        reg_data = reg_resp.json()
    except Exception as exc:  # pragma: no cover
        current_app.logger.error("Dynamic registration failed: %s", exc)
        abort(400, "registration failed")

    client_id = reg_data.get("client_id")
    registration_client_uri = reg_data.get("registration_client_uri")
    if not client_id:
        abort(400, "registration response missing client_id")

    # Upsert platform record
    platform = Platform.query.filter_by(issuer=issuer).first()
    if not platform:
        platform = Platform(issuer=issuer, created_at=datetime.utcnow())
    platform.client_id = client_id
    platform.auth_login_url = authorization_endpoint
    platform.auth_token_url = token_endpoint
    platform.jwks_uri = jwks_uri
    platform.registration_client_uri = registration_client_uri
    platform.updated_at = datetime.utcnow()

    db.session.add(platform)
    db.session.commit()

    return render_template("admin/registration_success.html", platform=platform)


@bp.get("/admin/registration")
def admin_registration():
    """Admin page showing the registration URL."""
    registration_url = url_for("registration.dynamic_registration", _external=True)
    return render_template("admin/registration.html", registration_url=registration_url)
