"""JWKS endpoint and key generation."""
from __future__ import annotations

import base64
import json
import secrets
from datetime import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Blueprint, jsonify

from .. import db
from ..models import ToolKey

bp = Blueprint("jwks", __name__)


def _b64encode_int(val: int) -> str:
    """Base64url encode an integer."""
    return base64.urlsafe_b64encode(val.to_bytes((val.bit_length() + 7) // 8, "big")).rstrip(b"=").decode("ascii")


def _generate_tool_key() -> ToolKey:
    """Generate a new RSA keypair and persist it."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_numbers = private_key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "n": _b64encode_int(public_numbers.n),
        "e": _b64encode_int(public_numbers.e),
    }
    kid = secrets.token_urlsafe(8)
    jwk["kid"] = kid

    tool_key = ToolKey(
        kid=kid,
        private_pem=private_pem,
        public_jwk_json=json.dumps(jwk),
        created_at=datetime.utcnow(),
        is_active=True,
    )
    db.session.add(tool_key)
    db.session.commit()
    return tool_key


@bp.get("/.well-known/jwks.json")
def jwks():
    """Return the active JSON Web Key Set.

    If no key exists, one is generated on the fly and stored.
    """
    keys = ToolKey.query.filter_by(is_active=True).all()
    if not keys:
        keys = [_generate_tool_key()]

    return jsonify({"keys": [json.loads(k.public_jwk_json) for k in keys]})
