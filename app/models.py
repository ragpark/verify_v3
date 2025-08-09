"""Database models used by the LTI tool."""
from __future__ import annotations

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship

from . import db


class Platform(db.Model):
    __tablename__ = "platforms"

    id = Column(Integer, primary_key=True)
    issuer = Column(String, unique=True, nullable=False)
    client_id = Column(String, nullable=False)
    auth_login_url = Column(String, nullable=False)
    auth_token_url = Column(String, nullable=False)
    jwks_uri = Column(String, nullable=False)
    registration_client_uri = Column(String)
    registration_access_token = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    deployments = relationship("Deployment", back_populates="platform")


class Deployment(db.Model):
    __tablename__ = "deployments"

    id = Column(Integer, primary_key=True)
    platform_id = Column(Integer, ForeignKey("platforms.id"), nullable=False)
    deployment_id = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    platform = relationship("Platform", back_populates="deployments")


class Nonce(db.Model):
    __tablename__ = "nonces"

    id = Column(Integer, primary_key=True)
    value = Column(String, unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)


class State(db.Model):
    __tablename__ = "states"

    id = Column(Integer, primary_key=True)
    value = Column(String, unique=True, nullable=False)
    redirect_after = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)


class ToolKey(db.Model):
    __tablename__ = "tool_keys"

    id = Column(Integer, primary_key=True)
    kid = Column(String, unique=True, nullable=False)
    private_pem = Column(String, nullable=False)
    public_jwk_json = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    rotated_at = Column(DateTime)
    is_active = Column(Boolean, default=True)
