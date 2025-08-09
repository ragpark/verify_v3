"""Initial database schema."""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

# Revision identifiers, used by Alembic.
revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "platforms",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("issuer", sa.String(), nullable=False, unique=True),
        sa.Column("client_id", sa.String(), nullable=False),
        sa.Column("auth_login_url", sa.String(), nullable=False),
        sa.Column("auth_token_url", sa.String(), nullable=False),
        sa.Column("jwks_uri", sa.String(), nullable=False),
        sa.Column("registration_client_uri", sa.String()),
        sa.Column("registration_access_token", sa.String()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )

    op.create_table(
        "deployments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("platform_id", sa.Integer(), sa.ForeignKey("platforms.id"), nullable=False),
        sa.Column("deployment_id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )

    op.create_table(
        "nonces",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("value", sa.String(), unique=True, nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
    )

    op.create_table(
        "states",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("value", sa.String(), unique=True, nullable=False),
        sa.Column("redirect_after", sa.String()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
    )

    op.create_table(
        "tool_keys",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kid", sa.String(), unique=True, nullable=False),
        sa.Column("private_pem", sa.String(), nullable=False),
        sa.Column("public_jwk_json", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("rotated_at", sa.DateTime()),
        sa.Column("is_active", sa.Boolean(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("tool_keys")
    op.drop_table("states")
    op.drop_table("nonces")
    op.drop_table("deployments")
    op.drop_table("platforms")
