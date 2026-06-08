"""Initial migration - create all tables

Revision ID: 001_initial
Revises:
Create Date: 2025-01-01 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSON

revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    user_tier_enum = sa.Enum("free", "pro", "enterprise", name="user_tier")
    user_tier_enum.create(op.get_bind(), checkfirst=True)

    threat_level_enum = sa.Enum(
        "safe", "low", "medium", "high", "critical", name="threat_level_enum"
    )
    threat_level_enum.create(op.get_bind(), checkfirst=True)

    threat_type_enum = sa.Enum(
        "phishing", "malware", "social_engineering", "credential_theft",
        "financial_fraud", "brand_impersonation", "homograph_attack",
        "typosquatting", "unknown", name="threat_type_enum",
    )
    threat_type_enum.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "users",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(255), unique=True, index=True, nullable=False),
        sa.Column("hashed_password", sa.Text, nullable=False),
        sa.Column("is_active", sa.Boolean, default=True, nullable=False),
        sa.Column("tier", user_tier_enum, default="free", nullable=False),
        sa.Column("two_factor_secret", sa.String(32), nullable=True),
        sa.Column("two_factor_enabled", sa.Boolean, default=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
    )

    op.create_table(
        "scan_results",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            index=True,
            nullable=False,
        ),
        sa.Column("url", sa.Text, nullable=False),
        sa.Column("domain", sa.String(255), index=True, nullable=False),
        sa.Column("risk_score", sa.Integer, nullable=False),
        sa.Column("threat_level", threat_level_enum, nullable=False),
        sa.Column("threat_type", threat_type_enum, default="unknown", nullable=False),
        sa.Column("signals", JSON, default=list, nullable=False),
        sa.Column("recommendation", sa.Text, default=""),
        sa.Column("scan_duration_ms", sa.Float, default=0.0),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            index=True,
        ),
    )

    op.create_table(
        "threat_reports",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("url", sa.Text, nullable=False),
        sa.Column("domain", sa.String(255), index=True, nullable=False),
        sa.Column("threat_type", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("signals", JSON, default=list, nullable=False),
        sa.Column("ml_votes", sa.Integer, default=0),
        sa.Column("community_reports", sa.Integer, default=0),
        sa.Column("is_confirmed", sa.Boolean, default=False),
        sa.Column(
            "first_seen",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column(
            "last_seen",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )

    op.create_table(
        "api_keys",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            index=True,
            nullable=False,
        ),
        sa.Column("key_hash", sa.String(255), unique=True, nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("is_active", sa.Boolean, default=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )

    op.create_index("ix_scan_results_created_at", "scan_results", ["created_at"])
    op.create_index("ix_scan_results_domain", "scan_results", ["domain"])
    op.create_index("ix_users_email", "users", ["email"])


def downgrade() -> None:
    op.drop_table("api_keys")
    op.drop_table("threat_reports")
    op.drop_table("scan_results")
    op.drop_table("users")

    sa.Enum(name="threat_type_enum").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="threat_level_enum").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="user_tier").drop(op.get_bind(), checkfirst=True)
