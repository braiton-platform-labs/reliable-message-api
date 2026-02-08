"""initial tables

Revision ID: 0001_initial
Revises: 
Create Date: 2026-02-06 00:00:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "messages",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("message_raw", sa.Text(), nullable=False),
        sa.Column("message_normalized", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_unique_constraint("uq_messages_normalized", "messages", ["message_normalized"])
    op.create_index("ix_messages_created_at", "messages", ["created_at"], unique=False)

    op.create_table(
        "idempotency_keys",
        sa.Column("key", sa.String(length=200), primary_key=True, nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("response_snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("message_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["message_id"], ["messages.id"], ondelete="SET NULL"),
    )
    op.create_unique_constraint("uq_idempotency_key", "idempotency_keys", ["key"])
    op.create_index("ix_idempotency_created_at", "idempotency_keys", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_idempotency_created_at", table_name="idempotency_keys")
    op.drop_constraint("uq_idempotency_key", "idempotency_keys", type_="unique")
    op.drop_table("idempotency_keys")

    op.drop_index("ix_messages_created_at", table_name="messages")
    op.drop_constraint("uq_messages_normalized", "messages", type_="unique")
    op.drop_table("messages")
