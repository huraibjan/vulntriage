"""brief cache and affected-product index

Revision ID: a41c7d2b9e10
Revises: ee72898df6cc
Create Date: 2026-10-08
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "a41c7d2b9e10"
down_revision: Union[str, None] = "ee72898df6cc"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "brief_cache",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("vulnerability_id", sa.UUID(), nullable=False),
        sa.Column("mode", sa.String(length=32), nullable=False),
        sa.Column("llm_model", sa.String(length=64), nullable=False),
        sa.Column("payload_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["vulnerability_id"], ["vulnerability.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("vulnerability_id", "mode", "llm_model", name="uq_brief_cache_key"),
    )
    # Containment lookups (affected product → CVEs) drive asset matching.
    op.create_index(
        "ix_vuln_affected_products_gin",
        "vulnerability",
        ["affected_products_json"],
        postgresql_using="gin",
        postgresql_ops={"affected_products_json": "jsonb_path_ops"},
    )


def downgrade() -> None:
    op.drop_index("ix_vuln_affected_products_gin", table_name="vulnerability")
    op.drop_table("brief_cache")
