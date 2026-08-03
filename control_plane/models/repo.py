"""Repository table (50_ §2.2).

A `repo` is a source-control repository we scan (via the GitHub App in mode-a,
or via SARIF upload in mode-b). Tenant-scoped.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from control_plane.models.base import Base, TenantMixin, TimestampMixin, pk_column, short_str


class Repo(Base, TenantMixin, TimestampMixin):
    __tablename__ = "repos"
    __table_args__ = (
        # A provider repo maps to at most one row per tenant.
        UniqueConstraint(
            "tenant_id", "provider", "external_id", name="uq_repo_provider_external"
        ),
    )

    id: Mapped[uuid.UUID] = pk_column()
    # tenant_id (FK orgs.id) supplied by TenantMixin.
    org_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("orgs.id"), nullable=False
    )
    provider: Mapped[str] = short_str(default="github")  # github | gitlab | ...
    external_id: Mapped[str] = short_str(nullable=False)  # provider's repo id
    full_name: Mapped[str] = short_str(default="")        # e.g. "acme/agent-bot"
    default_branch: Mapped[str] = short_str(default="main")
    # GitHub App installation that grants us a short-lived token (50_ §2.5).
    # Nullable for mode-b repos (customer runs the scan, we never clone).
    github_installation_id: Mapped[str | None] = short_str(nullable=True)

    scans: Mapped[list["Scan"]] = relationship(back_populates="repo")  # noqa: F821
