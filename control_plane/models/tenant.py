"""Multitenancy + identity + RBAC tables (50_ §2.2, §2.4).

    orgs        — the tenant boundary (tenant_id == org_id at MVP)
    teams       — sub-grouping within an org
    users       — global identities (SSO subject)
    memberships — the RBAC join: (user, team, role)

`orgs` is the tenant root, so it has an `id` but no `tenant_id` (it IS the
tenant). `users` are global (a user can belong to multiple orgs), so they are
NOT tenant-scoped either — the tenant scoping lives on `memberships`/`teams`
and everything downstream.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, UniqueConstraint, Enum as SAEnum
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from control_plane.models.base import (
    Base,
    TenantMixin,
    TimestampMixin,
    pk_column,
    short_str,
)
from control_plane.models.enums import DataRegion, Plan, Role


class Org(Base, TimestampMixin):
    """The tenant. `tenant_id` on every other table points here."""

    __tablename__ = "orgs"

    id: Mapped[uuid.UUID] = pk_column()
    name: Mapped[str] = short_str(nullable=False)
    plan: Mapped[Plan] = mapped_column(
        SAEnum(Plan, name="plan"), default=Plan.FREE, nullable=False
    )
    data_region: Mapped[DataRegion] = mapped_column(
        SAEnum(DataRegion, name="data_region"), default=DataRegion.US, nullable=False
    )

    teams: Mapped[list["Team"]] = relationship(back_populates="org")


class Team(Base, TenantMixin, TimestampMixin):
    __tablename__ = "teams"

    id: Mapped[uuid.UUID] = pk_column()
    # tenant_id (== org_id at MVP) comes from TenantMixin so RLS is uniform.
    org_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("orgs.id"), nullable=False
    )
    name: Mapped[str] = short_str(nullable=False)

    org: Mapped["Org"] = relationship(back_populates="teams")
    memberships: Mapped[list["Membership"]] = relationship(back_populates="team")


class User(Base, TimestampMixin):
    """Global identity. NOT tenant-scoped (one human, many orgs)."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = pk_column()
    email: Mapped[str] = short_str(nullable=False, unique=True)
    name: Mapped[str] = short_str(default="")
    # OIDC/SAML subject (50_ §2.4 — SSO is the enterprise paywall). Nullable for
    # local/dev accounts before an IdP is wired.
    sso_subject: Mapped[str | None] = short_str(nullable=True)

    memberships: Mapped[list["Membership"]] = relationship(back_populates="user")


class Membership(Base, TenantMixin, TimestampMixin):
    """RBAC edge: which user has which role on which team (50_ §2.4)."""

    __tablename__ = "memberships"
    __table_args__ = (
        UniqueConstraint("user_id", "team_id", name="uq_membership_user_team"),
    )

    id: Mapped[uuid.UUID] = pk_column()
    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    team_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("teams.id"), nullable=False
    )
    role: Mapped[Role] = mapped_column(
        SAEnum(Role, name="role"), default=Role.MEMBER, nullable=False
    )

    user: Mapped["User"] = relationship(back_populates="memberships")
    team: Mapped["Team"] = relationship(back_populates="memberships")
