from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def json_type():
    """Use PostgreSQL JSONB while remaining easy to test with SQLite."""
    return JSONB


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="analyst", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    emails: Mapped[list[Email]] = relationship(back_populates="user")


class Email(TimestampMixin, Base):
    __tablename__ = "emails"
    __table_args__ = (
        Index("ix_emails_user_created", "user_id", "created_at"),
        Index("ix_emails_message_id", "message_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    message_id: Mapped[str | None] = mapped_column(String(998), nullable=True)
    sender: Mapped[str | None] = mapped_column(String(998), nullable=True)
    recipient: Mapped[str | None] = mapped_column(Text, nullable=True)
    reply_to: Mapped[str | None] = mapped_column(Text, nullable=True)
    return_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    body_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    body_html: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_email_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship(back_populates="emails")
    headers: Mapped[list[EmailHeader]] = relationship(back_populates="email", cascade="all, delete-orphan")
    received_hops: Mapped[list[ReceivedHop]] = relationship(back_populates="email", cascade="all, delete-orphan")
    urls: Mapped[list[URL]] = relationship(back_populates="email", cascade="all, delete-orphan")
    domains: Mapped[list[Domain]] = relationship(back_populates="email", cascade="all, delete-orphan")
    ip_addresses: Mapped[list[IPAddress]] = relationship(back_populates="email", cascade="all, delete-orphan")
    authentication_result: Mapped[AuthenticationResult | None] = relationship(
        back_populates="email", cascade="all, delete-orphan", uselist=False
    )
    analyses: Mapped[list[Analysis]] = relationship(back_populates="email", cascade="all, delete-orphan")


class EmailHeader(Base):
    __tablename__ = "email_headers"
    __table_args__ = (Index("ix_email_headers_email_name", "email_id", "header_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email_id: Mapped[int] = mapped_column(ForeignKey("emails.id", ondelete="CASCADE"), nullable=False)
    header_name: Mapped[str] = mapped_column(String(255), nullable=False)
    header_value: Mapped[str] = mapped_column(Text, nullable=False)

    email: Mapped[Email] = relationship(back_populates="headers")


class ReceivedHop(Base):
    __tablename__ = "received_hops"
    __table_args__ = (
        UniqueConstraint("email_id", "hop_order", name="uq_received_hops_email_order"),
        Index("ix_received_hops_email_order", "email_id", "hop_order"),
        Index("ix_received_hops_source_ip", "source_ip"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email_id: Mapped[int] = mapped_column(ForeignKey("emails.id", ondelete="CASCADE"), nullable=False)
    hop_order: Mapped[int] = mapped_column(Integer, nullable=False)
    raw_received_header: Mapped[str] = mapped_column(Text, nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    destination_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_private_ip: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_public_ip: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_reliable: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    email: Mapped[Email] = relationship(back_populates="received_hops")


class URL(Base):
    __tablename__ = "urls"
    __table_args__ = (
        Index("ix_urls_email_id", "email_id"),
        Index("ix_urls_domain", "domain"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email_id: Mapped[int] = mapped_column(ForeignKey("emails.id", ondelete="CASCADE"), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    scheme: Mapped[str | None] = mapped_column(String(16), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    path: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_shortened: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_suspicious: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    classification: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    email: Mapped[Email] = relationship(back_populates="urls")


class Domain(Base):
    __tablename__ = "domains"
    __table_args__ = (
        Index("ix_domains_email_id", "email_id"),
        Index("ix_domains_domain", "domain"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email_id: Mapped[int] = mapped_column(ForeignKey("emails.id", ondelete="CASCADE"), nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    domain_age: Mapped[int | None] = mapped_column(Integer, nullable=True)
    registrar: Mapped[str | None] = mapped_column(String(255), nullable=True)
    creation_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expiration_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reputation: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_lookalike: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_suspicious: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)

    email: Mapped[Email] = relationship(back_populates="domains")


class IPAddress(Base):
    __tablename__ = "ip_addresses"
    __table_args__ = (
        Index("ix_ip_addresses_email_id", "email_id"),
        Index("ix_ip_addresses_ip", "ip"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email_id: Mapped[int] = mapped_column(ForeignKey("emails.id", ondelete="CASCADE"), nullable=False)
    ip: Mapped[str] = mapped_column(String(64), nullable=False)
    ip_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    country: Mapped[str | None] = mapped_column(String(128), nullable=True)
    region: Mapped[str | None] = mapped_column(String(128), nullable=True)
    city: Mapped[str | None] = mapped_column(String(128), nullable=True)
    latitude: Mapped[float | None] = mapped_column(nullable=True)
    longitude: Mapped[float | None] = mapped_column(nullable=True)
    isp: Mapped[str | None] = mapped_column(String(255), nullable=True)
    organization: Mapped[str | None] = mapped_column(String(255), nullable=True)
    asn: Mapped[str | None] = mapped_column(String(64), nullable=True)
    hosting_provider: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_vpn: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    is_proxy: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    is_tor: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    is_private: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    reputation: Mapped[str | None] = mapped_column(String(64), nullable=True)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)

    email: Mapped[Email] = relationship(back_populates="ip_addresses")


class Analysis(Base):
    __tablename__ = "analyses"
    __table_args__ = (
        Index("ix_analyses_email_created", "email_id", "created_at"),
        Index("ix_analyses_classification", "classification"),
        Index("ix_analyses_status", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email_id: Mapped[int] = mapped_column(ForeignKey("emails.id", ondelete="CASCADE"), nullable=False)
    classification: Mapped[str] = mapped_column(String(64), default="unknown", nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    confidence: Mapped[float] = mapped_column(nullable=False, default=0.0)
    status: Mapped[str] = mapped_column(String(32), default="queued", nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    email: Mapped[Email] = relationship(back_populates="analyses")
    indicators: Mapped[list[Indicator]] = relationship(back_populates="analysis", cascade="all, delete-orphan")
    graph_nodes: Mapped[list[GraphNode]] = relationship(back_populates="analysis", cascade="all, delete-orphan")
    graph_edges: Mapped[list[GraphEdge]] = relationship(back_populates="analysis", cascade="all, delete-orphan")
    reports: Mapped[list[Report]] = relationship(back_populates="analysis", cascade="all, delete-orphan")


class Indicator(Base):
    __tablename__ = "indicators"
    __table_args__ = (
        Index("ix_indicators_analysis_severity", "analysis_id", "severity"),
        Index("ix_indicators_category", "category"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    score_contribution: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    analysis: Mapped[Analysis] = relationship(back_populates="indicators")


class AuthenticationResult(Base):
    __tablename__ = "authentication_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email_id: Mapped[int] = mapped_column(
        ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    spf_result: Mapped[str] = mapped_column(String(32), default="unknown", nullable=False)
    dkim_result: Mapped[str] = mapped_column(String(32), default="unknown", nullable=False)
    dmarc_result: Mapped[str] = mapped_column(String(32), default="unknown", nullable=False)
    spf_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    dkim_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    dmarc_policy: Mapped[str | None] = mapped_column(String(32), nullable=True)
    raw_authentication_header: Mapped[str | None] = mapped_column(Text, nullable=True)

    email: Mapped[Email] = relationship(back_populates="authentication_result")


class GraphNode(Base):
    __tablename__ = "graph_nodes"
    __table_args__ = (
        Index("ix_graph_nodes_analysis_type", "analysis_id", "node_type"),
        UniqueConstraint("analysis_id", "node_type", "node_value", name="uq_graph_node_identity"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False)
    node_type: Mapped[str] = mapped_column(String(64), nullable=False)
    node_value: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(json_type(), nullable=True)

    analysis: Mapped[Analysis] = relationship(back_populates="graph_nodes")
    outgoing_edges: Mapped[list[GraphEdge]] = relationship(
        foreign_keys="GraphEdge.source_node_id", back_populates="source_node"
    )
    incoming_edges: Mapped[list[GraphEdge]] = relationship(
        foreign_keys="GraphEdge.target_node_id", back_populates="target_node"
    )


class GraphEdge(Base):
    __tablename__ = "graph_edges"
    __table_args__ = (
        Index("ix_graph_edges_analysis", "analysis_id"),
        Index("ix_graph_edges_source_target", "source_node_id", "target_node_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False)
    source_node_id: Mapped[int] = mapped_column(ForeignKey("graph_nodes.id", ondelete="CASCADE"), nullable=False)
    target_node_id: Mapped[int] = mapped_column(ForeignKey("graph_nodes.id", ondelete="CASCADE"), nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(64), nullable=False)
    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(json_type(), nullable=True)

    analysis: Mapped[Analysis] = relationship(back_populates="graph_edges")
    source_node: Mapped[GraphNode] = relationship(
        foreign_keys=[source_node_id], back_populates="outgoing_edges"
    )
    target_node: Mapped[GraphNode] = relationship(
        foreign_keys=[target_node_id], back_populates="incoming_edges"
    )


class Report(Base):
    __tablename__ = "reports"
    __table_args__ = (Index("ix_reports_analysis_created", "analysis_id", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False)
    report_type: Mapped[str] = mapped_column(String(32), nullable=False)
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    analysis: Mapped[Analysis] = relationship(back_populates="reports")


# Forward-reference aliases for static type checkers / relationship annotations.
# SQLAlchemy resolves the class names at mapper configuration time.
