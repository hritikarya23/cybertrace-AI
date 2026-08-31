"""initial SIH26106 database schema"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial_schema"
down_revision: Union[str, Sequence[str], None] = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=200), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False, server_default="analyst"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "emails",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("message_id", sa.String(length=998)),
        sa.Column("sender", sa.String(length=998)),
        sa.Column("recipient", sa.Text()),
        sa.Column("reply_to", sa.Text()),
        sa.Column("return_path", sa.Text()),
        sa.Column("subject", sa.Text()),
        sa.Column("body_text", sa.Text()),
        sa.Column("body_html", sa.Text()),
        sa.Column("raw_email_path", sa.Text()),
        sa.Column("received_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_emails_user_created", "emails", ["user_id", "created_at"])
    op.create_index("ix_emails_message_id", "emails", ["message_id"])

    op.create_table(
        "email_headers",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email_id", sa.Integer(), sa.ForeignKey("emails.id", ondelete="CASCADE"), nullable=False),
        sa.Column("header_name", sa.String(length=255), nullable=False),
        sa.Column("header_value", sa.Text(), nullable=False),
    )
    op.create_index("ix_email_headers_email_name", "email_headers", ["email_id", "header_name"])

    op.create_table(
        "received_hops",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email_id", sa.Integer(), sa.ForeignKey("emails.id", ondelete="CASCADE"), nullable=False),
        sa.Column("hop_order", sa.Integer(), nullable=False),
        sa.Column("raw_received_header", sa.Text(), nullable=False),
        sa.Column("source_ip", sa.String(length=64)),
        sa.Column("source_hostname", sa.String(length=255)),
        sa.Column("destination_hostname", sa.String(length=255)),
        sa.Column("timestamp", sa.DateTime(timezone=True)),
        sa.Column("is_private_ip", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_public_ip", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_reliable", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.UniqueConstraint("email_id", "hop_order", name="uq_received_hops_email_order"),
    )
    op.create_index("ix_received_hops_email_order", "received_hops", ["email_id", "hop_order"])
    op.create_index("ix_received_hops_source_ip", "received_hops", ["source_ip"])

    op.create_table(
        "urls",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email_id", sa.Integer(), sa.ForeignKey("emails.id", ondelete="CASCADE"), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("normalized_url", sa.Text()),
        sa.Column("domain", sa.String(length=255)),
        sa.Column("scheme", sa.String(length=16)),
        sa.Column("port", sa.Integer()),
        sa.Column("path", sa.Text()),
        sa.Column("is_shortened", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_suspicious", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("risk_score", sa.Integer()),
        sa.Column("classification", sa.String(length=64)),
        sa.Column("reason", sa.Text()),
    )
    op.create_index("ix_urls_email_id", "urls", ["email_id"])
    op.create_index("ix_urls_domain", "urls", ["domain"])

    op.create_table(
        "domains",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email_id", sa.Integer(), sa.ForeignKey("emails.id", ondelete="CASCADE"), nullable=False),
        sa.Column("domain", sa.String(length=255), nullable=False),
        sa.Column("domain_age", sa.Integer()),
        sa.Column("registrar", sa.String(length=255)),
        sa.Column("creation_date", sa.DateTime(timezone=True)),
        sa.Column("expiration_date", sa.DateTime(timezone=True)),
        sa.Column("reputation", sa.String(length=64)),
        sa.Column("is_lookalike", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_suspicious", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("risk_score", sa.Integer()),
    )
    op.create_index("ix_domains_email_id", "domains", ["email_id"])
    op.create_index("ix_domains_domain", "domains", ["domain"])

    op.create_table(
        "ip_addresses",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email_id", sa.Integer(), sa.ForeignKey("emails.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ip", sa.String(length=64), nullable=False),
        sa.Column("ip_version", sa.Integer()),
        sa.Column("country", sa.String(length=128)),
        sa.Column("region", sa.String(length=128)),
        sa.Column("city", sa.String(length=128)),
        sa.Column("latitude", sa.Float()),
        sa.Column("longitude", sa.Float()),
        sa.Column("isp", sa.String(length=255)),
        sa.Column("organization", sa.String(length=255)),
        sa.Column("asn", sa.String(length=64)),
        sa.Column("hosting_provider", sa.String(length=255)),
        sa.Column("is_vpn", sa.Boolean()),
        sa.Column("is_proxy", sa.Boolean()),
        sa.Column("is_tor", sa.Boolean()),
        sa.Column("is_private", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("reputation", sa.String(length=64)),
        sa.Column("risk_score", sa.Integer()),
    )
    op.create_index("ix_ip_addresses_email_id", "ip_addresses", ["email_id"])
    op.create_index("ix_ip_addresses_ip", "ip_addresses", ["ip"])

    op.create_table(
        "analyses",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email_id", sa.Integer(), sa.ForeignKey("emails.id", ondelete="CASCADE"), nullable=False),
        sa.Column("classification", sa.String(length=64), nullable=False, server_default="unknown"),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="queued"),
        sa.Column("summary", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_analyses_email_created", "analyses", ["email_id", "created_at"])
    op.create_index("ix_analyses_classification", "analyses", ["classification"])
    op.create_index("ix_analyses_status", "analyses", ["status"])

    op.create_table(
        "indicators",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("analysis_id", sa.Integer(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("evidence", sa.Text()),
        sa.Column("score_contribution", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_indicators_analysis_severity", "indicators", ["analysis_id", "severity"])
    op.create_index("ix_indicators_category", "indicators", ["category"])

    op.create_table(
        "authentication_results",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email_id", sa.Integer(), sa.ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("spf_result", sa.String(length=32), nullable=False, server_default="unknown"),
        sa.Column("dkim_result", sa.String(length=32), nullable=False, server_default="unknown"),
        sa.Column("dmarc_result", sa.String(length=32), nullable=False, server_default="unknown"),
        sa.Column("spf_domain", sa.String(length=255)),
        sa.Column("dkim_domain", sa.String(length=255)),
        sa.Column("dmarc_policy", sa.String(length=32)),
        sa.Column("raw_authentication_header", sa.Text()),
    )

    op.create_table(
        "graph_nodes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("analysis_id", sa.Integer(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("node_type", sa.String(length=64), nullable=False),
        sa.Column("node_value", sa.Text(), nullable=False),
        sa.Column("metadata_json", postgresql.JSONB()),
        sa.UniqueConstraint("analysis_id", "node_type", "node_value", name="uq_graph_node_identity"),
    )
    op.create_index("ix_graph_nodes_analysis_type", "graph_nodes", ["analysis_id", "node_type"])

    op.create_table(
        "graph_edges",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("analysis_id", sa.Integer(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_node_id", sa.Integer(), sa.ForeignKey("graph_nodes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_node_id", sa.Integer(), sa.ForeignKey("graph_nodes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("relationship_type", sa.String(length=64), nullable=False),
        sa.Column("metadata_json", postgresql.JSONB()),
    )
    op.create_index("ix_graph_edges_analysis", "graph_edges", ["analysis_id"])
    op.create_index("ix_graph_edges_source_target", "graph_edges", ["source_node_id", "target_node_id"])

    op.create_table(
        "reports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("analysis_id", sa.Integer(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("report_type", sa.String(length=32), nullable=False),
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_reports_analysis_created", "reports", ["analysis_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_reports_analysis_created", table_name="reports")
    op.drop_table("reports")
    op.drop_index("ix_graph_edges_source_target", table_name="graph_edges")
    op.drop_index("ix_graph_edges_analysis", table_name="graph_edges")
    op.drop_table("graph_edges")
    op.drop_index("ix_graph_nodes_analysis_type", table_name="graph_nodes")
    op.drop_table("graph_nodes")
    op.drop_table("authentication_results")
    op.drop_index("ix_indicators_category", table_name="indicators")
    op.drop_index("ix_indicators_analysis_severity", table_name="indicators")
    op.drop_table("indicators")
    op.drop_index("ix_analyses_status", table_name="analyses")
    op.drop_index("ix_analyses_classification", table_name="analyses")
    op.drop_index("ix_analyses_email_created", table_name="analyses")
    op.drop_table("analyses")
    op.drop_index("ix_ip_addresses_ip", table_name="ip_addresses")
    op.drop_index("ix_ip_addresses_email_id", table_name="ip_addresses")
    op.drop_table("ip_addresses")
    op.drop_index("ix_domains_domain", table_name="domains")
    op.drop_index("ix_domains_email_id", table_name="domains")
    op.drop_table("domains")
    op.drop_index("ix_urls_domain", table_name="urls")
    op.drop_index("ix_urls_email_id", table_name="urls")
    op.drop_table("urls")
    op.drop_index("ix_received_hops_source_ip", table_name="received_hops")
    op.drop_index("ix_received_hops_email_order", table_name="received_hops")
    op.drop_table("received_hops")
    op.drop_index("ix_email_headers_email_name", table_name="email_headers")
    op.drop_table("email_headers")
    op.drop_index("ix_emails_message_id", table_name="emails")
    op.drop_index("ix_emails_user_created", table_name="emails")
    op.drop_table("emails")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
