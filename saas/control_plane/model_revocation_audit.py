"""Deliver a distinct retained security intent through the shared audit contract."""

from __future__ import annotations

from sqlalchemy.engine import Connection

from saas.control_plane.model_disablement_audit import ModelDisablementAuditPublisher
from saas.control_plane.model_gateway_audit import verify_source_audit_function
from saas.control_plane.model_revocations import REVOCATION_EVENT

REVOCATION_AUDIT_SIGNATURE = "public.saas_audit_model_revocation_v1(uuid,jsonb)"
REVOCATION_AUDIT_SOURCE_SHA256 = "33d263ca882740db9c144df91421e218a4249dad107453b0bbd9200679140dfc"


def verify_revocation_audit_function(connection: Connection) -> int | None:
    return verify_source_audit_function(
        connection,
        signature=REVOCATION_AUDIT_SIGNATURE,
        expected_source_hash=REVOCATION_AUDIT_SOURCE_SHA256,
        source_table="public.saas_model_publication_revocations",
    )


class ModelRevocationAuditPublisher(ModelDisablementAuditPublisher):
    _event_type = REVOCATION_EVENT
    _reference_key = "revocation_id"
    _function_name = "public.saas_audit_model_revocation_v1"
    _failure_prefix = "model_revocation_audit"
    _query_name = "saas.model_revocation_audit.retain_evidence"

    def _verify_function(self, connection: Connection) -> int | None:
        return verify_revocation_audit_function(connection)
