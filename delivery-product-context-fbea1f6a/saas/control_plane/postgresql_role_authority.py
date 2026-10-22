"""Shared PostgreSQL catalog checks for one-purpose service roles.

PostgreSQL authority is spread across database-local and cluster-shared
catalogs.  Service startup checks must not treat the familiar table, schema,
function, and database ACLs as the complete privilege surface.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.engine import Connection

_ROLE_OWNED_CATALOG_AUTHORITY_SQL = sa.text(
    "/* omnigent_role_owned_catalog_authority */ "
    "WITH principal AS (SELECT oid FROM pg_roles WHERE rolname = :role), "
    "owned AS ("
    "SELECT 1 FROM pg_database object, principal WHERE object.datdba = principal.oid "
    "UNION ALL SELECT 1 FROM pg_namespace object, principal "
    "WHERE object.nspowner = principal.oid "
    "UNION ALL SELECT 1 FROM pg_class object, principal "
    "WHERE object.relowner = principal.oid "
    "UNION ALL SELECT 1 FROM pg_proc object, principal "
    "WHERE object.proowner = principal.oid "
    "UNION ALL SELECT 1 FROM pg_type object, principal "
    "WHERE object.typowner = principal.oid "
    "UNION ALL SELECT 1 FROM pg_language object, principal "
    "WHERE object.lanowner = principal.oid "
    "UNION ALL SELECT 1 FROM pg_largeobject_metadata object, principal "
    "WHERE object.lomowner = principal.oid "
    "UNION ALL SELECT 1 FROM pg_tablespace object, principal "
    "WHERE object.spcowner = principal.oid "
    "UNION ALL SELECT 1 FROM pg_foreign_data_wrapper object, principal "
    "WHERE object.fdwowner = principal.oid "
    "UNION ALL SELECT 1 FROM pg_foreign_server object, principal "
    "WHERE object.srvowner = principal.oid "
    "UNION ALL SELECT 1 FROM pg_extension object, principal "
    "WHERE object.extowner = principal.oid "
    "UNION ALL SELECT 1 FROM pg_event_trigger object, principal "
    "WHERE object.evtowner = principal.oid "
    "UNION ALL SELECT 1 FROM pg_publication object, principal "
    "WHERE object.pubowner = principal.oid "
    "UNION ALL SELECT 1 FROM pg_subscription object, principal "
    "WHERE object.subowner = principal.oid "
    "UNION ALL SELECT 1 FROM pg_collation object, principal "
    "WHERE object.collowner = principal.oid "
    "UNION ALL SELECT 1 FROM pg_conversion object, principal "
    "WHERE object.conowner = principal.oid "
    "UNION ALL SELECT 1 FROM pg_operator object, principal "
    "WHERE object.oprowner = principal.oid "
    "UNION ALL SELECT 1 FROM pg_opclass object, principal "
    "WHERE object.opcowner = principal.oid "
    "UNION ALL SELECT 1 FROM pg_opfamily object, principal "
    "WHERE object.opfowner = principal.oid "
    "UNION ALL SELECT 1 FROM pg_ts_dict object, principal "
    "WHERE object.dictowner = principal.oid "
    "UNION ALL SELECT 1 FROM pg_ts_config object, principal "
    "WHERE object.cfgowner = principal.oid "
    "UNION ALL SELECT 1 FROM pg_statistic_ext object, principal "
    "WHERE object.stxowner = principal.oid "
    "UNION ALL SELECT 1 FROM pg_default_acl object, principal "
    "WHERE object.defaclrole = principal.oid "
    "UNION ALL SELECT 1 FROM pg_user_mappings object, principal "
    "WHERE object.umuser = principal.oid "
    "UNION ALL SELECT 1 FROM pg_db_role_setting object, principal "
    "WHERE :include_role_settings AND object.setrole = principal.oid) "
    "SELECT count(*) FROM owned"
)

_ROLE_DIRECT_ACL_AUTHORITY_SQL = sa.text(
    "/* omnigent_role_direct_acl_authority */ "
    "WITH principal AS (SELECT oid FROM pg_roles WHERE rolname = :role), "
    "observed AS ("
    "SELECT 1 FROM pg_database object CROSS JOIN LATERAL "
    "aclexplode(object.datacl) acl, principal WHERE acl.grantee = principal.oid "
    "UNION ALL SELECT 1 FROM pg_namespace object CROSS JOIN LATERAL "
    "aclexplode(object.nspacl) acl, principal WHERE acl.grantee = principal.oid "
    "UNION ALL SELECT 1 FROM pg_class object CROSS JOIN LATERAL "
    "aclexplode(object.relacl) acl, principal WHERE acl.grantee = principal.oid "
    "UNION ALL SELECT 1 FROM pg_attribute object CROSS JOIN LATERAL "
    "aclexplode(object.attacl) acl, principal WHERE acl.grantee = principal.oid "
    "UNION ALL SELECT 1 FROM pg_proc object CROSS JOIN LATERAL "
    "aclexplode(object.proacl) acl, principal WHERE acl.grantee = principal.oid "
    "UNION ALL SELECT 1 FROM pg_type object CROSS JOIN LATERAL "
    "aclexplode(object.typacl) acl, principal WHERE acl.grantee = principal.oid "
    "UNION ALL SELECT 1 FROM pg_language object CROSS JOIN LATERAL "
    "aclexplode(object.lanacl) acl, principal WHERE acl.grantee = principal.oid "
    "UNION ALL SELECT 1 FROM pg_largeobject_metadata object CROSS JOIN LATERAL "
    "aclexplode(object.lomacl) acl, principal WHERE acl.grantee = principal.oid "
    "UNION ALL SELECT 1 FROM pg_foreign_data_wrapper object CROSS JOIN LATERAL "
    "aclexplode(object.fdwacl) acl, principal WHERE acl.grantee = principal.oid "
    "UNION ALL SELECT 1 FROM pg_foreign_server object CROSS JOIN LATERAL "
    "aclexplode(object.srvacl) acl, principal WHERE acl.grantee = principal.oid "
    "UNION ALL SELECT 1 FROM pg_tablespace object CROSS JOIN LATERAL "
    "aclexplode(object.spcacl) acl, principal WHERE acl.grantee = principal.oid "
    "UNION ALL SELECT 1 FROM pg_parameter_acl object CROSS JOIN LATERAL "
    "aclexplode(object.paracl) acl, principal WHERE acl.grantee = principal.oid "
    "UNION ALL SELECT 1 FROM pg_default_acl object CROSS JOIN LATERAL "
    "aclexplode(object.defaclacl) acl, principal WHERE acl.grantee = principal.oid) "
    "SELECT count(*) FROM observed"
)

_ROLE_GLOBAL_ACL_AUTHORITY_SQL = sa.text(
    "/* omnigent_role_global_acl_authority */ "
    "WITH principal AS (SELECT oid FROM pg_roles WHERE rolname = :role), "
    "observed AS ("
    "SELECT 1 FROM pg_language object CROSS JOIN LATERAL "
    "aclexplode(object.lanacl) acl, principal WHERE acl.grantee = principal.oid "
    "UNION ALL SELECT 1 FROM pg_largeobject_metadata object CROSS JOIN LATERAL "
    "aclexplode(object.lomacl) acl, principal WHERE acl.grantee = principal.oid "
    "UNION ALL SELECT 1 FROM pg_foreign_data_wrapper object CROSS JOIN LATERAL "
    "aclexplode(object.fdwacl) acl, principal WHERE acl.grantee = principal.oid "
    "UNION ALL SELECT 1 FROM pg_foreign_server object CROSS JOIN LATERAL "
    "aclexplode(object.srvacl) acl, principal WHERE acl.grantee = principal.oid "
    "UNION ALL SELECT 1 FROM pg_tablespace object CROSS JOIN LATERAL "
    "aclexplode(object.spcacl) acl, principal WHERE acl.grantee = principal.oid "
    "UNION ALL SELECT 1 FROM pg_parameter_acl object CROSS JOIN LATERAL "
    "aclexplode(object.paracl) acl, principal WHERE acl.grantee = principal.oid) "
    "SELECT count(*) FROM observed"
)


def count_owned_catalog_authorities(
    connection: Connection,
    *,
    role: str,
    include_role_settings: bool,
) -> int:
    """Count catalog ownership, mappings, defaults, and optional role settings."""

    return int(
        connection.execute(
            _ROLE_OWNED_CATALOG_AUTHORITY_SQL,
            {"role": role, "include_role_settings": include_role_settings},
        ).scalar_one()
    )


def count_direct_acl_authorities(connection: Connection, *, role: str) -> int:
    """Count explicit ACL entries across every PostgreSQL grantable object kind."""

    return int(connection.execute(_ROLE_DIRECT_ACL_AUTHORITY_SQL, {"role": role}).scalar_one())


def count_global_acl_authorities(connection: Connection, *, role: str) -> int:
    """Count ACLs outside the database-local relation/schema/routine surface."""

    return int(connection.execute(_ROLE_GLOBAL_ACL_AUTHORITY_SQL, {"role": role}).scalar_one())


__all__ = [
    "count_direct_acl_authorities",
    "count_global_acl_authorities",
    "count_owned_catalog_authorities",
]
