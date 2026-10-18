"""Least-privilege production PostgreSQL migration orchestration.

The migration job deliberately uses four direct LOGIN identities.  Cluster
principals, database authority, official schema ownership, and SaaS schema
ownership are separate trust boundaries; application processes must not reuse
any of these URLs.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal, cast

import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Connection, Engine
from sqlalchemy.engine import URL, make_url
from sqlalchemy.pool import NullPool

from omnigent.db import ConversationBase, OmnigentBase
from saas.runtime_rls import install_runtime_rls, load_runtime_rls_contract, verify_runtime_rls

from .service_bindings import (
    EXPECTED_MODEL_PROJECTION_SERVICE_ROLES,
    EXPECTED_PLATFORM_ADMIN_SERVICE_ROLES,
    EXPECTED_PLATFORM_MODEL_SERVICE_ROLES,
    EXPECTED_PRODUCTION_SERVICE_ROLES,
    ProductionServiceRoleBindings,
    ProductionServiceRoleBindingsError,
    ProductionServiceRoleGraph,
    compose_production_service_role_graph,
)

AuthorityKind = Literal[
    "principal_operator",
    "database_owner",
    "official_owner",
    "saas_owner",
]
_ServiceRoleProfile = ProductionServiceRoleBindings | ProductionServiceRoleGraph

_AUTHORITY_KINDS: tuple[AuthorityKind, ...] = (
    "principal_operator",
    "database_owner",
    "official_owner",
    "saas_owner",
)
_FULL_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_ROLE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_ALLOWED_QUERY_KEYS = frozenset(
    {
        "application_name",
        "connect_timeout",
        "sslcert",
        "sslkey",
        "sslmode",
        "sslrootcert",
        "target_session_attrs",
    }
)
_LOCK_NAME = "omnigent-saas-production-postgresql-migration-v1"
_RUNTIME_ROLE = "omnigent_runtime_app"
_RUNTIME_PROVIDER_JOURNAL_SERVICE = "runtime_provider_journal"
_RUNTIME_PROVIDER_JOURNAL_SEARCH_PATH = ("search_path=public",)
_SERVER_SERVICE_ROLES = {
    "runtime": _RUNTIME_ROLE,
    "authenticator": "saas_authenticator",
    "app": "saas_app",
    "governance": "saas_governance",
    "public_api": "saas_public_api",
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_RECEIPT_BYTES = 16 * 1024
_PG_TRGM_VERSION = "1.6"
_PG_TRGM_PREDECESSOR_INDEXES = {
    "ix_conversation_items_search_text_trgm": (
        "conversation_items",
        "lower(search_text)",
    ),
    "ix_conversations_title_trgm": ("conversations", "lower((title)::text)"),
}
_PG_TRGM_INDEXES = {
    "ix_conversations_title_trgm": ("conversations", "lower((title)::text)"),
}
_PG_TRGM_MEMBER_IDENTITIES = (
    ("pg_opclass", "operator class gin_trgm_ops for access method gin"),
    ("pg_opclass", "operator class gist_trgm_ops for access method gist"),
    ("pg_operator", "operator %(text,text)"),
    ("pg_operator", "operator %>(text,text)"),
    ("pg_operator", "operator %>>(text,text)"),
    ("pg_operator", "operator <%(text,text)"),
    ("pg_operator", "operator <->(text,text)"),
    ("pg_operator", "operator <->>(text,text)"),
    ("pg_operator", "operator <->>>(text,text)"),
    ("pg_operator", "operator <<%(text,text)"),
    ("pg_operator", "operator <<->(text,text)"),
    ("pg_operator", "operator <<<->(text,text)"),
    ("pg_opfamily", "operator family gin_trgm_ops for access method gin"),
    ("pg_opfamily", "operator family gist_trgm_ops for access method gist"),
    (
        "pg_proc",
        "function gin_extract_query_trgm(text,internal,smallint,internal,internal,"
        "internal,internal)",
    ),
    ("pg_proc", "function gin_extract_value_trgm(text,internal)"),
    (
        "pg_proc",
        "function gin_trgm_consistent(internal,smallint,text,integer,internal,internal,"
        "internal,internal)",
    ),
    (
        "pg_proc",
        "function gin_trgm_triconsistent(internal,smallint,text,integer,internal,internal,"
        "internal)",
    ),
    ("pg_proc", "function gtrgm_compress(internal)"),
    ("pg_proc", "function gtrgm_consistent(internal,text,smallint,oid,internal)"),
    ("pg_proc", "function gtrgm_decompress(internal)"),
    ("pg_proc", "function gtrgm_distance(internal,text,smallint,oid,internal)"),
    ("pg_proc", "function gtrgm_in(cstring)"),
    ("pg_proc", "function gtrgm_options(internal)"),
    ("pg_proc", "function gtrgm_out(gtrgm)"),
    ("pg_proc", "function gtrgm_penalty(internal,internal,internal)"),
    ("pg_proc", "function gtrgm_picksplit(internal,internal)"),
    ("pg_proc", "function gtrgm_same(gtrgm,gtrgm,internal)"),
    ("pg_proc", "function gtrgm_union(internal,internal)"),
    ("pg_proc", "function set_limit(real)"),
    ("pg_proc", "function show_limit()"),
    ("pg_proc", "function show_trgm(text)"),
    ("pg_proc", "function similarity(text,text)"),
    ("pg_proc", "function similarity_dist(text,text)"),
    ("pg_proc", "function similarity_op(text,text)"),
    ("pg_proc", "function strict_word_similarity(text,text)"),
    ("pg_proc", "function strict_word_similarity_commutator_op(text,text)"),
    ("pg_proc", "function strict_word_similarity_dist_commutator_op(text,text)"),
    ("pg_proc", "function strict_word_similarity_dist_op(text,text)"),
    ("pg_proc", "function strict_word_similarity_op(text,text)"),
    ("pg_proc", "function word_similarity(text,text)"),
    ("pg_proc", "function word_similarity_commutator_op(text,text)"),
    ("pg_proc", "function word_similarity_dist_commutator_op(text,text)"),
    ("pg_proc", "function word_similarity_dist_op(text,text)"),
    ("pg_proc", "function word_similarity_op(text,text)"),
    ("pg_type", "type gtrgm"),
)
_PG_TRGM_MEMBER_IDENTITIES_BY_MAJOR = {
    16: _PG_TRGM_MEMBER_IDENTITIES,
    # PostgreSQL 18 records the extension-owned array type explicitly.
    18: (*_PG_TRGM_MEMBER_IDENTITIES, ("pg_type", "type gtrgm[]")),
}
_PG_TRGM_FUNCTION_CONTRACTS = {
    (
        "gin_extract_query_trgm",
        "text, internal, smallint, internal, internal, internal, internal",
    ): ("internal", "i", True, "s"),
    ("gin_extract_value_trgm", "text, internal"): ("internal", "i", True, "s"),
    (
        "gin_trgm_consistent",
        "internal, smallint, text, integer, internal, internal, internal, internal",
    ): ("boolean", "i", True, "s"),
    (
        "gin_trgm_triconsistent",
        "internal, smallint, text, integer, internal, internal, internal",
    ): ('"char"', "i", True, "s"),
    ("gtrgm_compress", "internal"): ("internal", "i", True, "s"),
    ("gtrgm_consistent", "internal, text, smallint, oid, internal"): ("boolean", "i", True, "s"),
    ("gtrgm_decompress", "internal"): ("internal", "i", True, "s"),
    ("gtrgm_distance", "internal, text, smallint, oid, internal"): (
        "double precision",
        "i",
        True,
        "s",
    ),
    ("gtrgm_in", "cstring"): ("gtrgm", "i", True, "s"),
    ("gtrgm_options", "internal"): ("void", "i", False, "s"),
    ("gtrgm_out", "gtrgm"): ("cstring", "i", True, "s"),
    ("gtrgm_penalty", "internal, internal, internal"): ("internal", "i", True, "s"),
    ("gtrgm_picksplit", "internal, internal"): ("internal", "i", True, "s"),
    ("gtrgm_same", "gtrgm, gtrgm, internal"): ("internal", "i", True, "s"),
    ("gtrgm_union", "internal, internal"): ("gtrgm", "i", True, "s"),
    ("set_limit", "real"): ("real", "v", True, "u"),
    ("show_limit", ""): ("real", "s", True, "s"),
    ("show_trgm", "text"): ("text[]", "i", True, "s"),
    ("similarity", "text, text"): ("real", "i", True, "s"),
    ("similarity_dist", "text, text"): ("real", "i", True, "s"),
    ("similarity_op", "text, text"): ("boolean", "s", True, "s"),
    ("strict_word_similarity", "text, text"): ("real", "i", True, "s"),
    ("strict_word_similarity_commutator_op", "text, text"): ("boolean", "s", True, "s"),
    ("strict_word_similarity_dist_commutator_op", "text, text"): ("real", "i", True, "s"),
    ("strict_word_similarity_dist_op", "text, text"): ("real", "i", True, "s"),
    ("strict_word_similarity_op", "text, text"): ("boolean", "s", True, "s"),
    ("word_similarity", "text, text"): ("real", "i", True, "s"),
    ("word_similarity_commutator_op", "text, text"): ("boolean", "s", True, "s"),
    ("word_similarity_dist_commutator_op", "text, text"): ("real", "i", True, "s"),
    ("word_similarity_dist_op", "text, text"): ("real", "i", True, "s"),
    ("word_similarity_op", "text, text"): ("boolean", "s", True, "s"),
}
_PG_TRGM_OPCLASS_CONTRACTS = {
    ("gin_trgm_ops", "gin", "gin_trgm_ops", "text", "integer", False),
    ("gist_trgm_ops", "gist", "gist_trgm_ops", "text", "gtrgm", False),
}
# Generated from a clean, source-controlled official+SaaS Alembic replay.  The
# key binds the only supported PostgreSQL majors and both migration heads; the
# digest is deliberately not learned from a privileged migration receipt.
_PUBLIC_SCHEMA_INVENTORY_SHA256 = {
    # Source-derived immutable model cutoff authority.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2l00000001",
    ): "08f1821ffaf7fcf2b908b3931e6dc265ed97daf7d9a7d35e62c33ce295c790e2",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2l00000001",
    ): "e70aabdaeba80706f198962945c968e56e76b805fc2766f756e48ae800eaac91",
    # Fresh PG16/18 restricted-role replay for physical recovery confirmation.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2k00000001",
    ): "edf3d5f1b3e00dada1ea8d56b579b9336ef4e7d694548bea8c8784d8e9e7f8cc",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2k00000001",
    ): "d0b213c617dadebc5a23861bb66f414b9e3931f43dfbf9fcf33bba8cdbbdd865",
    # Fresh PG16/18 restricted-role replay for delegated Runner identity.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2j00000001",
    ): "b6177c7f36b9fee29752645c7f50ed3f7de4c81b7d8d06de7ed3eff19c2c4b1d",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2j00000001",
    ): "fa4ff004257e6a48e58abb964cda5b0c4536cb1ad23ced3d8f813c01118a03ee",
    # Fresh PG16/18 restricted-role replay; historical interactive ownership only.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2i00000001",
    ): "f3807527ee100cb185b84b2ace0aa18cedeb289c87954d51b1cece7422d22f93",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2i00000001",
    ): "851062ab220e1ef6ebe99d4d5d8492afcfda5868da4a97c18ef050a27bc4f099",
    # Restricted source replay; evidence-bound machine customer usage.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2h00000001",
    ): "d16fbc8570fa94113b9d4fb83ca0550f5995ada79c033b9b7f05e6835f007406",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2h00000001",
    ): "7b9e7cee18e9fb34d4318ea8a1a544cad5e363382174e2f9809b6be7c24723d6",
    # PG16/18 restricted source replay; true-Run gateway lineage.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2g00000001",
    ): "77c8d086691f98fa4090c57801e53938d347d84ff7727ca0dc2c54ee9a16da29",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2g00000001",
    ): "c726e3919bdad6ac9a52fa050dc98281dfe7e38821d988546fa00aa020acac88",
    # PG16/18 restricted source replay; renewable real-Run model credentials.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2f00000001",
    ): "e9de5e2e33125a6f2119427571c1b74805c1a576d825a1d7648f03e4c8dae2f7",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2f00000001",
    ): "ad8a8c8b3b8a5626d2d517c6161d8ec8446e22003c56316bd6ed0b3e7d26d027",
    # PG16/18 source replay 4f9ec55c; tenant-scoped model candidate reads.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2e00000001",
    ): "f82346dfffbd263065be83a4d094c0f9f8286d8d6c4e5169d1cfc25452d83b31",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2e00000001",
    ): "524da8b85b6146339c1baf7688fea8fb37f566c9b4210ea75ddc229b47009f7d",
    # PG16/18 source replay d841a033; frozen execution customer prices.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2d00000001",
    ): "99902979b536b51454c6f3c9704e7a7dca8ed772c8fb9e60c69e006651a1e81f",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2d00000001",
    ): "782e0072d141d8936814994a8a7794afd4a066078e5afbc4ceaf71270261b9f9",
    # PG16/18 source replay 20be0280; bounded gateway audit chain delivery.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2c00000001",
    ): "0d7fd85a98d6ccbb90c1d5d38c768d616f75dc5fda4637a6ad07def460e0534e",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2c00000001",
    ): "8cf7deb85a90d6102c2f9339aabadc0defd0adb02836e21222c8cd5f628e94b4",
    # PG16/18 source replay 6607f02c; append-only gateway usage evidence.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2b00000001",
    ): "e592868bb88080fbf9f071d293359f34e3a08f57e7b0b43bafa0f922246f47af",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2b00000001",
    ): "e3d0f903ef1792d2cfb8c8af5e20b198bf53604c27a727309182627c295214ba",
    # PG16/18 source replay e4042218; tenant-scoped publication commands and versions.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2a00000001",
    ): "0ecc902489def4d0151d7647463176ee96665beb2217d91a047e19462cca8bc4",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2a00000001",
    ): "5faefd9f138f7b8d3b1e11b07dcd39bd9dac7fb645a5b5f4e0cc39db46d580f5",
    # PG16/18 restricted source replay 8955d6c9; durable funded model verification.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1f00000001",
    ): "ca594c4036914447b9be6d30f7aa1c1f4b2181a5bf669656d8ddd4c5782af4d6",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1f00000001",
    ): "9b78e955515d42d55cb2d21690335fe53f9d3dec0277507ff3d86ee0270829a3",
    # PG16/18 restricted source replay 48e0f389; explicit platform test funding.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1e00000001",
    ): "08215d64d8d70615d1a10bf355708534f1f60684dcf3b14a27ccd3a77180a6a4",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1e00000001",
    ): "893d03b8e1bf05d740358c54ee7fec4c933f909f3af3e8685c66bacd3f885530",
    # PG16/18 restricted source replay b9528de4; retained inference budget holds.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1d00000001",
    ): "3f056feec34a5f87d73700e3bafe8ab51797aabc27b4dc6be0b3d1b0fc901ceb",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1d00000001",
    ): "cd78fdb34b71f91b0947958f7032b1ed42698b2f105e12ee4fe839bc4ce6812b",
    # PG16/18 restricted source replay 01d67d8d; immutable model drafts.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1c00000001",
    ): "78a572b84059c07a5f612ce0f5648acfe954af5837b66f7e666da5979c249c68",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1c00000001",
    ): "7396e0d0e5b992c8af4aa2c14cb30c379dcd33a98829e4f797b53054e8dda548",
    # PG16/18 four-authority replay source 0c88bfbf, including the projection receipt.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1b00000001",
    ): "561c4f917b9f6c4452ef3b21e7407f205d2439ac5e0cfa69a228e2b098210dea",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1b00000001",
    ): "9f29baaae9fc589622089831a668a89c5354d0f857f4df8b8f616f51e04bf9af",
    (
        16,
        "mm1a2b3c4d5e",
        "lm1a00000001",
    ): "73f27f7154831640b5959eb5cde053bbdf104112d37937dff24b6d2e8c3d739b",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1a00000001",
    ): "65f5ec6d09613562d255304cadb522d03b6eff2041e91932408683b2ff9b556b",
    (
        16,
        "mm1a2b3c4d5e",
        "p0s000000015",
    ): "1a591cada825f34b46245b0239c851e3bda5153f4f0c0f716faf8cc5a8aeb488",
    (
        18,
        "mm1a2b3c4d5e",
        "p0s000000015",
    ): "7697dac74222f3740b7a4f0297216433b3eda011adb622a9d5882cde6cdabb5b",
    (
        16,
        "mm1a2b3c4d5e",
        "p0s000000014",
    ): "1a591cada825f34b46245b0239c851e3bda5153f4f0c0f716faf8cc5a8aeb488",
    (
        18,
        "mm1a2b3c4d5e",
        "p0s000000014",
    ): "7697dac74222f3740b7a4f0297216433b3eda011adb622a9d5882cde6cdabb5b",
    (
        16,
        "ga1b2c3d4e5f",
        "p0s000000011",
    ): "42cbe5e35ffc8eb607bbc3c2592f34ede975ef391fe10804f7f655f419427f21",
    (
        18,
        "ga1b2c3d4e5f",
        "p0s000000011",
    ): "7d4597b46eebb96fd8e29bb3feeb6a91747ad6bb35520888cc9497ddcc2ae7b7",
    (
        16,
        "ga1b2c3d4e5f",
        "p0s000000012",
    ): "287bc061ec82bb53386bb42d3a2d81ed1181327ef99830cf8d8ba548b3f8f416",
    (
        18,
        "ga1b2c3d4e5f",
        "p0s000000012",
    ): "a1d8e39b147d2621837b66b5685293b56b1076d0fda44402a9a6050f7f80c7a5",
    (
        18,
        "ge1b2c3d4e5f",
        "p0s000000012",
    ): "a1d8e39b147d2621837b66b5685293b56b1076d0fda44402a9a6050f7f80c7a5",
    (
        16,
        "ge1b2c3d4e5f",
        "p0s000000012",
    ): "287bc061ec82bb53386bb42d3a2d81ed1181327ef99830cf8d8ba548b3f8f416",
    (
        16,
        "ge1b2c3d4e5f",
        "p0s000000013",
    ): "8094ae2186ca82f153be054043461e1997c8991a62b227cf7547845e4cf79d3b",
    (
        18,
        "ge1b2c3d4e5f",
        "p0s000000013",
    ): "6d49f0e2072cc4e82734e868c78e43dca828ae22d95c4b46a6767db6fd292022",
    (
        16,
        "ge1b2c3d4e5f",
        "p0s000000014",
    ): "775cdf24568506b246dd9bbc6c194541f34a93c41dc09a4412a1e9baae4e8a4a",
    (
        18,
        "ge1b2c3d4e5f",
        "p0s000000014",
    ): "f62f0d5cef73fae51870adeae0ce1553878eab3b59e3155eabb4ba063ed2c536",
    (
        16,
        "hh1b2c3d4e5f",
        "p0s000000014",
    ): "fae976ecc3e6d7cc37461f6e35dbb08df50cb7fd82bf255a6f14b79d9123eb67",
    (
        18,
        "hh1b2c3d4e5f",
        "p0s000000014",
    ): "2ad8a9980b6c18780079a2d0764e84c3cf63c9a23e2489b583b7918f2b7308fc",
}
_SOURCE_SECURITY_CATALOG_SHA256 = {
    # Source-derived immutable model cutoff authority.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2l00000001",
    ): "1d648b6318e09ada40220b69a077f71939bc1bb162ec6f0b3f59e164667cae17",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2l00000001",
    ): "5b42d57b26e593ab2f7eb93bb30f84569dea2c71d34a0c21d3c33e345638954d",
    # Fresh PG16/18 restricted-role replay for physical recovery confirmation.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2k00000001",
    ): "4507cad425cfef496af26f52edd9081733a786cdff284c3f0038ebe17b80856e",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2k00000001",
    ): "d84022fbf8b4a07e04f7e871617d1cfe5c35b2320de28edddc4d5987469e8b61",
    # Fresh PG16/18 restricted-role replay for delegated Runner identity.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2j00000001",
    ): "8a3d0d539947e7ab4ef179197bcfac7bb19158878cb54b7bce979632163f7ccd",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2j00000001",
    ): "619b3d66c53cbe04b2e2f098cf12a9489ab3478efdb50a7e8d6891e52460fc25",
    # Fresh PG16/18 restricted-role replay; historical interactive ownership only.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2i00000001",
    ): "6de163caf24361d0982efeff06de7a0a0f02e74acc6d1015b829de6f0761b79a",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2i00000001",
    ): "a59cd0cffd487aa8c986e049ca2bf6148e84b94c6dbed391ab611f4b1992f30f",
    # Restricted source replay; evidence-bound machine customer usage.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2h00000001",
    ): "1f97515b335376ee9079f72dafe0f07b19e11b3ec05c323c0a80d634ff2d6168",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2h00000001",
    ): "f6609b9bfd3f8837c4a12c229bcd2935f458fc4d5c4131410074f048df33ee84",
    # PG16/18 restricted source replay; true-Run gateway lineage.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2g00000001",
    ): "62c4fa24a02174947ad21c4c92e75d5a5dd7a52880d591317e6007d4c6625caf",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2g00000001",
    ): "9fa0d8f075fd8d185e878ad3480d1ba895eb41d61aeb6c79a88abaf17e6e81e9",
    # PG16/18 restricted source replay; renewable real-Run model credentials.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2f00000001",
    ): "18270f45a8c64fce0cdd6c276c10cf01b2476fad219a12931329cc1bd85d83d4",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2f00000001",
    ): "7aa2d3c3f995e047638bba61a1d4f6319847c042fa9056375368bf599bae72bf",
    # PG16/18 source replay 4f9ec55c; tenant-scoped model candidate reads.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2e00000001",
    ): "66a9b2290d9236d2d4dec7a08c14447a68dbb1bd95b707d19ee72b4fbc38e843",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2e00000001",
    ): "e64cf676bb68d26fe8430bfcd20222d0ad9a71e6e5d52a1eecf81566f1c7207f",
    # PG16/18 source replay d841a033; frozen execution customer prices.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2d00000001",
    ): "fc5b065cc923f6330ea1a4aa750d1c722e685484d80cf99e93b0d5110320c050",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2d00000001",
    ): "9dd07462838951ec84ad01948d5033e1612be8071f65d37833667be8286dbd9a",
    # PG16/18 source replay 20be0280; bounded gateway audit chain delivery.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2c00000001",
    ): "8dd1e3fe78cbd83bb20d1672ef30bddad5048b40c67eb02b59041d11db6c0a40",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2c00000001",
    ): "07deca6e9766ebd561ef7210536b62805993b2473e49789af576357e1db4b0bb",
    # PG16/18 source replay 6607f02c; append-only gateway usage evidence.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2b00000001",
    ): "46b1e0ca4cb7e296d4e7e3838d4da36db5194d900e9b11f1e9cf5b151cdf1bd5",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2b00000001",
    ): "c3cb9f1fc36f6ce21652a35121c9fdd73b0739a1cc3dc5a19b1e1e7b00ec3a3f",
    # PG16/18 source replay e4042218; tenant-scoped publication commands and versions.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2a00000001",
    ): "dbfc959e1d6bf64d1730b6f2422d9c7d7ebf4230245b7748d65be9440273295a",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2a00000001",
    ): "85e10e44347b1f89160696695c60153f0a35ed464d99cf1658ed8009d962f514",
    # PG16/18 restricted source replay 8955d6c9; durable funded model verification.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1f00000001",
    ): "3e1874ab8c2d9642be859fa2106ed08789a950e37eda6eef4c3ec94417daf46a",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1f00000001",
    ): "45bdb5562069d1557b17671632c75ae71cffea99a566f775abc5c8e91258c99d",
    # PG16/18 restricted source replay 48e0f389; explicit platform test funding.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1e00000001",
    ): "f2d2221c2204ea2b331d2debdd002a9baeae92a343d82ae6510d1c85b0892c9c",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1e00000001",
    ): "a77b2ca511cda787935f7837141544ef57e843db7d1f71fb7c5b81451f66c094",
    # PG16/18 restricted source replay b9528de4; retained inference budget holds.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1d00000001",
    ): "643d6bf9e81a9b3b98cba4c0f1f394ce04012f068f3e8d225a74e2134bb754cd",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1d00000001",
    ): "034e94372746d9a7b529bdbda11b1696f0e2158680d55e615ccbd9a3327248c2",
    # PG16/18 restricted source replay 01d67d8d; immutable model drafts.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1c00000001",
    ): "e523b42a7dccc3ce3b9730859b1f570a42d7eb66478941aab380727986d1da26",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1c00000001",
    ): "61d3fc2f85fa3a7e832b6be9a00998a3b7af9796916cc5b82c2dd75dab6922ff",
    (
        16,
        "mm1a2b3c4d5e",
        "lm1b00000001",
    ): "852647e15383916271ec758c48d79988be55f94fb98ce0d9cbe0e3bc734989c4",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1b00000001",
    ): "793c86853718d18e8dc3a6ffe0ceed96f1f914088972d53b660bbead3eccbecd",
    (
        16,
        "mm1a2b3c4d5e",
        "lm1a00000001",
    ): "1db51154613388ab5f620d768c83e4a0b6684664646dc233a07a762931b42e1f",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1a00000001",
    ): "4c0be04405439e86e581ca4e48d913dfcc4c01708d32719e4e9c70baa44f93c6",
    (
        16,
        "mm1a2b3c4d5e",
        "p0s000000015",
    ): "9033a4d3e71a7745753e75dfb065f02812cb7a84cf2c551b74338ea38e18a663",
    (
        18,
        "mm1a2b3c4d5e",
        "p0s000000015",
    ): "8843b7fb17e25bdf02473f07b2a615f0ae48f24e9857a2f9113520ec00db7ada",
    (
        16,
        "mm1a2b3c4d5e",
        "p0s000000014",
    ): "98d42de6312375303ad20b435b120e0dc5a5a85d0d4cac49db72ac8450372821",
    (
        18,
        "mm1a2b3c4d5e",
        "p0s000000014",
    ): "1f4b459c885578cd5085fb8a41f3f476a356cebbf5dec1890cef5602069ed21d",
    (
        16,
        "ga1b2c3d4e5f",
        "p0s000000011",
    ): "e797644cd4eadbb8c87d4c48a9019add359165968d9ac5b2430853e44f24ea2c",
    (
        18,
        "ga1b2c3d4e5f",
        "p0s000000011",
    ): "a26afc73de1347dbb0f105548efb402e5583004049ee3b5553b5a86863d7c392",
    (
        16,
        "ga1b2c3d4e5f",
        "p0s000000012",
    ): "09ca0010b36f5f0e3b6a41e8aafa3b373c3199f882a34ebc8fdda1f5522f91b2",
    (
        18,
        "ga1b2c3d4e5f",
        "p0s000000012",
    ): "5af8ea5fd95dcda61b94ad3d1fafa196bb76d9e971f7c637e49523750362ab85",
    (
        18,
        "ge1b2c3d4e5f",
        "p0s000000012",
    ): "486bea3f52073f5884a18df0dfa0b809cc19515847ef0023b6502d1d272cf1fc",
    (
        16,
        "ge1b2c3d4e5f",
        "p0s000000012",
    ): "ea8a5527e7ed08d6bd09baeb2137f94518ce06e758d5be0c68f074be63538ee5",
    (
        16,
        "ge1b2c3d4e5f",
        "p0s000000013",
    ): "f030f29ad8505f226ddcf4befdd085b7a6f0cefa3deedf2b948318f952e1483e",
    (
        18,
        "ge1b2c3d4e5f",
        "p0s000000013",
    ): "2f3d25460eab0c9bb6e903399e146f5ff17ac526ebec5cf27b4d727ca8ee8d55",
    (
        16,
        "ge1b2c3d4e5f",
        "p0s000000014",
    ): "35ed8656006aed4820d702cb50737fa6848bb10752679130ddccedd4c60ae341",
    (
        18,
        "ge1b2c3d4e5f",
        "p0s000000014",
    ): "7d0c59e271b9bd2c602dfadf99430598d9c952ac60f8f085d4ebb33e02872dfc",
    (
        16,
        "hh1b2c3d4e5f",
        "p0s000000014",
    ): "586ea4cd62657c609919fa2c9d72ea83ae72a4c2efa675f9f2a0a8dab28ad569",
    (
        18,
        "hh1b2c3d4e5f",
        "p0s000000014",
    ): "994a688be7fde4a234e7acd347bcf1b8fd47dc7a6856dd580ee530865f6003e9",
}
_PLATFORM_MODEL_SOURCE_SECURITY_CATALOG_SHA256 = {
    # Source-derived immutable model cutoff authority.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2l00000001",
    ): "5ce7f73cf1a8e3d94cf63b1ffb9494a392d971b798c795d31c4d047e71559555",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2l00000001",
    ): "92f9824717abbcec82932613f4705e5f9590456883d876feaff64b96642eeaa7",
    # Fresh PG16/18 restricted-role replay for physical recovery confirmation.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2k00000001",
    ): "63a65e1739f8a2592b2de88de397121af1216d78103dea137abf4efaf1a20c67",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2k00000001",
    ): "f91fdf3caaf052637d1d0c6e67f5150bf7e73463a93b7157d450815e9b4d0e23",
    # Fresh PG16/18 restricted-role replay for delegated Runner identity.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2j00000001",
    ): "237f203f10a28a9dbbcd4c5b365a2d69e1d7eeaff65f7b31cfc07b805caa619a",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2j00000001",
    ): "66f80962b9555b3582c4e597c3219944415f58f384fd8fa12a9c8f249254f7bf",
    # Fresh PG16/18 restricted-role replay; historical interactive ownership only.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2i00000001",
    ): "cb6004e75af03b926828d82263d55fe3f0dccc325b03e5f91ac0619e1dd2bfb8",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2i00000001",
    ): "4d08f476bc6c9bbd9febf909e77a0b254edc25f5aebfd89c6699c38ce62f33bb",
    # Restricted source replay; evidence-bound machine customer usage.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2h00000001",
    ): "26678caecb76d880350641e11e1aa4ba2962e4543b1360826e8f831bcf725adb",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2h00000001",
    ): "93afcdb479ba73e828f6d1ce7bd03edb1adc068c52fc51bbd6711e657c7f5689",
    # PG16/18 restricted source replay; true-Run gateway lineage.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2g00000001",
    ): "b5a31ab1e58390fe1be2b12a93ea9fd68105aeca9d04a60a2ddb45be67e23b68",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2g00000001",
    ): "4846b59cb193524a4f8f9321d6983192d649e8cea19c770768c4ba0fe16b8298",
    # PG16/18 restricted source replay; renewable real-Run model credentials.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2f00000001",
    ): "af415dce8b8f6faa023a53189d35636c4a2ee43466bb0b7069cc0e20f35074bd",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2f00000001",
    ): "978e7bef544fba72e155cc9291c5ddb15431e2fe385a0ca45f78c63b2750ea92",
    # PG16/18 source replay 4f9ec55c; tenant-scoped model candidate reads.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2e00000001",
    ): "e606146da4d7950f1e5a30450a3032c966edc72868aa6c2d76dfba7869b4c1e9",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2e00000001",
    ): "6db83f8196c5b04d20e792f1e21145965c83ddcbc938c23f49e12a52cdc86a46",
    # PG16/18 source replay d841a033; frozen execution customer prices.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2d00000001",
    ): "fb8a0d57b5a5a9d3401a29dc46b6a830d0d8c34235ef12320072e28bc1b69c5d",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2d00000001",
    ): "d79d2e7484d0d3d00fadd7c1e7dbc41bffba357727ca0bbba0b6b419632d43f7",
    # PG16/18 source replay 20be0280; bounded gateway audit chain delivery.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2c00000001",
    ): "8053df3700ad175de0eb1af9c5adddb5d611668865d45d196e33d2e7a6bf81b6",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2c00000001",
    ): "c8a61f0a085f55bc861a9a08e78ff5c0df2c2dd06a5e24b977b2f2871d09038f",
    # PG16/18 source replay 6607f02c; append-only gateway usage evidence.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2b00000001",
    ): "fc0dfd301fcd842d066a4601b24620155765159ba55508a7f247f2313344aac3",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2b00000001",
    ): "e72c9d007416d75654c729ad838eab8e1a69eb635738cfe1d22f2313229badce",
    # PG16/18 source replay e4042218; tenant-scoped publication commands and versions.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2a00000001",
    ): "2d43590b944a71c3b827c0ff74d6cb6555055f0f45ed5f94b8dcaf7951d46490",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2a00000001",
    ): "8f047164618ed8e073b28936432b41166ca511ec6078c0d580aa79b47f0f633b",
    # PG16/18 restricted source replay 8955d6c9; durable funded model verification.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1f00000001",
    ): "da225bb7f037ce85d64a7e287162bce6f55e19533c2af4c70d9c9ca04f863c21",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1f00000001",
    ): "f0be2eeff7a572d2813e135f5681d496136588c2f9f76e003c3f026aeba13c36",
    # PG16/18 restricted source replay 48e0f389; explicit platform test funding.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1e00000001",
    ): "9307e3089fc0c64a64f3f495bf6dc5311c3589c95ebd439624f0cccb0391ded2",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1e00000001",
    ): "e25720d7385832419a94584888334c14983e6a8a9cf24de6c2b1f7af666468f7",
    # PG16/18 restricted source replay b9528de4; retained inference budget holds.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1d00000001",
    ): "5605e9414c13aaeb57b7b1695fa4c110da13d6389361a3e083e8826383786260",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1d00000001",
    ): "ab166706b45c91c0d7937849d7ca4e7a474739019e6077ded008aa62df622a28",
    # PG16/18 restricted source replay 01d67d8d; immutable model drafts.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1c00000001",
    ): "87238927cb7e203bd12128a7904c9e3e9b3fbccfa681f2e3cbfcf24374861e4e",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1c00000001",
    ): "ca849a685569696117b3172733ca78d6761dac547e67eb910a4587c35df9a2fe",
    (
        16,
        "mm1a2b3c4d5e",
        "lm1b00000001",
    ): "db382ec680257bf24c46afbdadef564e6fef178bd3dc88ba39432c47e8cb032a",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1b00000001",
    ): "64ce3621f3d15dd1430b2ca030ab6adb6cab80c4fa35887ed6f45b0787945d25",
    (
        16,
        "mm1a2b3c4d5e",
        "lm1a00000001",
    ): "c8060cc83f22fefbd96080d84759f319a9d3ef1336a1a3f9f2cf516ab5b67698",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1a00000001",
    ): "5686d692300b36cf58f49b342d4a32ebb0e99727a6332e8c5608b74a7f52f024",
    (
        16,
        "mm1a2b3c4d5e",
        "p0s000000015",
    ): "61239caab9e58b03e93f9ee59a59f05c83ce28326c97d5580f275d47777660eb",
    (
        18,
        "mm1a2b3c4d5e",
        "p0s000000015",
    ): "5d92ba82a410c8b01c3f7e0c464286bdd2796ce2a61570f09adacdd88c23470e",
    (
        16,
        "mm1a2b3c4d5e",
        "p0s000000014",
    ): "2a899703b7bf50e645a7ab5c34b7353ff0c4bc3248ae8afa555ed5636030de26",
    (
        18,
        "mm1a2b3c4d5e",
        "p0s000000014",
    ): "cec5fec71df099d09537f954181234576961ab39a74724eff00530b680dd8a12",
    (
        16,
        "ge1b2c3d4e5f",
        "p0s000000013",
    ): "6c6463ae0fa483320413356afb526c4756e5d6fbbf392fab0074e8dd096e3e01",
    (
        18,
        "ge1b2c3d4e5f",
        "p0s000000013",
    ): "c5fe0b9dd94ffd3b378e6935ed7f611dc1f528e6cd2f1c4d2f199e72b6a6d416",
    (
        16,
        "ge1b2c3d4e5f",
        "p0s000000014",
    ): "813253bdda7aa38f62ba3a76afc523881cef7ff43ca6c9be199630df7742f2dd",
    (
        18,
        "ge1b2c3d4e5f",
        "p0s000000014",
    ): "7859924fdfb48d4a95c28b564b760248cf4e393f227bb9b17b45f16d2b0805b2",
    (
        16,
        "hh1b2c3d4e5f",
        "p0s000000014",
    ): "41e7dab760216847c11d921e7e61cbda2cc82c3b27febaf6c0e235891aac180a",
    (
        18,
        "hh1b2c3d4e5f",
        "p0s000000014",
    ): "41b4d089dda30cccd75b99436463fd44e94e01073460d4b1c756cbd6c670207d",
}
_PLATFORM_ADMIN_SOURCE_SECURITY_CATALOG_SHA256 = {
    # Source-derived immutable model cutoff authority.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2l00000001",
    ): "0ff60966d27af80fd9c3883a415d64fa698985cef309eaca2bc1134a4f544d51",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2l00000001",
    ): "1311fb551a3b388fa30e13fdad8afc0b3ebf4790055b701ff8b95d49683ff648",
    # Fresh PG16/18 restricted-role replay for physical recovery confirmation.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2k00000001",
    ): "dacd157cfb28ec23a8078109a979f8f8448ddf5596d90dd5db6d5e5670ff8e84",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2k00000001",
    ): "c658276859967d28811c37359cb55ed49efc7433976e05cdd10ec02591c66c7c",
    # Fresh PG16/18 restricted-role replay for delegated Runner identity.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2j00000001",
    ): "532ac01dd7e9ceda2f37bb6d82ad81b8d37daac90761518f6dc13fc83d1504cd",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2j00000001",
    ): "f898dceb8d6768fe830b8f5181addf58170636cc282580b97f4b320f30f46df0",
    # Fresh PG16/18 restricted-role replay; historical interactive ownership only.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2i00000001",
    ): "321eec703c2079f798d5cd8e76ca906758770f373356f5b2ec19e632e0e9582d",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2i00000001",
    ): "1511a306fdde0b7f27dce6a6ce57733d9c405b34f35b2706b1e22a925e7f9ce4",
    # Restricted source replay; evidence-bound machine customer usage.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2h00000001",
    ): "81e061489035d5afa2d45dfbd1126cdafa2da1b966139eeaf1fc64c094101bf9",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2h00000001",
    ): "7c054ecf4971557466de0a6b5b7bcbbbcbfe66598f6edab39624d051a71548e0",
    # PG16/18 restricted source replay; true-Run gateway lineage.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2g00000001",
    ): "3f0a59cf0c5db295b784978b3746c6fbf9069b4f37b26399a523f251c1afd4c8",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2g00000001",
    ): "1bd5e69dfd45a3f8ab70c35b466bb3b7d9808d1041d0836721d0f5c95ca2f960",
    # PG16/18 restricted source replay; renewable real-Run model credentials.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2f00000001",
    ): "4a2f42beb6a7be2cd867fd2e0a7ab934f459cba92a8e0480d914cb522663978c",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2f00000001",
    ): "80629949bca2595fd939e72d363fcdcb542042e76914cbcc9d9df06c04206ff8",
    # PG16/18 source replay 4f9ec55c; tenant-scoped model candidate reads.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2e00000001",
    ): "cf3df80d8483ca58fc4377e9929ed491035b7f8f0031b3e1599f6706f7b5b989",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2e00000001",
    ): "3b9ea929ceb35f1409ec36b397c82d71d684fd7f0691261bb05dbb4f51c87f18",
    # PG16/18 source replay d841a033; frozen execution customer prices.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2d00000001",
    ): "305b0494f4dc8d97af511035398941a593c459ea0091e34a54090f444b24efbe",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2d00000001",
    ): "ef801973ee42be4f6b4dc0687b93351083b4c0e7085a0e4f4039ea37ecb01fcb",
    # PG16/18 source replay 20be0280; bounded gateway audit chain delivery.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2c00000001",
    ): "a7a23fd84f6aef66dd4fe576b174625188e931c7aee46541cf17ce740ecc47e1",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2c00000001",
    ): "0ce5cf0a46a2b543e87809f1f4b7fc3ff7eb92b59f109d05d4f5dfaa313edd79",
    # PG16/18 source replay 6607f02c; append-only gateway usage evidence.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2b00000001",
    ): "13b3d53a77bfa3b4603b9a0ea6e5cad1fbf639bf2aa41518a3bf3d1530892941",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2b00000001",
    ): "af7bae30fa7b1e55afed4c5bb9f6b4c700e8a62316657cf473d38129498d3944",
    # PG16/18 source replay e4042218; tenant-scoped publication commands and versions.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2a00000001",
    ): "a3feb325df540c5d1ea49b9dc1129825204a75aa28c0f8980b2d1d3ad9837716",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2a00000001",
    ): "c380a1b24213dbb95765576c911f4b5ee43748e33fa65c3a2c3bb284ac040cbf",
    # PG16/18 restricted source replay 8955d6c9; durable funded model verification.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1f00000001",
    ): "1895b69968d9e7b15e4e261c06901bd09c2b41fdebbd98ad860f6e38a4756d52",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1f00000001",
    ): "26a9a3a5536dbfa5185e778d86c359968f2e0be318cb276eeed015ae7e1bcffc",
    # PG16/18 restricted source replay 48e0f389; explicit platform test funding.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1e00000001",
    ): "13ea4e8774cef8e7bcbab9a273598bbe77f61dc868ff5ffac57e31a51937a0f1",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1e00000001",
    ): "f4a4fdf32d8fa851790f82d2adf4c0f48a17d91907f96f10a098c5773e9e38ca",
    # PG16/18 restricted source replay b9528de4; retained inference budget holds.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1d00000001",
    ): "3f5cb8ab70f462c417695a5233378ce5b9d502547db1e487a42af4dfa06d0ce7",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1d00000001",
    ): "4796091adebffdb520b40fb798e7be85e37076cb7949ec5e753af51643537f12",
    # PG16/18 restricted source replay 01d67d8d; immutable model drafts.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1c00000001",
    ): "673b21e1727423bd9cb59624b4d286a9acc20801cc57d44b1a62859813a6a937",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1c00000001",
    ): "90c144fcda779457eac3f5c428161a36d4fbd9d934b55898f54f168e96f39a6a",
    (
        16,
        "mm1a2b3c4d5e",
        "lm1b00000001",
    ): "69cd74dcd6f9f108976c23d34c0ad855656fe14df5522806a94634ae68793cc0",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1b00000001",
    ): "56e62554598d37276cce8a198f3fe341bf8b695768d722ab51ca4e4ddee7d8bb",
    (
        16,
        "mm1a2b3c4d5e",
        "lm1a00000001",
    ): "e50bc4dfbcd82634b4f08600a66d25b8720603e3cf1ea7e7d8e11e5f0e283656",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1a00000001",
    ): "be834aa42f02b858f23130d08fc801851569720bea3b40250912b35b26f34361",
    (
        16,
        "mm1a2b3c4d5e",
        "p0s000000015",
    ): "fb328b45607f5117d72c3fcafabb9997ee9e33c18e3fe4334254546ffe875de4",
    (
        18,
        "mm1a2b3c4d5e",
        "p0s000000015",
    ): "da5d23cd334a6c42fd0f44cf1d4f6d26d665454d777d483ec0459e3949a90119",
    (
        16,
        "mm1a2b3c4d5e",
        "p0s000000014",
    ): "6d1dda4a40f1bce25219573239e8e8fb619e1e8c9dc5b93d03a5bb7fd6b7ebbe",
    (
        18,
        "mm1a2b3c4d5e",
        "p0s000000014",
    ): "12e581474667e90ba95df58943e39c242265c05a8c45421ca770d77fedd819a4",
    (
        16,
        "ge1b2c3d4e5f",
        "p0s000000014",
    ): "238747cc8731a8b0bbcf11b1c96df8bae6b3aeafbf9b2be211e7f6e4fde2bc4e",
    (
        18,
        "ge1b2c3d4e5f",
        "p0s000000014",
    ): "37565bbc3ba91e9950a3689f803bafd55f3ff714bf25c9a9b51a3e63e297488e",
    (
        16,
        "hh1b2c3d4e5f",
        "p0s000000014",
    ): "60e8f83d0992ec64c74194504d45bf9fcb492f8df94d7e5be4b890020abdac1d",
    (
        18,
        "hh1b2c3d4e5f",
        "p0s000000014",
    ): "901f8b5e547902df5b9406ee8ed9126ac88973683702af83085c50cfa700aab1",
}

# Exact deployment-time Preview authority projections accepted in addition to
# the clean-replay catalog.  These hashes bind the full public inventory and
# security catalog, so any extra object, ACL, policy, membership, or owner still
# fails closed.
_PREVIEW_AUTHORITY_PUBLIC_SCHEMA_INVENTORY_SHA256 = {
    # Source-derived immutable model cutoff authority.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2l00000001",
    ): "94f9e94cd866c938c2fe192fa6323942d8c86fbc8cc938a2c3dafba0c78fd021",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2l00000001",
    ): "06866b31c02dcb67733b8c3e271e0f084e68bad34f7c00c345eb69bef03a9802",
    # Fresh PG16/18 restricted-role replay for physical recovery confirmation.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2k00000001",
    ): "8e7cb0f1a98236bf96e2f7989d670de405a8f32ac1ef45aa2b51de7fe4ae4852",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2k00000001",
    ): "0bbb2f8e2ef90449295b5cd1bdfe11cc9dbb35cb13375a6a8c79af81be6ad056",
    # Fresh PG16/18 restricted-role replay for delegated Runner identity.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2j00000001",
    ): "89bbaffad24c2a7a108ec1f2a5a2f366b3ec4ac9f2f708949fb7088dd0e0b863",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2j00000001",
    ): "d7c1f73cf338fbf45e2e2b378da3403c324236bb2e9e4ca1a50a86ed951b5ce4",
    # Fresh PG16/18 restricted-role replay; historical interactive ownership only.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2i00000001",
    ): "077ff0181284fffba277aac12daf5e516cff722d384f2c0f106e1a0581452568",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2i00000001",
    ): "fe51f1433b677ce8c0bb6f2614eabc8e459b90e84551b0a556a509876cf1c982",
    # Restricted source replay; evidence-bound machine customer usage.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2h00000001",
    ): "e15c540345fa786dccb96a7827d5ac931f1cd43fdfc11d375d223a8851f76ac6",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2h00000001",
    ): "158237c9d4f0b7c6ba28cdc249f9858595de7333900569b008a5aca06a844f12",
    # PG16/18 restricted source replay; true-Run gateway lineage.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2g00000001",
    ): "7be520e79138a1e3ef353ebab61df7605e0e19fb64440df60f3c31bb4051ce47",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2g00000001",
    ): "cb15b6fad2342f02986d94d765be5090667327a3456fdcd9f47927c9cd09b6f6",
    # PG16/18 restricted source replay; renewable real-Run model credentials.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2f00000001",
    ): "38480c0a15fb2516bad4a5de3d8db2b4105f26c60a68b3d663147d65ff2b8a6a",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2f00000001",
    ): "2bcde72de58e3e00973dc31f2337c777b2fb8992da25fd998031441a001bdb46",
    # PG16/18 source replay 4f9ec55c; tenant-scoped model candidate reads.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2e00000001",
    ): "85d802b226f86abf4f7bc596093f8155da90db2d9d05b25615b5bc9d1a5f87dc",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2e00000001",
    ): "51fef83db0284bdb393dc629f4a13d8bf77a32ad1d34219ddb9bf99e6534a1e0",
    # PG16/18 source replay d841a033; frozen execution customer prices.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2d00000001",
    ): "0b38c4cc7383650b985a2ace83d4d4a7227de4fb59f49124c2ab4dafab4bfc00",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2d00000001",
    ): "4d6bd890729e3bdbcc081f67bff243b784b2abb31fa5b01879039e4bf1eb7f6b",
    # PG16/18 source replay 20be0280; bounded gateway audit chain delivery.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2c00000001",
    ): "7e76357715c6d41f9c6e84c99ec79efd6650d86a74296c70921167c3605d74d3",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2c00000001",
    ): "9af5b9d5783f9ea4c05867da65fed373efd1797dbe9d9a17b3e2feb61f4324a0",
    # PG16/18 source replay 6607f02c; append-only gateway usage evidence.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2b00000001",
    ): "7fb84329d90ffa91a188c3b9ad6da69b9373a191c5d38a9795121e19ebcfb110",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2b00000001",
    ): "f6d4b0763368a313f06c5ac041788bc04d85c1cc0affa40c4ae05fb0e2b0b841",
    # PG16/18 source replay e4042218; tenant-scoped publication commands and versions.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2a00000001",
    ): "943163ed51b2f2242c91831020b380b95000ded65cce13dc5abb899dfc617899",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2a00000001",
    ): "958dcde5966990068f93c7576ed74d445482515a7df255409e5b14e4dad6e211",
    # PG16/18 restricted source replay 8955d6c9; durable funded model verification.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1f00000001",
    ): "9c9d9d72ce2e175eaabbb0c09a836daf21bee14bf0139efaa4e8aaa9e5dc0437",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1f00000001",
    ): "909f0f2450ec7134646d850ee36631484f2c1a9a1b4fc1b8f8da6c45b39a9f89",
    # PG16/18 restricted source replay 48e0f389; explicit platform test funding.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1e00000001",
    ): "f8083ea5721f4f31faffc230f77a4d2b4ec3be4ec9e3fb28ca521f9a91595aed",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1e00000001",
    ): "1c1aef1c9deca4063f85ac9949157910eff0afbe2bbb8d397957865176ccd98c",
    # PG16/18 restricted source replay b9528de4; retained inference budget holds.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1d00000001",
    ): "28bfb8ba926b45805896901e678699ae0a37b1a959d73ec0138ebcdba79c7786",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1d00000001",
    ): "24f21d35404e2bd9dc97ed1b1985bff9cf845e112efed9d80d881df6713226f0",
    # PG16/18 restricted source replay 01d67d8d; immutable model drafts.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1c00000001",
    ): "1014a485862f91ee768815e33017c86eef0fb0d4b1cc0965a64bf9d187cc2330",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1c00000001",
    ): "0f5db660cc669afafb19f25d30aed4f7852c7063e915e58f95f2ee14820312c9",
    (
        16,
        "mm1a2b3c4d5e",
        "lm1b00000001",
    ): "76e11002abece6e57fba25394afae87a8bfc136b0e3c9bc4a8353a4d1a7f8eb4",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1b00000001",
    ): "df702a4ec3578d5cb8d53820066c2f02d9dc6f5f31aea3a25904f616f9041cb1",
    (
        16,
        "mm1a2b3c4d5e",
        "lm1a00000001",
    ): "536e22fb65125271c1644ac28117e941fb556f6f6b2dc8f4e288bc288c54a8da",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1a00000001",
    ): "e583ff6dc454d6f8f4cf5c14a909d02646c6bc2a61988ce4e4d122b551d396f8",
    (
        16,
        "mm1a2b3c4d5e",
        "p0s000000015",
    ): "389098bfb06040e6e5e8c0fdd00a3014057ef772769fd86760f03286e33c5f7f",
    (
        18,
        "mm1a2b3c4d5e",
        "p0s000000015",
    ): "b9259705dd665c9c08201bc929e75cd0c8db927dc94db98fad1c7b0c083b6fad",
    (
        18,
        "hh1b2c3d4e5f",
        "p0s000000015",
    ): "272092fc7608d49d8820a576aa00f8498f7736ba54decdd7db1fe1765c89e7bd",
    (
        18,
        "hh1b2c3d4e5f",
        "p0s000000014",
    ): "272092fc7608d49d8820a576aa00f8498f7736ba54decdd7db1fe1765c89e7bd",
}
_PREVIEW_AUTHORITY_PLATFORM_ADMIN_SOURCE_SECURITY_CATALOG_SHA256 = {
    # Source-derived immutable model cutoff authority.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2l00000001",
    ): "029cee8a43921289d55f1eaa595557f0871a104383e83364b77cb29c6a67f6b0",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2l00000001",
    ): "d6d4ba7afa365f4837c917f3d2b20296d47762e109fbb386b9e5eb4e4ce3d8f0",
    # Fresh PG16/18 restricted-role replay for physical recovery confirmation.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2k00000001",
    ): "d161731109f29d67c182dfcf2dbdb5ec964f72c40e2a49132e40087b44c94a2a",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2k00000001",
    ): "176d6ab130e661a0e95a1d3335978b7d413997e073595f6ed851ee794c1733d8",
    # Fresh PG16/18 restricted-role replay for delegated Runner identity.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2j00000001",
    ): "fa0a76c2b0aadef284a78e7af687103ec99f293da2b8c3ced3c52a89455fe9b8",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2j00000001",
    ): "2034aa322141e52b864f18dfda25c1277bcf73e814b159592c64567d8e3f498f",
    # Fresh PG16/18 restricted-role replay; historical interactive ownership only.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2i00000001",
    ): "118167417a3eebf254f3a27dfd53bfa4fcc5678c23b1b36c1f02f90b60905f64",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2i00000001",
    ): "21ee6ca9291f74d925f20d0d48a96cd39f1c486e4b57bb02b0fce5899e40e710",
    # Restricted source replay; evidence-bound machine customer usage.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2h00000001",
    ): "f532158c0d3df5eac0bd5404a80c3d7cd803060eab17c78140760779d8ec4667",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2h00000001",
    ): "213f5f17ada93ada12e307a4137de47aa4bf51264494acf72f70c2ca6122e5cc",
    # PG16/18 restricted source replay; true-Run gateway lineage.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2g00000001",
    ): "2e4ebd32ae2d769ea63749564886d5c0f42fa20e82c32cf0c7c52db4b27282ef",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2g00000001",
    ): "dd78235a033609d469fbd2cdf09b61acaffd00153fdc65af573b474d2fbba272",
    # PG16/18 restricted source replay; renewable real-Run model credentials.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2f00000001",
    ): "d8b25fff1f56a05ce4f9547693bae9259f0d7e997ce3434a0c8a155808dfa878",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2f00000001",
    ): "dfa0fd6e5c3dcfe52fc9e5d77b9a2f9f2bce529f4f3efc11445ac53137c73241",
    # PG16/18 source replay 4f9ec55c; tenant-scoped model candidate reads.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2e00000001",
    ): "62eecc799477d90700a18d12d15ea4a9bffade451aa93dd37920db09b41f169d",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2e00000001",
    ): "989bf297be8cfd63b0d191e5940158d8bd0171595c21a02f09acd365a3c961a9",
    # PG16/18 source replay d841a033; frozen execution customer prices.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2d00000001",
    ): "5e8c4ecbaf855d5cf48f318f91549b48354509ffdb633bc6854a46d2404fb6e7",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2d00000001",
    ): "c8e111139fd6e4fa201c909ee040bff05f35ccd6be9ec8ae6c248ed97d7f9ee8",
    # PG16/18 source replay 20be0280; bounded gateway audit chain delivery.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2c00000001",
    ): "46acb52f70b7280cad055a8b70a3a268563dfd6908bfdda6eb3d6445e82534b4",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2c00000001",
    ): "ac36d43dc8aea4932f7a17c0422dbb3a6314f83fdf75709434a8041155b16bfe",
    # PG16/18 source replay 6607f02c; append-only gateway usage evidence.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2b00000001",
    ): "61f6983a59170c38fa18e17ee270623c9a53c0345e6b94202ebd9cf6683ce58d",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2b00000001",
    ): "d273c85556296a19624da3a4679c2b6b2ca87f8ee8bae965efc74f87234ecdd1",
    # PG16/18 source replay e4042218; tenant-scoped publication commands and versions.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2a00000001",
    ): "f449476944e3074caa95168534c25ce98ab63fa93907ea776950c2a917d1f3bd",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2a00000001",
    ): "75d43675f05f81bc9350272af2e6a5602e340881823d9102b8b6c40a0152045e",
    # PG16/18 restricted source replay 8955d6c9; durable funded model verification.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1f00000001",
    ): "bb76a4278ea0866a4c4a52e61d6ba0c11b40557ff76cb37be219f5687d7afcaf",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1f00000001",
    ): "e95594607377cedff6b3e3c303da1f3d2a4a282b045ddb9f93134333d63739d0",
    # PG16/18 restricted source replay 48e0f389; explicit platform test funding.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1e00000001",
    ): "6a709684e319e43a620ccb2cb48ddcf2ef932df32612c8b8a4cb366d939395c7",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1e00000001",
    ): "959734fece24128a6604086345bc26684c04638855b00b4a1223b834e8b22815",
    # PG16/18 restricted source replay b9528de4; retained inference budget holds.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1d00000001",
    ): "77efd9287fc62c59563d278e36d36d9eb1e92b0b239d269a1e6c9a0302a1e24e",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1d00000001",
    ): "9a7b3e89d4a7929ead9bcde79074271a3a7d921af540d150257bf1c0d66ceb93",
    # PG16/18 restricted source replay 01d67d8d; immutable model drafts.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1c00000001",
    ): "d5e5c7e54bae52e55583927a99ab0fe24ac4eee7d5f3009af448d59adb981e39",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1c00000001",
    ): "f4ba422b561742f6cdfcb5c4c400afbb69ddcbea0613e9c46225f0c494fbce89",
    (
        16,
        "mm1a2b3c4d5e",
        "lm1b00000001",
    ): "043cf91b1998ba2c9032bcc9efcfd7daa56af0e6f293ea4bbc892609d6f2562a",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1b00000001",
    ): "38b7c4a8a0a0b71bc79ae47e52617167d4eb20f183591243cae9d511f1b57a06",
    (
        16,
        "mm1a2b3c4d5e",
        "lm1a00000001",
    ): "0e4bb916d19eeedbce2843641f66d7e50571b7bd3ce0fadf46d3224c17a7a8ee",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1a00000001",
    ): "7a1f878c6491e69fdb379b5240a91c512342a3e6b473a120061a897afd1d51ab",
    (
        16,
        "mm1a2b3c4d5e",
        "p0s000000015",
    ): "a335cad1a69229c893f8447692a79d8b4b23ea37ab7225dbc99396f447d10c79",
    (
        18,
        "mm1a2b3c4d5e",
        "p0s000000015",
    ): "65e6bee98f5c0c0bb29711a289c62877b8d0d470902132b62502128f040f120d",
    # Derived from the observed 2026-10-06 Preview authority projection
    # (P0S14 digest 9839f65f...) by advancing only saas_head. P0S15 replaces
    # a function body without changing its identity, ACL, owner or public
    # inventory. The isolated source-clone rehearsal must still verify this
    # projection before production admission.
    (
        18,
        "hh1b2c3d4e5f",
        "p0s000000015",
    ): "71d3bad161d93049a1702ed2e8f2c17833e2aecc1fca48ea3e77c9a50404fe1a",
    (
        18,
        "hh1b2c3d4e5f",
        "p0s000000014",
    ): "9839f65fa0ff7614c4bc7566fda9ae18223924cf9ad63adbf71e66433f995e34",
}

_LEGACY_ORDERED_SOURCE_SECURITY_HEADS = frozenset({"p0s000000011"})
_MODEL_PROJECTION_SOURCE_SECURITY_CATALOG_SHA256 = {
    # Source-derived immutable model cutoff authority.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2l00000001",
    ): "728b9900a505bd08e98a127f280e4dab25eecb2d3563e361c7335466a0691e0d",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2l00000001",
    ): "0723a043b0df2b2cbe286acb9982f06747925deee53d5bc05ea2c8d4c6d2a3ed",
    # Fresh PG16/18 restricted-role replay for physical recovery confirmation.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2k00000001",
    ): "7eb77dea8481cf23ba81f3873d8541ab8dd5543f5304be0370cf6840832f2e24",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2k00000001",
    ): "e0c04a73ffad77b8723c659a0bbf853de5540e2d4461394eca7b9d7c27647d19",
    # Fresh PG16/18 restricted-role replay for delegated Runner identity.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2j00000001",
    ): "a8854fadf251cd6f95d7f20ad3359128a1bd63cf702686099093d5a2cc905db0",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2j00000001",
    ): "41b0f5788660160d5662c816453b8329c88bd3d835ac5c1b9137cf4034574948",
    # Fresh PG16/18 restricted-role replay; historical interactive ownership only.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2i00000001",
    ): "dfadf1b5dedaca589d14882736a6d79155a3648d17a3302041fefaf6dd1e8fd9",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2i00000001",
    ): "f158e9796ce1dbc49ecb5ccd93e60c23a33417c8607700130e5ac6beae7812a2",
    # Restricted source replay; evidence-bound machine customer usage.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2h00000001",
    ): "022c00909f9404b3ad0f7e0fa8213ac4598de2ccef1f1f70348c4f151e48aff1",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2h00000001",
    ): "ab333c211f4b4ebeeb1a899a1f16c343cdde3d486d7d378d3b82d45c399bd254",
    # PG16/18 restricted source replay; true-Run gateway lineage.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2g00000001",
    ): "cd4b83cadfdaee5413e84522e5f2bb532466c2d2364b9f3b3265a912c94e922e",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2g00000001",
    ): "16693838ab76097e4656e98630b87b3709e90d4b328a9a24be540facf65332e1",
    # PG16/18 restricted source replay; renewable real-Run model credentials.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2f00000001",
    ): "3b167a082035c5dee2c1579034ce3597dee11fc33b4a28ce8b631989dccc2d3b",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2f00000001",
    ): "a818b8e2d8f53c00a37693528bd66772bacceec45ca7243fb5972b87e47553c4",
    # PG16/18 source replay 4f9ec55c; tenant-scoped model candidate reads.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2e00000001",
    ): "7588d4270d123f6a1717218fa1403278b9fc8e21a3921e0dc05f63dfe4e2c970",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2e00000001",
    ): "e76bebe85f1312f7e4484cb9e3f29b5dd3ab763aee1b412ea3cfd300b8f8b8c3",
    # PG16/18 source replay d841a033; frozen execution customer prices.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2d00000001",
    ): "2921f1a4a76b7d600e258eeda592fa31c1b7d0e6de0b03b14c189c06df97ee5a",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2d00000001",
    ): "c47c6878a697daf6ad6d757ac16cf449614d8aec9b517866940b2ff6f82f96fe",
    # PG16/18 source replay 20be0280; bounded gateway audit chain delivery.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2c00000001",
    ): "1e8ce6e73ea7160fddb0b70a4288d151fc265b63edfe38af4f7e7a5e161851f1",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2c00000001",
    ): "9d5473b3d89e3ee4db7305521feecbe1ce1f97269d92f93a30c8c1e968748044",
    # PG16/18 source replay 6607f02c; append-only gateway usage evidence.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2b00000001",
    ): "c13017fd6599a6a26db9b8b1882e9ed2a6ef6d45246d55d1204bf6462b866c1b",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2b00000001",
    ): "32e46a1ac2d80b7da6aa0344b845888a2d46978141af5a164a945e66e30fb0f3",
    # PG16/18 source replay e4042218; tenant-scoped publication commands and versions.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2a00000001",
    ): "626ed582906166f37f6571d13ce9809606afe1a6e433d0facce2db1c821f8aca",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2a00000001",
    ): "7f5952e8a4e16dffd85e686ce211d23fca6f85336397cf10e0ebb76aec388b06",
    # PG16/18 restricted source replay 8955d6c9; durable funded model verification.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1f00000001",
    ): "a88fec0bf5973e50f6dbc67c5689962824977a43c5214e01d45fb1e8ad0c7336",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1f00000001",
    ): "cea22b5d8f4decca30bde10d7867f3934442941643468f73d00676baada735c0",
    # PG16/18 restricted source replay 48e0f389; explicit platform test funding.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1e00000001",
    ): "cf2fd93f9181c18f00d053c69bf7caf41e4b37f22777f67f621b832dcf47c459",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1e00000001",
    ): "a15fec8fd15626c4ea3bd8e5bb0d688752fa017a4544d287abef632127d19047",
    # PG16/18 restricted source replay b9528de4; retained inference budget holds.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1d00000001",
    ): "f3dcfb6314e95241485a536578829fbe5bc289e576a6f550a01df86ce34f7183",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1d00000001",
    ): "b43e0bf129ea7e21b1f5b0187e79675f1b81fb337ee7ba374f49258d6ce44a35",
    # PG16/18 restricted source replay 01d67d8d; immutable model drafts.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1c00000001",
    ): "3fb2645f5fd2a43332455d8dbd6b68aa89d1818a4fdf96df32a9a950d324cb2d",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1c00000001",
    ): "f80c671c65b88eb37bfffdbc6381cd71d1cd6578dc40eadaf0c987ccd083ed13",
    (
        16,
        "mm1a2b3c4d5e",
        "lm1b00000001",
    ): "372608b04a82544dfe85e98a705d254f5e9aa4394a5fc2314e196f79f9f05af6",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1b00000001",
    ): "f95bcf25de167188742047c9e63b2253e74f1b14b7ed4a46364d42dfe82c7506",
}
_PREVIEW_AUTHORITY_MODEL_PROJECTION_SOURCE_SECURITY_CATALOG_SHA256: dict[
    tuple[int, str, str], str
] = {
    # Source-derived immutable model cutoff authority.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2l00000001",
    ): "a58f0a002e74add57de8afab5dd19315ce97eca8e7fb6760936857e84b46fb32",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2l00000001",
    ): "910582a1328f91b5a0044a79889a1cf1a9002dfba763e9d44db80e48b4fb1b68",
    # Fresh PG16/18 restricted-role replay for physical recovery confirmation.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2k00000001",
    ): "40e06c81d2c446c27ea297107b86907fdaf40cc733e1d42efbcb218447bb5d38",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2k00000001",
    ): "848d7967659d9e391eabf638974092b6d2d920190d3d2167eb3fe241d572311a",
    # Fresh PG16/18 restricted-role replay for delegated Runner identity.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2j00000001",
    ): "5c8d1d2f1a50f5168bf84ba221b65514a759a9c1f77a3f7ce1d98ffe8f181386",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2j00000001",
    ): "9e5190917adb60a33a9616a173b970a9698ed4a1ec660d5863bcead1764d12f5",
    # Fresh PG16/18 restricted-role replay; historical interactive ownership only.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2i00000001",
    ): "5b0968e98655f5b241eee44f05da8eac41e1a764bda6c4bd3148d1c48e03f18b",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2i00000001",
    ): "09ee4b7f206f359649c12452f7f8e0266a9a32234a2917fdb1e31380c4888c6b",
    # Restricted source replay; evidence-bound machine customer usage.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2h00000001",
    ): "665b149579c9777cc874771bcf5cd81e922219ff2cd10a69991e9a89481e961b",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2h00000001",
    ): "36d48f4ade00e0fc460a6947f3890d24e1e6051e79a221c39b747cddc12f4036",
    # PG16/18 restricted source replay; true-Run gateway lineage.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2g00000001",
    ): "dfa9c1764c7cbfbbf62647db90c71898ece8e677fc63c602be845787859f7e17",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2g00000001",
    ): "5566911fb984e15bc9f441fe030649bde8d77958eecd8cd4bf874b4a767ee63b",
    # PG16/18 restricted source replay; renewable real-Run model credentials.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2f00000001",
    ): "b145028cb4333d008d7f4f33371015a66711f29a5e4b45d3e54e51c278ba51c6",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2f00000001",
    ): "28cf65f315b5561d74d6b43c4dc4d5ebc74bc8587a3d3322840ad927b93ed73e",
    # PG16/18 source replay 4f9ec55c; tenant-scoped model candidate reads.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2e00000001",
    ): "718b542a937564894a458d55d39843c734e70a17f94b991b852ff12f00704da7",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2e00000001",
    ): "4030f963cf5327fadec62ceecd95450302df0d2d6170cb17a13112ec869a2efb",
    # PG16/18 source replay d841a033; frozen execution customer prices.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2d00000001",
    ): "ecdc7a0d28d426aee29612dc55f523573542f2affdb6ca9e6713569d1ae51249",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2d00000001",
    ): "6f18b34f9b35ac5f6a1b6aa35d4ae8733049d8a8227714350fab273c2b3492f8",
    # PG16/18 source replay 20be0280; bounded gateway audit chain delivery.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2c00000001",
    ): "e996fdcbd94397f3ee56180f9a44a48ce035fff2032ec6014b977d6cbb57d3e9",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2c00000001",
    ): "cd7a69c9c08dce9c35f490791dcd57f49107437456782c8a41dd381dbcfd1ca7",
    # PG16/18 source replay 6607f02c; append-only gateway usage evidence.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2b00000001",
    ): "ee6b90425d0ede040d8b1d22b42c662ed55ccfdd94ffc721f2ddc7d450986b4d",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2b00000001",
    ): "eeda2fd90804bff220d0dabc72580ce9de5d765e18ec233f15a1a252aa651574",
    # PG16/18 source replay e4042218; tenant-scoped publication commands and versions.
    (
        16,
        "mm1a2b3c4d5e",
        "lm2a00000001",
    ): "e577d74759159c592859b333be9e1cbfb0c92cf96ef67ed86161592f888aef01",
    (
        18,
        "mm1a2b3c4d5e",
        "lm2a00000001",
    ): "af25421cd340c59f3f37b31197f13457ee1d42776b383838af033c1199f82596",
    # PG16/18 restricted source replay 8955d6c9; durable funded model verification.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1f00000001",
    ): "8d7a7722e73072e7ff1e2e491b67714cff0a67c6be4d58719c58d9c01bd3d54e",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1f00000001",
    ): "c45857b9e78d26548d8a05397deaa86b9e340adec6c540a3756565797de83d01",
    # PG16/18 restricted source replay 48e0f389; explicit platform test funding.
    (
        16,
        "mm1a2b3c4d5e",
        "lm1e00000001",
    ): "48cd96276e31fa9ea61cd0102b07e98f3624d74a51ba88e3936234a63a4562f7",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1e00000001",
    ): "d2a2075574f70f058bf33ee56bf0fa5263baf3730e45501f4964eff621257b56",
    (
        16,
        "mm1a2b3c4d5e",
        "lm1d00000001",
    ): "5b576a5035910c79e823e92a27145bed967bc9fd0001f4cf7835c6ee7b7fc9a8",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1d00000001",
    ): "e1c63b2f660220514b11e3c797e669d2f1c66af55e20b67059d32ae33e3e852a",
    (
        16,
        "mm1a2b3c4d5e",
        "lm1c00000001",
    ): "bd14208e978cb3affc4b1a1aee7df5480e37054db36c3dae87986903b7ba0845",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1c00000001",
    ): "5b16a688dc4559a12b4712ffc81b52f5ce07e32f80501da76ce8523e96806a60",
    (
        16,
        "mm1a2b3c4d5e",
        "lm1b00000001",
    ): "e1fa4316e74e6b0cf61d8475c6762fd0901d983c0bd48d8da916caf76a270f1b",
    (
        18,
        "mm1a2b3c4d5e",
        "lm1b00000001",
    ): "2046e9e8550bf5dafab2111e24cb4276418f483a2b0ef169fea3881a750622db",
}
_CAPABILITY_ROLES = (
    "saas_app",
    "saas_authenticator",
    "saas_governance",
    "saas_dispatcher",
    "saas_dispatcher_n1_compat",
    "saas_executor",
    "saas_runner_agent",
    "saas_model_projection",
    "saas_secret_broker",
    "saas_preview_gateway",
    "saas_preview_edge",
    "saas_preview_owner",
    "saas_webhook_dispatcher",
    "saas_billing",
    "saas_metering",
    "saas_public_api",
    "saas_platform",
    "saas_platform_authenticator",
    "saas_platform_app",
    "saas_platform_governance",
    "saas_platform_projector",
    "saas_platform_support",
    "saas_privacy_executor",
    "saas_privacy_dispatcher",
    "saas_privacy_verifier",
    "saas_notification_scheduler",
    "saas_notification_dispatcher",
    "saas_notification_directory",
    "saas_approval_scheduler_enterprise",
    "saas_approval_scheduler_privacy",
    "saas_approval_scheduler_audit",
    "saas_approval_scheduler_support_customer",
    "saas_approval_scheduler_support_staff",
    "saas_registration",
    "saas_onboarding",
    "saas_onboarding_status",
    "saas_runtime_provider_journal",
    _RUNTIME_ROLE,
)
_RUNNER_AGENT_LOGIN = re.compile(r"^runner_([0-9a-f]{32})_g([1-9][0-9]{0,18})$")
_RoleGraphEdge = tuple[str, str, str, bool, bool, bool, int]


class PostgreSqlMigrationError(RuntimeError):
    """A content-free production migration rejection."""

    def __init__(self, code: str, phase: str) -> None:
        self.code = code
        self.phase = phase
        super().__init__(f"PostgreSQL migration rejected: phase={phase}; code={code}")


@dataclass(frozen=True, slots=True, repr=False)
class PostgreSqlAuthority:
    """One redacted direct-login PostgreSQL authority."""

    kind: AuthorityKind
    url: URL
    login: str

    def redacted_url(self) -> str:
        return self.url.render_as_string(hide_password=True)


@dataclass(frozen=True, slots=True, repr=False)
class ProductionPostgreSqlPlan:
    """Four-authority plan for one exact product and database target."""

    product_revision: str
    principal_operator: PostgreSqlAuthority
    database_owner: PostgreSqlAuthority
    official_owner: PostgreSqlAuthority
    saas_owner: PostgreSqlAuthority
    service_role_bindings: ProductionServiceRoleBindings
    platform_model_service_role_bindings: ProductionServiceRoleBindings | None = None
    platform_admin_service_role_bindings: ProductionServiceRoleBindings | None = None
    model_projection_service_role_bindings: ProductionServiceRoleBindings | None = None
    require_tls: bool = True
    lock_timeout_seconds: float = 30.0

    @classmethod
    def from_urls(
        cls,
        *,
        product_revision: str,
        principal_operator_url: str,
        database_owner_url: str,
        official_owner_url: str,
        saas_owner_url: str,
        service_role_bindings: ProductionServiceRoleBindings,
        platform_model_service_role_bindings: ProductionServiceRoleBindings | None = None,
        platform_admin_service_role_bindings: ProductionServiceRoleBindings | None = None,
        model_projection_service_role_bindings: ProductionServiceRoleBindings | None = None,
        require_tls: bool = True,
        lock_timeout_seconds: float = 30.0,
    ) -> ProductionPostgreSqlPlan:
        return cls(
            product_revision=product_revision,
            principal_operator=parse_production_postgresql_url(
                principal_operator_url,
                kind="principal_operator",
                require_tls=require_tls,
            ),
            database_owner=parse_production_postgresql_url(
                database_owner_url,
                kind="database_owner",
                require_tls=require_tls,
            ),
            official_owner=parse_production_postgresql_url(
                official_owner_url,
                kind="official_owner",
                require_tls=require_tls,
            ),
            saas_owner=parse_production_postgresql_url(
                saas_owner_url,
                kind="saas_owner",
                require_tls=require_tls,
            ),
            service_role_bindings=service_role_bindings,
            platform_model_service_role_bindings=platform_model_service_role_bindings,
            platform_admin_service_role_bindings=platform_admin_service_role_bindings,
            model_projection_service_role_bindings=model_projection_service_role_bindings,
            require_tls=require_tls,
            lock_timeout_seconds=lock_timeout_seconds,
        )

    def authorities(self) -> tuple[PostgreSqlAuthority, ...]:
        return (
            self.principal_operator,
            self.database_owner,
            self.official_owner,
            self.saas_owner,
        )

    @property
    def service_role_graph(self) -> ProductionServiceRoleGraph:
        """Return the exact core plus optional Platform-model role graph."""

        try:
            return compose_production_service_role_graph(
                self.service_role_bindings,
                self.platform_model_service_role_bindings,
                self.platform_admin_service_role_bindings,
                self.model_projection_service_role_bindings,
            )
        except ProductionServiceRoleBindingsError as error:
            raise PostgreSqlMigrationError(
                "service_role_bindings_invalid", "configuration"
            ) from error


@dataclass(frozen=True, slots=True)
class PostgreSqlMigrationReceipt:
    """Secret-free database state emitted only after complete verification."""

    schema_version: int
    status: str
    verify_only: bool
    product_revision: str
    database_identity_sha256: str
    official_head: str
    saas_head: str
    runtime_rls_table_count: int
    authorities: tuple[tuple[str, str], ...]
    phases: tuple[str, ...]
    catalog_sha256: str
    service_role_bindings_sha256: str
    service_role_graph_sha256: str
    completed_at: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "verify_only": self.verify_only,
            "product_revision": self.product_revision,
            "database_identity_sha256": self.database_identity_sha256,
            "official_head": self.official_head,
            "saas_head": self.saas_head,
            "runtime_rls_table_count": self.runtime_rls_table_count,
            "authorities": [{"kind": kind, "login": login} for kind, login in self.authorities],
            "phases": list(self.phases),
            "catalog_sha256": self.catalog_sha256,
            "service_role_bindings_sha256": self.service_role_bindings_sha256,
            "service_role_graph_sha256": self.service_role_graph_sha256,
            "completed_at": self.completed_at,
        }


@dataclass(frozen=True, slots=True)
class _SessionFacts:
    kind: AuthorityKind
    login: str
    database: str
    database_oid: int
    database_owner: str
    server_version_num: int
    server_address: str
    server_port: int
    tls: bool


@dataclass(frozen=True, slots=True)
class _VerifiedState:
    official_head: str
    saas_head: str
    runtime_rls_table_count: int
    catalog_sha256: str


@dataclass(frozen=True, slots=True)
class _ServiceSessionFacts:
    login: str
    database: str
    database_oid: int
    database_owner: str
    server_version_num: int
    server_address: str
    server_port: int


@dataclass(frozen=True, slots=True)
class _RuntimeReceipt:
    product_revision: str
    official_head: str
    saas_head: str
    database_identity_sha256: str
    catalog_sha256: str
    service_role_bindings_sha256: str
    service_role_graph_sha256: str
    runtime_rls_table_count: int
    official_owner: str
    saas_owner: str
    principal_operator: str
    database_owner: str


_MIGRATION_RECEIPT_SCHEMA_VERSION = 2


def _database_identity_payload(
    facts: _SessionFacts | _ServiceSessionFacts,
) -> dict[str, object]:
    """Return stable database identity, excluding connection endpoint facts."""

    return {
        "database": facts.database,
        "database_oid": facts.database_oid,
        "database_owner": facts.database_owner,
    }


def _database_identity_sha256(
    facts: _SessionFacts | _ServiceSessionFacts,
) -> str:
    return hashlib.sha256(
        json.dumps(
            _database_identity_payload(facts),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def parse_production_postgresql_url(
    raw_url: str,
    *,
    kind: AuthorityKind,
    require_tls: bool = True,
) -> PostgreSqlAuthority:
    """Parse one explicit TCP psycopg URL without exposing its password."""

    if kind not in _AUTHORITY_KINDS:
        raise PostgreSqlMigrationError("authority_kind_invalid", "configuration")
    try:
        url = make_url(raw_url)
    except (TypeError, ValueError, sa.exc.ArgumentError):
        raise PostgreSqlMigrationError("authority_url_invalid", "configuration") from None
    if url.drivername != "postgresql+psycopg":
        raise PostgreSqlMigrationError("postgresql_psycopg_required", "configuration")
    if not url.username or not url.host or not url.port or not url.database:
        raise PostgreSqlMigrationError("authority_tcp_target_required", "configuration")
    if _ROLE_NAME.fullmatch(url.username) is None:
        raise PostgreSqlMigrationError("authority_login_invalid", "configuration")
    query_keys = frozenset(str(key) for key in url.query)
    if not query_keys.issubset(_ALLOWED_QUERY_KEYS):
        raise PostgreSqlMigrationError("authority_query_option_forbidden", "configuration")
    if any(isinstance(value, tuple) for value in url.query.values()):
        raise PostgreSqlMigrationError("authority_query_option_ambiguous", "configuration")
    sslmode = url.query.get("sslmode")
    if require_tls and sslmode != "verify-full":
        raise PostgreSqlMigrationError("authority_tls_verify_full_required", "configuration")
    target_session_attrs = url.query.get("target_session_attrs")
    if target_session_attrs is not None and target_session_attrs != "read-write":
        raise PostgreSqlMigrationError("authority_read_write_target_required", "configuration")
    return PostgreSqlAuthority(kind=kind, url=url, login=url.username)


def _installed_product_revision() -> str:
    try:
        from omnigent import _build_info

        value = _build_info.COMMIT_SHA
    except (AttributeError, ImportError):
        return ""
    return value if isinstance(value, str) else ""


def _validate_plan(plan: ProductionPostgreSqlPlan) -> None:
    if _FULL_GIT_SHA.fullmatch(plan.product_revision) is None:
        raise PostgreSqlMigrationError("product_revision_invalid", "configuration")
    if _installed_product_revision() != plan.product_revision:
        raise PostgreSqlMigrationError("installed_product_revision_mismatch", "configuration")
    if not 0 < plan.lock_timeout_seconds <= 300:
        raise PostgreSqlMigrationError("lock_timeout_invalid", "configuration")
    authorities = plan.authorities()
    if tuple(authority.kind for authority in authorities) != _AUTHORITY_KINDS:
        raise PostgreSqlMigrationError("authority_order_invalid", "configuration")
    logins = [authority.login for authority in authorities]
    if len(set(logins)) != len(logins):
        raise PostgreSqlMigrationError("authority_logins_not_distinct", "configuration")
    bindings = plan.service_role_bindings.bindings
    if (
        {binding.service: binding.base_role for binding in bindings}
        != dict(EXPECTED_PRODUCTION_SERVICE_ROLES)
        or len({binding.login for binding in bindings}) != len(bindings)
        or any(binding.login in _CAPABILITY_ROLES for binding in bindings)
        or set(logins) & {binding.login for binding in bindings}
        or _SHA256.fullmatch(plan.service_role_bindings.sha256) is None
    ):
        raise PostgreSqlMigrationError("service_role_bindings_invalid", "configuration")
    platform_bindings = plan.platform_model_service_role_bindings
    if platform_bindings is not None:
        if (
            {binding.service: binding.base_role for binding in platform_bindings.bindings}
            != dict(EXPECTED_PLATFORM_MODEL_SERVICE_ROLES)
            or len({binding.login for binding in platform_bindings.bindings})
            != len(platform_bindings.bindings)
            or any(binding.login in _CAPABILITY_ROLES for binding in platform_bindings.bindings)
            or set(logins) & {binding.login for binding in platform_bindings.bindings}
            or _SHA256.fullmatch(platform_bindings.sha256) is None
        ):
            raise PostgreSqlMigrationError("service_role_bindings_invalid", "configuration")
    platform_admin_bindings = plan.platform_admin_service_role_bindings
    if platform_admin_bindings is not None:
        if (
            {binding.service: binding.base_role for binding in platform_admin_bindings.bindings}
            != dict(EXPECTED_PLATFORM_ADMIN_SERVICE_ROLES)
            or len({binding.login for binding in platform_admin_bindings.bindings})
            != len(platform_admin_bindings.bindings)
            or any(
                binding.login in _CAPABILITY_ROLES for binding in platform_admin_bindings.bindings
            )
            or set(logins) & {binding.login for binding in platform_admin_bindings.bindings}
            or _SHA256.fullmatch(platform_admin_bindings.sha256) is None
        ):
            raise PostgreSqlMigrationError("service_role_bindings_invalid", "configuration")
    projection_bindings = plan.model_projection_service_role_bindings
    if projection_bindings is not None:
        if (
            {binding.service: binding.base_role for binding in projection_bindings.bindings}
            != dict(EXPECTED_MODEL_PROJECTION_SERVICE_ROLES)
            or len(projection_bindings.bindings) != 1
            or any(binding.login in _CAPABILITY_ROLES for binding in projection_bindings.bindings)
            or set(logins) & {binding.login for binding in projection_bindings.bindings}
            or _SHA256.fullmatch(projection_bindings.sha256) is None
        ):
            raise PostgreSqlMigrationError("service_role_bindings_invalid", "configuration")
    graph = plan.service_role_graph
    if set(logins) & {binding.login for binding in graph.bindings}:
        raise PostgreSqlMigrationError("service_role_bindings_invalid", "configuration")
    targets = {
        (
            authority.url.drivername,
            (authority.url.host or "").lower().rstrip("."),
            authority.url.port,
            authority.url.database,
        )
        for authority in authorities
    }
    if len(targets) != 1:
        raise PostgreSqlMigrationError("authority_targets_differ", "configuration")


def _create_engines(plan: ProductionPostgreSqlPlan) -> dict[AuthorityKind, Engine]:
    return {
        authority.kind: sa.create_engine(
            authority.url,
            pool_pre_ping=True,
            poolclass=NullPool,
        )
        for authority in plan.authorities()
    }


def _dispose_engines(engines: Mapping[AuthorityKind, Engine]) -> None:
    for engine in engines.values():
        engine.dispose()


def _authority_memberships_are_safe(
    kind: AuthorityKind,
    outgoing: tuple[tuple[str, bool, bool, bool], ...],
    incoming_count: int,
) -> bool:
    if incoming_count != 0:
        return False
    if kind != "principal_operator":
        return not outgoing
    role_names = [row[0] for row in outgoing]
    return (
        len(role_names) == len(set(role_names))
        and all(role_name in _CAPABILITY_ROLES for role_name in role_names)
        and all(admin and not inherit and not can_set for _, admin, inherit, can_set in outgoing)
    )


def _inspect_authority(
    engine: Engine,
    authority: PostgreSqlAuthority,
    *,
    require_tls: bool,
) -> _SessionFacts:
    try:
        with engine.connect() as connection:
            identity = connection.execute(
                sa.text(
                    "SELECT current_user, session_user, current_database(), "
                    "current_schema(), current_schemas(false), database.oid, "
                    "pg_get_userbyid(database.datdba), "
                    "current_setting('server_version_num')::integer, "
                    "COALESCE(inet_server_addr()::text, ''), "
                    "COALESCE(inet_server_port(), 0), pg_is_in_recovery(), "
                    "COALESCE(ssl.ssl, false) "
                    "FROM pg_database AS database "
                    "LEFT JOIN pg_stat_ssl AS ssl ON ssl.pid = pg_backend_pid() "
                    "WHERE database.datname = current_database()"
                )
            ).one()
            role = connection.execute(
                sa.text(
                    "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                    "rolreplication, rolbypassrls, rolinherit, rolconnlimit, rolconfig "
                    "FROM pg_roles WHERE rolname = current_user"
                )
            ).one_or_none()
            role_settings = connection.execute(
                sa.text(
                    "SELECT count(*) FROM pg_db_role_setting AS setting "
                    "JOIN pg_roles AS role ON role.oid = setting.setrole "
                    "WHERE role.rolname = current_user"
                )
            ).scalar_one()
            outgoing_memberships = tuple(
                (
                    str(row[0]),
                    bool(row[1]),
                    bool(row[2]),
                    bool(row[3]),
                )
                for row in connection.execute(
                    sa.text(
                        "SELECT granted.rolname, membership.admin_option, "
                        "COALESCE((to_jsonb(membership) ->> 'inherit_option')::boolean, false), "
                        "COALESCE((to_jsonb(membership) ->> 'set_option')::boolean, false) "
                        "FROM pg_auth_members AS membership "
                        "JOIN pg_roles AS member ON member.oid = membership.member "
                        "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
                        "WHERE member.rolname = current_user ORDER BY granted.rolname"
                    )
                ).all()
            )
            incoming_memberships = connection.execute(
                sa.text(
                    "SELECT count(*) FROM pg_auth_members AS membership "
                    "JOIN pg_roles AS role ON role.oid = membership.roleid "
                    "WHERE role.rolname = current_user"
                )
            ).scalar_one()
    except sa.exc.SQLAlchemyError:
        raise PostgreSqlMigrationError("authority_connection_failed", "preflight") from None

    (
        current_user,
        session_user,
        database,
        current_schema,
        search_path,
        database_oid,
        database_owner,
        server_version_num,
        server_address,
        server_port,
        in_recovery,
        tls,
    ) = identity
    if current_user != authority.login or session_user != authority.login:
        raise PostgreSqlMigrationError("authority_session_identity_mismatch", "preflight")
    schemas = list(search_path)
    if authority.kind == "principal_operator":
        schema_target_safe = (current_schema is None and schemas == []) or (
            current_schema == "public" and schemas == ["public"]
        )
    else:
        schema_target_safe = current_schema == "public" and schemas == ["public"]
    if database != authority.url.database or not schema_target_safe:
        raise PostgreSqlMigrationError("authority_session_target_mismatch", "preflight")
    if in_recovery:
        raise PostgreSqlMigrationError("authority_target_is_read_only", "preflight")
    if require_tls and not tls:
        raise PostgreSqlMigrationError("authority_tls_not_active", "preflight")
    if (
        role is None
        or role_settings != 0
        or not _authority_memberships_are_safe(
            authority.kind,
            outgoing_memberships,
            int(incoming_memberships),
        )
    ):
        raise PostgreSqlMigrationError("authority_role_graph_unsafe", "preflight")
    (
        can_login,
        is_superuser,
        can_create_database,
        can_create_role,
        can_replicate,
        bypasses_rls,
        inherits_roles,
        connection_limit,
        role_config,
    ) = role
    common_safe = (
        can_login
        and not is_superuser
        and not can_replicate
        and not bypasses_rls
        and inherits_roles
        and connection_limit == -1
        and role_config is None
    )
    if authority.kind == "principal_operator":
        role_safe = common_safe and can_create_role and not can_create_database
    else:
        role_safe = common_safe and not can_create_role and not can_create_database
    if not role_safe:
        raise PostgreSqlMigrationError("authority_role_flags_unsafe", "preflight")
    if authority.kind == "database_owner":
        if database_owner != authority.login:
            raise PostgreSqlMigrationError("database_owner_identity_mismatch", "preflight")
    elif database_owner == authority.login:
        raise PostgreSqlMigrationError("authority_owns_database_unexpectedly", "preflight")
    return _SessionFacts(
        kind=authority.kind,
        login=authority.login,
        database=str(database),
        database_oid=int(database_oid),
        database_owner=str(database_owner),
        server_version_num=int(server_version_num),
        server_address=str(server_address),
        server_port=int(server_port),
        tls=bool(tls),
    )


def _preflight(
    plan: ProductionPostgreSqlPlan,
    engines: Mapping[AuthorityKind, Engine],
) -> tuple[_SessionFacts, ...]:
    facts = tuple(
        _inspect_authority(
            engines[authority.kind],
            authority,
            require_tls=plan.require_tls,
        )
        for authority in plan.authorities()
    )
    identities = {_database_identity_sha256(item) for item in facts}
    if len(identities) != 1:
        raise PostgreSqlMigrationError("authority_database_identity_drift", "preflight")
    if any(item.server_version_num < 160000 for item in facts):
        raise PostgreSqlMigrationError("postgresql_16_required", "preflight")
    if any(not item.server_address or item.server_port <= 0 for item in facts):
        raise PostgreSqlMigrationError("authority_server_identity_missing", "preflight")
    for server_major in {item.server_version_num // 10000 for item in facts}:
        _require_source_catalog_baselines(
            server_major,
            bindings=plan.service_role_graph,
        )
    return facts


def _source_security_catalog_baselines(
    bindings: _ServiceRoleProfile | None,
) -> Mapping[tuple[int, str, str], str]:
    """Select the only source-pinned catalog profile for an exact role graph."""

    if bindings is None:
        return _SOURCE_SECURITY_CATALOG_SHA256
    observed = {binding.service: binding.base_role for binding in bindings.bindings}
    core = dict(EXPECTED_PRODUCTION_SERVICE_ROLES)
    if observed == core:
        return _SOURCE_SECURITY_CATALOG_SHA256
    platform_model = {**core, **dict(EXPECTED_PLATFORM_MODEL_SERVICE_ROLES)}
    if observed == platform_model:
        return _PLATFORM_MODEL_SOURCE_SECURITY_CATALOG_SHA256
    platform_admin = {**platform_model, **dict(EXPECTED_PLATFORM_ADMIN_SERVICE_ROLES)}
    if observed == platform_admin:
        return _PLATFORM_ADMIN_SOURCE_SECURITY_CATALOG_SHA256
    if observed == {**platform_admin, **dict(EXPECTED_MODEL_PROJECTION_SERVICE_ROLES)}:
        return _MODEL_PROJECTION_SOURCE_SECURITY_CATALOG_SHA256
    raise PostgreSqlMigrationError("service_role_bindings_invalid", "configuration")


def _require_source_catalog_baselines(
    server_major: int,
    *,
    bindings: _ServiceRoleProfile | None = None,
) -> None:
    """Reject an unanchored release before any authority or schema mutation."""

    key = (server_major, _expected_head("official"), _expected_head("saas"))
    source_security_baselines = _source_security_catalog_baselines(bindings)
    if key not in _PUBLIC_SCHEMA_INVENTORY_SHA256 or key not in source_security_baselines:
        raise PostgreSqlMigrationError("source_catalog_baseline_missing", "preflight")


def _read_resource(package: str, name: str) -> str:
    return files(package).joinpath(name).read_text(encoding="utf-8")


def _verify_capability_principal_flags(
    connection: Connection,
    *,
    require_complete: bool,
) -> None:
    rows = connection.execute(
        sa.text(
            "SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
            "rolreplication, rolbypassrls, rolinherit, rolconnlimit, rolconfig "
            "FROM pg_roles WHERE rolname = ANY(:roles) ORDER BY rolname"
        ),
        {"roles": list(_CAPABILITY_ROLES)},
    ).all()
    expected_flags = (False, False, False, False, False, False, True, -1, None)
    if (require_complete and len(rows) != len(_CAPABILITY_ROLES)) or any(
        tuple(row[1:]) != expected_flags for row in rows
    ):
        raise PostgreSqlMigrationError("capability_principal_projection_failed", "principals")


def _verify_service_principal_graph(
    connection: Connection,
    *,
    bindings: _ServiceRoleProfile,
    principal_operator: str,
    require_complete: bool,
) -> None:
    """Verify the complete cluster role boundary for production services."""

    service_logins = [binding.login for binding in bindings.bindings]
    login_rows = connection.execute(
        sa.text(
            "SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
            "rolreplication, rolbypassrls, rolinherit, rolconnlimit, rolconfig "
            "FROM pg_roles WHERE rolname = ANY(:logins) ORDER BY rolname"
        ),
        {"logins": service_logins},
    ).all()
    journal_login = bindings.by_service[_RUNTIME_PROVIDER_JOURNAL_SERVICE].login
    if len(login_rows) != len(service_logins) or any(
        not _service_login_flags_are_safe(
            tuple(row),
            journal_login=journal_login,
            require_complete=require_complete,
        )
        for row in login_rows
    ):
        raise PostgreSqlMigrationError("service_login_projection_failed", "principals")

    direct_authority = connection.execute(
        sa.text(
            "WITH service_login AS (SELECT oid, rolname FROM pg_roles "
            "WHERE rolname = ANY(:logins)), "
            "authority AS ("
            "SELECT 1 FROM pg_db_role_setting object JOIN service_login login "
            "ON object.setrole = login.oid WHERE NOT ("
            "login.rolname = :journal_login AND object.setdatabase = 0 AND "
            "object.setconfig = ARRAY['search_path=public']::text[]) UNION ALL "
            "SELECT 1 FROM pg_database object JOIN service_login login "
            "ON object.datdba = login.oid UNION ALL "
            "SELECT 1 FROM pg_namespace object JOIN service_login login "
            "ON object.nspowner = login.oid UNION ALL "
            "SELECT 1 FROM pg_class object JOIN service_login login "
            "ON object.relowner = login.oid UNION ALL "
            "SELECT 1 FROM pg_proc object JOIN service_login login "
            "ON object.proowner = login.oid UNION ALL "
            "SELECT 1 FROM pg_type object JOIN service_login login "
            "ON object.typowner = login.oid UNION ALL "
            "SELECT 1 FROM pg_default_acl object JOIN service_login login "
            "ON object.defaclrole = login.oid UNION ALL "
            "SELECT 1 FROM pg_database object CROSS JOIN LATERAL "
            "aclexplode(object.datacl) acl JOIN service_login login "
            "ON acl.grantee = login.oid UNION ALL "
            "SELECT 1 FROM pg_namespace object CROSS JOIN LATERAL "
            "aclexplode(object.nspacl) acl JOIN service_login login "
            "ON acl.grantee = login.oid UNION ALL "
            "SELECT 1 FROM pg_class object CROSS JOIN LATERAL "
            "aclexplode(object.relacl) acl JOIN service_login login "
            "ON acl.grantee = login.oid UNION ALL "
            "SELECT 1 FROM pg_attribute object CROSS JOIN LATERAL "
            "aclexplode(object.attacl) acl JOIN service_login login "
            "ON acl.grantee = login.oid WHERE object.attnum > 0 "
            "AND NOT object.attisdropped UNION ALL "
            "SELECT 1 FROM pg_proc object CROSS JOIN LATERAL "
            "aclexplode(object.proacl) acl JOIN service_login login "
            "ON acl.grantee = login.oid UNION ALL "
            "SELECT 1 FROM pg_type object CROSS JOIN LATERAL "
            "aclexplode(object.typacl) acl JOIN service_login login "
            "ON acl.grantee = login.oid UNION ALL "
            "SELECT 1 FROM pg_default_acl object CROSS JOIN LATERAL "
            "aclexplode(object.defaclacl) acl JOIN service_login login "
            "ON acl.grantee = login.oid) SELECT count(*) FROM authority"
        ),
        {"logins": service_logins, "journal_login": journal_login},
    ).scalar_one()
    if direct_authority:
        raise PostgreSqlMigrationError("service_login_direct_authority", "principals")

    managed_roles = [*_CAPABILITY_ROLES, *service_logins, principal_operator]
    observed = {
        (
            str(granted),
            str(member),
            str(grantor),
            bool(admin),
            bool(inherit),
            bool(can_set),
            int(grantor_oid),
        )
        for granted, member, grantor, admin, inherit, can_set, grantor_oid in connection.execute(
            sa.text(
                "SELECT granted.rolname, member.rolname, grantor.rolname, "
                "membership.admin_option, "
                "COALESCE((to_jsonb(membership) ->> 'inherit_option')::boolean, true), "
                "COALESCE((to_jsonb(membership) ->> 'set_option')::boolean, true), "
                "membership.grantor "
                "FROM pg_auth_members AS membership "
                "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
                "JOIN pg_roles AS member ON member.oid = membership.member "
                "JOIN pg_roles AS grantor ON grantor.oid = membership.grantor "
                "WHERE granted.rolname = ANY(:managed) OR member.rolname = ANY(:managed) "
                "ORDER BY 1, 2, 3"
            ),
            {"managed": managed_roles},
        ).all()
    }
    principal_operator_oid = int(
        connection.execute(
            sa.text("SELECT oid FROM pg_roles WHERE rolname = :principal_operator"),
            {"principal_operator": principal_operator},
        ).scalar_one()
    )
    bootstrap_name = connection.execute(
        sa.text("SELECT rolname FROM pg_roles WHERE oid = 10")
    ).scalar_one_or_none()
    if not bootstrap_name:
        raise PostgreSqlMigrationError("bootstrap_principal_missing", "principals")
    bootstrap_name = str(bootstrap_name)
    runtime_runner_edges = {
        edge
        for edge in observed
        if _runtime_runner_membership_is_safe(edge, bootstrap_name=bootstrap_name)
    }
    runtime_runner_logins = sorted({edge[1] for edge in runtime_runner_edges})
    if runtime_runner_logins:
        runtime_runner_rows = tuple(
            connection.execute(
                sa.text(
                    "SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                    "rolreplication, rolbypassrls, rolinherit, rolconnlimit, rolconfig "
                    "FROM pg_roles WHERE rolname = ANY(:logins) ORDER BY rolname"
                ),
                {"logins": runtime_runner_logins},
            ).all()
        )
        if (
            len(runtime_runner_rows) != len(runtime_runner_logins)
            or [str(row[0]) for row in runtime_runner_rows] != runtime_runner_logins
            or any(
                not _runtime_runner_login_flags_are_safe(tuple(row)) for row in runtime_runner_rows
            )
        ):
            raise PostgreSqlMigrationError("service_role_graph_drifted", "principals")
        observed.difference_update(runtime_runner_edges)
    expected_complete = _expected_service_principal_graph(
        bindings=bindings,
        principal_operator=principal_operator,
        principal_operator_oid=principal_operator_oid,
        bootstrap_name=bootstrap_name,
    )
    if not _role_graph_projection_is_safe(
        observed,
        expected=expected_complete,
        require_complete=require_complete,
    ):
        raise PostgreSqlMigrationError("service_role_graph_drifted", "principals")


def _expected_service_principal_graph(
    *,
    bindings: _ServiceRoleProfile,
    principal_operator: str,
    principal_operator_oid: int,
    bootstrap_name: str,
) -> set[_RoleGraphEdge]:
    """Return the exact terminal role graph and each edge's real grantor."""

    service_edges: set[_RoleGraphEdge] = {
        (
            binding.base_role,
            binding.login,
            principal_operator,
            False,
            True,
            False,
            principal_operator_oid,
        )
        for binding in bindings.bindings
    }
    fixed_edges: set[_RoleGraphEdge] = {
        (
            "saas_dispatcher",
            "saas_dispatcher_n1_compat",
            principal_operator,
            False,
            False,
            False,
            principal_operator_oid,
        ),
        (
            "saas_platform_governance",
            "saas_privacy_executor",
            principal_operator,
            False,
            True,
            True,
            principal_operator_oid,
        ),
    }
    management_edges: set[_RoleGraphEdge] = {
        (
            role_name,
            principal_operator,
            bootstrap_name,
            True,
            False,
            False,
            10,
        )
        for role_name in _CAPABILITY_ROLES
    }
    return service_edges | fixed_edges | management_edges


def _role_graph_projection_is_safe(
    observed: set[_RoleGraphEdge],
    *,
    expected: set[_RoleGraphEdge],
    require_complete: bool,
) -> bool:
    """Allow the admitted runtime Runner-management edge to be absent.

    The principal operator needs ADMIN on ``saas_runner_agent`` while the
    deployment stages Runner logins.  The independently signed Runner fleet
    admission requires that management edge to be revoked before the runtime
    fleet becomes online.  Both states are valid terminal projections: all
    other expected edges remain mandatory and every unexpected edge is denied.
    """

    if not observed.issubset(expected):
        return False
    if not require_complete:
        return True
    missing = expected - observed
    return not missing or (
        len(missing) == 1
        and next(iter(missing))[0] == "saas_runner_agent"
        and next(iter(missing))[3:] == (True, False, False, 10)
    )


def _runtime_runner_membership_is_safe(
    edge: tuple[object, ...],
    *,
    bootstrap_name: str,
) -> bool:
    if len(edge) != 7:
        return False
    granted, member, grantor, admin, inherit, can_set, grantor_oid = edge
    if not isinstance(member, str):
        return False
    match = _RUNNER_AGENT_LOGIN.fullmatch(member)
    return bool(
        granted == "saas_runner_agent"
        and match is not None
        and int(match.group(1), 16) != 0
        and int(match.group(2)) <= (1 << 63) - 1
        and grantor == bootstrap_name
        and not admin
        and inherit
        and not can_set
        and grantor_oid == 10
    )


def _runtime_runner_login_flags_are_safe(row: tuple[object, ...]) -> bool:
    if len(row) != 10:
        return False
    login = str(row[0])
    match = _RUNNER_AGENT_LOGIN.fullmatch(login)
    return bool(
        match is not None
        and int(match.group(1), 16) != 0
        and int(match.group(2)) <= (1 << 63) - 1
        and tuple(row[1:9]) == (True, False, False, False, False, False, True, 8)
        and row[9] is None
    )


def _stable_control_plane_memberships(
    rows: list[list[object]],
    *,
    bootstrap_name: str,
) -> list[list[object]]:
    """Exclude validated dynamic Runner edges from the static catalog anchor."""

    return [
        row[:6]
        for row in rows
        if not _runtime_runner_membership_is_safe(
            tuple(row),
            bootstrap_name=bootstrap_name,
        )
    ]


def _canonical_runner_management_catalog(
    catalog: Mapping[str, object],
    *,
    principal_operator: str,
    bootstrap_name: str,
) -> dict[str, object]:
    """Hash both admitted Runner lifecycle states as the original staging state.

    Call only after the complete principal graph has been verified. Revoking
    its sole optional management edge must not invalidate the source anchor or
    the immutable staging receipt; every other catalog fact stays authoritative.
    This projection changes no database permissions or caller-owned values.
    """

    security = catalog.get("control_plane_security")
    memberships = security.get("memberships") if isinstance(security, Mapping) else None
    if not isinstance(memberships, list) or any(
        not isinstance(row, list) or len(row) != 6 for row in memberships
    ):
        raise PostgreSqlMigrationError("service_role_graph_drifted", "verification")
    management = ["saas_runner_agent", principal_operator, bootstrap_name, True, False, False]
    observed = [
        row
        for row in memberships
        if row[0] == "saas_runner_agent" and row[1] == principal_operator
    ]
    if observed == [management]:
        return dict(catalog)
    if observed:
        raise PostgreSqlMigrationError("service_role_graph_drifted", "verification")
    projected = [*memberships, management]
    projected.sort(key=lambda row: tuple(str(value) for value in row[:3]))
    return {
        **catalog,
        "control_plane_security": {
            **cast(Mapping[str, object], security),
            "memberships": projected,
        },
    }


def _service_login_flags_are_safe(
    row: tuple[object, ...],
    *,
    journal_login: str,
    require_complete: bool,
) -> bool:
    """Admit only the journal LOGIN's exact, non-overridable search path."""

    if len(row) != 10:
        return False
    login = str(row[0])
    common_flags = tuple(row[1:9])
    role_config = row[9]
    if common_flags != (True, False, False, False, False, False, True, -1):
        return False
    if login != journal_login:
        return role_config is None
    if role_config is None:
        return not require_complete
    if not isinstance(role_config, (list, tuple)):
        return False
    normalized = tuple(str(value) for value in role_config)
    return normalized == _RUNTIME_PROVIDER_JOURNAL_SEARCH_PATH


def _verify_capability_principals(
    connection: Connection,
    *,
    bindings: _ServiceRoleProfile,
    principal_operator: str,
) -> None:
    _verify_capability_principal_flags(connection, require_complete=True)
    _verify_service_principal_graph(
        connection,
        bindings=bindings,
        principal_operator=principal_operator,
        require_complete=True,
    )


def _apply_principals(
    engine: Engine,
    *,
    bindings: _ServiceRoleProfile,
    principal_operator: str,
) -> None:
    with engine.begin() as connection:
        _verify_capability_principal_flags(connection, require_complete=False)
        _verify_service_principal_graph(
            connection,
            bindings=bindings,
            principal_operator=principal_operator,
            require_complete=False,
        )
        connection.exec_driver_sql(
            _read_resource("saas.control_plane", "postgresql_principals.sql")
        )
        quote = connection.dialect.identifier_preparer.quote
        for binding in bindings.bindings:
            connection.exec_driver_sql(
                f"GRANT {quote(binding.base_role)} TO {quote(binding.login)} "
                "WITH ADMIN FALSE, INHERIT TRUE, SET FALSE"
            )
        _verify_capability_principals(
            connection,
            bindings=bindings,
            principal_operator=principal_operator,
        )


def _database_acl_projection(
    connection: Connection,
) -> set[tuple[str, str, str, bool]]:
    return {
        (str(grantee), str(grantor), str(privilege), bool(grantable))
        for grantee, grantor, privilege, grantable in connection.execute(
            sa.text(
                "SELECT CASE WHEN acl.grantee = 0 THEN 'PUBLIC' "
                "ELSE pg_get_userbyid(acl.grantee) END, "
                "pg_get_userbyid(acl.grantor), acl.privilege_type, acl.is_grantable "
                "FROM pg_database AS database CROSS JOIN LATERAL "
                "aclexplode(COALESCE(database.datacl, acldefault('d', database.datdba))) acl "
                "WHERE database.datname = current_database()"
            )
        ).all()
    }


def _schema_acl_projection(
    connection: Connection,
) -> set[tuple[str, str, str, bool]]:
    return {
        (str(grantee), str(grantor), str(privilege), bool(grantable))
        for grantee, grantor, privilege, grantable in connection.execute(
            sa.text(
                "SELECT CASE WHEN acl.grantee = 0 THEN 'PUBLIC' "
                "ELSE pg_get_userbyid(acl.grantee) END, "
                "pg_get_userbyid(acl.grantor), acl.privilege_type, acl.is_grantable "
                "FROM pg_namespace AS namespace CROSS JOIN LATERAL "
                "aclexplode(COALESCE(namespace.nspacl, acldefault('n', namespace.nspowner))) acl "
                "WHERE namespace.nspname = 'public'"
            )
        ).all()
    }


def _public_schema_owner(connection: Connection) -> str:
    owner = connection.execute(
        sa.text(
            "SELECT pg_get_userbyid(namespace.nspowner) FROM pg_namespace AS namespace "
            "WHERE namespace.nspname = 'public'"
        )
    ).scalar_one_or_none()
    if not owner:
        raise PostgreSqlMigrationError("public_schema_owner_missing", "database")
    return str(owner)


def _preflight_database_acl_grantors(connection: Connection) -> None:
    unsafe = connection.execute(
        sa.text(
            "SELECT count(*) FROM ("
            "SELECT 1 FROM pg_database AS database CROSS JOIN LATERAL "
            "aclexplode(database.datacl) acl LEFT JOIN pg_roles grantee "
            "ON grantee.oid = acl.grantee WHERE database.datname = current_database() "
            "AND acl.grantee <> database.datdba AND (acl.grantor <> database.datdba "
            "OR (acl.grantee <> 0 AND grantee.oid IS NULL)) UNION ALL "
            "SELECT 1 FROM pg_namespace AS namespace CROSS JOIN LATERAL "
            "aclexplode(namespace.nspacl) acl LEFT JOIN pg_roles grantee "
            "ON grantee.oid = acl.grantee WHERE namespace.nspname = 'public' "
            "AND acl.grantee <> namespace.nspowner AND (acl.grantor <> namespace.nspowner "
            "OR (acl.grantee <> 0 AND grantee.oid IS NULL))) unsafe"
        )
    ).scalar_one()
    if unsafe:
        raise PostgreSqlMigrationError("database_foreign_grantor_drifted", "database")


def _owned_object_acl_grantees(
    connection: Connection,
    *,
    official_owner: str,
    saas_owner: str,
) -> set[str]:
    """Return exact capability roles that need public schema USAGE."""

    rows = connection.execute(
        sa.text(
            "WITH owner_roles AS (SELECT oid FROM pg_roles WHERE rolname = ANY(:owners)), "
            "grantee AS ("
            "SELECT acl.grantee FROM pg_class object JOIN pg_namespace namespace "
            "ON namespace.oid = object.relnamespace JOIN owner_roles owner "
            "ON owner.oid = object.relowner CROSS JOIN LATERAL aclexplode(object.relacl) acl "
            "WHERE namespace.nspname = 'public' AND acl.grantee <> object.relowner UNION "
            "SELECT acl.grantee FROM pg_attribute attribute JOIN pg_class object "
            "ON object.oid = attribute.attrelid JOIN pg_namespace namespace "
            "ON namespace.oid = object.relnamespace JOIN owner_roles owner "
            "ON owner.oid = object.relowner CROSS JOIN LATERAL aclexplode(attribute.attacl) acl "
            "WHERE namespace.nspname = 'public' AND attribute.attnum > 0 "
            "AND NOT attribute.attisdropped AND acl.grantee <> object.relowner UNION "
            "SELECT acl.grantee FROM pg_proc object JOIN pg_namespace namespace "
            "ON namespace.oid = object.pronamespace JOIN owner_roles owner "
            "ON owner.oid = object.proowner CROSS JOIN LATERAL "
            "aclexplode(COALESCE(object.proacl, acldefault('f', object.proowner))) acl "
            "WHERE namespace.nspname = 'public' AND acl.grantee <> object.proowner) "
            "SELECT CASE WHEN grantee.grantee = 0 THEN 'PUBLIC' "
            "ELSE pg_get_userbyid(grantee.grantee) END FROM grantee ORDER BY 1"
        ),
        {"owners": [official_owner, saas_owner]},
    ).scalars()
    grantees = {str(role) for role in rows}
    if "PUBLIC" in grantees or not grantees.issubset(_CAPABILITY_ROLES):
        raise PostgreSqlMigrationError("object_acl_grantee_drifted", "database")
    return grantees


def _apply_database_authority(
    engine: Engine,
    *,
    principal_operator: str,
    official_owner: str,
    saas_owner: str,
    bindings: _ServiceRoleProfile,
) -> None:
    with engine.begin() as connection:
        _preflight_database_acl_grantors(connection)
        connection.exec_driver_sql(_read_resource("saas.control_plane", "postgresql_database.sql"))
        _converge_database_acl_projection(
            connection,
            principal_operator=principal_operator,
            official_owner=official_owner,
            saas_owner=saas_owner,
            bindings=bindings,
            schema_usage_roles={
                official_owner,
                saas_owner,
                *_CAPABILITY_ROLES,
            },
        )


def _converge_database_acl_projection(
    connection: Connection,
    *,
    principal_operator: str,
    official_owner: str,
    saas_owner: str,
    bindings: _ServiceRoleProfile,
    schema_usage_roles: set[str],
) -> None:
    quote = connection.dialect.identifier_preparer.quote
    database_name, database_owner = connection.execute(
        sa.text(
            "SELECT database.datname, pg_get_userbyid(database.datdba) "
            "FROM pg_database database WHERE database.datname = current_database()"
        )
    ).one()
    database_grantees = connection.execute(
        sa.text(
            "SELECT DISTINCT CASE WHEN acl.grantee = 0 THEN 'PUBLIC' "
            "ELSE pg_get_userbyid(acl.grantee) END FROM pg_database database "
            "CROSS JOIN LATERAL aclexplode(database.datacl) acl "
            "WHERE database.datname = current_database() AND acl.grantee <> database.datdba"
        )
    ).scalars()
    schema_grantees = connection.execute(
        sa.text(
            "SELECT DISTINCT CASE WHEN acl.grantee = 0 THEN 'PUBLIC' "
            "ELSE pg_get_userbyid(acl.grantee) END FROM pg_namespace namespace "
            "CROSS JOIN LATERAL aclexplode(namespace.nspacl) acl "
            "WHERE namespace.nspname = 'public' AND acl.grantee <> namespace.nspowner"
        )
    ).scalars()
    for grantee in database_grantees:
        rendered = "PUBLIC" if grantee == "PUBLIC" else quote(str(grantee))
        connection.exec_driver_sql(
            f"REVOKE ALL PRIVILEGES ON DATABASE {quote(str(database_name))} FROM {rendered}"
        )
    for grantee in schema_grantees:
        rendered = "PUBLIC" if grantee == "PUBLIC" else quote(str(grantee))
        connection.exec_driver_sql(f"REVOKE ALL PRIVILEGES ON SCHEMA public FROM {rendered}")

    connect_roles = {
        principal_operator,
        official_owner,
        saas_owner,
        "saas_runner_agent",
        *(binding.base_role for binding in bindings.bindings),
    }
    connection.exec_driver_sql(
        f"GRANT CONNECT ON DATABASE {quote(str(database_name))} TO "
        + ", ".join(quote(role_name) for role_name in sorted(connect_roles))
    )
    connection.exec_driver_sql(
        f"GRANT CREATE ON DATABASE {quote(str(database_name))} TO {quote(official_owner)}"
    )
    connection.exec_driver_sql(
        "GRANT USAGE ON SCHEMA public TO "
        + ", ".join(quote(role_name) for role_name in sorted(schema_usage_roles))
    )
    connection.exec_driver_sql(
        "GRANT CREATE ON SCHEMA public TO "
        + ", ".join(quote(role_name) for role_name in sorted({official_owner, saas_owner}))
    )
    _verify_database_acl_projection(
        connection,
        database_owner=str(database_owner),
        principal_operator=principal_operator,
        official_owner=official_owner,
        saas_owner=saas_owner,
        bindings=bindings,
        schema_usage_roles=schema_usage_roles,
    )


def _verify_database_acl_projection(
    connection: Connection,
    *,
    database_owner: str,
    principal_operator: str,
    official_owner: str,
    saas_owner: str,
    bindings: _ServiceRoleProfile,
    schema_usage_roles: set[str],
) -> None:
    database_nonowner = {
        row for row in _database_acl_projection(connection) if row[0] != database_owner
    }
    expected_connect = {
        principal_operator,
        official_owner,
        saas_owner,
        "saas_runner_agent",
        *(binding.base_role for binding in bindings.bindings),
    }
    expected_database = {
        (role_name, database_owner, "CONNECT", False) for role_name in expected_connect
    } | {(official_owner, database_owner, "CREATE", False)}
    schema_owner = _public_schema_owner(connection)
    schema_nonowner = {row for row in _schema_acl_projection(connection) if row[0] != schema_owner}
    expected_schema = {
        (role_name, schema_owner, "USAGE", False) for role_name in schema_usage_roles
    } | {(role_name, schema_owner, "CREATE", False) for role_name in (official_owner, saas_owner)}
    if database_nonowner != expected_database or schema_nonowner != expected_schema:
        raise PostgreSqlMigrationError("database_acl_projection_drifted", "database")


def _migration_config(kind: Literal["official", "saas"]) -> Config:
    if kind == "official":
        ini_path = files("omnigent.db").joinpath("alembic.ini")
        script_path = files("omnigent.db").joinpath("migrations")
    else:
        ini_path = files("saas.control_plane").joinpath("alembic.ini")
        script_path = files("saas.control_plane").joinpath("migrations")
    config = Config(str(ini_path))
    config.set_main_option("script_location", str(script_path))
    return config


def _expected_head(kind: Literal["official", "saas"]) -> str:
    head = ScriptDirectory.from_config(_migration_config(kind)).get_current_head()
    if head is None:
        raise PostgreSqlMigrationError("migration_head_missing", f"{kind}_alembic")
    return head


def _upgrade(engine: Engine, kind: Literal["official", "saas"]) -> None:
    config = _migration_config(kind)
    # Official migrations contain an autocommit block; Alembic must own this
    # connection's transaction boundary.
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")


def _version_at_head(
    connection: Connection,
    *,
    kind: Literal["official", "saas"],
) -> str:
    table = "alembic_version" if kind == "official" else "saas_alembic_version"
    rows = connection.exec_driver_sql(f"SELECT version_num FROM {table}").scalars().all()
    expected = _expected_head(kind)
    if rows != [expected]:
        raise PostgreSqlMigrationError("migration_revision_not_at_head", f"{kind}_alembic")
    return expected


def _preflight_owner_acl_surface(connection: Connection, *, phase: str) -> None:
    """Reject ACL edges the direct object owner cannot safely converge."""

    foreign = connection.execute(
        sa.text(
            "WITH owner AS (SELECT oid FROM pg_roles WHERE rolname = current_user), "
            "unsafe AS ("
            "SELECT 1 FROM pg_class object JOIN pg_namespace namespace "
            "ON namespace.oid = object.relnamespace CROSS JOIN owner "
            "CROSS JOIN LATERAL aclexplode(object.relacl) acl LEFT JOIN pg_roles grantee "
            "ON grantee.oid = acl.grantee WHERE namespace.nspname = 'public' "
            "AND object.relowner = owner.oid AND object.relkind IN ('r','p','S','v','m','f') "
            "AND acl.grantee <> object.relowner AND (acl.grantor <> owner.oid "
            "OR (acl.grantee <> 0 AND grantee.oid IS NULL)) UNION ALL "
            "SELECT 1 FROM pg_attribute attribute JOIN pg_class object "
            "ON object.oid = attribute.attrelid JOIN pg_namespace namespace "
            "ON namespace.oid = object.relnamespace CROSS JOIN owner "
            "CROSS JOIN LATERAL aclexplode(attribute.attacl) acl LEFT JOIN pg_roles grantee "
            "ON grantee.oid = acl.grantee WHERE namespace.nspname = 'public' "
            "AND object.relowner = owner.oid AND attribute.attnum > 0 "
            "AND NOT attribute.attisdropped AND acl.grantee <> object.relowner "
            "AND (acl.grantor <> owner.oid OR (acl.grantee <> 0 AND grantee.oid IS NULL)) "
            "UNION ALL SELECT 1 FROM pg_proc object JOIN pg_namespace namespace "
            "ON namespace.oid = object.pronamespace CROSS JOIN owner "
            "CROSS JOIN LATERAL aclexplode(COALESCE(object.proacl, "
            "acldefault('f', object.proowner))) acl LEFT JOIN pg_roles grantee "
            "ON grantee.oid = acl.grantee WHERE namespace.nspname = 'public' "
            "AND object.proowner = owner.oid AND acl.grantee <> object.proowner "
            "AND (acl.grantor <> owner.oid OR (acl.grantee <> 0 AND grantee.oid IS NULL)) "
            "UNION ALL SELECT 1 FROM pg_type object JOIN pg_namespace namespace "
            "ON namespace.oid = object.typnamespace CROSS JOIN owner "
            "CROSS JOIN LATERAL aclexplode(object.typacl) acl LEFT JOIN pg_roles grantee "
            "ON grantee.oid = acl.grantee WHERE namespace.nspname = 'public' "
            "AND object.typowner = owner.oid AND acl.grantee <> object.typowner "
            "AND (acl.grantor <> owner.oid OR (acl.grantee <> 0 AND grantee.oid IS NULL)) "
            "UNION ALL SELECT 1 FROM pg_default_acl object CROSS JOIN owner "
            "LEFT JOIN pg_namespace namespace ON namespace.oid = object.defaclnamespace "
            "CROSS JOIN LATERAL aclexplode(object.defaclacl) acl LEFT JOIN pg_roles grantee "
            "ON grantee.oid = acl.grantee WHERE object.defaclrole = owner.oid "
            "AND (namespace.nspname = 'public' OR object.defaclnamespace = 0) "
            "AND acl.grantee <> owner.oid AND (acl.grantor <> owner.oid "
            "OR (acl.grantee <> 0 AND grantee.oid IS NULL)) UNION ALL "
            "SELECT 1 FROM pg_default_acl object CROSS JOIN owner "
            "LEFT JOIN pg_namespace namespace ON namespace.oid = object.defaclnamespace "
            "WHERE object.defaclrole = owner.oid AND object.defaclnamespace <> 0 "
            "AND namespace.nspname IS DISTINCT FROM 'public') SELECT count(*) FROM unsafe"
        )
    ).scalar_one()
    if foreign:
        raise PostgreSqlMigrationError("owner_acl_foreign_grantor_drifted", phase)


def _revoke_owner_acl_surface(connection: Connection) -> None:
    """Remove every owner-granted non-owner edge before rebuilding exact ACLs."""

    quote = connection.dialect.identifier_preparer.quote

    def grantee_sql(value: str) -> str:
        return "PUBLIC" if value == "PUBLIC" else quote(value)

    relations = connection.execute(
        sa.text(
            "SELECT DISTINCT object.relname, object.relkind, "
            "CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantee) END "
            "FROM pg_class object JOIN pg_namespace namespace "
            "ON namespace.oid = object.relnamespace CROSS JOIN LATERAL "
            "aclexplode(object.relacl) acl WHERE namespace.nspname = 'public' "
            "AND object.relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user) "
            "AND object.relkind IN ('r','p','S','v','m','f') "
            "AND acl.grantee <> object.relowner ORDER BY 1, 2, 3"
        )
    ).all()
    for name, relkind, grantee in relations:
        object_kind = "SEQUENCE" if relkind == "S" else "TABLE"
        connection.exec_driver_sql(
            f"REVOKE ALL PRIVILEGES ON {object_kind} public.{quote(str(name))} "
            f"FROM {grantee_sql(str(grantee))}"
        )

    columns = connection.execute(
        sa.text(
            "SELECT object.relname, acl.privilege_type, "
            "CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantee) END, "
            "string_agg(quote_ident(attribute.attname), ', ' ORDER BY attribute.attnum) "
            "FROM pg_attribute attribute JOIN pg_class object "
            "ON object.oid = attribute.attrelid JOIN pg_namespace namespace "
            "ON namespace.oid = object.relnamespace CROSS JOIN LATERAL "
            "aclexplode(attribute.attacl) acl WHERE namespace.nspname = 'public' "
            "AND object.relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user) "
            "AND attribute.attnum > 0 AND NOT attribute.attisdropped "
            "AND acl.grantee <> object.relowner GROUP BY 1, 2, 3 ORDER BY 1, 2, 3"
        )
    ).all()
    for table, privilege, grantee, column_list in columns:
        connection.exec_driver_sql(
            f"REVOKE {privilege} ({column_list}) ON TABLE public.{quote(str(table))} "
            f"FROM {grantee_sql(str(grantee))}"
        )

    routines = connection.execute(
        sa.text(
            "SELECT DISTINCT quote_ident(object.proname) || '(' || "
            "pg_get_function_identity_arguments(object.oid) || ')', "
            "CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantee) END "
            "FROM pg_proc object JOIN pg_namespace namespace "
            "ON namespace.oid = object.pronamespace CROSS JOIN LATERAL "
            "aclexplode(COALESCE(object.proacl, acldefault('f', object.proowner))) acl "
            "WHERE namespace.nspname = 'public' "
            "AND object.proowner = (SELECT oid FROM pg_roles WHERE rolname = current_user) "
            "AND acl.grantee <> object.proowner ORDER BY 1, 2"
        )
    ).all()
    for signature, grantee in routines:
        connection.exec_driver_sql(
            f"REVOKE ALL PRIVILEGES ON FUNCTION public.{signature} "
            f"FROM {grantee_sql(str(grantee))}"
        )

    types = connection.execute(
        sa.text(
            "SELECT DISTINCT object.typname, CASE WHEN acl.grantee = 0 THEN 'PUBLIC' "
            "ELSE pg_get_userbyid(acl.grantee) END FROM pg_type object "
            "JOIN pg_namespace namespace ON namespace.oid = object.typnamespace "
            "CROSS JOIN LATERAL aclexplode(COALESCE(object.typacl, "
            "acldefault('T', object.typowner))) acl WHERE namespace.nspname = 'public' "
            "AND object.typowner = (SELECT oid FROM pg_roles WHERE rolname = current_user) "
            "AND object.typelem = 0 AND acl.grantee <> object.typowner ORDER BY 1, 2"
        )
    ).all()
    for type_name, grantee in types:
        connection.exec_driver_sql(
            f"REVOKE ALL PRIVILEGES ON TYPE public.{quote(str(type_name))} "
            f"FROM {grantee_sql(str(grantee))}"
        )

    # PostgreSQL's implicit defaults grant EXECUTE on every future function
    # and USAGE on every future type to PUBLIC.  Persist an explicit owner-wide
    # deny so a later migration cannot silently reopen either surface.
    connection.exec_driver_sql("ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC")
    connection.exec_driver_sql("ALTER DEFAULT PRIVILEGES REVOKE USAGE ON TYPES FROM PUBLIC")

    defaults = connection.execute(
        sa.text(
            "SELECT DISTINCT COALESCE(namespace.nspname, ''), object.defaclobjtype, "
            "CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantee) END "
            "FROM pg_default_acl object LEFT JOIN pg_namespace namespace "
            "ON namespace.oid = object.defaclnamespace CROSS JOIN LATERAL "
            "aclexplode(object.defaclacl) acl WHERE object.defaclrole = "
            "(SELECT oid FROM pg_roles WHERE rolname = current_user) "
            "AND (namespace.nspname = 'public' OR object.defaclnamespace = 0) "
            "AND acl.grantee <> object.defaclrole ORDER BY 1, 2, 3"
        )
    ).all()
    object_types = {"r": "TABLES", "S": "SEQUENCES", "f": "FUNCTIONS", "T": "TYPES"}
    for namespace, object_type, grantee in defaults:
        if object_type not in object_types:
            raise PostgreSqlMigrationError("default_acl_object_type_unsupported", "acl")
        scope = f" IN SCHEMA {quote(str(namespace))}" if namespace else ""
        connection.exec_driver_sql(
            f"ALTER DEFAULT PRIVILEGES{scope} REVOKE ALL PRIVILEGES ON "
            f"{object_types[str(object_type)]} FROM {grantee_sql(str(grantee))}"
        )


def _verify_owner_acl_surface(connection: Connection, *, phase: str) -> None:
    unexpected = connection.execute(
        sa.text(
            "WITH owner AS (SELECT oid FROM pg_roles WHERE rolname = current_user), "
            "capability AS (SELECT oid FROM pg_roles WHERE rolname = ANY(:roles)), "
            "unexpected AS ("
            "SELECT 1 FROM pg_class object JOIN pg_namespace namespace "
            "ON namespace.oid = object.relnamespace CROSS JOIN owner "
            "CROSS JOIN LATERAL aclexplode(object.relacl) acl LEFT JOIN capability allowed "
            "ON allowed.oid = acl.grantee WHERE namespace.nspname = 'public' "
            "AND object.relowner = owner.oid AND object.relkind IN ('r','p','S','v','m','f') "
            "AND acl.grantee <> owner.oid AND (allowed.oid IS NULL OR acl.grantor <> owner.oid "
            "OR acl.is_grantable) UNION ALL "
            "SELECT 1 FROM pg_attribute attribute JOIN pg_class object "
            "ON object.oid = attribute.attrelid JOIN pg_namespace namespace "
            "ON namespace.oid = object.relnamespace CROSS JOIN owner "
            "CROSS JOIN LATERAL aclexplode(attribute.attacl) acl LEFT JOIN capability allowed "
            "ON allowed.oid = acl.grantee WHERE namespace.nspname = 'public' "
            "AND object.relowner = owner.oid AND attribute.attnum > 0 "
            "AND NOT attribute.attisdropped AND acl.grantee <> owner.oid "
            "AND (allowed.oid IS NULL OR acl.grantor <> owner.oid OR acl.is_grantable) "
            "UNION ALL SELECT 1 FROM pg_proc object JOIN pg_namespace namespace "
            "ON namespace.oid = object.pronamespace CROSS JOIN owner "
            "CROSS JOIN LATERAL aclexplode(COALESCE(object.proacl, "
            "acldefault('f', object.proowner))) acl LEFT JOIN capability allowed "
            "ON allowed.oid = acl.grantee WHERE namespace.nspname = 'public' "
            "AND object.proowner = owner.oid AND acl.grantee <> owner.oid "
            "AND (allowed.oid IS NULL OR acl.grantor <> owner.oid OR acl.is_grantable) "
            "UNION ALL SELECT 1 FROM pg_type object JOIN pg_namespace namespace "
            "ON namespace.oid = object.typnamespace CROSS JOIN owner "
            "CROSS JOIN LATERAL aclexplode(COALESCE(object.typacl, "
            "acldefault('T', object.typowner))) acl WHERE namespace.nspname = 'public' "
            "AND object.typowner = owner.oid AND object.typelem = 0 "
            "AND acl.grantee <> owner.oid UNION ALL "
            "SELECT 1 FROM pg_default_acl object CROSS JOIN owner "
            "LEFT JOIN pg_namespace namespace ON namespace.oid = object.defaclnamespace "
            "CROSS JOIN LATERAL aclexplode(object.defaclacl) acl "
            "WHERE object.defaclrole = owner.oid "
            "AND (namespace.nspname = 'public' OR object.defaclnamespace = 0) "
            "AND acl.grantee <> owner.oid) SELECT count(*) FROM unexpected"
        ),
        {"roles": list(_CAPABILITY_ROLES)},
    ).scalar_one()
    if unexpected:
        raise PostgreSqlMigrationError("owner_acl_projection_drifted", phase)


def _apply_runtime_authority(engine: Engine) -> None:
    with engine.begin() as connection:
        _preflight_owner_acl_surface(connection, phase="runtime_authority")
        _revoke_owner_acl_surface(connection)
        install_runtime_rls(connection)
        verify_runtime_rls(connection)
        connection.exec_driver_sql(_read_resource("saas.runtime_rls", "postgresql_roles.sql"))
        _verify_owner_acl_surface(connection, phase="runtime_authority")


def _preview_authority_grants_present(connection: Connection) -> bool:
    rows = connection.execute(
        sa.text(
            "SELECT relation.relname, '' AS column_name, grantee.rolname, "
            "pg_get_userbyid(acl.grantor), acl.is_grantable "
            "FROM pg_class relation JOIN pg_namespace namespace "
            "ON namespace.oid = relation.relnamespace "
            "CROSS JOIN LATERAL aclexplode(relation.relacl) acl "
            "JOIN pg_roles grantee ON grantee.oid = acl.grantee "
            "WHERE namespace.nspname = 'public' "
            "AND relation.relname IN ('saas_preview_gateway_certificates', "
            "'saas_preview_gateway_instances') "
            "AND grantee.rolname IN ('saas_preview_edge', 'saas_preview_owner') "
            "AND acl.privilege_type = 'SELECT' "
            "UNION ALL "
            "SELECT relation.relname, attribute.attname, grantee.rolname, "
            "pg_get_userbyid(acl.grantor), acl.is_grantable "
            "FROM pg_attribute attribute JOIN pg_class relation "
            "ON relation.oid = attribute.attrelid "
            "JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace "
            "CROSS JOIN LATERAL aclexplode(attribute.attacl) acl "
            "JOIN pg_roles grantee ON grantee.oid = acl.grantee "
            "WHERE namespace.nspname = 'public' "
            "AND relation.relname = 'saas_preview_gateway_instances' "
            "AND attribute.attname = 'server_name' "
            "AND grantee.rolname = 'saas_preview_owner' "
            "AND acl.privilege_type = 'SELECT'"
        )
    ).all()
    observed = {tuple(row) for row in rows}
    owner = connection.execute(sa.text("SELECT current_user")).scalar_one()
    expected = {
        ("saas_preview_gateway_certificates", "", "saas_preview_edge", owner, False),
        ("saas_preview_gateway_certificates", "", "saas_preview_owner", owner, False),
        ("saas_preview_gateway_instances", "", "saas_preview_edge", owner, False),
        ("saas_preview_gateway_instances", "server_name", "saas_preview_owner", owner, False),
    }
    if observed not in (set(), expected):
        raise PostgreSqlMigrationError("preview_authority_acl_partial", "control_plane_authority")
    return bool(observed)


def _apply_control_plane_authority(engine: Engine) -> None:
    with engine.begin() as connection:
        _preflight_owner_acl_surface(connection, phase="control_plane_authority")
        preview_authority = _preview_authority_grants_present(connection)
        _revoke_owner_acl_surface(connection)
        connection.exec_driver_sql(_read_resource("saas.control_plane", "postgresql_roles.sql"))
        if preview_authority:
            connection.exec_driver_sql(
                "GRANT SELECT (server_name) ON public.saas_preview_gateway_instances "
                "TO saas_preview_owner; "
                "GRANT SELECT ON public.saas_preview_gateway_certificates "
                "TO saas_preview_edge, saas_preview_owner; "
                "GRANT SELECT ON public.saas_preview_gateway_instances "
                "TO saas_preview_edge"
            )
        _verify_owner_acl_surface(connection, phase="control_plane_authority")


def _finalize_database_authority(
    engine: Engine,
    *,
    principal_operator: str,
    official_owner: str,
    saas_owner: str,
    bindings: _ServiceRoleProfile,
) -> None:
    with engine.begin() as connection:
        _preflight_database_acl_grantors(connection)
        object_grantees = _owned_object_acl_grantees(
            connection,
            official_owner=official_owner,
            saas_owner=saas_owner,
        )
        _converge_database_acl_projection(
            connection,
            principal_operator=principal_operator,
            official_owner=official_owner,
            saas_owner=saas_owner,
            bindings=bindings,
            schema_usage_roles={official_owner, saas_owner, *object_grantees},
        )


def _verify_database_boundary(
    connection: Connection,
    *,
    principal_operator: str,
    official_owner: str,
    saas_owner: str,
    bindings: _ServiceRoleProfile,
) -> None:
    database_owner = connection.execute(
        sa.text(
            "SELECT pg_get_userbyid(database.datdba) FROM pg_database database "
            "WHERE database.datname = current_database()"
        )
    ).scalar_one()
    object_grantees = _owned_object_acl_grantees(
        connection,
        official_owner=official_owner,
        saas_owner=saas_owner,
    )
    _verify_database_acl_projection(
        connection,
        database_owner=str(database_owner),
        principal_operator=principal_operator,
        official_owner=official_owner,
        saas_owner=saas_owner,
        bindings=bindings,
        schema_usage_roles={official_owner, saas_owner, *object_grantees},
    )


def _official_table_names() -> tuple[str, ...]:
    names: set[str] = {"alembic_version"}
    for metadata in (OmnigentBase.metadata, ConversationBase.metadata):
        names.update(table.name for table in metadata.tables.values() if table.schema is None)
    return tuple(sorted(names))


def _public_schema_inventory(
    connection: Connection,
    *,
    official_owner: str,
    saas_owner: str,
) -> list[list[str]]:
    """Return a stable, owner-normalized inventory of every public-schema object."""

    principal_rows = connection.execute(
        sa.text(
            "SELECT role.rolname, role.oid FROM pg_roles role "
            "WHERE role.rolname = ANY(:owners) OR role.oid = 10 ORDER BY role.oid"
        ),
        {"owners": [official_owner, saas_owner]},
    ).all()
    principal_oids = {str(name): int(oid) for name, oid in principal_rows}
    bootstrap_names = [str(name) for name, oid in principal_rows if int(oid) == 10]
    if (
        len(principal_rows) != 3
        or len(bootstrap_names) != 1
        or set(principal_oids) != {official_owner, saas_owner, bootstrap_names[0]}
        or principal_oids.get(official_owner) in {None, 10}
        or principal_oids.get(saas_owner) in {None, 10, principal_oids.get(official_owner)}
        or not any(int(oid) == 10 for _name, oid in principal_rows)
    ):
        raise PostgreSqlMigrationError("public_schema_owner_anchor_drifted", "verification")
    owner_classes = {
        10: "bootstrap",
        principal_oids[official_owner]: "official_owner",
        principal_oids[saas_owner]: "saas_owner",
    }

    schema_owner = connection.execute(
        sa.text(
            "SELECT owner.rolname FROM pg_namespace namespace JOIN pg_roles owner "
            "ON owner.oid = namespace.nspowner WHERE namespace.nspname = 'public'"
        )
    ).scalar_one_or_none()
    if schema_owner != "pg_database_owner":
        raise PostgreSqlMigrationError("public_schema_owner_anchor_drifted", "verification")

    inventory: list[list[str]] = [["namespace", "public", "database_owner"]]

    def add_owned(statement: str) -> None:
        for category, identity, owner_oid in connection.execute(sa.text(statement)).all():
            owner_class = owner_classes.get(int(owner_oid))
            if owner_class is None:
                raise PostgreSqlMigrationError(
                    "public_schema_foreign_owner_drifted", "verification"
                )
            inventory.append([str(category), str(identity), owner_class])

    add_owned(
        "SELECT 'relation', relation.relkind::text || ':' || relation.relname, "
        "relation.relowner FROM pg_class relation JOIN pg_namespace namespace "
        "ON namespace.oid = relation.relnamespace WHERE namespace.nspname = 'public'"
    )
    add_owned(
        "SELECT 'routine', routine.prokind::text || ':' || routine.proname || '(' || "
        "pg_get_function_identity_arguments(routine.oid) || ')', routine.proowner "
        "FROM pg_proc routine JOIN pg_namespace namespace "
        "ON namespace.oid = routine.pronamespace WHERE namespace.nspname = 'public'"
    )
    add_owned(
        "SELECT 'type', type.typtype::text || ':' || type.typname, type.typowner "
        "FROM pg_type type JOIN pg_namespace namespace ON namespace.oid = type.typnamespace "
        "WHERE namespace.nspname = 'public'"
    )
    add_owned(
        "SELECT 'operator', operator.oprname || '(' || "
        "operator.oprleft::regtype::text || ',' || operator.oprright::regtype::text || ')', "
        "operator.oprowner FROM pg_operator operator JOIN pg_namespace namespace "
        "ON namespace.oid = operator.oprnamespace WHERE namespace.nspname = 'public'"
    )
    add_owned(
        "SELECT 'opclass', access.amname || ':' || opclass.opcname || '(' || "
        "opclass.opcintype::regtype::text || ')', opclass.opcowner FROM pg_opclass opclass "
        "JOIN pg_namespace namespace ON namespace.oid = opclass.opcnamespace "
        "JOIN pg_am access ON access.oid = opclass.opcmethod "
        "WHERE namespace.nspname = 'public'"
    )
    add_owned(
        "SELECT 'opfamily', access.amname || ':' || family.opfname, family.opfowner "
        "FROM pg_opfamily family JOIN pg_namespace namespace "
        "ON namespace.oid = family.opfnamespace JOIN pg_am access "
        "ON access.oid = family.opfmethod WHERE namespace.nspname = 'public'"
    )
    add_owned(
        "SELECT 'collation', object.collname || ':' || object.collprovider::text || ':' || "
        "object.collencoding::text, object.collowner FROM pg_collation object "
        "JOIN pg_namespace namespace ON namespace.oid = object.collnamespace "
        "WHERE namespace.nspname = 'public'"
    )
    add_owned(
        "SELECT 'conversion', object.conname || '(' || object.conforencoding::text || "
        "',' || object.contoencoding::text || ')', object.conowner "
        "FROM pg_conversion object JOIN pg_namespace namespace "
        "ON namespace.oid = object.connamespace WHERE namespace.nspname = 'public'"
    )
    add_owned(
        "SELECT 'statistics', statistics.stxname, statistics.stxowner "
        "FROM pg_statistic_ext statistics JOIN pg_namespace namespace "
        "ON namespace.oid = statistics.stxnamespace WHERE namespace.nspname = 'public'"
    )
    add_owned(
        "SELECT 'ts_config', config.cfgname, config.cfgowner FROM pg_ts_config config "
        "JOIN pg_namespace namespace ON namespace.oid = config.cfgnamespace "
        "WHERE namespace.nspname = 'public' UNION ALL "
        "SELECT 'ts_dictionary', dictionary.dictname, dictionary.dictowner "
        "FROM pg_ts_dict dictionary JOIN pg_namespace namespace "
        "ON namespace.oid = dictionary.dictnamespace WHERE namespace.nspname = 'public'"
    )

    # Constraints, triggers, policies, and rewrite rules do not carry their own
    # owner.  Bind each identity to its owning relation/type and, for triggers,
    # also to the exact trigger-function owner class.
    add_owned(
        "SELECT 'constraint', object.contype::text || ':' || object.conname || ':' || "
        "CASE WHEN object.conrelid <> 0 THEN object.conrelid::regclass::text "
        "ELSE object.contypid::regtype::text END, "
        "COALESCE(relation.relowner, type.typowner) FROM pg_constraint object "
        "LEFT JOIN pg_class relation ON relation.oid = object.conrelid "
        "LEFT JOIN pg_type type ON type.oid = object.contypid "
        "JOIN pg_namespace namespace ON namespace.oid = object.connamespace "
        "WHERE namespace.nspname = 'public'"
    )
    trigger_rows = connection.execute(
        sa.text(
            "SELECT relation.relname, trigger.tgname, routine.proname, "
            "pg_get_function_identity_arguments(routine.oid), relation.relowner, "
            "routine.proowner FROM pg_trigger trigger JOIN pg_class relation "
            "ON relation.oid = trigger.tgrelid JOIN pg_namespace namespace "
            "ON namespace.oid = relation.relnamespace JOIN pg_proc routine "
            "ON routine.oid = trigger.tgfoid WHERE namespace.nspname = 'public' "
            "AND NOT trigger.tgisinternal"
        )
    ).all()
    for table, trigger, routine, arguments, relation_owner, routine_owner in trigger_rows:
        relation_class = owner_classes.get(int(relation_owner))
        routine_class = owner_classes.get(int(routine_owner))
        if relation_class is None or routine_class is None:
            raise PostgreSqlMigrationError("public_schema_foreign_owner_drifted", "verification")
        inventory.append(
            [
                "trigger",
                f"{table}:{trigger}:{routine}({arguments}):{routine_class}",
                relation_class,
            ]
        )
    add_owned(
        "SELECT 'policy', relation.relname || ':' || policy.polname, relation.relowner "
        "FROM pg_policy policy JOIN pg_class relation ON relation.oid = policy.polrelid "
        "JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace "
        "WHERE namespace.nspname = 'public'"
    )
    add_owned(
        "SELECT 'rewrite', relation.relname || ':' || rewrite.rulename, relation.relowner "
        "FROM pg_rewrite rewrite JOIN pg_class relation ON relation.oid = rewrite.ev_class "
        "JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace "
        "WHERE namespace.nspname = 'public'"
    )
    inventory.append(
        [
            "extension",
            f"pg_trgm:{_PG_TRGM_VERSION}:public",
            "official_owner",
        ]
    )
    inventory.sort()
    return inventory


def _verify_public_schema_inventory(
    connection: Connection,
    *,
    official_owner: str,
    saas_owner: str,
) -> str:
    inventory = _public_schema_inventory(
        connection,
        official_owner=official_owner,
        saas_owner=saas_owner,
    )
    server_major = (
        int(
            connection.execute(
                sa.text("SELECT current_setting('server_version_num')::integer")
            ).scalar_one()
        )
        // 10000
    )
    key = (server_major, _expected_head("official"), _expected_head("saas"))
    return _verify_public_schema_inventory_digest(inventory, key=key)


def _verify_public_schema_inventory_digest(
    inventory: list[list[str]],
    *,
    key: tuple[int, str, str],
) -> str:
    """Validate a catalog against the source-pinned clean-replay digest."""

    expected_digest = _PUBLIC_SCHEMA_INVENTORY_SHA256.get(key)
    digest = hashlib.sha256(
        json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    accepted_digests = {
        item
        for item in (
            expected_digest,
            _PREVIEW_AUTHORITY_PUBLIC_SCHEMA_INVENTORY_SHA256.get(key),
        )
        if item is not None
    }
    if digest not in accepted_digests:
        raise PostgreSqlMigrationError("public_schema_inventory_drifted", "verification")
    return digest


def _source_catalog_role_aliases(
    *,
    principal_operator: str,
    database_owner: str,
    official_owner: str,
    saas_owner: str,
    bootstrap_name: str,
    bindings: _ServiceRoleProfile,
) -> dict[str, str]:
    """Map deployment-chosen login names to stable source-catalog classes."""

    aliases = {
        principal_operator: "authority:principal_operator",
        database_owner: "authority:database_owner",
        official_owner: "authority:official_owner",
        saas_owner: "authority:saas_owner",
        bootstrap_name: "authority:bootstrap",
    }
    aliases.update(
        {binding.login: f"service_login:{binding.service}" for binding in bindings.bindings}
    )
    if len(aliases) != 5 + len(bindings.bindings):
        raise PostgreSqlMigrationError("source_catalog_role_alias_drifted", "verification")
    return aliases


def _normalize_source_catalog(value: object, *, role_aliases: Mapping[str, str]) -> object:
    """Replace only exact role-name values before hashing a clean catalog."""

    if isinstance(value, str):
        return role_aliases.get(value, value)
    if isinstance(value, Mapping):
        return {
            str(key): _normalize_source_catalog(item, role_aliases=role_aliases)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_normalize_source_catalog(item, role_aliases=role_aliases) for item in value]
    return value


def _sort_normalized_source_catalog_rows(value: object) -> object:
    """Sort catalog row collections after deployment-specific role aliasing.

    PostgreSQL queries order rows by their concrete role names.  Those names
    are replaced by stable aliases above, so the original database order can
    no longer be part of the source digest.  Only lists whose elements are all
    rows are sorted; column order inside each row remains authoritative.
    """

    if isinstance(value, Mapping):
        return {
            str(key): _sort_normalized_source_catalog_rows(item) for key, item in value.items()
        }
    if isinstance(value, list):
        items = [_sort_normalized_source_catalog_rows(item) for item in value]
        if items and all(isinstance(item, list) for item in items):
            items.sort(key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
        return items
    return value


def _verify_source_security_catalog_digest(
    catalog: Mapping[str, object],
    *,
    key: tuple[int, str, str],
    role_aliases: Mapping[str, str],
    bindings: _ServiceRoleProfile | None = None,
) -> str:
    """Reject ACL/policy/role drift against a clean-replay source anchor."""

    normalized = _normalize_source_catalog(catalog, role_aliases=role_aliases)
    normalized = _source_catalog_without_dormant_projection_role(normalized, saas_head=key[2])
    if key[2] not in _LEGACY_ORDERED_SOURCE_SECURITY_HEADS:
        normalized = _sort_normalized_source_catalog_rows(normalized)
    digest = hashlib.sha256(
        json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    accepted_digests = {_source_security_catalog_baselines(bindings).get(key)}
    if bindings is not None:
        observed = {binding.service: binding.base_role for binding in bindings.bindings}
        platform_admin = {
            **dict(EXPECTED_PRODUCTION_SERVICE_ROLES),
            **dict(EXPECTED_PLATFORM_MODEL_SERVICE_ROLES),
            **dict(EXPECTED_PLATFORM_ADMIN_SERVICE_ROLES),
        }
        if observed == platform_admin:
            accepted_digests.add(
                _PREVIEW_AUTHORITY_PLATFORM_ADMIN_SOURCE_SECURITY_CATALOG_SHA256.get(key)
            )
        if observed == {**platform_admin, **dict(EXPECTED_MODEL_PROJECTION_SERVICE_ROLES)}:
            accepted_digests.add(
                _PREVIEW_AUTHORITY_MODEL_PROJECTION_SOURCE_SECURITY_CATALOG_SHA256.get(key)
            )
    if digest not in accepted_digests:
        raise PostgreSqlMigrationError("source_security_catalog_drifted", "verification")
    return digest


def _source_catalog_without_dormant_projection_role(catalog: object, *, saas_head: str) -> object:
    """Preserve old anchors only for a newly staged role with no business authority."""

    if saas_head not in {
        "p0s000000011",
        "p0s000000012",
        "p0s000000013",
        "p0s000000014",
        "p0s000000015",
        "lm1a00000001",
    } or not isinstance(catalog, dict):
        return catalog
    security = catalog.get("control_plane_security")
    if not isinstance(security, dict):
        return catalog
    role = "saas_model_projection"
    roles = security.get("roles")
    if not isinstance(roles, list) or not any(
        isinstance(row, list) and role in row for row in roles
    ):
        return catalog
    expected_role = [role, False, False, False, False, False, False, True, -1, "null"]
    management = [role, "authority:principal_operator", "authority:bootstrap", True, False, False]
    usage = [role, "pg_database_owner", "USAGE", False]
    admitted = {"roles": expected_role, "memberships": management, "schema_acls": usage}
    projected = dict(security)
    for key, expected in admitted.items():
        rows = security.get(key)
        if not isinstance(rows, list):
            raise PostgreSqlMigrationError("source_security_catalog_drifted", "verification")
        matching = [row for row in rows if isinstance(row, list) and role in row]
        if matching != [expected] and not (key == "schema_acls" and matching == []):
            raise PostgreSqlMigrationError("source_security_catalog_drifted", "verification")
        projected[key] = [row for row in rows if row not in matching]
    result = {**catalog, "control_plane_security": projected}

    def references_role(value: object) -> bool:
        if isinstance(value, str):
            return (
                re.search(r"(?<![A-Za-z0-9_])saas_model_projection(?![A-Za-z0-9_])", value)
                is not None
            )
        if isinstance(value, dict):
            return any(
                references_role(key) or references_role(item) for key, item in value.items()
            )
        if isinstance(value, (list, tuple)):
            return any(references_role(item) for item in value)
        return False

    if references_role(result):
        raise PostgreSqlMigrationError("source_security_catalog_drifted", "verification")
    return result


_PREVIEW_OWNER_LEASE_DEFINER_SHA256 = {
    "saas_preview_owner_heartbeat_gateway_v1(text,text)": (
        "860cb95916d06a36922b9c2d2f71904fc589c15a393705d12199abc27e4820ac"
    ),
    "saas_preview_owner_release_gateway_v1(text,text)": (
        "2a3d3e19554821e1f259bb82da3dab23b3a0e93acae64a66c9ceef54750ace89"
    ),
}


def _preview_owner_lease_definers_are_safe(
    function_rows: Iterable[Sequence[object]],
    acl_rows: Iterable[Sequence[object]],
    *,
    bootstrap_name: str,
) -> bool:
    """Admit only the two digest-pinned bootstrap RLS bypass functions."""

    functions = list(function_rows)
    if len(functions) != len(_PREVIEW_OWNER_LEASE_DEFINER_SHA256):
        return False
    identities: set[str] = set()
    signatures: set[str] = set()
    for signature, identity, owner, kind, security_definer, config, definition in functions:
        signature = str(signature)
        if (
            _PREVIEW_OWNER_LEASE_DEFINER_SHA256.get(signature)
            != hashlib.sha256(str(definition).encode()).hexdigest()
            or str(owner) != bootstrap_name
            or str(kind) != "f"
            or not bool(security_definer)
            or not isinstance(config, (list, tuple))
            or list(config) != ["search_path=pg_catalog, pg_temp"]
        ):
            return False
        signatures.add(signature)
        identities.add(f"routine:{identity}")
    expected_acl = {
        (signature, grantee, bootstrap_name, "EXECUTE", False)
        for signature in signatures
        for grantee in (bootstrap_name, "saas_preview_owner")
    }
    observed_acl = {
        (str(signature), str(grantee), str(grantor), str(privilege), bool(grantable))
        for signature, grantee, grantor, privilege, grantable in acl_rows
    }
    return observed_acl == expected_acl and len(identities) == len(signatures)


def _verify_preview_owner_lease_definers(
    connection: Connection,
    *,
    bootstrap_name: str,
) -> frozenset[str]:
    names = [signature.partition("(")[0] for signature in _PREVIEW_OWNER_LEASE_DEFINER_SHA256]
    function_rows = connection.execute(
        sa.text(
            "SELECT routine.oid::regprocedure::text, routine.proname || '(' || "
            "pg_get_function_identity_arguments(routine.oid) || ')', "
            "pg_get_userbyid(routine.proowner), routine.prokind, routine.prosecdef, "
            "routine.proconfig, pg_get_functiondef(routine.oid) FROM pg_proc routine "
            "JOIN pg_namespace namespace ON namespace.oid = routine.pronamespace "
            "WHERE namespace.nspname = 'public' AND routine.proname = ANY(:names) "
            "ORDER BY routine.proname"
        ),
        {"names": names},
    ).all()
    acl_rows = connection.execute(
        sa.text(
            "SELECT routine.oid::regprocedure::text, "
            "CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantee) END, "
            "CASE WHEN acl.grantor = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantor) END, "
            "acl.privilege_type, acl.is_grantable FROM pg_proc routine "
            "JOIN pg_namespace namespace ON namespace.oid = routine.pronamespace "
            "CROSS JOIN LATERAL aclexplode(routine.proacl) acl "
            "WHERE namespace.nspname = 'public' AND routine.proname = ANY(:names) "
            "ORDER BY routine.proname, 2, 3, 4, 5"
        ),
        {"names": names},
    ).all()
    if not _preview_owner_lease_definers_are_safe(
        function_rows,
        acl_rows,
        bootstrap_name=bootstrap_name,
    ):
        raise PostgreSqlMigrationError("saas_object_ownership_drifted", "verification")
    return frozenset(f"routine:{row[1]}" for row in function_rows)


def _verify_object_ownership(
    official_connection: Connection,
    saas_connection: Connection,
    *,
    official_owner: str,
    saas_owner: str,
) -> tuple[tuple[str, str], ...]:
    official_names = _official_table_names()
    official_rows = official_connection.execute(
        sa.text(
            "SELECT relation.relname, owner.rolname FROM pg_class AS relation "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "JOIN pg_roles AS owner ON owner.oid = relation.relowner "
            "WHERE namespace.nspname = 'public' "
            "AND relation.relname = ANY(:table_names) ORDER BY relation.relname"
        ),
        {"table_names": list(official_names)},
    ).all()
    if len(official_rows) != len(official_names) or any(
        owner != official_owner for _table, owner in official_rows
    ):
        raise PostgreSqlMigrationError("official_object_ownership_drifted", "verification")
    saas_rows = saas_connection.execute(
        sa.text(
            "SELECT 'relation:' || relation.relname, owner.rolname "
            "FROM pg_class AS relation "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "JOIN pg_roles AS owner ON owner.oid = relation.relowner "
            "WHERE namespace.nspname = 'public' "
            "AND left(relation.relname, 5) = 'saas_' "
            "AND relation.relkind IN ('r', 'p', 'S', 'v', 'm', 'f') UNION ALL "
            "SELECT 'routine:' || routine.proname || '(' || "
            "pg_get_function_identity_arguments(routine.oid) || ')', owner.rolname "
            "FROM pg_proc routine JOIN pg_namespace namespace "
            "ON namespace.oid = routine.pronamespace JOIN pg_roles owner "
            "ON owner.oid = routine.proowner WHERE namespace.nspname = 'public' AND ("
            "left(routine.proname, 5) = 'saas_' OR routine.proname IN ("
            "'approval_source_work_binding_is_valid', "
            "'approval_notification_binding_is_valid') OR EXISTS ("
            "SELECT 1 FROM pg_trigger trigger JOIN pg_class relation "
            "ON relation.oid = trigger.tgrelid JOIN pg_namespace relation_namespace "
            "ON relation_namespace.oid = relation.relnamespace "
            "WHERE trigger.tgfoid = routine.oid AND NOT trigger.tgisinternal "
            "AND relation_namespace.nspname = 'public' "
            "AND left(relation.relname, 5) = 'saas_')) UNION ALL "
            "SELECT 'type:' || type.typname, owner.rolname FROM pg_type type "
            "JOIN pg_namespace namespace ON namespace.oid = type.typnamespace "
            "JOIN pg_roles owner ON owner.oid = type.typowner "
            "WHERE namespace.nspname = 'public' AND (left(type.typname, 5) = 'saas_' "
            "OR EXISTS (SELECT 1 FROM pg_class relation WHERE relation.reltype = type.oid "
            "AND left(relation.relname, 5) = 'saas_')) ORDER BY 1"
        )
    ).all()
    foreign_saas_owners = {
        (str(table), str(owner)) for table, owner in saas_rows if owner != saas_owner
    }
    preview_lease_definers: frozenset[str] = frozenset()
    bootstrap_name = ""
    if foreign_saas_owners:
        bootstrap_name = str(
            saas_connection.execute(
                sa.text("SELECT rolname FROM pg_roles WHERE oid = 10")
            ).scalar_one()
        )
        preview_lease_definers = _verify_preview_owner_lease_definers(
            saas_connection,
            bootstrap_name=bootstrap_name,
        )
    if not saas_rows or any(
        table not in preview_lease_definers or owner != bootstrap_name
        for table, owner in foreign_saas_owners
    ):
        raise PostgreSqlMigrationError("saas_object_ownership_drifted", "verification")
    _verify_public_schema_inventory(
        official_connection,
        official_owner=official_owner,
        saas_owner=saas_owner,
    )
    return tuple((str(table), str(owner)) for table, owner in (*official_rows, *saas_rows))


def _verify_runtime_acl(connection: Connection) -> tuple[tuple[str, str, bool], ...]:
    contracts = load_runtime_rls_contract()
    official_names = _official_table_names()
    expected = {
        (contract.table_name, privilege, False)
        for contract in contracts
        for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE")
    }
    expected.add(("alembic_version", "SELECT", False))
    relation_acls = {
        (str(table), str(privilege), bool(grantable))
        for table, privilege, grantable in connection.execute(
            sa.text(
                "SELECT relation.relname, acl.privilege_type, acl.is_grantable "
                "FROM pg_class AS relation "
                "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                "JOIN pg_roles AS role ON role.rolname = :role "
                "CROSS JOIN LATERAL aclexplode(relation.relacl) AS acl "
                "WHERE namespace.nspname = 'public' AND acl.grantee = role.oid "
                "ORDER BY relation.relname, acl.privilege_type"
            ),
            {"role": _RUNTIME_ROLE},
        ).all()
    }
    schema_acls = connection.execute(
        sa.text(
            "SELECT acl.privilege_type, acl.is_grantable "
            "FROM pg_namespace AS namespace "
            "JOIN pg_roles AS role ON role.rolname = :role "
            "CROSS JOIN LATERAL aclexplode(namespace.nspacl) AS acl "
            "WHERE namespace.nspname = 'public' AND acl.grantee = role.oid"
        ),
        {"role": _RUNTIME_ROLE},
    ).all()
    other_authority = connection.execute(
        sa.text(
            "WITH runtime AS (SELECT oid FROM pg_roles WHERE rolname = :role), "
            "unexpected AS ("
            "SELECT 1 FROM pg_attribute AS attribute "
            "CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl "
            "JOIN runtime ON acl.grantee = runtime.oid "
            "WHERE attribute.attnum > 0 AND NOT attribute.attisdropped UNION ALL "
            "SELECT 1 FROM pg_proc AS routine "
            "CROSS JOIN LATERAL aclexplode(routine.proacl) AS acl "
            "JOIN runtime ON acl.grantee = runtime.oid UNION ALL "
            "SELECT 1 FROM pg_type AS type "
            "CROSS JOIN LATERAL aclexplode(type.typacl) AS acl "
            "JOIN runtime ON acl.grantee = runtime.oid UNION ALL "
            "SELECT 1 FROM pg_default_acl AS defaults "
            "CROSS JOIN LATERAL aclexplode(defaults.defaclacl) AS acl "
            "JOIN runtime ON acl.grantee = runtime.oid) "
            "SELECT count(*) FROM unexpected"
        ),
        {"role": _RUNTIME_ROLE},
    ).scalar_one()
    unexpected_official_authority = connection.execute(
        sa.text(
            "WITH runtime AS (SELECT oid FROM pg_roles WHERE rolname = :role), "
            "official_owner AS ("
            "SELECT relation.relowner AS oid FROM pg_class AS relation "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "WHERE namespace.nspname = 'public' AND relation.relname = :anchor), "
            "unexpected AS ("
            "SELECT 1 FROM pg_class AS relation "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "CROSS JOIN LATERAL aclexplode(relation.relacl) AS acl "
            "CROSS JOIN runtime CROSS JOIN official_owner "
            "WHERE namespace.nspname = 'public' "
            "AND relation.relname = ANY(:official_names) "
            "AND acl.grantee <> relation.relowner AND NOT ("
            "acl.grantee = runtime.oid AND acl.grantor = official_owner.oid "
            "AND NOT acl.is_grantable AND (("
            "relation.relname = ANY(:runtime_names) "
            "AND acl.privilege_type IN ('SELECT','INSERT','UPDATE','DELETE')) OR ("
            "relation.relname = :schema_revision_table "
            "AND acl.privilege_type = 'SELECT'))) UNION ALL "
            "SELECT 1 FROM pg_attribute AS attribute "
            "JOIN pg_class AS relation ON relation.oid = attribute.attrelid "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl "
            "WHERE namespace.nspname = 'public' "
            "AND relation.relname = ANY(:official_names) "
            "AND attribute.attnum > 0 AND NOT attribute.attisdropped "
            "AND acl.grantee <> relation.relowner UNION ALL "
            "SELECT 1 FROM pg_class AS relation "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "CROSS JOIN official_owner WHERE namespace.nspname = 'public' "
            "AND relation.relowner = official_owner.oid "
            "AND relation.relkind IN ('r','p','S','v','m','f') "
            "AND relation.relname <> ALL(:official_names) UNION ALL "
            "SELECT 1 FROM pg_proc AS routine "
            "JOIN pg_namespace AS namespace ON namespace.oid = routine.pronamespace "
            "CROSS JOIN official_owner WHERE namespace.nspname = 'public' "
            "AND routine.proowner = official_owner.oid UNION ALL "
            "SELECT 1 FROM pg_type AS type "
            "JOIN pg_namespace AS namespace ON namespace.oid = type.typnamespace "
            "CROSS JOIN LATERAL aclexplode(type.typacl) AS acl "
            "CROSS JOIN official_owner WHERE namespace.nspname = 'public' "
            "AND type.typowner = official_owner.oid "
            "AND acl.grantee <> type.typowner UNION ALL "
            "SELECT 1 FROM pg_default_acl AS defaults CROSS JOIN official_owner "
            "CROSS JOIN LATERAL aclexplode(defaults.defaclacl) AS acl "
            "WHERE defaults.defaclrole = official_owner.oid AND ("
            "defaults.defaclnamespace <> 0 OR defaults.defaclobjtype NOT IN ('f','T') "
            "OR acl.grantee <> official_owner.oid OR acl.grantor <> official_owner.oid "
            "OR acl.is_grantable OR (defaults.defaclobjtype = 'f' "
            "AND acl.privilege_type <> 'EXECUTE') OR (defaults.defaclobjtype = 'T' "
            "AND acl.privilege_type <> 'USAGE')) UNION ALL "
            "SELECT 1 FROM official_owner WHERE (SELECT count(*) FROM pg_default_acl defaults "
            "CROSS JOIN LATERAL aclexplode(defaults.defaclacl) acl "
            "WHERE defaults.defaclrole = official_owner.oid "
            "AND defaults.defaclnamespace = 0 AND ((defaults.defaclobjtype = 'f' "
            "AND acl.grantee = official_owner.oid AND acl.grantor = official_owner.oid "
            "AND acl.privilege_type = 'EXECUTE' AND NOT acl.is_grantable) "
            "OR (defaults.defaclobjtype = 'T' AND acl.grantee = official_owner.oid "
            "AND acl.grantor = official_owner.oid AND acl.privilege_type = 'USAGE' "
            "AND NOT acl.is_grantable))) <> 2) "
            "SELECT count(*) FROM unexpected"
        ),
        {
            "role": _RUNTIME_ROLE,
            "anchor": official_names[0],
            "official_names": list(official_names),
            "runtime_names": [contract.table_name for contract in contracts],
            "schema_revision_table": "alembic_version",
        },
    ).scalar_one()
    if (
        relation_acls != expected
        or schema_acls != [("USAGE", False)]
        or other_authority
        or unexpected_official_authority
    ):
        raise PostgreSqlMigrationError("runtime_acl_projection_drifted", "verification")
    return tuple(sorted(relation_acls))


def _pg_trgm_security_catalog(
    connection: Connection,
    *,
    official_owner: str,
    expected_indexes: Mapping[str, tuple[str, str]] = _PG_TRGM_INDEXES,
) -> dict[str, object]:
    server_major = (
        int(
            connection.execute(
                sa.text("SELECT current_setting('server_version_num')::integer")
            ).scalar_one()
        )
        // 10000
    )
    expected_members = _PG_TRGM_MEMBER_IDENTITIES_BY_MAJOR.get(server_major)
    if expected_members is None:
        raise PostgreSqlMigrationError("pg_trgm_member_contract_drifted", "verification")
    extension = connection.execute(
        sa.text(
            "SELECT extension.extversion, namespace.nspname, owner.rolname "
            "FROM pg_extension extension JOIN pg_namespace namespace "
            "ON namespace.oid = extension.extnamespace JOIN pg_roles owner "
            "ON owner.oid = extension.extowner WHERE extension.extname = 'pg_trgm'"
        )
    ).one_or_none()
    if extension is None or tuple(extension) != (_PG_TRGM_VERSION, "public", official_owner):
        raise PostgreSqlMigrationError("pg_trgm_extension_drifted", "verification")

    member_rows = connection.execute(
        sa.text(
            "SELECT dependency.classid::regclass::text, "
            "pg_describe_object(dependency.classid, dependency.objid, "
            "dependency.objsubid), CASE dependency.classid "
            "WHEN 'pg_proc'::regclass THEN (SELECT routine.proowner FROM pg_proc routine "
            "WHERE routine.oid = dependency.objid) "
            "WHEN 'pg_type'::regclass THEN (SELECT type.typowner FROM pg_type type "
            "WHERE type.oid = dependency.objid) "
            "WHEN 'pg_operator'::regclass THEN (SELECT operator.oprowner "
            "FROM pg_operator operator "
            "WHERE operator.oid = dependency.objid) "
            "WHEN 'pg_opclass'::regclass THEN (SELECT opclass.opcowner FROM pg_opclass opclass "
            "WHERE opclass.oid = dependency.objid) "
            "WHEN 'pg_opfamily'::regclass THEN (SELECT family.opfowner FROM pg_opfamily family "
            "WHERE family.oid = dependency.objid) END "
            "FROM pg_depend dependency JOIN pg_extension extension "
            "ON extension.oid = dependency.refobjid WHERE dependency.refclassid = "
            "'pg_extension'::regclass AND dependency.deptype = 'e' "
            "AND extension.extname = 'pg_trgm' ORDER BY 1, 2"
        )
    ).all()
    members = _canonical_pg_trgm_members(member_rows)
    if tuple((row[0], row[1]) for row in members) != expected_members or any(
        row[2] != 10 for row in members
    ):
        raise PostgreSqlMigrationError("pg_trgm_member_contract_drifted", "verification")

    functions = [
        [
            str(name),
            str(arguments),
            str(result),
            int(owner_oid),
            str(language),
            str(binary),
            str(source),
            str(volatility),
            bool(strict),
            bool(security_definer),
            bool(leakproof),
            str(parallel),
            list(config) if config is not None else None,
            str(kind),
            bool(returns_set),
            float(cost),
            float(rows),
            int(variadic_oid),
        ]
        for (
            name,
            arguments,
            result,
            owner_oid,
            language,
            binary,
            source,
            volatility,
            strict,
            security_definer,
            leakproof,
            parallel,
            config,
            kind,
            returns_set,
            cost,
            rows,
            variadic_oid,
        ) in connection.execute(
            sa.text(
                "SELECT routine.proname, pg_get_function_identity_arguments(routine.oid), "
                "pg_get_function_result(routine.oid), routine.proowner, language.lanname, "
                "routine.probin, routine.prosrc, routine.provolatile, routine.proisstrict, "
                "routine.prosecdef, routine.proleakproof, routine.proparallel, routine.proconfig, "
                "routine.prokind, routine.proretset, routine.procost, routine.prorows, "
                "routine.provariadic "
                "FROM pg_depend dependency JOIN pg_extension extension "
                "ON extension.oid = dependency.refobjid JOIN pg_proc routine "
                "ON dependency.classid = 'pg_proc'::regclass "
                "AND routine.oid = dependency.objid JOIN pg_language language "
                "ON language.oid = routine.prolang WHERE extension.extname = 'pg_trgm' "
                "AND dependency.deptype = 'e' ORDER BY 1, 2"
            )
        ).all()
    ]
    observed_function_contracts = {
        (row[0], row[1]): (row[2], row[7], row[8], row[11]) for row in functions
    }
    if observed_function_contracts != _PG_TRGM_FUNCTION_CONTRACTS or any(
        row[3] != 10
        or row[4] != "c"
        or row[5] != "$libdir/pg_trgm"
        or row[6] != row[0]
        or row[9]
        or row[10]
        or row[12] is not None
        or row[13] != "f"
        or row[14]
        or row[15:18] != [1.0, 0.0, 0]
        for row in functions
    ):
        raise PostgreSqlMigrationError("pg_trgm_member_contract_drifted", "verification")

    function_acls = [
        list(row)
        for row in connection.execute(
            sa.text(
                "SELECT routine.proname, pg_get_function_identity_arguments(routine.oid), "
                "acl.grantee, acl.grantor, acl.privilege_type, acl.is_grantable "
                "FROM pg_depend dependency JOIN pg_extension extension "
                "ON extension.oid = dependency.refobjid JOIN pg_proc routine "
                "ON dependency.classid = 'pg_proc'::regclass AND routine.oid = dependency.objid "
                "CROSS JOIN LATERAL aclexplode(COALESCE(routine.proacl, "
                "acldefault('f', routine.proowner))) acl WHERE extension.extname = 'pg_trgm' "
                "AND dependency.deptype = 'e' ORDER BY 1, 2, 3, 4, 5, 6"
            )
        ).all()
    ]
    expected_function_acls = {
        (name, arguments, grantee, 10, "EXECUTE", False)
        for name, arguments in _PG_TRGM_FUNCTION_CONTRACTS
        for grantee in (0, 10)
    }
    if {tuple(row) for row in function_acls} != expected_function_acls:
        raise PostgreSqlMigrationError("pg_trgm_function_acl_drifted", "verification")

    types = [
        list(row)
        for row in connection.execute(
            sa.text(
                "WITH extension_type AS (SELECT type.oid FROM pg_depend dependency "
                "JOIN pg_extension extension ON extension.oid = dependency.refobjid "
                "JOIN pg_type type ON dependency.classid = 'pg_type'::regclass "
                "AND type.oid = dependency.objid WHERE extension.extname = 'pg_trgm' "
                "AND dependency.deptype = 'e') SELECT type.typname, type.typowner, "
                "type.typtype, type.typcategory, type.typispreferred, type.typisdefined, "
                "type.typrelid, type.typelem::regtype::text, type.typarray::regtype::text, "
                "type.typinput::regproc::text, type.typoutput::regproc::text, "
                "type.typreceive::regproc::text, type.typsend::regproc::text, "
                "type.typmodin::regproc::text, type.typmodout::regproc::text, "
                "type.typanalyze::regproc::text, type.typsubscript::regproc::text, "
                "type.typcollation FROM pg_type type WHERE type.oid IN "
                "(SELECT oid FROM extension_type) OR type.typelem IN "
                "(SELECT oid FROM extension_type) ORDER BY type.typname"
            )
        ).all()
    ]
    expected_types = [
        [
            "_gtrgm",
            10,
            "b",
            "A",
            False,
            True,
            0,
            "gtrgm",
            "-",
            "array_in",
            "array_out",
            "array_recv",
            "array_send",
            "-",
            "-",
            "array_typanalyze",
            "array_subscript_handler",
            0,
        ],
        [
            "gtrgm",
            10,
            "b",
            "U",
            False,
            True,
            0,
            "-",
            "gtrgm[]",
            "gtrgm_in",
            "gtrgm_out",
            "-",
            "-",
            "-",
            "-",
            "-",
            "-",
            0,
        ],
    ]
    if types != expected_types:
        raise PostgreSqlMigrationError("pg_trgm_type_contract_drifted", "verification")
    type_acls = [
        list(row)
        for row in connection.execute(
            sa.text(
                "WITH extension_type AS (SELECT type.oid FROM pg_depend dependency "
                "JOIN pg_extension extension ON extension.oid = dependency.refobjid "
                "JOIN pg_type type ON dependency.classid = 'pg_type'::regclass "
                "AND type.oid = dependency.objid WHERE extension.extname = 'pg_trgm' "
                "AND dependency.deptype = 'e'), extension_and_array AS ("
                "SELECT type.* FROM pg_type type WHERE type.oid IN "
                "(SELECT oid FROM extension_type) "
                "OR type.typelem IN (SELECT oid FROM extension_type)) "
                "SELECT type.typname, acl.grantee, acl.grantor, acl.privilege_type, "
                "acl.is_grantable FROM extension_and_array type CROSS JOIN LATERAL "
                "aclexplode(COALESCE(type.typacl, acldefault('T', type.typowner))) acl "
                "ORDER BY 1, 2, 3, 4, 5"
            )
        ).all()
    ]
    expected_type_acls = {
        (name, grantee, 10, "USAGE", False) for name in ("_gtrgm", "gtrgm") for grantee in (0, 10)
    }
    if {tuple(row) for row in type_acls} != expected_type_acls:
        raise PostgreSqlMigrationError("pg_trgm_type_acl_drifted", "verification")

    opclasses = [
        [
            str(name),
            str(method),
            str(family),
            str(input_type),
            str(key_type) if key_type is not None else None,
            bool(is_default),
            int(owner_oid),
        ]
        for name, method, family, input_type, key_type, is_default, owner_oid in (
            connection.execute(
                sa.text(
                    "SELECT opclass.opcname, access.amname, family.opfname, "
                    "format_type(opclass.opcintype, NULL), "
                    "CASE WHEN opclass.opckeytype = 0 THEN NULL "
                    "ELSE format_type(opclass.opckeytype, NULL) END, "
                    "opclass.opcdefault, opclass.opcowner "
                    "FROM pg_depend dependency JOIN pg_extension extension "
                    "ON extension.oid = dependency.refobjid JOIN pg_opclass opclass "
                    "ON dependency.classid = 'pg_opclass'::regclass "
                    "AND opclass.oid = dependency.objid JOIN pg_am access "
                    "ON access.oid = opclass.opcmethod JOIN pg_opfamily family "
                    "ON family.oid = opclass.opcfamily WHERE extension.extname = 'pg_trgm' "
                    "AND dependency.deptype = 'e' ORDER BY 1, 2"
                )
            ).all()
        )
    ]
    if {tuple(row[:6]) for row in opclasses} != _PG_TRGM_OPCLASS_CONTRACTS or any(
        row[6] != 10 for row in opclasses
    ):
        raise PostgreSqlMigrationError("pg_trgm_opclass_drifted", "verification")

    indexes = [
        [
            str(index_namespace),
            str(index_name),
            str(table_namespace),
            str(table_name),
            str(owner),
            str(method),
            str(opclass),
            bool(valid),
            bool(ready),
            bool(live),
            int(attribute_count),
            str(expression) if expression is not None else None,
            str(predicate) if predicate is not None else None,
        ]
        for (
            index_namespace,
            index_name,
            table_namespace,
            table_name,
            owner,
            method,
            opclass,
            valid,
            ready,
            live,
            attribute_count,
            expression,
            predicate,
        ) in connection.execute(
            sa.text(
                "SELECT index_namespace.nspname, index_relation.relname, "
                "table_namespace.nspname, table_relation.relname, "
                "pg_get_userbyid(index_relation.relowner), access.amname, opclass.opcname, "
                "index.indisvalid, index.indisready, index.indislive, index.indnkeyatts, "
                "pg_get_expr(index.indexprs, index.indrelid), "
                "pg_get_expr(index.indpred, index.indrelid) FROM pg_index index "
                "JOIN pg_class index_relation ON index_relation.oid = index.indexrelid "
                "JOIN pg_class table_relation ON table_relation.oid = index.indrelid "
                "JOIN pg_namespace index_namespace "
                "ON index_namespace.oid = index_relation.relnamespace "
                "JOIN pg_namespace table_namespace "
                "ON table_namespace.oid = table_relation.relnamespace "
                "JOIN pg_am access ON access.oid = index_relation.relam "
                "JOIN pg_opclass opclass ON opclass.oid = index.indclass[0] "
                "JOIN pg_depend opclass_dependency ON opclass_dependency.classid = "
                "'pg_opclass'::regclass AND opclass_dependency.objid = opclass.oid "
                "AND opclass_dependency.deptype = 'e' JOIN pg_extension extension "
                "ON extension.oid = opclass_dependency.refobjid "
                "WHERE extension.extname = 'pg_trgm' ORDER BY 1, 2"
            )
        ).all()
    ]
    observed_indexes = {
        row[1]: (row[3], row[11])
        for row in indexes
        if row[0] == "public"
        and row[2] == "public"
        and row[4] == official_owner
        and row[5] == "gin"
        and row[6] == "gin_trgm_ops"
        and row[7:11] == [True, True, True, 1]
        and row[12] is None
    }
    if observed_indexes != expected_indexes or len(indexes) != len(expected_indexes):
        raise PostgreSqlMigrationError("pg_trgm_index_contract_drifted", "verification")
    return {
        "extension": [str(value) for value in extension],
        "members": members,
        "functions": functions,
        "function_acls": function_acls,
        "types": types,
        "type_acls": type_acls,
        "opclasses": opclasses,
        "indexes": indexes,
    }


def _canonical_pg_trgm_members(member_rows: Iterable[Any]) -> list[list[str | int]]:
    """Canonicalize extension members independently of database collation."""

    return sorted(
        [
            [str(class_name), str(description), int(owner_oid)]
            for class_name, description, owner_oid in member_rows
        ],
        key=lambda row: (str(row[0]), str(row[1])),
    )


def _preflight_pg_trgm_extension(connection: Connection, *, official_owner: str) -> None:
    exists = bool(
        connection.execute(
            sa.text("SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm')")
        ).scalar_one()
    )
    if not exists:
        return
    revisions: list[str] = []
    if connection.execute(sa.text("SELECT to_regclass('public.alembic_version')")).scalar_one():
        revisions = list(
            connection.execute(sa.text("SELECT version_num FROM public.alembic_version")).scalars()
        )
    server_major = (
        int(
            connection.execute(
                sa.text("SELECT current_setting('server_version_num')::integer")
            ).scalar_one()
        )
        // 10000
    )
    if len(revisions) != 1:
        raise PostgreSqlMigrationError("pg_trgm_preexisting_before_head", "official_alembic")
    revision = revisions[0]
    if revision == _expected_head("official"):
        expected_indexes = _PG_TRGM_INDEXES
    elif _source_pinned_pg_trgm_predecessor(revision, server_major):
        expected_indexes = _PG_TRGM_PREDECESSOR_INDEXES
    else:
        raise PostgreSqlMigrationError("pg_trgm_preexisting_before_head", "official_alembic")
    _pg_trgm_security_catalog(
        connection,
        official_owner=official_owner,
        expected_indexes=expected_indexes,
    )


def _source_pinned_pg_trgm_predecessor(revision: str, server_major: int) -> bool:
    """Only admit a source-anchored ancestor with the verified extension contract."""

    anchored = any(
        key[0] == server_major and key[1] == revision and key in _SOURCE_SECURITY_CATALOG_SHA256
        for key in _PUBLIC_SCHEMA_INVENTORY_SHA256
    )
    if not anchored:
        return False
    scripts = ScriptDirectory.from_config(_migration_config("official"))
    return any(item.revision == revision for item in scripts.walk_revisions())


def _official_security_catalog(
    connection: Connection,
    *,
    official_owner: str,
) -> dict[str, object]:
    """Return the full official-owner security projection for receipt binding."""

    def rows(statement: str, parameters: Mapping[str, object] | None = None) -> list[list[object]]:
        return [
            [list(value) if isinstance(value, tuple) else value for value in row]
            for row in connection.execute(sa.text(statement), parameters or {}).all()
        ]

    role_name = "CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantee) END"
    grantor_name = "CASE WHEN acl.grantor = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantor) END"
    parameters = {"owner": official_owner}
    return {
        "pg_trgm": _pg_trgm_security_catalog(
            connection,
            official_owner=official_owner,
        ),
        "relations": rows(
            "SELECT relation.relname, relation.relkind, relation.relrowsecurity, "
            "relation.relforcerowsecurity FROM pg_class AS relation "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "JOIN pg_roles AS owner ON owner.oid = relation.relowner "
            "WHERE namespace.nspname = 'public' AND owner.rolname = :owner "
            "ORDER BY relation.relname, relation.relkind",
            parameters,
        ),
        "relation_acls": rows(
            f"SELECT relation.relname, {role_name}, {grantor_name}, "
            "acl.privilege_type, acl.is_grantable FROM pg_class AS relation "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "JOIN pg_roles AS owner ON owner.oid = relation.relowner "
            "CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl, "
            "acldefault(CASE WHEN relation.relkind = 'S' THEN 's'::\"char\" "
            "ELSE 'r'::\"char\" END, relation.relowner))) AS acl "
            "WHERE namespace.nspname = 'public' AND owner.rolname = :owner "
            "AND relation.relkind IN ('r','p','S','v','m','f') "
            "ORDER BY 1, 2, 3, 4, 5",
            parameters,
        ),
        "column_acls": rows(
            f"SELECT relation.relname, attribute.attname, {role_name}, {grantor_name}, "
            "acl.privilege_type, acl.is_grantable FROM pg_attribute AS attribute "
            "JOIN pg_class AS relation ON relation.oid = attribute.attrelid "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "JOIN pg_roles AS owner ON owner.oid = relation.relowner "
            "CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl "
            "WHERE namespace.nspname = 'public' AND owner.rolname = :owner "
            "AND attribute.attnum > 0 AND NOT attribute.attisdropped "
            "ORDER BY 1, 2, 3, 4, 5, 6",
            parameters,
        ),
        "routines": rows(
            f"SELECT routine.proname, pg_get_function_identity_arguments(routine.oid), "
            f"routine.prokind, routine.prosecdef, {role_name}, {grantor_name}, "
            "acl.privilege_type, acl.is_grantable FROM pg_proc AS routine "
            "JOIN pg_namespace AS namespace ON namespace.oid = routine.pronamespace "
            "JOIN pg_roles AS owner ON owner.oid = routine.proowner "
            "CROSS JOIN LATERAL aclexplode(COALESCE(routine.proacl, "
            "acldefault('f', routine.proowner))) AS acl "
            "WHERE namespace.nspname = 'public' AND owner.rolname = :owner "
            "ORDER BY 1, 2, 3, 4, 5, 6, 7, 8",
            parameters,
        ),
        "types": rows(
            f"SELECT type.typname, type.typtype, {role_name}, {grantor_name}, "
            "acl.privilege_type, acl.is_grantable FROM pg_type AS type "
            "JOIN pg_namespace AS namespace ON namespace.oid = type.typnamespace "
            "JOIN pg_roles AS owner ON owner.oid = type.typowner "
            "CROSS JOIN LATERAL aclexplode(COALESCE(type.typacl, "
            "acldefault('T', type.typowner))) AS acl "
            "WHERE namespace.nspname = 'public' AND owner.rolname = :owner "
            "AND type.typelem = 0 "
            "ORDER BY 1, 2, 3, 4, 5, 6",
            parameters,
        ),
        "policies": rows(
            "SELECT relation.relname, policy.polname, policy.polpermissive, "
            "policy.polcmd, ARRAY(SELECT CASE WHEN role_oid = 0 THEN 'PUBLIC' "
            "ELSE pg_get_userbyid(role_oid) END FROM unnest(policy.polroles) AS role_oid "
            "ORDER BY 1), pg_get_expr(policy.polqual, policy.polrelid), "
            "pg_get_expr(policy.polwithcheck, policy.polrelid) "
            "FROM pg_policy AS policy JOIN pg_class AS relation "
            "ON relation.oid = policy.polrelid JOIN pg_namespace AS namespace "
            "ON namespace.oid = relation.relnamespace JOIN pg_roles AS owner "
            "ON owner.oid = relation.relowner WHERE namespace.nspname = 'public' "
            "AND owner.rolname = :owner ORDER BY relation.relname, policy.polname",
            parameters,
        ),
        "triggers": rows(
            "SELECT relation.relname, trigger.tgname, trigger.tgenabled, "
            "pg_get_triggerdef(trigger.oid, true) FROM pg_trigger AS trigger "
            "JOIN pg_class AS relation ON relation.oid = trigger.tgrelid "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "JOIN pg_roles AS owner ON owner.oid = relation.relowner "
            "WHERE namespace.nspname = 'public' AND owner.rolname = :owner "
            "AND NOT trigger.tgisinternal ORDER BY relation.relname, trigger.tgname",
            parameters,
        ),
        "default_acls": rows(
            f"SELECT COALESCE(namespace.nspname, ''), defaults.defaclobjtype, "
            f"{role_name}, {grantor_name}, acl.privilege_type, acl.is_grantable "
            "FROM pg_default_acl AS defaults JOIN pg_roles AS owner "
            "ON owner.oid = defaults.defaclrole LEFT JOIN pg_namespace AS namespace "
            "ON namespace.oid = defaults.defaclnamespace CROSS JOIN LATERAL "
            "aclexplode(defaults.defaclacl) AS acl WHERE owner.rolname = :owner "
            "ORDER BY 1, 2, 3, 4, 5, 6",
            parameters,
        ),
    }


def _control_plane_security_catalog(
    connection: Connection,
    *,
    saas_owner: str,
) -> dict[str, list[list[object]]]:
    """Project security-relevant SaaS catalog state into a stable hash input.

    The role SQL remains the authority that proves the expected projection.
    This read-only snapshot makes every later startup prove that the exact role
    graph, ACL, RLS, policy, trigger, and ownership facts have not drifted since
    the privileged migration receipt was issued.
    """

    def rows(statement: str, parameters: Mapping[str, object] | None = None) -> list[list[object]]:
        return [
            [list(value) if isinstance(value, tuple) else value for value in row]
            for row in connection.execute(sa.text(statement), parameters or {}).all()
        ]

    roles = list(_CAPABILITY_ROLES)
    bootstrap_name = str(
        connection.execute(sa.text("SELECT rolname FROM pg_roles WHERE oid = 10")).scalar_one()
    )
    role_name = "CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantee) END"
    grantor_name = "CASE WHEN acl.grantor = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantor) END"
    parameters = {"owner": saas_owner}
    return {
        "roles": rows(
            "SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
            "rolreplication, rolbypassrls, rolinherit, rolconnlimit, "
            "COALESCE(to_jsonb(rolconfig)::text, 'null') FROM pg_roles "
            "WHERE rolname = ANY(:roles) ORDER BY rolname",
            {"roles": roles},
        ),
        "memberships": _stable_control_plane_memberships(
            rows(
                "SELECT granted.rolname, member.rolname, grantor.rolname, "
                "membership.admin_option, "
                "COALESCE((to_jsonb(membership) ->> 'inherit_option')::boolean, true), "
                "COALESCE((to_jsonb(membership) ->> 'set_option')::boolean, true), "
                "membership.grantor "
                "FROM pg_auth_members AS membership "
                "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
                "JOIN pg_roles AS member ON member.oid = membership.member "
                "JOIN pg_roles AS grantor ON grantor.oid = membership.grantor "
                "WHERE granted.rolname = ANY(:roles) OR member.rolname = ANY(:roles) "
                "ORDER BY granted.rolname, member.rolname, grantor.rolname",
                {"roles": roles},
            ),
            bootstrap_name=bootstrap_name,
        ),
        "database_acls": rows(
            f"SELECT {role_name}, {grantor_name}, acl.privilege_type, acl.is_grantable "
            "FROM pg_database AS database CROSS JOIN LATERAL aclexplode(COALESCE("
            "database.datacl, acldefault('d', database.datdba))) AS acl "
            "WHERE database.datname = current_database() "
            "ORDER BY 1, 2, 3, 4"
        ),
        "schema_acls": rows(
            f"SELECT {role_name}, {grantor_name}, acl.privilege_type, acl.is_grantable "
            "FROM pg_namespace AS namespace CROSS JOIN LATERAL aclexplode(COALESCE("
            "namespace.nspacl, acldefault('n', namespace.nspowner))) AS acl "
            "WHERE namespace.nspname = 'public' ORDER BY 1, 2, 3, 4"
        ),
        "relations": rows(
            "SELECT relation.relname, relation.relkind, owner.rolname, "
            "relation.relrowsecurity, relation.relforcerowsecurity "
            "FROM pg_class AS relation "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "JOIN pg_roles AS owner ON owner.oid = relation.relowner "
            "WHERE namespace.nspname = 'public' AND owner.rolname = :owner "
            "ORDER BY relation.relname",
            parameters,
        ),
        "relation_acls": rows(
            f"SELECT relation.relname, {role_name}, {grantor_name}, "
            "acl.privilege_type, acl.is_grantable FROM pg_class AS relation "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "JOIN pg_roles AS owner ON owner.oid = relation.relowner "
            "CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl, "
            "acldefault(CASE WHEN relation.relkind = 'S' THEN 's'::\"char\" "
            "ELSE 'r'::\"char\" END, relation.relowner))) AS acl "
            "WHERE namespace.nspname = 'public' AND owner.rolname = :owner "
            "AND relation.relkind IN ('r','p','S','v','m','f') "
            "ORDER BY 1, 2, 3, 4, 5",
            parameters,
        ),
        "column_acls": rows(
            f"SELECT relation.relname, attribute.attname, {role_name}, {grantor_name}, "
            "acl.privilege_type, acl.is_grantable FROM pg_attribute AS attribute "
            "JOIN pg_class AS relation ON relation.oid = attribute.attrelid "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "JOIN pg_roles AS owner ON owner.oid = relation.relowner "
            "CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl "
            "WHERE namespace.nspname = 'public' AND owner.rolname = :owner "
            "AND attribute.attnum > 0 AND NOT attribute.attisdropped "
            "ORDER BY 1, 2, 3, 4, 5, 6",
            parameters,
        ),
        "routines": rows(
            f"SELECT routine.proname, pg_get_function_identity_arguments(routine.oid), "
            f"owner.rolname, {role_name}, {grantor_name}, acl.privilege_type, "
            "acl.is_grantable, routine.prosecdef FROM pg_proc AS routine "
            "JOIN pg_namespace AS namespace ON namespace.oid = routine.pronamespace "
            "JOIN pg_roles AS owner ON owner.oid = routine.proowner "
            "CROSS JOIN LATERAL aclexplode(COALESCE(routine.proacl, "
            "acldefault('f', routine.proowner))) AS acl "
            "WHERE namespace.nspname = 'public' AND owner.rolname = :owner "
            "ORDER BY 1, 2, 3, 4, 5, 6, 7, 8",
            parameters,
        ),
        "types": rows(
            f"SELECT type.typname, owner.rolname, {role_name}, {grantor_name}, "
            "acl.privilege_type, acl.is_grantable FROM pg_type AS type "
            "JOIN pg_namespace AS namespace ON namespace.oid = type.typnamespace "
            "JOIN pg_roles AS owner ON owner.oid = type.typowner "
            "CROSS JOIN LATERAL aclexplode(COALESCE(type.typacl, "
            "acldefault('T', type.typowner))) AS acl "
            "WHERE namespace.nspname = 'public' AND owner.rolname = :owner "
            "AND type.typelem = 0 "
            "ORDER BY 1, 2, 3, 4, 5, 6",
            parameters,
        ),
        "policies": rows(
            "SELECT relation.relname, policy.polname, policy.polpermissive, policy.polcmd, "
            "ARRAY(SELECT CASE WHEN role_oid = 0 THEN 'PUBLIC' "
            "ELSE pg_get_userbyid(role_oid) END FROM unnest(policy.polroles) AS role_oid "
            "ORDER BY 1), pg_get_expr(policy.polqual, policy.polrelid), "
            "pg_get_expr(policy.polwithcheck, policy.polrelid) FROM pg_policy AS policy "
            "JOIN pg_class AS relation ON relation.oid = policy.polrelid "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "JOIN pg_roles AS owner ON owner.oid = relation.relowner "
            "WHERE namespace.nspname = 'public' AND owner.rolname = :owner "
            "ORDER BY relation.relname, policy.polname",
            parameters,
        ),
        "triggers": rows(
            "SELECT relation.relname, trigger.tgname, trigger.tgenabled, "
            "pg_get_triggerdef(trigger.oid, true) FROM pg_trigger AS trigger "
            "JOIN pg_class AS relation ON relation.oid = trigger.tgrelid "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "JOIN pg_roles AS owner ON owner.oid = relation.relowner "
            "WHERE namespace.nspname = 'public' AND owner.rolname = :owner "
            "AND NOT trigger.tgisinternal ORDER BY relation.relname, trigger.tgname",
            parameters,
        ),
        "default_acls": rows(
            f"SELECT owner.rolname, COALESCE(namespace.nspname, ''), defaults.defaclobjtype, "
            f"{role_name}, {grantor_name}, acl.privilege_type, acl.is_grantable "
            "FROM pg_default_acl AS defaults "
            "JOIN pg_roles AS owner ON owner.oid = defaults.defaclrole "
            "LEFT JOIN pg_namespace AS namespace ON namespace.oid = defaults.defaclnamespace "
            "CROSS JOIN LATERAL aclexplode(defaults.defaclacl) AS acl "
            "WHERE owner.rolname = :owner AND (namespace.nspname = 'public' "
            "OR defaults.defaclnamespace = 0) ORDER BY 1, 2, 3, 4, 5, 6, 7",
            parameters,
        ),
    }


def _verify_state(
    plan: ProductionPostgreSqlPlan,
    engines: Mapping[AuthorityKind, Engine],
) -> _VerifiedState:
    with engines["principal_operator"].connect() as principal_connection:
        _verify_capability_principals(
            principal_connection,
            bindings=plan.service_role_graph,
            principal_operator=plan.principal_operator.login,
        )
    with engines["database_owner"].connect() as database_connection:
        _verify_database_boundary(
            database_connection,
            principal_operator=plan.principal_operator.login,
            official_owner=plan.official_owner.login,
            saas_owner=plan.saas_owner.login,
            bindings=plan.service_role_graph,
        )
    with engines["official_owner"].connect() as official_connection:
        server_version_num, bootstrap_name = official_connection.execute(
            sa.text(
                "SELECT current_setting('server_version_num')::integer, "
                "(SELECT rolname FROM pg_roles WHERE oid = 10)"
            )
        ).one()
        official_head = _version_at_head(official_connection, kind="official")
        verify_runtime_rls(official_connection)
        runtime_acls = _verify_runtime_acl(official_connection)
        official_security = _official_security_catalog(
            official_connection,
            official_owner=plan.official_owner.login,
        )
        with engines["saas_owner"].connect() as saas_connection:
            saas_head = _version_at_head(saas_connection, kind="saas")
            ownership = _verify_object_ownership(
                official_connection,
                saas_connection,
                official_owner=plan.official_owner.login,
                saas_owner=plan.saas_owner.login,
            )
            control_plane_security = _control_plane_security_catalog(
                saas_connection,
                saas_owner=plan.saas_owner.login,
            )
    catalog = _canonical_runner_management_catalog(
        {
            "official_head": official_head,
            "saas_head": saas_head,
            "ownership": ownership,
            "runtime_acls": runtime_acls,
            "runtime_rls_tables": [
                contract.table_name for contract in load_runtime_rls_contract()
            ],
            "official_security": official_security,
            "control_plane_security": control_plane_security,
        },
        principal_operator=plan.principal_operator.login,
        bootstrap_name=str(bootstrap_name),
    )
    _verify_source_security_catalog_digest(
        catalog,
        key=(int(server_version_num) // 10000, official_head, saas_head),
        role_aliases=_source_catalog_role_aliases(
            principal_operator=plan.principal_operator.login,
            database_owner=plan.database_owner.login,
            official_owner=plan.official_owner.login,
            saas_owner=plan.saas_owner.login,
            bootstrap_name=str(bootstrap_name),
            bindings=plan.service_role_graph,
        ),
        bindings=plan.service_role_graph,
    )
    digest = hashlib.sha256(
        json.dumps(catalog, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return _VerifiedState(
        official_head=official_head,
        saas_head=saas_head,
        runtime_rls_table_count=len(load_runtime_rls_contract()),
        catalog_sha256=digest,
    )


def _load_runtime_receipt(config: Any) -> _RuntimeReceipt:
    configured = getattr(config, "migration_receipt", None)
    path_value = getattr(configured, "path", None)
    if configured is None or not isinstance(path_value, Path) or not path_value.is_absolute():
        raise PostgreSqlMigrationError("migration_receipt_missing", "runtime_verification")
    try:
        metadata = path_value.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_size <= 0
            or metadata.st_size > _MAX_RECEIPT_BYTES
            or mode & 0o277
            or not mode & 0o400
        ):
            raise OSError
        document = json.loads(path_value.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise PostgreSqlMigrationError(
            "migration_receipt_invalid", "runtime_verification"
        ) from None
    if not isinstance(document, dict):
        raise PostgreSqlMigrationError("migration_receipt_invalid", "runtime_verification")

    product_revision = getattr(config, "product_revision", None)
    official_head = getattr(config, "official_schema_revision", None)
    saas_head = getattr(config, "control_plane_schema_revision", None)
    bindings = {
        "product_revision": product_revision,
        "official_head": official_head,
        "saas_head": saas_head,
    }
    if (
        document.get("schema_version") != _MIGRATION_RECEIPT_SCHEMA_VERSION
        or document.get("status") != "pass"
        or any(document.get(key) != value for key, value in bindings.items())
        or any(getattr(configured, key, None) != value for key, value in bindings.items())
        or product_revision != _installed_product_revision()
        or official_head != _expected_head("official")
        or saas_head != _expected_head("saas")
    ):
        raise PostgreSqlMigrationError(
            "migration_receipt_binding_mismatch", "runtime_verification"
        )
    database_identity = document.get("database_identity_sha256")
    catalog = document.get("catalog_sha256")
    service_bindings = document.get("service_role_bindings_sha256")
    service_graph = document.get("service_role_graph_sha256", service_bindings)
    table_count = document.get("runtime_rls_table_count")
    if (
        not isinstance(database_identity, str)
        or _SHA256.fullmatch(database_identity) is None
        or not isinstance(catalog, str)
        or _SHA256.fullmatch(catalog) is None
        or not isinstance(service_bindings, str)
        or _SHA256.fullmatch(service_bindings) is None
        or not isinstance(service_graph, str)
        or _SHA256.fullmatch(service_graph) is None
        or service_bindings != config.service_role_bindings.sha256
        or service_graph != config.service_role_graph.sha256
        or getattr(configured, "service_role_bindings_sha256", None) != service_bindings
        or getattr(configured, "service_role_graph_sha256", None) != service_graph
        or isinstance(table_count, bool)
        or table_count != len(load_runtime_rls_contract())
        or getattr(configured, "database_identity_sha256", None) != database_identity
        or getattr(configured, "catalog_sha256", None) != catalog
        or getattr(configured, "runtime_rls_table_count", None) != table_count
        or "state:verified" not in document.get("phases", [])
    ):
        raise PostgreSqlMigrationError("migration_receipt_facts_invalid", "runtime_verification")
    raw_authorities = document.get("authorities")
    if not isinstance(raw_authorities, list):
        raise PostgreSqlMigrationError(
            "migration_receipt_authorities_invalid", "runtime_verification"
        )
    authorities: dict[str, str] = {}
    for item in raw_authorities:
        if (
            not isinstance(item, dict)
            or set(item) != {"kind", "login"}
            or item.get("kind") not in _AUTHORITY_KINDS
            or not isinstance(item.get("login"), str)
            or _ROLE_NAME.fullmatch(item["login"]) is None
            or item["kind"] in authorities
        ):
            raise PostgreSqlMigrationError(
                "migration_receipt_authorities_invalid", "runtime_verification"
            )
        authorities[item["kind"]] = item["login"]
    if set(authorities) != set(_AUTHORITY_KINDS):
        raise PostgreSqlMigrationError(
            "migration_receipt_authorities_invalid", "runtime_verification"
        )
    return _RuntimeReceipt(
        product_revision=str(product_revision),
        official_head=str(official_head),
        saas_head=str(saas_head),
        database_identity_sha256=database_identity,
        catalog_sha256=catalog,
        service_role_bindings_sha256=service_bindings,
        service_role_graph_sha256=service_graph,
        runtime_rls_table_count=cast(int, table_count),
        official_owner=authorities["official_owner"],
        saas_owner=authorities["saas_owner"],
        principal_operator=authorities["principal_operator"],
        database_owner=authorities["database_owner"],
    )


def _inspect_service_login(
    engine: Engine,
    *,
    expected_login: str,
    expected_role: str,
) -> _ServiceSessionFacts:
    if engine.dialect.name != "postgresql" or _ROLE_NAME.fullmatch(expected_login) is None:
        raise PostgreSqlMigrationError("service_engine_invalid", "runtime_verification")
    try:
        with engine.connect() as connection:
            identity = connection.execute(
                sa.text(
                    "SELECT current_user, session_user, current_database(), current_schema(), "
                    "current_schemas(false), database.oid, pg_get_userbyid(database.datdba), "
                    "current_setting('server_version_num')::integer, "
                    "COALESCE(inet_server_addr()::text, ''), COALESCE(inet_server_port(), 0), "
                    "pg_is_in_recovery(), COALESCE(ssl.ssl, false), "
                    "has_schema_privilege(current_user, 'public', 'CREATE') "
                    "FROM pg_database AS database LEFT JOIN pg_stat_ssl AS ssl "
                    "ON ssl.pid = pg_backend_pid() WHERE database.datname = current_database()"
                )
            ).one()
            login_role = connection.execute(
                sa.text(
                    "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                    "rolreplication, rolbypassrls, rolinherit, rolconnlimit, rolconfig "
                    "FROM pg_roles WHERE rolname = current_user"
                )
            ).one_or_none()
            base_role = connection.execute(
                sa.text(
                    "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                    "rolreplication, rolbypassrls, rolinherit, rolconnlimit, rolconfig "
                    "FROM pg_roles WHERE rolname = :role"
                ),
                {"role": expected_role},
            ).one_or_none()
            membership_projection = (
                "granted.rolname, membership.admin_option, "
                "COALESCE((to_jsonb(membership) ->> 'inherit_option')::boolean, true), "
                "COALESCE((to_jsonb(membership) ->> 'set_option')::boolean, true) "
            )
            login_memberships = [
                tuple(row)
                for row in connection.execute(
                    sa.text(
                        f"SELECT {membership_projection}"
                        "FROM pg_auth_members AS membership "
                        "JOIN pg_roles AS member ON member.oid = membership.member "
                        "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
                        "WHERE member.rolname = current_user ORDER BY granted.rolname"
                    )
                ).all()
            ]
            base_memberships = connection.execute(
                sa.text(
                    "SELECT count(*) FROM pg_auth_members AS membership "
                    "JOIN pg_roles AS member ON member.oid = membership.member "
                    "WHERE member.rolname = :role"
                ),
                {"role": expected_role},
            ).scalar_one()
            login_incoming = connection.execute(
                sa.text(
                    "SELECT count(*) FROM pg_auth_members AS membership "
                    "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
                    "WHERE granted.rolname = current_user"
                )
            ).scalar_one()
            role_settings = connection.execute(
                sa.text(
                    "SELECT count(*) FROM pg_db_role_setting AS setting "
                    "JOIN pg_roles AS role ON role.oid = setting.setrole "
                    "WHERE role.rolname IN (:login, :base)"
                ),
                {"login": expected_login, "base": expected_role},
            ).scalar_one()
            direct_authority = connection.execute(
                sa.text(
                    "WITH login AS (SELECT oid FROM pg_roles WHERE rolname = current_user), "
                    "authority AS ("
                    "SELECT 1 FROM pg_database object JOIN login ON object.datdba = login.oid "
                    "UNION ALL SELECT 1 FROM pg_namespace object "
                    "JOIN login ON object.nspowner = login.oid "
                    "UNION ALL SELECT 1 FROM pg_class object "
                    "JOIN login ON object.relowner = login.oid "
                    "UNION ALL SELECT 1 FROM pg_proc object "
                    "JOIN login ON object.proowner = login.oid "
                    "UNION ALL SELECT 1 FROM pg_type object "
                    "JOIN login ON object.typowner = login.oid "
                    "UNION ALL SELECT 1 FROM pg_default_acl object "
                    "JOIN login ON object.defaclrole = login.oid "
                    "UNION ALL SELECT 1 FROM pg_database object "
                    "CROSS JOIN LATERAL aclexplode(object.datacl) acl "
                    "JOIN login ON acl.grantee = login.oid "
                    "UNION ALL SELECT 1 FROM pg_namespace object "
                    "CROSS JOIN LATERAL aclexplode(object.nspacl) acl "
                    "JOIN login ON acl.grantee = login.oid "
                    "UNION ALL SELECT 1 FROM pg_class object "
                    "CROSS JOIN LATERAL aclexplode(object.relacl) acl "
                    "JOIN login ON acl.grantee = login.oid "
                    "UNION ALL SELECT 1 FROM pg_attribute object "
                    "CROSS JOIN LATERAL aclexplode(object.attacl) acl "
                    "JOIN login ON acl.grantee = login.oid "
                    "WHERE object.attnum > 0 AND NOT object.attisdropped "
                    "UNION ALL SELECT 1 FROM pg_proc object "
                    "CROSS JOIN LATERAL aclexplode(object.proacl) acl "
                    "JOIN login ON acl.grantee = login.oid "
                    "UNION ALL SELECT 1 FROM pg_type object "
                    "CROSS JOIN LATERAL aclexplode(object.typacl) acl "
                    "JOIN login ON acl.grantee = login.oid "
                    "UNION ALL SELECT 1 FROM pg_default_acl object "
                    "CROSS JOIN LATERAL aclexplode(object.defaclacl) acl "
                    "JOIN login ON acl.grantee = login.oid) "
                    "SELECT count(*) FROM authority"
                )
            ).scalar_one()
    except sa.exc.SQLAlchemyError:
        raise PostgreSqlMigrationError(
            "service_login_probe_failed", "runtime_verification"
        ) from None

    (
        current_user,
        session_user,
        database,
        current_schema,
        search_path,
        database_oid,
        database_owner,
        server_version_num,
        server_address,
        server_port,
        in_recovery,
        tls,
        can_create_schema,
    ) = identity
    expected_login_flags = (True, False, False, False, False, False, True, -1, None)
    expected_base_flags = (False, False, False, False, False, False, True, -1, None)
    if (
        current_user != expected_login
        or session_user != expected_login
        or current_schema != "public"
        or list(search_path) != ["public"]
        or in_recovery
        or not tls
        or can_create_schema
        or tuple(login_role or ()) != expected_login_flags
        or tuple(base_role or ()) != expected_base_flags
        or login_memberships != [(expected_role, False, True, False)]
        or base_memberships
        or login_incoming
        or role_settings
        or direct_authority
    ):
        raise PostgreSqlMigrationError("service_login_authority_drifted", "runtime_verification")
    return _ServiceSessionFacts(
        login=expected_login,
        database=str(database),
        database_oid=int(database_oid),
        database_owner=str(database_owner),
        server_version_num=int(server_version_num),
        server_address=str(server_address),
        server_port=int(server_port),
    )


def verify_production_postgresql_state(
    *,
    engines: Mapping[str, Engine],
    config: Any,
) -> None:
    """Verify an immutable migration receipt against every enabled service login.

    This startup path performs catalog reads only.  It never opens an owner
    authority, runs Alembic, changes a role, or grants a privilege.
    """

    try:
        expected_service_roles = dict(_SERVER_SERVICE_ROLES)
        if "billing" in config.capabilities:
            expected_service_roles["billing"] = "saas_billing"
        _verify_service_postgresql_state(
            engines=engines,
            config=config,
            expected_service_roles=expected_service_roles,
            configured_urls=config.secrets.database_urls.as_mapping(),
        )
    except PostgreSqlMigrationError:
        raise
    except Exception:  # noqa: BLE001 - malformed deployment objects stay content-free.
        raise PostgreSqlMigrationError(
            "runtime_verification_failed", "runtime_verification"
        ) from None


def verify_model_projection_postgresql_state(
    *, engine: Engine, database_url: str, config: Any
) -> None:
    """Apply the same receipt and catalog proof through only the projection login."""

    _verify_service_postgresql_state(
        engines={"model_projection": engine},
        config=config,
        expected_service_roles=EXPECTED_MODEL_PROJECTION_SERVICE_ROLES,
        configured_urls={"model_projection": database_url},
    )


def _verify_service_postgresql_state(
    *,
    engines: Mapping[str, Engine],
    config: Any,
    expected_service_roles: Mapping[str, str],
    configured_urls: Mapping[str, str],
) -> None:

    try:
        receipt = _load_runtime_receipt(config)
        if set(engines) != set(expected_service_roles):
            raise PostgreSqlMigrationError("service_engine_set_invalid", "runtime_verification")
        if set(configured_urls) != set(expected_service_roles):
            raise PostgreSqlMigrationError("service_url_set_invalid", "runtime_verification")
        facts: list[_ServiceSessionFacts] = []
        for service, expected_role in expected_service_roles.items():
            parsed = make_url(configured_urls[service])
            if parsed.username is None:
                raise PostgreSqlMigrationError("service_url_login_missing", "runtime_verification")
            if parsed.username != config.service_role_graph.login_for(service):
                raise PostgreSqlMigrationError(
                    "service_url_binding_mismatch", "runtime_verification"
                )
            facts.append(
                _inspect_service_login(
                    engines[service],
                    expected_login=parsed.username,
                    expected_role=expected_role,
                )
            )
        if len({fact.login for fact in facts}) != len(expected_service_roles):
            raise PostgreSqlMigrationError("service_login_not_distinct", "runtime_verification")
        database_facts = {_database_identity_sha256(fact) for fact in facts}
        if len(database_facts) != 1:
            raise PostgreSqlMigrationError(
                "service_database_identity_drifted", "runtime_verification"
            )
        if any(fact.server_version_num < 160000 for fact in facts):
            raise PostgreSqlMigrationError(
                "service_postgresql_16_required", "runtime_verification"
            )
        if any(not fact.server_address or fact.server_port <= 0 for fact in facts):
            raise PostgreSqlMigrationError(
                "service_database_endpoint_missing", "runtime_verification"
            )
        first = facts[0]
        identity_digest = _database_identity_sha256(first)
        if identity_digest != receipt.database_identity_sha256:
            raise PostgreSqlMigrationError(
                "service_database_receipt_mismatch", "runtime_verification"
            )
        with engines[next(iter(expected_service_roles))].connect() as connection:
            server_version_num, bootstrap_name = connection.execute(
                sa.text(
                    "SELECT current_setting('server_version_num')::integer, "
                    "(SELECT rolname FROM pg_roles WHERE oid = 10)"
                )
            ).one()
            _verify_capability_principals(
                connection,
                bindings=config.service_role_graph,
                principal_operator=receipt.principal_operator,
            )
            _verify_database_boundary(
                connection,
                principal_operator=receipt.principal_operator,
                official_owner=receipt.official_owner,
                saas_owner=receipt.saas_owner,
                bindings=config.service_role_graph,
            )
            verify_runtime_rls(connection)
            runtime_acls = _verify_runtime_acl(connection)
            official_security = _official_security_catalog(
                connection,
                official_owner=receipt.official_owner,
            )
            control_plane_security = _control_plane_security_catalog(
                connection,
                saas_owner=receipt.saas_owner,
            )
            ownership = _verify_object_ownership(
                connection,
                connection,
                official_owner=receipt.official_owner,
                saas_owner=receipt.saas_owner,
            )
        catalog = _canonical_runner_management_catalog(
            {
                "official_head": receipt.official_head,
                "saas_head": receipt.saas_head,
                "ownership": ownership,
                "runtime_acls": runtime_acls,
                "runtime_rls_tables": [
                    contract.table_name for contract in load_runtime_rls_contract()
                ],
                "official_security": official_security,
                "control_plane_security": control_plane_security,
            },
            principal_operator=receipt.principal_operator,
            bootstrap_name=str(bootstrap_name),
        )
        _verify_source_security_catalog_digest(
            catalog,
            key=(
                int(server_version_num) // 10000,
                receipt.official_head,
                receipt.saas_head,
            ),
            role_aliases=_source_catalog_role_aliases(
                principal_operator=receipt.principal_operator,
                database_owner=receipt.database_owner,
                official_owner=receipt.official_owner,
                saas_owner=receipt.saas_owner,
                bootstrap_name=str(bootstrap_name),
                bindings=config.service_role_graph,
            ),
            bindings=config.service_role_graph,
        )
        catalog_digest = hashlib.sha256(
            json.dumps(catalog, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if catalog_digest != receipt.catalog_sha256:
            raise PostgreSqlMigrationError(
                "service_catalog_receipt_mismatch", "runtime_verification"
            )
    except PostgreSqlMigrationError:
        raise
    except Exception:  # noqa: BLE001 - startup verification never leaks DSN/provider data
        raise PostgreSqlMigrationError(
            "runtime_verification_failed", "runtime_verification"
        ) from None


@contextmanager
def _migration_lock(engine: Engine, *, timeout_seconds: float) -> Iterator[None]:
    with engine.connect() as connection:
        deadline = time.monotonic() + timeout_seconds
        acquired = False
        while time.monotonic() < deadline:
            try:
                acquired = bool(
                    connection.execute(
                        sa.text("SELECT pg_try_advisory_lock(hashtextextended(:name, 0))"),
                        {"name": _LOCK_NAME},
                    ).scalar_one()
                )
                # Session-level advisory locks survive COMMIT.  Ending SQLAlchemy's
                # implicit transaction here is required because the official
                # Alembic stream contains CREATE INDEX CONCURRENTLY; leaving this
                # connection idle in transaction makes that DDL wait forever on
                # this session's virtual xid.
                connection.commit()
            except sa.exc.SQLAlchemyError:
                connection.rollback()
                raise
            if acquired:
                break
            time.sleep(0.1)
        if not acquired:
            raise PostgreSqlMigrationError("migration_lock_timeout", "lock")
        try:
            yield
        finally:
            try:
                connection.execute(
                    sa.text("SELECT pg_advisory_unlock(hashtextextended(:name, 0))"),
                    {"name": _LOCK_NAME},
                ).scalar_one()
                connection.commit()
            except sa.exc.SQLAlchemyError:
                connection.rollback()


def _phase(name: str, operation: Callable[[], None]) -> None:
    try:
        operation()
    except PostgreSqlMigrationError:
        raise
    except Exception:  # noqa: BLE001 - never expose driver/Alembic text containing DSNs
        raise PostgreSqlMigrationError("phase_execution_failed", name) from None


def run_production_postgresql_migration(
    plan: ProductionPostgreSqlPlan,
    *,
    verify_only: bool = False,
) -> PostgreSqlMigrationReceipt:
    """Apply the ordered authority chain, or verify it without mutations."""

    _validate_plan(plan)
    engines = _create_engines(plan)
    phases: list[str] = []
    try:
        session_facts = _preflight(plan, engines)
        phases.append("preflight:verified")
        with engines["official_owner"].connect() as official_connection:
            _preflight_pg_trgm_extension(
                official_connection,
                official_owner=plan.official_owner.login,
            )
        phases.append("pg_trgm_preflight:verified")
        if not verify_only:
            with _migration_lock(
                engines["database_owner"],
                timeout_seconds=plan.lock_timeout_seconds,
            ):
                locked_session_facts = _preflight(plan, engines)
                if locked_session_facts != session_facts:
                    raise PostgreSqlMigrationError(
                        "authority_identity_changed_under_lock",
                        "preflight",
                    )
                phases.append("lock_preflight:verified")
                with engines["official_owner"].connect() as official_connection:
                    _preflight_pg_trgm_extension(
                        official_connection,
                        official_owner=plan.official_owner.login,
                    )
                phases.append("lock_pg_trgm_preflight:verified")
                _phase(
                    "principals",
                    lambda: _apply_principals(
                        engines["principal_operator"],
                        bindings=plan.service_role_graph,
                        principal_operator=plan.principal_operator.login,
                    ),
                )
                phases.append("principals:applied")
                _phase(
                    "database",
                    lambda: _apply_database_authority(
                        engines["database_owner"],
                        principal_operator=plan.principal_operator.login,
                        official_owner=plan.official_owner.login,
                        saas_owner=plan.saas_owner.login,
                        bindings=plan.service_role_graph,
                    ),
                )
                phases.append("database:applied")
                _phase("official_alembic", lambda: _upgrade(engines["official_owner"], "official"))
                phases.append("official_alembic:applied")
                _phase("saas_alembic", lambda: _upgrade(engines["saas_owner"], "saas"))
                phases.append("saas_alembic:applied")
                _phase(
                    "runtime_authority",
                    lambda: _apply_runtime_authority(engines["official_owner"]),
                )
                phases.append("runtime_authority:applied")
                _phase(
                    "control_plane_authority",
                    lambda: _apply_control_plane_authority(engines["saas_owner"]),
                )
                phases.append("control_plane_authority:applied")
                _phase(
                    "database_acl_finalize",
                    lambda: _finalize_database_authority(
                        engines["database_owner"],
                        principal_operator=plan.principal_operator.login,
                        official_owner=plan.official_owner.login,
                        saas_owner=plan.saas_owner.login,
                        bindings=plan.service_role_graph,
                    ),
                )
                phases.append("database_acl_finalize:applied")
        verified = _verify_state(plan, engines)
        phases.append("state:verified")
    except PostgreSqlMigrationError:
        raise
    except Exception:  # noqa: BLE001 - verification errors stay content-free
        raise PostgreSqlMigrationError("verification_failed", "verification") from None
    finally:
        _dispose_engines(engines)

    identity_sha256 = _database_identity_sha256(session_facts[0])
    return PostgreSqlMigrationReceipt(
        schema_version=_MIGRATION_RECEIPT_SCHEMA_VERSION,
        status="pass",
        verify_only=verify_only,
        product_revision=plan.product_revision,
        database_identity_sha256=identity_sha256,
        official_head=verified.official_head,
        saas_head=verified.saas_head,
        runtime_rls_table_count=verified.runtime_rls_table_count,
        authorities=tuple((authority.kind, authority.login) for authority in plan.authorities()),
        phases=tuple(phases),
        catalog_sha256=verified.catalog_sha256,
        service_role_bindings_sha256=plan.service_role_bindings.sha256,
        service_role_graph_sha256=plan.service_role_graph.sha256,
        completed_at=datetime.now(UTC).isoformat(),
    )


__all__ = [
    "PostgreSqlAuthority",
    "PostgreSqlMigrationError",
    "PostgreSqlMigrationReceipt",
    "ProductionPostgreSqlPlan",
    "parse_production_postgresql_url",
    "run_production_postgresql_migration",
    "verify_model_projection_postgresql_state",
    "verify_production_postgresql_state",
]
