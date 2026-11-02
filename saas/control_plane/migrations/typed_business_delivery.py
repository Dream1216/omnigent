"""Frozen P17 native SQL; fresh install and preserving reattach are distinct.

Receipt policies/append-only guards/ACL migrate with the original table OIDs.
After independently verified reattach, recreate only SOURCE_NATIVE_SQL. This
module does not authorize or execute the preserving operation.
"""

SOURCE_OWNER_NATIVE_SQL = r"""
-- Frozen P17 native source: no caller-generated SQL or ambient search_path.
CREATE POLICY "rls_usage_events_delivery_owner_source" ON public."saas_usage_events" FOR
    SELECT TO PUBLIC USING (current_user=pg_get_userbyid((SELECT c.relowner FROM
    pg_catalog.pg_class c WHERE c.oid='public.saas_usage_events'::regclass)));

CREATE POLICY "rls_pricing_snapshots_delivery_owner_source" ON
    public."saas_pricing_snapshots" FOR SELECT TO PUBLIC USING
    (current_user=pg_get_userbyid((SELECT c.relowner FROM pg_catalog.pg_class c WHERE
    c.oid='public.saas_pricing_snapshots'::regclass)));

CREATE POLICY "rls_platform_audit_events_delivery_owner_source" ON
    public."saas_platform_audit_events" FOR SELECT TO PUBLIC USING
    (current_user=pg_get_userbyid((SELECT c.relowner FROM pg_catalog.pg_class c WHERE
    c.oid='public.saas_platform_audit_events'::regclass)));

CREATE POLICY "rls_global_users_delivery_owner_source" ON public."saas_global_users" FOR
    SELECT TO PUBLIC USING (current_user=pg_get_userbyid((SELECT c.relowner FROM
    pg_catalog.pg_class c WHERE c.oid='public.saas_global_users'::regclass)));

CREATE POLICY "rls_service_accounts_delivery_owner_source" ON
    public."saas_service_accounts" FOR SELECT TO PUBLIC USING
    (current_user=pg_get_userbyid((SELECT c.relowner FROM pg_catalog.pg_class c WHERE
    c.oid='public.saas_service_accounts'::regclass)));

CREATE POLICY "rls_api_credentials_delivery_owner_source" ON public."saas_api_credentials"
    FOR SELECT TO PUBLIC USING (current_user=pg_get_userbyid((SELECT c.relowner FROM
    pg_catalog.pg_class c WHERE c.oid='public.saas_api_credentials'::regclass)));

""".removeprefix("\n")

RECEIPT_NATIVE_SQL = r"""
ALTER TABLE public.saas_usage_reconciliation_ingress ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.saas_usage_reconciliation_ingress FORCE ROW LEVEL SECURITY;

CREATE POLICY "rls_usage_reconciliation_ingress_delivery_owner_read" ON
    public."saas_usage_reconciliation_ingress" FOR SELECT TO PUBLIC USING
    (current_user=pg_get_userbyid((SELECT c.relowner FROM pg_catalog.pg_class c WHERE
    c.oid='public.saas_usage_reconciliation_ingress'::regclass)));

CREATE POLICY "rls_usage_reconciliation_ingress_delivery_owner_insert" ON
    public."saas_usage_reconciliation_ingress" FOR INSERT TO PUBLIC WITH CHECK
    (current_user=pg_get_userbyid((SELECT c.relowner FROM pg_catalog.pg_class c WHERE
    c.oid='public.saas_usage_reconciliation_ingress'::regclass)));

CREATE POLICY "rls_usage_reconciliation_ingress_delivery_consumer_read" ON
    public."saas_usage_reconciliation_ingress" FOR SELECT TO saas_usage_consumer USING (true);

CREATE POLICY "rls_usage_reconciliation_ingress_delivery_consumer_insert" ON
    public."saas_usage_reconciliation_ingress" FOR INSERT TO saas_usage_consumer WITH CHECK
    (true);

REVOKE ALL ON public.saas_usage_reconciliation_ingress FROM PUBLIC;

GRANT SELECT,INSERT ON public.saas_usage_reconciliation_ingress TO saas_usage_consumer;

CREATE TRIGGER saas_delivery_receipt_append_only BEFORE UPDATE OR DELETE ON
    public.saas_usage_reconciliation_ingress FOR EACH ROW EXECUTE FUNCTION
    public.saas_reject_platform_audit_mutation();

ALTER TABLE public.saas_platform_audit_journal_deliveries ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.saas_platform_audit_journal_deliveries FORCE ROW LEVEL SECURITY;

CREATE POLICY "rls_platform_audit_journal_deliveries_delivery_owner_read" ON
    public."saas_platform_audit_journal_deliveries" FOR SELECT TO PUBLIC USING
    (current_user=pg_get_userbyid((SELECT c.relowner FROM pg_catalog.pg_class c WHERE
    c.oid='public.saas_platform_audit_journal_deliveries'::regclass)));

CREATE POLICY "rls_platform_audit_journal_deliveries_delivery_owner_insert" ON
    public."saas_platform_audit_journal_deliveries" FOR INSERT TO PUBLIC WITH CHECK
    (current_user=pg_get_userbyid((SELECT c.relowner FROM pg_catalog.pg_class c WHERE
    c.oid='public.saas_platform_audit_journal_deliveries'::regclass)));

CREATE POLICY "rls_platform_audit_journal_deliveries_delivery_consumer_read" ON
    public."saas_platform_audit_journal_deliveries" FOR SELECT TO saas_audit_delivery USING
    (true);

CREATE POLICY "rls_platform_audit_journal_deliveries_delivery_consumer_insert" ON
    public."saas_platform_audit_journal_deliveries" FOR INSERT TO saas_audit_delivery WITH
    CHECK (true);

REVOKE ALL ON public.saas_platform_audit_journal_deliveries FROM PUBLIC;

GRANT SELECT,INSERT ON public.saas_platform_audit_journal_deliveries TO saas_audit_delivery;

CREATE TRIGGER saas_delivery_receipt_append_only BEFORE UPDATE OR DELETE ON
    public.saas_platform_audit_journal_deliveries FOR EACH ROW EXECUTE FUNCTION
    public.saas_reject_platform_audit_mutation();

ALTER TABLE public.saas_revocation_replica_applied ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.saas_revocation_replica_applied FORCE ROW LEVEL SECURITY;

CREATE POLICY "rls_revocation_replica_applied_delivery_owner_read" ON
    public."saas_revocation_replica_applied" FOR SELECT TO PUBLIC USING
    (current_user=pg_get_userbyid((SELECT c.relowner FROM pg_catalog.pg_class c WHERE
    c.oid='public.saas_revocation_replica_applied'::regclass)));

CREATE POLICY "rls_revocation_replica_applied_delivery_owner_insert" ON
    public."saas_revocation_replica_applied" FOR INSERT TO PUBLIC WITH CHECK
    (current_user=pg_get_userbyid((SELECT c.relowner FROM pg_catalog.pg_class c WHERE
    c.oid='public.saas_revocation_replica_applied'::regclass)));

CREATE POLICY "rls_revocation_replica_applied_delivery_consumer_read" ON
    public."saas_revocation_replica_applied" FOR SELECT TO saas_revocation_consumer USING (true);

CREATE POLICY "rls_revocation_replica_applied_delivery_consumer_insert" ON
    public."saas_revocation_replica_applied" FOR INSERT TO saas_revocation_consumer WITH CHECK
    (true);

REVOKE ALL ON public.saas_revocation_replica_applied FROM PUBLIC;

GRANT SELECT,INSERT ON public.saas_revocation_replica_applied TO saas_revocation_consumer;

CREATE TRIGGER saas_delivery_receipt_append_only BEFORE UPDATE OR DELETE ON
    public.saas_revocation_replica_applied FOR EACH ROW EXECUTE FUNCTION
    public.saas_reject_platform_audit_mutation();

CREATE POLICY "rls_usage_reconciliation_ingress_delivery_billing_read" ON
    public."saas_usage_reconciliation_ingress" FOR SELECT TO saas_billing USING
    (tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid);

GRANT SELECT ON public.saas_usage_reconciliation_ingress TO saas_billing;

""".removeprefix("\n")

SOURCE_OBJECT_NATIVE_SQL = r"""
CREATE POLICY rls_outbox_typed_delivery_provenance ON public.saas_control_plane_outbox AS
    RESTRICTIVE FOR INSERT TO PUBLIC WITH CHECK (aggregate_type NOT IN ('platform_audit',
    'authorization_user','authorization_service_account','authorization_api_credential') OR
    current_user=pg_get_userbyid((SELECT c.relowner FROM pg_catalog.pg_class c WHERE
    c.oid='public.saas_control_plane_outbox'::regclass)));

CREATE INDEX ix_outbox_typed_delivery_scan ON public.saas_control_plane_outbox(aggregate_type,
    event_type,id);

CREATE FUNCTION public.saas_delivery_usage_outbox_source_v1(source_id uuid) RETURNS TABLE(id
    uuid,tenant_id uuid,aggregate_type text,aggregate_key text,event_type text,payload json,
    request_hash text,created_at timestamptz) LANGUAGE sql STABLE SECURITY DEFINER SET
    search_path=pg_catalog,pg_temp AS $fn$ SELECT o.id,o.tenant_id,o.aggregate_type::text,
    o.aggregate_key::text,o.event_type::text,o.payload,o.request_hash::text,o.created_at FROM
    public.saas_control_plane_outbox o WHERE o.id=source_id AND (o.aggregate_type='billing' AND
    o.event_type='billing.usage.recorded') $fn$;

REVOKE ALL ON FUNCTION public.saas_delivery_usage_outbox_source_v1(uuid) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION public.saas_delivery_usage_outbox_source_v1(uuid) TO
    saas_usage_consumer;

CREATE FUNCTION public.saas_delivery_audit_outbox_source_v1(source_id uuid) RETURNS TABLE(id
    uuid,tenant_id uuid,aggregate_type text,aggregate_key text,event_type text,payload json,
    request_hash text,created_at timestamptz) LANGUAGE sql STABLE SECURITY DEFINER SET
    search_path=pg_catalog,pg_temp AS $fn$ SELECT o.id,o.tenant_id,o.aggregate_type::text,
    o.aggregate_key::text,o.event_type::text,o.payload,o.request_hash::text,o.created_at FROM
    public.saas_control_plane_outbox o WHERE o.id=source_id AND
    (o.aggregate_type='platform_audit' AND o.event_type='platform.audit.persisted') $fn$;

REVOKE ALL ON FUNCTION public.saas_delivery_audit_outbox_source_v1(uuid) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION public.saas_delivery_audit_outbox_source_v1(uuid) TO
    saas_audit_delivery;

CREATE FUNCTION public.saas_delivery_revocation_outbox_source_v1(source_id uuid) RETURNS
    TABLE(id uuid,tenant_id uuid,aggregate_type text,aggregate_key text,event_type text,payload
    json,request_hash text,created_at timestamptz,quarantined_at timestamptz) LANGUAGE sql STABLE
    SECURITY DEFINER SET
    search_path=pg_catalog,pg_temp AS $fn$ SELECT o.id,o.tenant_id,o.aggregate_type::text,
    o.aggregate_key::text,o.event_type::text,o.payload,o.request_hash::text,o.created_at,o.quarantined_at
    FROM
    public.saas_control_plane_outbox o WHERE o.id=source_id AND ((o.aggregate_type,
    o.event_type) IN (('authorization_user','authorization.user.version_changed'),
    ('authorization_service_account','authorization.service_account.version_changed'),
    ('authorization_api_credential','authorization.api_credential.revoked'))) $fn$;

REVOKE ALL ON FUNCTION public.saas_delivery_revocation_outbox_source_v1(uuid) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION public.saas_delivery_revocation_outbox_source_v1(uuid) TO
    saas_revocation_consumer;

CREATE FUNCTION public.saas_delivery_usage_facts_v1(source_id uuid) RETURNS TABLE(id uuid,
    tenant_id uuid,space_id uuid,project_id uuid,run_id uuid,meter text,quantity numeric,unit
    text,provider text,provider_request_id text,pricing_snapshot_id uuid,currency text,
    customer_charge_minor bigint,attributes json,occurred_at timestamptz) LANGUAGE sql STABLE
    SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$ SELECT u.id,u.tenant_id,
    u.space_id,u.project_id,u.run_id,u.meter::text,u.quantity,u.unit::text,u.provider::text,
    u.provider_request_id::text,u.pricing_snapshot_id,u.currency::text,
    u.customer_charge_minor::bigint,u.attributes,u.occurred_at FROM
    public.saas_delivery_usage_outbox_source_v1(source_id) o JOIN public.saas_usage_events u ON
    u.id::text=o.aggregate_key AND u.id::text=o.payload->>'usage_event_id' AND
    u.tenant_id=o.tenant_id $fn$;

REVOKE ALL ON FUNCTION public.saas_delivery_usage_facts_v1(uuid) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION public.saas_delivery_usage_facts_v1(uuid) TO saas_usage_consumer;

CREATE FUNCTION public.saas_delivery_pricing_facts_v1(source_id uuid) RETURNS TABLE(id uuid,
    tenant_id uuid,plan_key text,currency text,rates json,version integer,effective_from
    timestamptz,effective_until timestamptz) LANGUAGE sql STABLE SECURITY DEFINER SET
    search_path=pg_catalog,pg_temp AS $fn$ SELECT p.id,p.tenant_id,p.plan_key::text,
    p.currency::text,p.rates,p.version,p.effective_from,p.effective_until FROM
    public.saas_delivery_usage_facts_v1(source_id) u JOIN public.saas_pricing_snapshots p ON
    p.id=u.pricing_snapshot_id AND p.tenant_id=u.tenant_id $fn$;

REVOKE ALL ON FUNCTION public.saas_delivery_pricing_facts_v1(uuid) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION public.saas_delivery_pricing_facts_v1(uuid) TO saas_usage_consumer;

CREATE FUNCTION public.saas_delivery_audit_chain_v1(source_id uuid) RETURNS TABLE(id uuid,
    sequence_no integer,tenant_id uuid,actor_type text,actor_id uuid,event_type text,
    target_type text,target_id uuid,operation_id uuid,payload json,payload_hash text,
    previous_hash text,event_hash text,occurred_at timestamptz) LANGUAGE sql STABLE SECURITY
    DEFINER SET search_path=pg_catalog,pg_temp AS $fn$ SELECT a.id,a.sequence_no,a.tenant_id,
    a.actor_type::text,a.actor_id,a.event_type::text,a.target_type::text,a.target_id,
    a.operation_id,a.payload,a.payload_hash::text,a.previous_hash::text,a.event_hash::text,
    a.occurred_at FROM public.saas_delivery_audit_outbox_source_v1(source_id) o JOIN
    public.saas_platform_audit_events head ON head.id::text=o.aggregate_key AND
    head.id::text=o.payload->>'audit_event_id'
    AND head.tenant_id IS NOT DISTINCT FROM o.tenant_id
    AND head.event_hash=o.request_hash AND head.event_hash=o.payload->>'event_hash'
    AND head.sequence_no::text=o.payload->>'sequence_no'
    JOIN public.saas_platform_audit_events a ON
    a.sequence_no IN (head.sequence_no,head.sequence_no-1) ORDER BY a.sequence_no $fn$;

REVOKE ALL ON FUNCTION public.saas_delivery_audit_chain_v1(uuid) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION public.saas_delivery_audit_chain_v1(uuid) TO saas_audit_delivery;

CREATE FUNCTION public.saas_delivery_revocation_authority_v1(source_id uuid) RETURNS TABLE(id
    uuid,status text,security_version bigint,revoked_at timestamptz) LANGUAGE sql STABLE
    SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$ WITH source AS (SELECT payload
    FROM public.saas_delivery_revocation_outbox_source_v1(source_id)) SELECT u.id,
    u.status::text,u.security_version::bigint,NULL::timestamptz FROM source o JOIN
    public.saas_global_users u ON o.payload->>'kind'='user' AND
    u.id::text=o.payload->>'entity_id' UNION ALL SELECT a.id,a.status::text,
    a.security_version::bigint,NULL::timestamptz FROM source o JOIN
    public.saas_service_accounts a ON o.payload->>'kind'='service_account' AND
    a.id::text=o.payload->>'entity_id' UNION ALL SELECT k.id,k.status::text,1::bigint,
    k.revoked_at FROM source o JOIN public.saas_api_credentials k ON
    o.payload->>'kind'='api_credential' AND k.id::text=o.payload->>'entity_id' $fn$;

REVOKE ALL ON FUNCTION public.saas_delivery_revocation_authority_v1(uuid) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION public.saas_delivery_revocation_authority_v1(uuid) TO
    saas_revocation_consumer;

CREATE FUNCTION public.saas_delivery_revocation_scan_v1(after_id uuid, maximum integer) RETURNS
    TABLE(id uuid) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp
    AS $fn$ BEGIN IF maximum IS NULL OR maximum<1 OR maximum>128 THEN RAISE EXCEPTION
    'revocation scan bound invalid'; END IF; RETURN QUERY SELECT o.id FROM
    public.saas_control_plane_outbox o WHERE (after_id IS NULL OR o.id>after_id) AND
    (o.aggregate_type,o.event_type) IN (('authorization_user',
    'authorization.user.version_changed'),('authorization_service_account',
    'authorization.service_account.version_changed'),('authorization_api_credential',
    'authorization.api_credential.revoked')) ORDER BY o.id LIMIT maximum; END $fn$;

REVOKE ALL ON FUNCTION public.saas_delivery_revocation_scan_v1(uuid,integer) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION public.saas_delivery_revocation_scan_v1(uuid,integer) TO
    saas_revocation_consumer;

CREATE FUNCTION public.saas_delivery_audit_enqueue_record_v1(audit_id uuid)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE original public.saas_platform_audit_events%ROWTYPE; body jsonb; idem text; emitted uuid;
BEGIN
    SELECT * INTO STRICT original FROM public.saas_platform_audit_events WHERE id=audit_id;
    body:=jsonb_build_object('audit_event_id',original.id::text,
        'sequence_no',original.sequence_no,'event_hash',original.event_hash);
    idem:='platform-audit:'||original.id::text;
    INSERT INTO public.saas_control_plane_outbox(id,tenant_id,aggregate_type,aggregate_key,
        event_type,payload,idempotency_key,request_hash,attempt_count,created_at)
    VALUES(gen_random_uuid(),original.tenant_id,'platform_audit',original.id::text,
        'platform.audit.persisted',body,idem,original.event_hash,0,clock_timestamp())
    ON CONFLICT(idempotency_key) DO NOTHING;
    SELECT o.id INTO emitted FROM public.saas_control_plane_outbox o
    WHERE o.idempotency_key=idem AND o.tenant_id IS NOT DISTINCT FROM original.tenant_id
        AND o.aggregate_type='platform_audit' AND o.aggregate_key=original.id::text
        AND o.event_type='platform.audit.persisted' AND o.payload::jsonb=body
        AND o.request_hash=original.event_hash;
    IF emitted IS NULL THEN RAISE EXCEPTION 'audit source idempotency conflict'; END IF;
    RETURN emitted;
END $fn$;
REVOKE ALL ON FUNCTION public.saas_delivery_audit_enqueue_record_v1(uuid) FROM PUBLIC;

CREATE FUNCTION public.saas_delivery_enqueue_audit_v1() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
BEGIN
    IF TG_RELID<>'public.saas_platform_audit_events'::regclass OR TG_OP<>'INSERT'
        OR TG_WHEN<>'AFTER' THEN RAISE EXCEPTION 'audit trigger binding invalid'; END IF;
    PERFORM public.saas_delivery_audit_enqueue_record_v1(NEW.id);
    RETURN NEW;
END $fn$;
CREATE TRIGGER saas_delivery_audit_source_v1 AFTER INSERT ON public.saas_platform_audit_events
FOR EACH ROW EXECUTE FUNCTION public.saas_delivery_enqueue_audit_v1();

CREATE FUNCTION public.saas_delivery_audit_backfill_v1(after_sequence bigint, maximum integer)
RETURNS TABLE(last_sequence bigint, processed integer) LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE original record; last_seen bigint:=after_sequence; count_seen integer:=0;
BEGIN
    IF after_sequence IS NULL OR after_sequence<0 OR maximum IS NULL
        OR maximum<1 OR maximum>128 THEN RAISE EXCEPTION 'audit backfill bound invalid'; END IF;
    FOR original IN SELECT a.id,a.sequence_no FROM public.saas_platform_audit_events a
        WHERE a.sequence_no>after_sequence ORDER BY a.sequence_no LIMIT maximum
    LOOP
        PERFORM public.saas_delivery_audit_enqueue_record_v1(original.id);
        last_seen:=original.sequence_no; count_seen:=count_seen+1;
    END LOOP;
    RETURN QUERY SELECT last_seen,count_seen;
END $fn$;
REVOKE ALL ON FUNCTION public.saas_delivery_audit_backfill_v1(bigint,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.saas_delivery_audit_backfill_v1(bigint,integer)
TO saas_platform;

CREATE FUNCTION public.saas_delivery_enqueue_revocation_v1() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
    DECLARE kind text; topic text; native_event_type text; entity uuid;
    floor bigint; deleted boolean;
    body jsonb; idem text; emitted uuid;
    BEGIN
      IF TG_WHEN<>'AFTER' OR TG_OP NOT IN ('UPDATE','DELETE') THEN RAISE EXCEPTION
    'revocation trigger binding invalid'; END IF;
      deleted:=TG_OP='DELETE';
      IF TG_RELID='public.saas_global_users'::regclass THEN kind:='user';
      ELSIF TG_RELID='public.saas_service_accounts'::regclass THEN kind:='service_account';
      ELSIF TG_RELID='public.saas_api_credentials'::regclass THEN kind:='api_credential';
      ELSE RAISE EXCEPTION 'revocation source table invalid'; END IF;
      IF kind='api_credential' THEN
        IF NOT deleted AND OLD.status='revoked' AND NEW.status<>'revoked' THEN RAISE EXCEPTION
    'revoked credential cannot be reactivated'; END IF;
        IF NOT deleted AND NOT(OLD.status='active' AND (NEW.status='revoked' OR NEW.revoked_at
    IS NOT NULL)) THEN RETURN NEW; END IF;
        floor:=1; entity:=OLD.id; native_event_type:='authorization.api_credential.revoked';
      ELSE
        IF deleted THEN floor:=OLD.security_version::bigint+1; entity:=OLD.id;
        ELSE
          IF NEW.security_version<OLD.security_version THEN RAISE EXCEPTION
    'security version must not regress'; END IF;
          IF NEW.security_version=OLD.security_version THEN RETURN NEW; END IF;
          floor:=NEW.security_version; entity:=NEW.id;
        END IF;
        native_event_type:='authorization.'||kind||'.version_changed';
      END IF;
      topic:='authorization_'||kind;
      body:=jsonb_build_object('kind',kind,'entity_id',entity::text,'version_floor',floor);
      IF deleted THEN body:=body||jsonb_build_object('deleted',true); END IF;
      idem:='authorization:'||kind||':'||entity::text||':'||floor::text||':'||CASE WHEN deleted
    THEN 'delete' ELSE 'change' END;
      INSERT INTO public.saas_control_plane_outbox(id,tenant_id,aggregate_type,aggregate_key,
    event_type,payload,idempotency_key,request_hash,attempt_count,created_at)
        VALUES(gen_random_uuid(),NULL,topic,entity::text,native_event_type,body,idem,
    public.saas_canonical_json_sha256_v1(body),0,clock_timestamp()) ON
    CONFLICT(idempotency_key) DO NOTHING;
      SELECT o.id INTO emitted FROM public.saas_control_plane_outbox o WHERE
    o.idempotency_key=idem AND o.tenant_id IS NULL AND o.aggregate_type=topic AND
    o.aggregate_key=entity::text AND o.event_type=native_event_type AND o.payload::jsonb=body AND
    o.request_hash=public.saas_canonical_json_sha256_v1(body);
      IF emitted IS NULL THEN RAISE EXCEPTION 'revocation source idempotency conflict'; END IF;
      PERFORM pg_notify('saas_authorization_invalidation_v1',emitted::text);
      IF deleted THEN RETURN OLD; END IF; RETURN NEW;
    END $fn$;

CREATE TRIGGER saas_delivery_revocation_source_v1 AFTER UPDATE OR DELETE ON
    public.saas_global_users FOR EACH ROW EXECUTE FUNCTION
    public.saas_delivery_enqueue_revocation_v1();

CREATE TRIGGER saas_delivery_revocation_source_v1 AFTER UPDATE OR DELETE ON
    public.saas_service_accounts FOR EACH ROW EXECUTE FUNCTION
    public.saas_delivery_enqueue_revocation_v1();

CREATE TRIGGER saas_delivery_revocation_source_v1 AFTER UPDATE OR DELETE ON
    public.saas_api_credentials FOR EACH ROW EXECUTE FUNCTION
    public.saas_delivery_enqueue_revocation_v1();

CREATE FUNCTION public.saas_delivery_protect_typed_source_v1() RETURNS trigger LANGUAGE plpgsql
    SET search_path=pg_catalog,pg_temp AS $fn$
    BEGIN
      IF OLD.aggregate_type IN ('platform_audit','authorization_user',
    'authorization_service_account','authorization_api_credential') THEN
        IF TG_OP='DELETE' THEN RAISE EXCEPTION 'typed source facts are append-only'; END IF;
        IF ROW(NEW.id,NEW.tenant_id,NEW.aggregate_type,NEW.aggregate_key,NEW.event_type,
    NEW.payload::jsonb,NEW.idempotency_key,NEW.request_hash,NEW.created_at) IS DISTINCT FROM
    ROW(OLD.id,OLD.tenant_id,OLD.aggregate_type,OLD.aggregate_key,OLD.event_type,
    OLD.payload::jsonb,OLD.idempotency_key,OLD.request_hash,OLD.created_at) THEN RAISE
    EXCEPTION 'typed source facts are immutable'; END IF;
      ELSIF TG_OP='UPDATE' AND NEW.aggregate_type IN ('platform_audit','authorization_user',
    'authorization_service_account','authorization_api_credential') THEN RAISE EXCEPTION
    'existing source cannot become a typed fact';
      END IF;
      IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW;
    END $fn$;

CREATE TRIGGER saas_delivery_typed_source_immutable_v1 BEFORE UPDATE OR DELETE ON
    public.saas_control_plane_outbox FOR EACH ROW EXECUTE FUNCTION
    public.saas_delivery_protect_typed_source_v1();

REVOKE ALL ON FUNCTION public.saas_delivery_enqueue_audit_v1() FROM PUBLIC;

REVOKE ALL ON FUNCTION public.saas_delivery_enqueue_revocation_v1() FROM PUBLIC;

REVOKE ALL ON FUNCTION public.saas_delivery_protect_typed_source_v1() FROM PUBLIC;

CREATE FUNCTION public.saas_delivery_revocation_fanout_ready_v1(source_id uuid,
    product_sha text) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY INVOKER SET
    search_path=pg_catalog,pg_temp AS $fn$
DECLARE listeners uuid[] := ARRAY[]::uuid[]; actual_name text; total integer := 0;
    source_row record; listener_id uuid;
BEGIN
    IF product_sha !~ '^[0-9a-f]{40}$' THEN RETURN false; END IF;
    SELECT * INTO source_row FROM
        public.saas_delivery_revocation_outbox_source_v1(source_id);
    IF NOT FOUND OR source_row.quarantined_at IS NOT NULL THEN RETURN false; END IF;
    FOR actual_name IN SELECT a.application_name FROM pg_catalog.pg_stat_activity a
        WHERE a.datname=current_database() AND a.usename=session_user
        AND a.backend_type='client backend' ORDER BY a.pid LIMIT 129 LOOP
        total := total+1;
        IF total>128 THEN RETURN false; END IF;
        IF actual_name ~ '^saas-revocation-listen:[0-9a-f]{32}$' THEN
            listeners := array_append(listeners,substring(actual_name from 24)::uuid);
        ELSIF actual_name NOT IN ('saas-revocation-worker','saas-revocation-probe')
            THEN RETURN false;
        END IF;
    END LOOP;
    IF cardinality(listeners)=0 OR cardinality(listeners) <>
        (SELECT count(DISTINCT item) FROM unnest(listeners) item) THEN RETURN false; END IF;
    FOREACH listener_id IN ARRAY listeners LOOP
        IF (SELECT count(*) FROM public.saas_revocation_replica_applied r WHERE
            r.outbox_event_id=source_id AND r.listener_epoch_uid=listener_id AND
            r.product_revision=product_sha AND
            r.version_floor>=(source_row.payload->>'version_floor')::bigint) <> 1
            THEN RETURN false;
        END IF;
    END LOOP;
    RETURN true;
END $fn$;

REVOKE ALL ON FUNCTION public.saas_delivery_revocation_fanout_ready_v1(uuid,text)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.saas_delivery_revocation_fanout_ready_v1(uuid,text)
    TO saas_revocation_consumer;

""".removeprefix("\n")

SOURCE_NATIVE_SQL = SOURCE_OWNER_NATIVE_SQL + SOURCE_OBJECT_NATIVE_SQL
NATIVE_SQL = SOURCE_OWNER_NATIVE_SQL + RECEIPT_NATIVE_SQL + SOURCE_OBJECT_NATIVE_SQL
