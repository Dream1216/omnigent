CREATE OR REPLACE FUNCTION public.saas_preview_owner_scope_is_current_v1()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT pg_has_role(session_user, 'saas_preview_owner', 'member') AND EXISTS (
        SELECT 1 FROM public.saas_preview_gateway_instances AS gateway
        WHERE gateway.id = NULLIF(current_setting('app.preview_gateway_instance_id', true), '')
          AND gateway.registration_token_hash = NULLIF(
              current_setting('app.preview_gateway_registration_token_hash', true), '')
          AND gateway.status = 'active' AND gateway.lease_expires_at > CURRENT_TIMESTAMP
    )
$function$;
REVOKE ALL ON FUNCTION public.saas_preview_owner_scope_is_current_v1() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.saas_preview_owner_scope_is_current_v1() TO saas_preview_owner;
-- Install only after the production migration has authenticated the source catalog.
DROP POLICY IF EXISTS rls_preview_gateway_instances_preview_edge ON public.saas_preview_gateway_instances;
DROP POLICY IF EXISTS rls_preview_gateway_instances_preview_owner_certificate ON public.saas_preview_gateway_instances;
DROP POLICY IF EXISTS rls_preview_gateway_certificates_preview_edge ON public.saas_preview_gateway_certificates;
DROP POLICY IF EXISTS rls_preview_gateway_certificates_preview_owner ON public.saas_preview_gateway_certificates;
DROP POLICY IF EXISTS rls_saas_preview_tunnel_registrations_definer ON public.saas_preview_tunnel_registrations;
DROP POLICY IF EXISTS rls_preview_gateway_instances_owner_lease_update ON public.saas_preview_gateway_instances;
CREATE POLICY rls_preview_gateway_instances_preview_edge
ON public.saas_preview_gateway_instances FOR SELECT TO saas_preview_edge
USING (pg_has_role(current_user, 'saas_preview_edge', 'member')
       AND status IN ('active', 'draining') AND lease_expires_at > CURRENT_TIMESTAMP);
CREATE POLICY rls_preview_gateway_instances_preview_owner_certificate
ON public.saas_preview_gateway_instances FOR SELECT TO saas_preview_owner
USING (pg_has_role(current_user, 'saas_preview_owner', 'member')
       AND public.saas_preview_owner_scope_is_current_v1()
       AND status IN ('active', 'draining') AND lease_expires_at > CURRENT_TIMESTAMP);
CREATE POLICY rls_preview_gateway_certificates_preview_edge
ON public.saas_preview_gateway_certificates FOR SELECT TO saas_preview_edge
USING (pg_has_role(current_user, 'saas_preview_edge', 'member')
       AND purpose = NULLIF(current_setting('app.presented_certificate_purpose', true), '')
       AND fingerprint_sha256 = NULLIF(current_setting('app.presented_certificate_fingerprint', true), '')
       AND certificate_not_before <= CURRENT_TIMESTAMP AND certificate_not_after > CURRENT_TIMESTAMP
       AND (status = 'active' OR (status = 'retiring' AND retire_at > CURRENT_TIMESTAMP))
       AND EXISTS (SELECT 1 FROM public.saas_preview_gateway_instances AS gateway
                   WHERE gateway.id = saas_preview_gateway_certificates.gateway_instance_id
                   AND gateway.status IN ('active', 'draining')
                   AND gateway.lease_expires_at > CURRENT_TIMESTAMP));
CREATE POLICY rls_preview_gateway_certificates_preview_owner
ON public.saas_preview_gateway_certificates FOR SELECT TO saas_preview_owner
USING (pg_has_role(current_user, 'saas_preview_owner', 'member')
       AND public.saas_preview_owner_scope_is_current_v1()
       AND purpose = NULLIF(current_setting('app.presented_certificate_purpose', true), '')
       AND fingerprint_sha256 = NULLIF(current_setting('app.presented_certificate_fingerprint', true), '')
       AND certificate_not_before <= CURRENT_TIMESTAMP AND certificate_not_after > CURRENT_TIMESTAMP
       AND (status = 'active' OR (status = 'retiring' AND retire_at > CURRENT_TIMESTAMP))
       AND EXISTS (SELECT 1 FROM public.saas_preview_gateway_instances AS gateway
                   WHERE gateway.id = saas_preview_gateway_certificates.gateway_instance_id
                   AND gateway.status IN ('active', 'draining')
                   AND gateway.lease_expires_at > CURRENT_TIMESTAMP));
GRANT SELECT (id, status, lease_expires_at, server_name, connect_host, connect_port)
ON public.saas_preview_gateway_instances TO saas_preview_edge;
GRANT SELECT ON public.saas_preview_gateway_certificates TO saas_preview_edge;
GRANT SELECT (id, status, lease_expires_at, server_name, connect_host, connect_port)
ON public.saas_preview_gateway_instances TO saas_preview_owner;
GRANT SELECT ON public.saas_preview_gateway_certificates TO saas_preview_owner;
CREATE POLICY rls_saas_preview_tunnel_registrations_definer
ON public.saas_preview_tunnel_registrations FOR ALL
USING (current_user = pg_get_userbyid((SELECT relation.relowner FROM pg_catalog.pg_class AS relation
                                     WHERE relation.oid = 'public.saas_preview_tunnel_registrations'::regclass)))
WITH CHECK (current_user = pg_get_userbyid((SELECT relation.relowner FROM pg_catalog.pg_class AS relation
                                          WHERE relation.oid = 'public.saas_preview_tunnel_registrations'::regclass)));
CREATE POLICY rls_preview_gateway_instances_owner_lease_update
ON public.saas_preview_gateway_instances FOR UPDATE
USING (current_user = pg_get_userbyid((SELECT relation.relowner FROM pg_catalog.pg_class AS relation
                                     WHERE relation.oid = 'public.saas_preview_gateway_instances'::regclass))
       AND pg_has_role(session_user, 'saas_preview_owner', 'member'))
WITH CHECK (current_user = pg_get_userbyid((SELECT relation.relowner FROM pg_catalog.pg_class AS relation
                                          WHERE relation.oid = 'public.saas_preview_gateway_instances'::regclass))
            AND pg_has_role(session_user, 'saas_preview_owner', 'member'));
-- The route policy already requires this role; limit expansion to it to avoid
-- the Owner runner/placement policy cycle before PostgreSQL evaluates predicates.
ALTER POLICY rls_runner_tunnel_placements_preview_route
ON public.saas_runner_tunnel_placements TO saas_preview_gateway;
