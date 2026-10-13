-- Replay the reviewed Preview deployment projection on a dedicated test cluster.
-- The object owners grant relation access; only the bootstrap owns lease definers.
SET ROLE replay_saas;
CREATE POLICY rls_preview_gateway_instances_preview_edge
ON public.saas_preview_gateway_instances FOR SELECT TO saas_preview_edge
USING (pg_has_role(current_user, 'saas_preview_edge', 'member')
       AND status IN ('active', 'draining') AND lease_expires_at > CURRENT_TIMESTAMP);
CREATE POLICY rls_preview_gateway_instances_preview_owner_certificate
ON public.saas_preview_gateway_instances FOR SELECT TO saas_preview_owner
USING (pg_has_role(current_user, 'saas_preview_owner', 'member')
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
       AND purpose = NULLIF(current_setting('app.presented_certificate_purpose', true), '')
       AND fingerprint_sha256 = NULLIF(current_setting('app.presented_certificate_fingerprint', true), '')
       AND certificate_not_before <= CURRENT_TIMESTAMP AND certificate_not_after > CURRENT_TIMESTAMP
       AND (status = 'active' OR (status = 'retiring' AND retire_at > CURRENT_TIMESTAMP))
       AND EXISTS (SELECT 1 FROM public.saas_preview_gateway_instances AS gateway
                   WHERE gateway.id = saas_preview_gateway_certificates.gateway_instance_id
                   AND gateway.status IN ('active', 'draining')
                   AND gateway.lease_expires_at > CURRENT_TIMESTAMP));
GRANT SELECT ON public.saas_preview_gateway_instances,
                public.saas_preview_gateway_certificates TO saas_preview_edge;
GRANT SELECT (id, status, lease_expires_at, server_name)
ON public.saas_preview_gateway_instances TO saas_preview_owner;
GRANT SELECT ON public.saas_preview_gateway_certificates TO saas_preview_owner;
CREATE POLICY rls_saas_preview_tunnel_registrations_definer
ON public.saas_preview_tunnel_registrations FOR ALL
USING (current_user = pg_get_userbyid((SELECT relation.relowner FROM pg_catalog.pg_class AS relation
                                     WHERE relation.oid = 'public.saas_preview_tunnel_registrations'::regclass)))
WITH CHECK (current_user = pg_get_userbyid((SELECT relation.relowner FROM pg_catalog.pg_class AS relation
                                          WHERE relation.oid = 'public.saas_preview_tunnel_registrations'::regclass)));
RESET ROLE;
ALTER FUNCTION public.saas_preview_owner_heartbeat_gateway_v1(text,text) OWNER TO postgres;
ALTER FUNCTION public.saas_preview_owner_release_gateway_v1(text,text) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.saas_preview_owner_heartbeat_gateway_v1(text,text) FROM PUBLIC, saas_preview_owner;
REVOKE ALL ON FUNCTION public.saas_preview_owner_release_gateway_v1(text,text) FROM PUBLIC, saas_preview_owner;
GRANT EXECUTE ON FUNCTION public.saas_preview_owner_heartbeat_gateway_v1(text,text) TO saas_preview_owner;
GRANT EXECUTE ON FUNCTION public.saas_preview_owner_release_gateway_v1(text,text) TO saas_preview_owner;
