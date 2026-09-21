package com.eudistack.verifierclient.credential;

import com.eudistack.verifierclient.exception.InvalidConfigurationException;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.util.List;
import java.util.Map;

/**
 * A parsed machine credential JWT (e.g. a LEARCredentialMachine), exposing only the fields
 * this SDK needs: the mandatee's {@code client_id} (its {@code did:key}), the tenant it is
 * scoped to, its confirmation key, and the original compact JWT string to embed in the VP.
 *
 * <p>This SDK does not validate the credential's own signature or expiry — it is the
 * caller's responsibility to supply a credential it trusts; the SDK only presents it.
 */
public final class MachineCredential {

    private final String compactJwt;
    private final String clientId;
    private final String tenant;
    private final String confirmationKey;

    private MachineCredential(String compactJwt, String clientId, String tenant, String confirmationKey) {
        this.compactJwt = compactJwt;
        this.clientId = clientId;
        this.tenant = tenant;
        this.confirmationKey = confirmationKey;
    }

    /** Parses a machine credential JWT, extracting the {@code credentialSubject.mandate} block. */
    public static MachineCredential parse(String credentialJwt) {
        if (credentialJwt == null || credentialJwt.isBlank()) {
            throw new InvalidConfigurationException("credentialJwt must not be blank");
        }

        JWTClaimsSet claims;
        try {
            claims = SignedJWT.parse(credentialJwt).getJWTClaimsSet();
        } catch (ParseException e) {
            throw new InvalidConfigurationException("credentialJwt is not a valid JWT", e);
        }

        Map<String, Object> vc = asVcObject(claims);
        Map<String, Object> credentialSubject = nestedObject(vc, "credentialSubject");
        Map<String, Object> mandate = nestedObject(credentialSubject, "mandate");
        Map<String, Object> mandatee = nestedObject(mandate, "mandatee");

        String clientId = stringField(mandatee, "id", "credentialSubject.mandate.mandatee.id");
        String tenant = extractTenant(mandate);
        // 'cnf' may live at the top level of the JWT claims, or nested inside 'vc' —
        // support both since different issuers place it differently.
        Object cnf = claims.getClaim("cnf") != null ? claims.getClaim("cnf") : vc.get("cnf");
        String confirmationKey = extractConfirmationKey(cnf);

        return new MachineCredential(credentialJwt, clientId, tenant, confirmationKey);
    }

    /** The mandatee's {@code did:key}, used as {@code client_id} in the token request. */
    public String clientId() {
        return clientId;
    }

    /** Tenant this credential is scoped to, derived from {@code mandate.power[].domain}. */
    public String tenant() {
        return tenant;
    }

    /** The credential's confirmation key, either a JWK-object JSON string or a {@code did:key}. */
    public String confirmationKey() {
        return confirmationKey;
    }

    /** The original compact JWT string, as supplied — embedded verbatim in the VP. */
    public String compactJwt() {
        return compactJwt;
    }

    @SuppressWarnings("unchecked")
    private static String extractTenant(Map<String, Object> mandate) {
        Object powerObj = mandate.get("power");
        if (powerObj instanceof List<?> powerList && !powerList.isEmpty()) {
            for (Object entry : powerList) {
                if (entry instanceof Map<?, ?> powerEntry) {
                    Object domain = powerEntry.get("domain");
                    if (domain instanceof String domainString && !domainString.isBlank()) {
                        return domainString;
                    }
                }
            }
        }
        throw new InvalidConfigurationException(
                "credentialJwt has no mandate.power[].domain — cannot derive the tenant");
    }

    @SuppressWarnings("unchecked")
    private static String extractConfirmationKey(Object cnf) {
        if (cnf instanceof String didKey) {
            return didKey;
        }
        if (cnf instanceof Map<?, ?> cnfMap) {
            Object jwk = ((Map<String, Object>) cnfMap).get("jwk");
            if (jwk != null) {
                return JSONObjectUtils.toJSONString((Map<String, Object>) jwk);
            }
        }
        throw new InvalidConfigurationException(
                "credentialJwt has no cnf claim (expected a did:key string or a {\"jwk\": {...}} object)");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> nestedObject(Map<String, Object> parent, String field) {
        Object value = parent == null ? null : parent.get(field);
        if (!(value instanceof Map)) {
            throw new InvalidConfigurationException(
                    "credentialJwt is missing expected object field: " + field);
        }
        return (Map<String, Object>) value;
    }

    private static String stringField(Map<String, Object> parent, String field, String path) {
        Object value = parent.get(field);
        if (!(value instanceof String str) || str.isBlank()) {
            throw new InvalidConfigurationException(
                    "credentialJwt is missing expected string field: " + path);
        }
        return str;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asVcObject(JWTClaimsSet claims) {
        Object vcClaim = claims.getClaim("vc");
        if (vcClaim instanceof Map) {
            return (Map<String, Object>) vcClaim;
        }
        // Some issuers flatten the VC directly into the top-level JWT claims instead of
        // nesting it under a 'vc' claim — fall back to the full claim set in that case.
        return claims.getClaims();
    }
}
