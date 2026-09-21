package net.eudistack.verifierclient.config;

import net.eudistack.verifierclient.exception.InvalidConfigurationException;

/**
 * The three values needed to authenticate: the caller's private key (JWK JSON or a raw hex
 * scalar — see {@link net.eudistack.verifierclient.jwt.EcKeyLoader}), its machine credential,
 * and the Verifier's base URL. Tenant and client_id are derived from the credential, not
 * configured directly.
 */
public record VerifierM2MClientConfig(String verifierUrl, String privateKey, String credentialJwt) {

    public VerifierM2MClientConfig {
        requireNonBlank(verifierUrl, "verifierUrl");
        requireNonBlank(privateKey, "privateKey");
        requireNonBlank(credentialJwt, "credentialJwt");
    }

    private static void requireNonBlank(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new InvalidConfigurationException(field + " must not be blank");
        }
    }

    /**
     * Redacts {@code privateKey} and {@code credentialJwt} — a record's generated
     * {@code toString()} would otherwise print both verbatim, and this is a public type a
     * caller could easily log (e.g. {@code log.debug("config={}", config)}).
     */
    @Override
    public String toString() {
        return "VerifierM2MClientConfig[verifierUrl="
                + verifierUrl
                + ", privateKey=<redacted>, credentialJwt=<redacted>]";
    }
}
