package net.eudistack.verifierclient.config;

import net.eudistack.verifierclient.exception.InvalidConfigurationException;

/**
 * The three values needed to authenticate: the caller's private key, its machine credential,
 * and the Verifier's base URL. Tenant and client_id are derived from the credential, not
 * configured directly.
 */
public record VerifierM2MClientConfig(String verifierUrl, String privateKeyJwk, String credentialJwt) {

    public VerifierM2MClientConfig {
        requireNonBlank(verifierUrl, "verifierUrl");
        requireNonBlank(privateKeyJwk, "privateKeyJwk");
        requireNonBlank(credentialJwt, "credentialJwt");
    }

    private static void requireNonBlank(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new InvalidConfigurationException(field + " must not be blank");
        }
    }
}
