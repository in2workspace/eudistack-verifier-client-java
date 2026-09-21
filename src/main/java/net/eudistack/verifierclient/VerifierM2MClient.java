package net.eudistack.verifierclient;

import net.eudistack.verifierclient.binding.CnfBindingValidator;
import net.eudistack.verifierclient.config.ConfigLoader;
import net.eudistack.verifierclient.config.VerifierM2MClientConfig;
import net.eudistack.verifierclient.credential.MachineCredential;
import net.eudistack.verifierclient.exception.CredentialKeyMismatchException;
import net.eudistack.verifierclient.exception.InvalidConfigurationException;
import net.eudistack.verifierclient.exception.TokenRequestFailedException;
import net.eudistack.verifierclient.jwt.EcKeyLoader;
import net.eudistack.verifierclient.model.AccessToken;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Authenticates against an OID4VP-style Verifier's M2M ({@code client_credentials}) grant,
 * proving possession of a private key bound to a machine credential.
 *
 * <p>Construction eagerly validates that the configured private key matches the credential's
 * confirmation key ({@code cnf}) — see {@link CredentialKeyMismatchException} — so a
 * misconfigured client fails at startup, not on the first call to {@link #authenticate()}.
 *
 * <h2>Quick start</h2>
 *
 * <pre>{@code
 * VerifierM2MClient client = VerifierM2MClient.builder()
 *     .verifierUrl("https://verifier.example.org")
 *     .privateKey(privateKey)
 *     .credentialJwt(machineCredentialJwt)
 *     .build();
 *
 * AccessToken token = client.authenticate();
 * }</pre>
 */
public interface VerifierM2MClient {

    /**
     * Performs the M2M {@code client_credentials} grant and returns the issued access token.
     *
     * @throws TokenRequestFailedException if the Verifier rejects the request or is unreachable
     */
    AccessToken authenticate();

    static Builder builder() {
        return new Builder();
    }

    /** Builds a client from a {@code .yaml}/{@code .yml} or {@code .properties} config file. */
    static VerifierM2MClient fromConfig(String path) {
        return fromConfig(Path.of(path));
    }

    static VerifierM2MClient fromConfig(Path path) {
        if (!Files.isRegularFile(path)) {
            throw new InvalidConfigurationException("Config file not found: " + path);
        }
        VerifierM2MClientConfig config = ConfigLoader.load(path);
        return fromConfig(config);
    }

    static VerifierM2MClient fromConfig(VerifierM2MClientConfig config) {
        return fromConfig(config, false);
    }

    private static VerifierM2MClient fromConfig(VerifierM2MClientConfig config, boolean allowInsecureHttp) {
        var privateKey = EcKeyLoader.loadPrivateKey(config.privateKey());
        var credential = MachineCredential.parse(config.credentialJwt());
        CnfBindingValidator.validate(privateKey, credential);
        return new VerifierM2MClientImpl(config.verifierUrl(), privateKey, credential, allowInsecureHttp);
    }

    /** Builder for {@link VerifierM2MClient}, taking the 3 configuration values directly. */
    final class Builder {

        private String verifierUrl;
        private String privateKey;
        private String credentialJwt;
        private boolean allowInsecureHttp = false;

        private Builder() {}

        public Builder verifierUrl(String verifierUrl) {
            this.verifierUrl = verifierUrl;
            return this;
        }

        /**
         * The private key, as either a JWK JSON object or a raw hex-encoded P-256 scalar —
         * see {@link net.eudistack.verifierclient.jwt.EcKeyLoader}.
         */
        public Builder privateKey(String privateKey) {
            this.privateKey = privateKey;
            return this;
        }

        public Builder privateKeyFile(Path path) {
            this.privateKey = readFile(path, "privateKeyFile");
            return this;
        }

        public Builder credentialJwt(String credentialJwt) {
            this.credentialJwt = credentialJwt;
            return this;
        }

        public Builder credentialJwtFile(Path path) {
            this.credentialJwt = readFile(path, "credentialJwtFile");
            return this;
        }

        /**
         * Allows {@code verifierUrl} to use plain {@code http://} instead of requiring
         * {@code https://}. <b>Test-only.</b> The {@code client_assertion} sent on every
         * {@link #authenticate()} call is a replayable, bearer-equivalent credential valid
         * for a short window — sending it over a cleartext channel lets a passive network
         * observer capture and replay it. Never use this against a production Verifier.
         */
        public Builder allowInsecureHttp() {
            this.allowInsecureHttp = true;
            return this;
        }

        /**
         * Builds the client, eagerly validating the private key against the credential's
         * {@code cnf}.
         *
         * @throws InvalidConfigurationException if any of the 3 fields is missing/malformed
         * @throws CredentialKeyMismatchException if the private key does not match {@code cnf}
         */
        public VerifierM2MClient build() {
            var config = new VerifierM2MClientConfig(verifierUrl, privateKey, credentialJwt);
            return fromConfig(config, allowInsecureHttp);
        }

        private static String readFile(Path path, String field) {
            try {
                return Files.readString(path);
            } catch (java.io.IOException e) {
                throw new InvalidConfigurationException(
                        "Failed to read file for " + field + ": " + path, e);
            }
        }
    }
}
