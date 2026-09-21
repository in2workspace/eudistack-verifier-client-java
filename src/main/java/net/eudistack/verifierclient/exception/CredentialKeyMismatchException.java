package net.eudistack.verifierclient.exception;

/**
 * Thrown at client construction time when the configured private key's public counterpart
 * does not match the machine credential's declared confirmation key ({@code cnf}).
 *
 * <p>This is a client-side, fail-fast safety check performed before any network call —
 * catching a misconfigured key/credential pair during application startup instead of
 * letting the Verifier reject the eventual token request opaquely.
 */
public class CredentialKeyMismatchException extends VerifierClientException {

    public CredentialKeyMismatchException(String message) {
        super(message);
    }
}
