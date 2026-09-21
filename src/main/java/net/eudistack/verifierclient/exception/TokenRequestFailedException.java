package net.eudistack.verifierclient.exception;

/**
 * Thrown when the Verifier's token endpoint responds with a non-2xx status, or the response
 * body cannot be parsed as an OAuth2 token response.
 *
 * <p><b>Logging note:</b> {@link #getMessage()} deliberately does not include the Verifier's
 * response body — a hostile or compromised Verifier controls that content, and callers
 * commonly log exception messages at INFO/ERROR by default. Use {@link #responseBody()} if
 * you need it, and sanitize/size-limit it before logging.
 */
public class TokenRequestFailedException extends VerifierClientException {

    private final int httpStatus;
    private final String responseBody;

    public TokenRequestFailedException(int httpStatus, String responseBody) {
        super("Verifier token request failed with HTTP " + httpStatus
                + " (see responseBody() for the response, not included here)");
        this.httpStatus = httpStatus;
        this.responseBody = responseBody;
    }

    public TokenRequestFailedException(String message, Throwable cause) {
        super(message, cause);
        this.httpStatus = -1;
        this.responseBody = null;
    }

    /** HTTP status returned by the Verifier, or {@code -1} if the request never completed. */
    public int httpStatus() {
        return httpStatus;
    }

    /** Raw response body returned by the Verifier, or {@code null} if unavailable. */
    public String responseBody() {
        return responseBody;
    }
}
