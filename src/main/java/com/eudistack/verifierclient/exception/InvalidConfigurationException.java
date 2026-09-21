package com.eudistack.verifierclient.exception;

/**
 * Thrown when the SDK's configuration (private key, credential JWT, verifier URL, or a
 * loaded config file) is missing, malformed, or internally inconsistent.
 */
public class InvalidConfigurationException extends VerifierClientException {

    public InvalidConfigurationException(String message) {
        super(message);
    }

    public InvalidConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}
