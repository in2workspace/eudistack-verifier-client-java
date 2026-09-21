package com.eudistack.verifierclient.exception;

/** Base type for every checked failure this SDK raises. */
public class VerifierClientException extends RuntimeException {

    public VerifierClientException(String message) {
        super(message);
    }

    public VerifierClientException(String message, Throwable cause) {
        super(message, cause);
    }
}
