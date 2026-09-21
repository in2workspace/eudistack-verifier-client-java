package com.eudistack.verifierclient.model;

/**
 * OAuth2 access token issued by the Verifier's {@code client_credentials} (M2M) grant.
 */
public record AccessToken(String accessToken, String tokenType, long expiresIn) {
}
