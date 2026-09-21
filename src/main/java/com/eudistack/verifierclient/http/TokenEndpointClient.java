package com.eudistack.verifierclient.http;

import com.eudistack.verifierclient.exception.TokenRequestFailedException;
import com.eudistack.verifierclient.model.AccessToken;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

/** POSTs the {@code client_credentials} grant to the Verifier's token endpoint. */
public final class TokenEndpointClient {

    private static final String CLIENT_ASSERTION_TYPE =
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

    private final HttpClient httpClient;

    public TokenEndpointClient() {
        this(HttpClient.newBuilder().connectTimeout(REQUEST_TIMEOUT).build());
    }

    public TokenEndpointClient(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public AccessToken requestToken(
            URI tokenEndpoint, String clientId, String clientAssertion, String tenant) {
        String body =
                "grant_type="
                        + encode("client_credentials")
                        + "&client_id="
                        + encode(clientId)
                        + "&client_assertion_type="
                        + encode(CLIENT_ASSERTION_TYPE)
                        + "&client_assertion="
                        + encode(clientAssertion);

        HttpRequest request =
                HttpRequest.newBuilder(tokenEndpoint)
                        .timeout(REQUEST_TIMEOUT)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .header("X-Tenant", tenant)
                        .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                        .build();

        HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new TokenRequestFailedException("Failed to reach the Verifier token endpoint", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TokenRequestFailedException("Interrupted while calling the Verifier", e);
        }

        if (response.statusCode() / 100 != 2) {
            throw new TokenRequestFailedException(response.statusCode(), response.body());
        }

        return parseAccessToken(response.body());
    }

    private static AccessToken parseAccessToken(String responseBody) {
        Map<String, Object> json;
        try {
            json = JSONObjectUtils.parse(responseBody);
        } catch (java.text.ParseException e) {
            throw new TokenRequestFailedException(
                    "Verifier returned a 2xx response that is not valid JSON", e);
        }

        Object accessToken = json.get("access_token");
        if (!(accessToken instanceof String)) {
            throw new TokenRequestFailedException(200, responseBody);
        }
        Object tokenType = json.getOrDefault("token_type", "Bearer");
        Object expiresIn = json.getOrDefault("expires_in", 0);

        return new AccessToken(
                (String) accessToken,
                String.valueOf(tokenType),
                expiresIn instanceof Number number ? number.longValue() : parseLongOrZero(expiresIn));
    }

    private static long parseLongOrZero(Object value) {
        try {
            return Long.parseLong(String.valueOf(value));
        } catch (NumberFormatException e) {
            return 0L;
        }
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
