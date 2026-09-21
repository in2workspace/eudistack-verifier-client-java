package com.eudistack.verifierclient;

import com.eudistack.verifierclient.credential.MachineCredential;
import com.eudistack.verifierclient.exception.InvalidConfigurationException;
import com.eudistack.verifierclient.http.TokenEndpointClient;
import com.eudistack.verifierclient.jwt.ClientAssertionBuilder;
import com.eudistack.verifierclient.jwt.VpJwtBuilder;
import com.eudistack.verifierclient.model.AccessToken;
import com.nimbusds.jose.jwk.ECKey;
import java.net.URI;
import java.net.URISyntaxException;

final class VerifierM2MClientImpl implements VerifierM2MClient {

    private final URI tokenEndpoint;
    private final URI audience;
    private final ECKey privateKey;
    private final MachineCredential credential;
    private final TokenEndpointClient httpClient;

    VerifierM2MClientImpl(String verifierUrl, ECKey privateKey, MachineCredential credential) {
        this.audience = toUri(verifierUrl);
        this.tokenEndpoint = toUri(trimSlash(verifierUrl) + "/oidc/token");
        this.privateKey = privateKey;
        this.credential = credential;
        this.httpClient = new TokenEndpointClient();
    }

    @Override
    public AccessToken authenticate() {
        String vpJwt = VpJwtBuilder.build(privateKey, credential.clientId(), credential.compactJwt());
        String clientAssertion =
                ClientAssertionBuilder.build(privateKey, credential.clientId(), audience.toString(), vpJwt);

        return httpClient.requestToken(
                tokenEndpoint, credential.clientId(), clientAssertion, credential.tenant());
    }

    private static URI toUri(String verifierUrl) {
        try {
            URI uri = new URI(verifierUrl);
            if (uri.getScheme() == null || uri.getHost() == null) {
                throw new InvalidConfigurationException("verifierUrl must be an absolute URL: " + verifierUrl);
            }
            return uri;
        } catch (URISyntaxException e) {
            throw new InvalidConfigurationException("verifierUrl is not a valid URL: " + verifierUrl, e);
        }
    }

    private static String trimSlash(String path) {
        if (path == null || path.isEmpty()) {
            return "";
        }
        return path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
    }
}
