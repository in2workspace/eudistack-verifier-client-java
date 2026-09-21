package net.eudistack.verifierclient;

import net.eudistack.verifierclient.credential.MachineCredential;
import net.eudistack.verifierclient.exception.InvalidConfigurationException;
import net.eudistack.verifierclient.http.TokenEndpointClient;
import net.eudistack.verifierclient.jwt.ClientAssertionBuilder;
import net.eudistack.verifierclient.jwt.VpJwtBuilder;
import net.eudistack.verifierclient.model.AccessToken;
import com.nimbusds.jose.jwk.ECKey;
import java.net.URI;
import java.net.URISyntaxException;

final class VerifierM2MClientImpl implements VerifierM2MClient {

    private final URI tokenEndpoint;
    private final URI audience;
    private final ECKey privateKey;
    private final MachineCredential credential;
    private final TokenEndpointClient httpClient;

    VerifierM2MClientImpl(
            String verifierUrl, ECKey privateKey, MachineCredential credential, boolean allowInsecureHttp) {
        this.audience = toUri(verifierUrl, allowInsecureHttp);
        this.tokenEndpoint = toUri(trimSlash(verifierUrl) + "/oidc/token", allowInsecureHttp);
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

    private static URI toUri(String verifierUrl, boolean allowInsecureHttp) {
        try {
            URI uri = new URI(verifierUrl);
            if (uri.getScheme() == null || uri.getHost() == null) {
                throw new InvalidConfigurationException("verifierUrl must be an absolute URL: " + verifierUrl);
            }
            boolean isHttps = "https".equalsIgnoreCase(uri.getScheme());
            boolean isHttp = "http".equalsIgnoreCase(uri.getScheme());
            if (!isHttps && !(isHttp && allowInsecureHttp)) {
                throw new InvalidConfigurationException(
                        "verifierUrl must use https (the client_assertion is a replayable "
                                + "bearer-equivalent credential and must not be sent in cleartext); "
                                + "found scheme '"
                                + uri.getScheme()
                                + "'. Use VerifierM2MClient.builder().allowInsecureHttp() only for local "
                                + "testing against a non-TLS Verifier.");
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
