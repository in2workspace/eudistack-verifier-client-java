package net.eudistack.verifierclient;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import net.eudistack.verifierclient.credential.CredentialFixtures;
import net.eudistack.verifierclient.exception.CredentialKeyMismatchException;
import net.eudistack.verifierclient.exception.TokenRequestFailedException;
import net.eudistack.verifierclient.model.AccessToken;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class VerifierM2MClientIntegrationTest {

    private WireMockServer wireMockServer;

    @BeforeEach
    void startServer() {
        wireMockServer = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        wireMockServer.start();
    }

    @AfterEach
    void stopServer() {
        wireMockServer.stop();
    }

    @Test
    void authenticatesAndReturnsTheAccessToken() throws Exception {
        wireMockServer.stubFor(
                post(urlEqualTo("/oidc/token"))
                        .withHeader("Content-Type", equalTo("application/x-www-form-urlencoded"))
                        .withHeader("X-Tenant", equalTo(CredentialFixtures.TENANT))
                        .withRequestBody(containing("grant_type=client_credentials"))
                        .withRequestBody(containing("client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"abc123\",\"token_type\":\"Bearer\",\"expires_in\":3600}")));

        VerifierM2MClient client = buildClientAgainstStub();

        AccessToken token = client.authenticate();

        assertThat(token.accessToken()).isEqualTo("abc123");
        assertThat(token.tokenType()).isEqualTo("Bearer");
        assertThat(token.expiresIn()).isEqualTo(3600L);
    }

    @Test
    void surfacesA4xxAsTokenRequestFailedException() throws Exception {
        wireMockServer.stubFor(
                post(urlEqualTo("/oidc/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(400)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"error\":\"invalid_client\"}")));

        VerifierM2MClient client = buildClientAgainstStub();

        assertThatThrownBy(client::authenticate)
                .isInstanceOf(TokenRequestFailedException.class)
                .satisfies(
                        e -> {
                            var ex = (TokenRequestFailedException) e;
                            assertThat(ex.httpStatus()).isEqualTo(400);
                            assertThat(ex.responseBody()).contains("invalid_client");
                        });
    }

    @Test
    void refusesToBuildWhenPrivateKeyDoesNotMatchCredentialCnf() {
        ECKey configuredKey = generateKey();
        ECKey unrelatedPublicKey = generateKey().toPublicJWK();
        Map<String, Object> mismatchedCnf =
                Map.of(
                        "jwk",
                        Map.of(
                                "kty", "EC",
                                "crv", "P-256",
                                "x", unrelatedPublicKey.getX().toString(),
                                "y", unrelatedPublicKey.getY().toString()));
        String credentialJwt = CredentialFixtures.machineCredentialJwt(mismatchedCnf);

        assertThatThrownBy(
                        () ->
                                VerifierM2MClient.builder()
                                        .verifierUrl(wireMockServer.baseUrl())
                                        .privateKeyJwk(configuredKey.toJSONString())
                                        .credentialJwt(credentialJwt)
                                        .build())
                .isInstanceOf(CredentialKeyMismatchException.class);
    }

    private VerifierM2MClient buildClientAgainstStub() throws Exception {
        ECKey privateKey = generateKey();
        ECKey publicJwk = privateKey.toPublicJWK();
        Map<String, Object> cnf =
                Map.of(
                        "jwk",
                        Map.of(
                                "kty", "EC",
                                "crv", "P-256",
                                "x", publicJwk.getX().toString(),
                                "y", publicJwk.getY().toString()));
        String credentialJwt = CredentialFixtures.machineCredentialJwt(cnf);

        return VerifierM2MClient.builder()
                .verifierUrl(wireMockServer.baseUrl())
                .privateKeyJwk(privateKey.toJSONString())
                .credentialJwt(credentialJwt)
                .build();
    }

    private static ECKey generateKey() {
        try {
            return new ECKeyGenerator(Curve.P_256).generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
