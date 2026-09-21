package net.eudistack.verifierclient.http;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import net.eudistack.verifierclient.exception.TokenRequestFailedException;
import net.eudistack.verifierclient.model.AccessToken;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import java.net.URI;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TokenEndpointClientTest {

    private WireMockServer wireMockServer;
    private TokenEndpointClient client;

    @BeforeEach
    void startServer() {
        wireMockServer = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        wireMockServer.start();
        client = new TokenEndpointClient();
    }

    @AfterEach
    void stopServer() {
        wireMockServer.stop();
    }

    @Test
    void defaultsTokenTypeAndExpiresInWhenTheVerifierOmitsThem() {
        wireMockServer.stubFor(
                post(urlEqualTo("/oidc/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"access_token\":\"abc123\"}")));

        AccessToken token = client.requestToken(tokenEndpoint(), "client-id", "assertion", "tenant");

        assertThat(token.accessToken()).isEqualTo("abc123");
        assertThat(token.tokenType()).isEqualTo("Bearer");
        assertThat(token.expiresIn()).isZero();
    }

    @Test
    void rejectsA2xxResponseThatIsNotValidJson() {
        wireMockServer.stubFor(
                post(urlEqualTo("/oidc/token"))
                        .willReturn(aResponse().withStatus(200).withBody("not-json")));

        assertThatThrownBy(() -> client.requestToken(tokenEndpoint(), "client-id", "assertion", "tenant"))
                .isInstanceOf(TokenRequestFailedException.class);
    }

    @Test
    void rejectsA2xxResponseMissingTheAccessTokenField() {
        wireMockServer.stubFor(
                post(urlEqualTo("/oidc/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"token_type\":\"Bearer\"}")));

        assertThatThrownBy(() -> client.requestToken(tokenEndpoint(), "client-id", "assertion", "tenant"))
                .isInstanceOf(TokenRequestFailedException.class)
                .satisfies(e -> assertThat(((TokenRequestFailedException) e).httpStatus()).isEqualTo(200));
    }

    @Test
    void wrapsAConnectionFailureAsTokenRequestFailedException() {
        URI unreachableEndpoint = tokenEndpoint();
        wireMockServer.stop();

        assertThatThrownBy(
                        () -> client.requestToken(unreachableEndpoint, "client-id", "assertion", "tenant"))
                .isInstanceOf(TokenRequestFailedException.class)
                .hasMessageContaining("Failed to reach");
    }

    private URI tokenEndpoint() {
        return URI.create(wireMockServer.baseUrl() + "/oidc/token");
    }
}
