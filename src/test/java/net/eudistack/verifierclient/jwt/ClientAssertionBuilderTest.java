package net.eudistack.verifierclient.jwt;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class ClientAssertionBuilderTest {

    private static final String CLIENT_ID = "did:key:zDnaeTest";
    private static final String AUDIENCE = "https://verifier.example.org";

    @Test
    void issuesTimestampsInSecondsNotMilliseconds() throws Exception {
        ECKey privateKey = new ECKeyGenerator(Curve.P_256).generate();
        String vpJwt = VpJwtBuilder.build(privateKey, CLIENT_ID, "dummy-credential-jwt");

        String clientAssertion = ClientAssertionBuilder.build(privateKey, CLIENT_ID, AUDIENCE, vpJwt);

        var claims = SignedJWT.parse(clientAssertion).getJWTClaimsSet();
        long nowSeconds = Instant.now().getEpochSecond();
        long iatSeconds = claims.getIssueTime().toInstant().getEpochSecond();
        long expSeconds = claims.getExpirationTime().toInstant().getEpochSecond();

        assertThat(iatSeconds).isCloseTo(nowSeconds, org.assertj.core.data.Offset.offset(5L));
        assertThat(expSeconds).isGreaterThan(iatSeconds).isLessThan(iatSeconds + 300);
    }

    @Test
    void encodesVpTokenAsStandardBase64NotUrlSafe() throws Exception {
        ECKey privateKey = new ECKeyGenerator(Curve.P_256).generate();
        String vpJwt = VpJwtBuilder.build(privateKey, CLIENT_ID, "dummy-credential-jwt");

        String clientAssertion = ClientAssertionBuilder.build(privateKey, CLIENT_ID, AUDIENCE, vpJwt);

        var claims = SignedJWT.parse(clientAssertion).getJWTClaimsSet();
        String vpToken = (String) claims.getClaim("vp_token");

        // vp_token must decode with the STANDARD Base64 alphabet (not URL-safe) to reproduce
        // the original VP-JWT — see ClientAssertionBuilder's class Javadoc for why.
        String decoded = new String(Base64.getDecoder().decode(vpToken), StandardCharsets.US_ASCII);
        assertThat(decoded).isEqualTo(vpJwt);
    }

    @Test
    void embedsPublicKeyInJwsHeader() throws Exception {
        ECKey privateKey = new ECKeyGenerator(Curve.P_256).generate();
        String vpJwt = VpJwtBuilder.build(privateKey, CLIENT_ID, "dummy-credential-jwt");

        String clientAssertion = ClientAssertionBuilder.build(privateKey, CLIENT_ID, AUDIENCE, vpJwt);

        var header = SignedJWT.parse(clientAssertion).getHeader();
        assertThat(header.getJWK()).isNotNull();
        assertThat(((ECKey) header.getJWK()).getCurve()).isEqualTo(Curve.P_256);
        assertThat(((ECKey) header.getJWK()).getX()).isEqualTo(privateKey.getX());
    }
}
