package com.eudistack.verifierclient.jwt;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class VpJwtBuilderTest {

    private static final String CLIENT_ID = "did:key:zDnaeTest";
    private static final String CREDENTIAL_JWT = "header.payload.signature";

    @Test
    void producesASelfSignedJwtVerifiableWithItsOwnEmbeddedKey() throws Exception {
        ECKey privateKey = new ECKeyGenerator(Curve.P_256).generate();

        String vpJwt = VpJwtBuilder.build(privateKey, CLIENT_ID, CREDENTIAL_JWT);

        SignedJWT parsed = SignedJWT.parse(vpJwt);
        ECKey embeddedPublicKey = (ECKey) parsed.getHeader().getJWK();
        assertThat(parsed.verify(new ECDSAVerifier(embeddedPublicKey))).isTrue();
    }

    @Test
    void payloadCarriesIssSubAndWrapsTheCredentialInAVerifiablePresentation() throws Exception {
        ECKey privateKey = new ECKeyGenerator(Curve.P_256).generate();

        String vpJwt = VpJwtBuilder.build(privateKey, CLIENT_ID, CREDENTIAL_JWT);
        var claims = SignedJWT.parse(vpJwt).getJWTClaimsSet();

        assertThat(claims.getIssuer()).isEqualTo(CLIENT_ID);
        assertThat(claims.getSubject()).isEqualTo(CLIENT_ID);
        assertThat(claims.getJWTID()).isNotBlank();

        @SuppressWarnings("unchecked")
        Map<String, Object> vp = (Map<String, Object>) claims.getClaim("vp");
        assertThat(vp.get("type")).isEqualTo(List.of("VerifiablePresentation"));
        assertThat(vp.get("verifiableCredential")).isEqualTo(List.of(CREDENTIAL_JWT));
    }

    @Test
    void expiresFiveMinutesAfterIssuance() throws Exception {
        ECKey privateKey = new ECKeyGenerator(Curve.P_256).generate();

        String vpJwt = VpJwtBuilder.build(privateKey, CLIENT_ID, CREDENTIAL_JWT);
        var claims = SignedJWT.parse(vpJwt).getJWTClaimsSet();

        long iat = claims.getIssueTime().toInstant().getEpochSecond();
        long exp = claims.getExpirationTime().toInstant().getEpochSecond();
        assertThat(exp - iat).isEqualTo(300L);
        assertThat(iat).isCloseTo(Instant.now().getEpochSecond(), org.assertj.core.data.Offset.offset(5L));
    }
}
