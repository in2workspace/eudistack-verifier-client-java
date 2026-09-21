package net.eudistack.verifierclient.jwt;

import net.eudistack.verifierclient.exception.InvalidConfigurationException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

/**
 * Builds the {@code client_assertion} JWT (RFC 7523 {@code private_key_jwt}) carrying the
 * VP-JWT as its {@code vp_token} claim.
 *
 * <p><b>Interop gotcha:</b> the Verifier decodes {@code vp_token} with
 * {@code java.util.Base64.getDecoder()} — i.e. <em>standard</em> Base64, not the URL-safe
 * variant used for JWS/JWT encoding. Encoding this claim with the wrong alphabet is silently
 * wrong (mismatched padding/charset) and only surfaces as an opaque rejection at the
 * Verifier, so it is deliberately spelled out here.
 */
public final class ClientAssertionBuilder {

    private static final long CLIENT_ASSERTION_LIFETIME_SECONDS = 120;

    private ClientAssertionBuilder() {}

    public static String build(ECKey privateKey, String clientId, String audience, String vpJwt) {
        Instant now = Instant.now();
        long iat = now.getEpochSecond();
        long exp = iat + CLIENT_ASSERTION_LIFETIME_SECONDS;

        String vpTokenStandardBase64 =
                Base64.getEncoder().encodeToString(vpJwt.getBytes(StandardCharsets.US_ASCII));

        JWTClaimsSet claims =
                new JWTClaimsSet.Builder()
                        .issuer(clientId)
                        .subject(clientId)
                        .audience(audience)
                        // Nimbus's JWTClaimsSet.Builder only accepts java.util.Date — this is the
                        // one unavoidable conversion point at that API boundary, not a choice.
                        .issueTime(Date.from(now))
                        .expirationTime(Date.from(Instant.ofEpochSecond(exp)))
                        .jwtID(UUID.randomUUID().toString())
                        .claim("vp_token", vpTokenStandardBase64)
                        .build();

        JWSHeader header =
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(JOSEObjectType.JWT)
                        .jwk(privateKey.toPublicJWK())
                        .build();

        SignedJWT signedJwt = new SignedJWT(header, claims);
        try {
            signedJwt.sign(new ECDSASigner(privateKey));
        } catch (JOSEException e) {
            throw new InvalidConfigurationException("Failed to sign the client_assertion JWT", e);
        }
        return signedJwt.serialize();
    }
}
