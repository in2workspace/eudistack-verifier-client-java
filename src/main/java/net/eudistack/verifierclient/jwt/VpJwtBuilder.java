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
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Builds the self-signed Verifiable Presentation JWT that wraps the machine credential.
 *
 * <p>Per the Verifier's proof-of-possession check, the JWS header carries the signer's own
 * public key ({@code jwk}) — this, not the credential's {@code cnf}, is what the Verifier
 * validates the signature against for the M2M grant.
 */
public final class VpJwtBuilder {

    private static final String VP_CONTEXT = "https://www.w3.org/2018/credentials/v1";
    private static final long VP_JWT_LIFETIME_SECONDS = 300;

    private VpJwtBuilder() {}

    public static String build(ECKey privateKey, String clientId, String credentialJwt) {
        Instant now = Instant.now();
        long iat = now.getEpochSecond();
        long exp = iat + VP_JWT_LIFETIME_SECONDS;

        Map<String, Object> vp =
                Map.of(
                        "@context", List.of(VP_CONTEXT),
                        "type", List.of("VerifiablePresentation"),
                        "verifiableCredential", List.of(credentialJwt));

        JWTClaimsSet claims =
                new JWTClaimsSet.Builder()
                        .issuer(clientId)
                        .subject(clientId)
                        .issueTime(Date.from(now))
                        .expirationTime(Date.from(Instant.ofEpochSecond(exp)))
                        .jwtID(UUID.randomUUID().toString())
                        .claim("vp", vp)
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
            throw new InvalidConfigurationException("Failed to sign the VP-JWT", e);
        }
        return signedJwt.serialize();
    }
}
