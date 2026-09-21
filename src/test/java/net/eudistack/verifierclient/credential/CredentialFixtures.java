package net.eudistack.verifierclient.credential;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.util.List;
import java.util.Map;

/**
 * Builds minimal, realistic machine credential JWTs for tests. The signing key here is
 * unrelated to the credential's {@code cnf} — {@link MachineCredential} does not verify
 * credential signatures, it only extracts fields, mirroring how this SDK's caller is
 * expected to supply an already-trusted credential.
 */
public final class CredentialFixtures {

    public static final String CLIENT_ID = "did:key:zDnaeTestMandatee";
    public static final String TENANT = "dome";

    private CredentialFixtures() {}

    public static String machineCredentialJwt(Object cnfClaimValue) {
        try {
            ECKey signingKey = new ECKeyGenerator(Curve.P_256).generate();

            Map<String, Object> mandatee = Map.of("id", CLIENT_ID);
            Map<String, Object> power = Map.of("domain", TENANT);
            Map<String, Object> mandate = Map.of("mandatee", mandatee, "power", List.of(power));
            Map<String, Object> credentialSubject = Map.of("mandate", mandate);
            Map<String, Object> vc =
                    Map.of("credentialSubject", credentialSubject, "cnf", cnfClaimValue);

            JWTClaimsSet claims =
                    new JWTClaimsSet.Builder().claim("vc", vc).claim("cnf", cnfClaimValue).build();

            SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claims);
            jwt.sign(new ECDSASigner(signingKey));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build fixture credential JWT", e);
        }
    }
}
