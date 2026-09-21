package net.eudistack.verifierclient.binding;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import net.eudistack.verifierclient.credential.CredentialFixtures;
import net.eudistack.verifierclient.credential.MachineCredential;
import net.eudistack.verifierclient.exception.CredentialKeyMismatchException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CnfBindingValidatorTest {

    @Test
    void passesWhenPrivateKeyMatchesAJwkCnf() throws Exception {
        ECKey keyPair = new ECKeyGenerator(Curve.P_256).generate();
        ECKey publicJwk = keyPair.toPublicJWK();
        Map<String, Object> cnf =
                Map.of(
                        "jwk",
                        Map.of(
                                "kty", "EC",
                                "crv", "P-256",
                                "x", publicJwk.getX().toString(),
                                "y", publicJwk.getY().toString()));
        MachineCredential credential =
                MachineCredential.parse(CredentialFixtures.machineCredentialJwt(cnf));

        assertThatCode(() -> CnfBindingValidator.validate(keyPair, credential)).doesNotThrowAnyException();
    }

    @Test
    void failsFastWhenPrivateKeyDoesNotMatchAJwkCnf() throws Exception {
        ECKey configuredKey = new ECKeyGenerator(Curve.P_256).generate();
        ECKey unrelatedKey = new ECKeyGenerator(Curve.P_256).generate().toPublicJWK();
        Map<String, Object> cnf =
                Map.of(
                        "jwk",
                        Map.of(
                                "kty", "EC",
                                "crv", "P-256",
                                "x", unrelatedKey.getX().toString(),
                                "y", unrelatedKey.getY().toString()));
        MachineCredential credential =
                MachineCredential.parse(CredentialFixtures.machineCredentialJwt(cnf));

        assertThatThrownBy(() -> CnfBindingValidator.validate(configuredKey, credential))
                .isInstanceOf(CredentialKeyMismatchException.class);
    }

    @Test
    void passesWhenPrivateKeyMatchesADidKeyCnf() throws Exception {
        // Independently computed test vector shared with DidKeyCodecTest.
        String privateKeyJwk =
                "{\"kty\":\"EC\",\"crv\":\"P-256\","
                        + "\"x\":\"LVYqYX6d-wQ31mE6A4b7ucJBjo6JV9TXqf17FRiIMno\","
                        + "\"y\":\"OOzX2baxZnRthbl0-4prn9K6s4uaQO3bYAijgNB4bM8\","
                        + "\"d\":\"ABI0VniQq83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq80\"}";
        String matchingDidKey = "did:key:zDnaekiFy89Lofk88Qrjorneke49pTLfEDxbMPSQjWeNBRtvD";
        Map<String, Object> cnf = Map.of("kid", matchingDidKey + "#" + matchingDidKey.substring("did:key:".length()));
        ECKey privateKey = ECKey.parse(privateKeyJwk);
        MachineCredential credential =
                MachineCredential.parse(CredentialFixtures.machineCredentialJwt(cnf));

        assertThatCode(() -> CnfBindingValidator.validate(privateKey, credential)).doesNotThrowAnyException();
    }

    @Test
    void failsFastWhenPrivateKeyDoesNotMatchADidKeyCnf() throws Exception {
        ECKey configuredKey = new ECKeyGenerator(Curve.P_256).generate();
        String unrelatedDidKey = "did:key:zDnaekiFy89Lofk88Qrjorneke49pTLfEDxbMPSQjWeNBRtvD";
        Map<String, Object> cnf =
                Map.of("kid", unrelatedDidKey + "#" + unrelatedDidKey.substring("did:key:".length()));
        MachineCredential credential =
                MachineCredential.parse(CredentialFixtures.machineCredentialJwt(cnf));

        assertThatThrownBy(() -> CnfBindingValidator.validate(configuredKey, credential))
                .isInstanceOf(CredentialKeyMismatchException.class);
    }
}
