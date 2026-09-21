package net.eudistack.verifierclient;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import net.eudistack.verifierclient.credential.CredentialFixtures;
import net.eudistack.verifierclient.exception.InvalidConfigurationException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class VerifierM2MClientBuilderTest {

    @TempDir Path tempDir;

    @Test
    void buildsFromPrivateKeyAndCredentialFiles() throws Exception {
        ECKey privateKey = new ECKeyGenerator(Curve.P_256).generate();
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

        Path keyFile = tempDir.resolve("key.jwk.json");
        Files.writeString(keyFile, privateKey.toJSONString());
        Path credentialFile = tempDir.resolve("credential.jwt");
        Files.writeString(credentialFile, credentialJwt);

        assertThatCode(
                        () ->
                                VerifierM2MClient.builder()
                                        .verifierUrl("https://verifier.example.org")
                                        .privateKeyJwkFile(keyFile)
                                        .credentialJwtFile(credentialFile)
                                        .build())
                .doesNotThrowAnyException();
    }

    @Test
    void privateKeyJwkFileWrapsAMissingFileAsInvalidConfigurationException() {
        Path missing = tempDir.resolve("does-not-exist.jwk.json");
        VerifierM2MClient.Builder builder = VerifierM2MClient.builder();

        assertThatThrownBy(() -> builder.privateKeyJwkFile(missing))
                .isInstanceOf(InvalidConfigurationException.class)
                .hasCauseInstanceOf(IOException.class);
    }

    @Test
    void credentialJwtFileWrapsAMissingFileAsInvalidConfigurationException() {
        Path missing = tempDir.resolve("does-not-exist.jwt");
        VerifierM2MClient.Builder builder = VerifierM2MClient.builder();

        assertThatThrownBy(() -> builder.credentialJwtFile(missing))
                .isInstanceOf(InvalidConfigurationException.class)
                .hasCauseInstanceOf(IOException.class);
    }
}
