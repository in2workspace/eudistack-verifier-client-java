package net.eudistack.verifierclient;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import net.eudistack.verifierclient.config.VerifierM2MClientConfig;
import net.eudistack.verifierclient.credential.CredentialFixtures;
import net.eudistack.verifierclient.exception.InvalidConfigurationException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class VerifierM2MClientFromConfigTest {

    @TempDir Path tempDir;

    @Test
    void fromConfigStringLoadsAPropertiesFile() throws Exception {
        Path file = writeValidConfigFile("verifier-client.properties");

        assertThatCode(() -> VerifierM2MClient.fromConfig(file.toString())).doesNotThrowAnyException();
    }

    @Test
    void fromConfigPathLoadsAPropertiesFile() throws Exception {
        Path file = writeValidConfigFile("verifier-client.properties");

        assertThatCode(() -> VerifierM2MClient.fromConfig(file)).doesNotThrowAnyException();
    }

    @Test
    void fromConfigPathRejectsAMissingFile() {
        Path missing = tempDir.resolve("does-not-exist.properties");

        assertThatThrownBy(() -> VerifierM2MClient.fromConfig(missing))
                .isInstanceOf(InvalidConfigurationException.class)
                .hasMessageContaining("not found");
    }

    @Test
    void fromConfigRecordBuildsAClient() throws Exception {
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
        var config =
                new VerifierM2MClientConfig(
                        "https://verifier.example.org", privateKey.toJSONString(), credentialJwt);

        assertThatCode(() -> VerifierM2MClient.fromConfig(config)).doesNotThrowAnyException();
    }

    private Path writeValidConfigFile(String fileName) throws Exception {
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

        Path file = tempDir.resolve(fileName);
        Files.writeString(
                file,
                "verifier.url=https://verifier.example.org\n"
                        + "verifier.client.private-key-jwk="
                        + privateKey.toJSONString()
                        + "\n"
                        + "verifier.client.credential-jwt="
                        + credentialJwt
                        + "\n");
        return file;
    }
}
