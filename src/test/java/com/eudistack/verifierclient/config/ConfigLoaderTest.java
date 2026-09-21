package com.eudistack.verifierclient.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.eudistack.verifierclient.exception.InvalidConfigurationException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ConfigLoaderTest {

    @TempDir Path tempDir;

    @Test
    void loadsInlineValuesFromProperties() throws IOException {
        Path file = tempDir.resolve("verifier-client.properties");
        Files.writeString(
                file,
                """
                verifier.url=https://verifier.example.org
                verifier.private-key-jwk={"kty":"EC"}
                verifier.credential-jwt=header.payload.signature
                """);

        VerifierM2MClientConfig config = ConfigLoader.load(file);

        assertThat(config.verifierUrl()).isEqualTo("https://verifier.example.org");
        assertThat(config.privateKeyJwk()).isEqualTo("{\"kty\":\"EC\"}");
        assertThat(config.credentialJwt()).isEqualTo("header.payload.signature");
    }

    @Test
    void loadsFileReferencesFromProperties() throws IOException {
        Path keyFile = tempDir.resolve("key.jwk.json");
        Files.writeString(keyFile, "{\"kty\":\"EC\"}");
        Path credentialFile = tempDir.resolve("credential.jwt");
        Files.writeString(credentialFile, "header.payload.signature");

        Path file = tempDir.resolve("verifier-client.properties");
        Files.writeString(
                file,
                """
                verifier.url=https://verifier.example.org
                verifier.private-key-jwk-path=key.jwk.json
                verifier.credential-jwt-path=credential.jwt
                """);

        VerifierM2MClientConfig config = ConfigLoader.load(file);

        assertThat(config.privateKeyJwk()).isEqualTo("{\"kty\":\"EC\"}");
        assertThat(config.credentialJwt()).isEqualTo("header.payload.signature");
    }

    @Test
    void loadsInlineValuesFromYaml() throws IOException {
        Path file = tempDir.resolve("verifier-client.yaml");
        Files.writeString(
                file,
                """
                verifier:
                  url: https://verifier.example.org
                  private-key-jwk: '{"kty":"EC"}'
                  credential-jwt: header.payload.signature
                """);

        VerifierM2MClientConfig config = ConfigLoader.load(file);

        assertThat(config.verifierUrl()).isEqualTo("https://verifier.example.org");
        assertThat(config.privateKeyJwk()).isEqualTo("{\"kty\":\"EC\"}");
        assertThat(config.credentialJwt()).isEqualTo("header.payload.signature");
    }

    @Test
    void rejectsBothInlineAndPathSetForTheSameField() throws IOException {
        Path file = tempDir.resolve("verifier-client.properties");
        Files.writeString(
                file,
                """
                verifier.url=https://verifier.example.org
                verifier.private-key-jwk={"kty":"EC"}
                verifier.private-key-jwk-path=key.jwk.json
                verifier.credential-jwt=header.payload.signature
                """);

        assertThatThrownBy(() -> ConfigLoader.load(file))
                .isInstanceOf(InvalidConfigurationException.class);
    }

    @Test
    void rejectsAMissingRequiredKey() throws IOException {
        Path file = tempDir.resolve("verifier-client.properties");
        Files.writeString(file, "verifier.url=https://verifier.example.org\n");

        assertThatThrownBy(() -> ConfigLoader.load(file))
                .isInstanceOf(InvalidConfigurationException.class);
    }
}
