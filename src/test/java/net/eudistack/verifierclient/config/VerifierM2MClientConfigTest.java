package net.eudistack.verifierclient.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import net.eudistack.verifierclient.exception.InvalidConfigurationException;
import org.junit.jupiter.api.Test;

class VerifierM2MClientConfigTest {

    @Test
    void toStringRedactsThePrivateKeyAndCredential() {
        var config =
                new VerifierM2MClientConfig(
                        "https://verifier.example.org", "0xdeadbeef", "header.payload.signature");

        String rendered = config.toString();

        assertThat(rendered).contains("https://verifier.example.org");
        assertThat(rendered).doesNotContain("0xdeadbeef").doesNotContain("header.payload.signature");
    }

    @Test
    void rejectsABlankVerifierUrl() {
        assertThatThrownBy(() -> new VerifierM2MClientConfig(" ", "0xdeadbeef", "jwt"))
                .isInstanceOf(InvalidConfigurationException.class);
    }

    @Test
    void rejectsABlankPrivateKey() {
        assertThatThrownBy(
                        () -> new VerifierM2MClientConfig("https://verifier.example.org", " ", "jwt"))
                .isInstanceOf(InvalidConfigurationException.class);
    }

    @Test
    void rejectsABlankCredentialJwt() {
        assertThatThrownBy(
                        () ->
                                new VerifierM2MClientConfig(
                                        "https://verifier.example.org", "0xdeadbeef", " "))
                .isInstanceOf(InvalidConfigurationException.class);
    }
}
