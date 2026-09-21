package net.eudistack.verifierclient.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import net.eudistack.verifierclient.exception.InvalidConfigurationException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.Test;

class EcKeyLoaderTest {

    @Test
    void loadsAValidP256PrivateKey() throws Exception {
        ECKey privateKey = new ECKeyGenerator(Curve.P_256).generate();

        ECKey loaded = EcKeyLoader.loadPrivateKey(privateKey.toJSONString());

        assertThat(loaded.getCurve()).isEqualTo(Curve.P_256);
        assertThat(loaded.isPrivate()).isTrue();
        assertThat(loaded.getX()).isEqualTo(privateKey.getX());
    }

    @Test
    void rejectsBlankInput() {
        assertThatThrownBy(() -> EcKeyLoader.loadPrivateKey(" "))
                .isInstanceOf(InvalidConfigurationException.class)
                .hasMessageContaining("must not be blank");
    }

    @Test
    void rejectsNullInput() {
        assertThatThrownBy(() -> EcKeyLoader.loadPrivateKey(null))
                .isInstanceOf(InvalidConfigurationException.class);
    }

    @Test
    void rejectsMalformedJwkJson() {
        assertThatThrownBy(() -> EcKeyLoader.loadPrivateKey("{not-json"))
                .isInstanceOf(InvalidConfigurationException.class)
                .hasMessageContaining("not a valid JWK");
    }

    @Test
    void rejectsAKeyOnTheWrongCurve() throws Exception {
        String p384KeyJson = new ECKeyGenerator(Curve.P_384).generate().toJSONString();

        assertThatThrownBy(() -> EcKeyLoader.loadPrivateKey(p384KeyJson))
                .isInstanceOf(InvalidConfigurationException.class)
                .hasMessageContaining("P-256");
    }

    @Test
    void rejectsAPublicOnlyKeyWithNoPrivateComponent() throws Exception {
        String publicOnlyKeyJson = new ECKeyGenerator(Curve.P_256).generate().toPublicJWK().toJSONString();

        assertThatThrownBy(() -> EcKeyLoader.loadPrivateKey(publicOnlyKeyJson))
                .isInstanceOf(InvalidConfigurationException.class)
                .hasMessageContaining("private component");
    }

    @Test
    void loadsAKeyFromARawHexScalarWithA0xPrefix() {
        // Independently computed (Python, cryptography.hazmat), not via this codec.
        String hexScalar = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd";

        ECKey loaded = EcKeyLoader.loadPrivateKey(hexScalar);

        assertThat(loaded.getCurve()).isEqualTo(Curve.P_256);
        assertThat(loaded.isPrivate()).isTrue();
        assertThat(loaded.getX()).hasToString("LVYqYX6d-wQ31mE6A4b7ucJBjo6JV9TXqf17FRiIMno");
        assertThat(loaded.getY()).hasToString("OOzX2baxZnRthbl0-4prn9K6s4uaQO3bYAijgNB4bM8");
    }

    @Test
    void loadsAKeyFromARawHexScalarWithoutA0xPrefix() {
        String hexScalar = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd";

        ECKey loaded = EcKeyLoader.loadPrivateKey(hexScalar);

        assertThat(loaded.getX()).hasToString("LVYqYX6d-wQ31mE6A4b7ucJBjo6JV9TXqf17FRiIMno");
        assertThat(loaded.getY()).hasToString("OOzX2baxZnRthbl0-4prn9K6s4uaQO3bYAijgNB4bM8");
    }

    @Test
    void loadsAKeyFromAShortHexScalarWithoutFullZeroPadding() {
        // A scalar whose leading bytes are zero is sometimes handed out a few hex digits
        // short of the full 32-byte width — still valid, just a smaller number.
        ECKey loaded = EcKeyLoader.loadPrivateKey("0xabcd");

        assertThat(loaded.getCurve()).isEqualTo(Curve.P_256);
        assertThat(loaded.isPrivate()).isTrue();
    }

    @Test
    void rejectsAHexScalarLongerThan32Bytes() {
        String tooLong = "ab".repeat(33);
        assertThatThrownBy(() -> EcKeyLoader.loadPrivateKey(tooLong))
                .isInstanceOf(InvalidConfigurationException.class)
                .hasMessageContaining("P-256 private scalar");
    }

    @Test
    void rejectsAStringThatIsNeitherJwkNorValidHex() {
        assertThatThrownBy(() -> EcKeyLoader.loadPrivateKey("not-json-and-not-hex-either"))
                .isInstanceOf(InvalidConfigurationException.class);
    }

    @Test
    void rejectsAZeroScalarAsItProducesThePointAtInfinity() {
        assertThatThrownBy(() -> EcKeyLoader.loadPrivateKey("0x0"))
                .isInstanceOf(InvalidConfigurationException.class);
    }
}
