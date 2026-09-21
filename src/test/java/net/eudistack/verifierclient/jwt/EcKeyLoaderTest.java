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
        ECKey p384Key = new ECKeyGenerator(Curve.P_384).generate();

        assertThatThrownBy(() -> EcKeyLoader.loadPrivateKey(p384Key.toJSONString()))
                .isInstanceOf(InvalidConfigurationException.class)
                .hasMessageContaining("P-256");
    }

    @Test
    void rejectsAPublicOnlyKeyWithNoPrivateComponent() throws Exception {
        ECKey publicOnlyKey = new ECKeyGenerator(Curve.P_256).generate().toPublicJWK();

        assertThatThrownBy(() -> EcKeyLoader.loadPrivateKey(publicOnlyKey.toJSONString()))
                .isInstanceOf(InvalidConfigurationException.class)
                .hasMessageContaining("private component");
    }
}
