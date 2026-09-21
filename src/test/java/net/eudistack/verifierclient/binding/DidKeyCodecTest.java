package net.eudistack.verifierclient.binding;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import net.eudistack.verifierclient.exception.InvalidConfigurationException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import org.junit.jupiter.api.Test;

class DidKeyCodecTest {

    // Independently computed (Python, pure stdlib + cryptography — not via this codec) from
    // a fixed P-256 private key d=0x1234...cd. See the private JWK in CnfBindingValidatorTest.
    private static final String KNOWN_DID_KEY =
            "did:key:zDnaekiFy89Lofk88Qrjorneke49pTLfEDxbMPSQjWeNBRtvD";
    private static final String EXPECTED_X = "LVYqYX6d-wQ31mE6A4b7ucJBjo6JV9TXqf17FRiIMno";
    private static final String EXPECTED_Y = "OOzX2baxZnRthbl0-4prn9K6s4uaQO3bYAijgNB4bM8";

    @Test
    void isDidKeyRecognisesThePrefix() {
        assertThat(DidKeyCodec.isDidKey(KNOWN_DID_KEY)).isTrue();
        assertThat(DidKeyCodec.isDidKey("{\"kty\":\"EC\"}")).isFalse();
        assertThat(DidKeyCodec.isDidKey(null)).isFalse();
    }

    @Test
    void decodesAKnownDidKeyToItsExpectedPublicCoordinates() {
        ECKey decoded = DidKeyCodec.decodeP256PublicKey(KNOWN_DID_KEY);

        assertThat(decoded.getCurve()).isEqualTo(Curve.P_256);
        assertThat(decoded.getX().toString()).isEqualTo(EXPECTED_X);
        assertThat(decoded.getY().toString()).isEqualTo(EXPECTED_Y);
    }

    @Test
    void decodesADidUrlWithAVerificationMethodFragmentTheSameAsTheBareDidKey() {
        String didUrl = KNOWN_DID_KEY + "#" + KNOWN_DID_KEY.substring("did:key:".length());

        ECKey decoded = DidKeyCodec.decodeP256PublicKey(didUrl);

        assertThat(decoded.getX().toString()).isEqualTo(EXPECTED_X);
        assertThat(decoded.getY().toString()).isEqualTo(EXPECTED_Y);
    }

    @Test
    void rejectsAMalformedDidKey() {
        assertThatThrownBy(() -> DidKeyCodec.decodeP256PublicKey("did:key:z000invalid!!!"))
                .isInstanceOf(InvalidConfigurationException.class);
    }

    @Test
    void rejectsANonDidKeyValue() {
        assertThatThrownBy(() -> DidKeyCodec.decodeP256PublicKey("not-a-did-key"))
                .isInstanceOf(InvalidConfigurationException.class);
    }
}
