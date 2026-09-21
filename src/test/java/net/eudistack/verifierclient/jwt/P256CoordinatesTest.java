package net.eudistack.verifierclient.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;

class P256CoordinatesTest {

    @Test
    void encodesAValidCoordinateToFixedWidthBase64Url() {
        BigInteger coordinate = BigInteger.ONE;

        var encoded = P256Coordinates.toBase64Url(coordinate);

        assertThat(encoded.decode()).hasSize(32);
    }

    @Test
    void rejectsANegativeCoordinate() {
        assertThatThrownBy(() -> P256Coordinates.toBase64Url(BigInteger.valueOf(-1)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsACoordinateWiderThan256Bits() {
        BigInteger tooWide = BigInteger.TWO.pow(257);

        assertThatThrownBy(() -> P256Coordinates.toBase64Url(tooWide))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void acceptsTheLargestValid256BitValue() {
        BigInteger largest = BigInteger.TWO.pow(256).subtract(BigInteger.ONE);

        var encoded = P256Coordinates.toBase64Url(largest);

        assertThat(encoded.decode()).hasSize(32);
    }
}
