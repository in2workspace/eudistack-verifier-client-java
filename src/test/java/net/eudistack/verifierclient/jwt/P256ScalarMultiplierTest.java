package net.eudistack.verifierclient.jwt;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;

class P256ScalarMultiplierTest {

    // Independently computed (Python, cryptography.hazmat) — same d used across
    // DidKeyCodecTest / CnfBindingValidatorTest for the matching x/y test vector.
    private static final BigInteger D =
            new BigInteger("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd", 16);
    private static final BigInteger EXPECTED_X =
            new BigInteger("2d562a617e9dfb0437d6613a0386fbb9c2418e8e8957d4d7a9fd7b151888327a", 16);
    private static final BigInteger EXPECTED_Y =
            new BigInteger("38ecd7d9b6b166746d85b974fb8a6b9fd2bab38b9a40eddb6008a380d0786ccf", 16);

    @Test
    void derivesTheExpectedPublicPointForAKnownScalar() {
        BigInteger[] point = P256ScalarMultiplier.derivePublicPoint(D);

        assertThat(point[0]).isEqualTo(EXPECTED_X);
        assertThat(point[1]).isEqualTo(EXPECTED_Y);
    }

    @Test
    void derivesConsistentPointsForSeveralRandomScalars() {
        // Cross-check against DidKeyCodec's own on-curve verification: derivePublicPoint
        // must always land on the curve, for scalars with varying bit lengths/patterns.
        BigInteger p =
                new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
        BigInteger a = p.subtract(BigInteger.valueOf(3));
        BigInteger b =
                new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);

        BigInteger[] scalars = {
            BigInteger.ONE,
            BigInteger.TWO,
            BigInteger.valueOf(12345),
            new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550", 16),
            new BigInteger("abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567", 16)
        };

        for (BigInteger d : scalars) {
            BigInteger[] point = P256ScalarMultiplier.derivePublicPoint(d);
            BigInteger x = point[0];
            BigInteger y = point[1];
            BigInteger lhs = y.modPow(BigInteger.TWO, p);
            BigInteger rhs = x.modPow(BigInteger.valueOf(3), p).add(a.multiply(x)).add(b).mod(p);
            assertThat(lhs).as("point for d=%s is on the curve", d).isEqualTo(rhs);
        }
    }
}
