package net.eudistack.verifierclient.jwt;

import java.math.BigInteger;

/**
 * Computes {@code d·G} on the P-256 (secp256r1) curve — deriving a public key's {@code (x, y)}
 * coordinates from a raw private scalar {@code d} — using pure {@link BigInteger} arithmetic,
 * with no external crypto library. The JDK's own {@code java.security} APIs can construct an
 * {@code ECPrivateKey} from a scalar directly, but expose no public point-multiplication
 * primitive to derive its public counterpart, so this SDK needs its own.
 *
 * <p>Some machine credential issuers hand out the mandatee's private key as this raw scalar
 * (hex-encoded) rather than as a JWK, so {@link EcKeyLoader} uses this to build the JWK the
 * rest of the SDK needs.
 */
final class P256ScalarMultiplier {

    // secp256r1 field prime, curve coefficients (a = p-3), and generator point, per FIPS 186-4.
    private static final BigInteger P =
            new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
    private static final BigInteger A = P.subtract(BigInteger.valueOf(3));
    private static final BigInteger GX =
            new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
    private static final BigInteger GY =
            new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);
    private static final BigInteger ORDER =
            new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);

    private P256ScalarMultiplier() {}

    /** Derives {@code (x, y)} for {@code d·G}. {@code d} must be in {@code [1, order-1]}. */
    static BigInteger[] derivePublicPoint(BigInteger d) {
        BigInteger[] jacobian = multiply(d.mod(ORDER), new BigInteger[] {GX, GY, BigInteger.ONE});
        return toAffine(jacobian);
    }

    // Jacobian double-and-add: (X, Y, Z) represents affine (X/Z^2, Y/Z^3), avoiding a modular
    // inverse at every step — only the final conversion back to affine needs one.
    private static BigInteger[] multiply(BigInteger scalar, BigInteger[] basePoint) {
        BigInteger[] result = null; // point at infinity
        BigInteger[] addend = basePoint;
        for (int bit = scalar.bitLength() - 1; bit >= 0; bit--) {
            result = result == null ? null : doubleJacobian(result);
            if (scalar.testBit(bit)) {
                result = result == null ? addend : addJacobian(result, addend);
            }
        }
        return result;
    }

    private static BigInteger[] doubleJacobian(BigInteger[] p) {
        BigInteger x = p[0];
        BigInteger y = p[1];
        BigInteger z = p[2];
        if (y.signum() == 0) {
            return p;
        }
        BigInteger ySq = y.multiply(y).mod(P);
        BigInteger s = x.multiply(ySq).shiftLeft(2).mod(P);
        BigInteger m =
                BigInteger.valueOf(3)
                        .multiply(x.multiply(x))
                        .add(A.multiply(z.multiply(z).modPow(BigInteger.TWO, P)))
                        .mod(P);
        BigInteger xNew = m.multiply(m).subtract(s.shiftLeft(1)).mod(P);
        BigInteger yNew =
                m.multiply(s.subtract(xNew))
                        .subtract(BigInteger.valueOf(8).multiply(ySq.multiply(ySq)))
                        .mod(P);
        BigInteger zNew = BigInteger.TWO.multiply(y).multiply(z).mod(P);
        return new BigInteger[] {xNew, yNew, zNew};
    }

    private static BigInteger[] addJacobian(BigInteger[] p1, BigInteger[] p2) {
        BigInteger x1 = p1[0];
        BigInteger y1 = p1[1];
        BigInteger z1 = p1[2];
        BigInteger x2 = p2[0];
        BigInteger y2 = p2[1];
        BigInteger z2 = p2[2];

        BigInteger z1Sq = z1.multiply(z1).mod(P);
        BigInteger z2Sq = z2.multiply(z2).mod(P);
        BigInteger u1 = x1.multiply(z2Sq).mod(P);
        BigInteger u2 = x2.multiply(z1Sq).mod(P);
        BigInteger s1 = y1.multiply(z2).multiply(z2Sq).mod(P);
        BigInteger s2 = y2.multiply(z1).multiply(z1Sq).mod(P);

        if (u1.equals(u2)) {
            return s1.equals(s2) ? doubleJacobian(p1) : null; // p2 == -p1: sum is infinity
        }

        BigInteger h = u2.subtract(u1).mod(P);
        BigInteger r = s2.subtract(s1).mod(P);
        BigInteger hSq = h.multiply(h).mod(P);
        BigInteger hCu = hSq.multiply(h).mod(P);
        BigInteger u1HSq = u1.multiply(hSq).mod(P);

        BigInteger x3 = r.multiply(r).subtract(hCu).subtract(u1HSq.shiftLeft(1)).mod(P);
        BigInteger y3 = r.multiply(u1HSq.subtract(x3)).subtract(s1.multiply(hCu)).mod(P);
        BigInteger z3 = h.multiply(z1).multiply(z2).mod(P);
        return new BigInteger[] {x3, y3, z3};
    }

    private static BigInteger[] toAffine(BigInteger[] jacobian) {
        if (jacobian == null) {
            throw new ArithmeticException("Scalar multiplication produced the point at infinity");
        }
        BigInteger zInv = jacobian[2].modInverse(P);
        BigInteger zInvSq = zInv.multiply(zInv).mod(P);
        BigInteger x = jacobian[0].multiply(zInvSq).mod(P);
        BigInteger y = jacobian[1].multiply(zInvSq).multiply(zInv).mod(P);
        return new BigInteger[] {x, y};
    }
}
