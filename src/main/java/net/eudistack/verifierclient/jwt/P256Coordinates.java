package net.eudistack.verifierclient.jwt;

import com.nimbusds.jose.util.Base64URL;
import java.math.BigInteger;

/** Encodes a P-256 field element as the fixed-width, unsigned Base64URL a JWK coordinate needs. */
public final class P256Coordinates {

    private static final int COORDINATE_LENGTH_BYTES = 32;
    private static final int MAX_COORDINATE_BITS = COORDINATE_LENGTH_BYTES * 8;

    private P256Coordinates() {}

    /**
     * @throws IllegalArgumentException if {@code coordinate} is negative or wider than 256
     *     bits — this method never silently truncates, since a caller passing an
     *     out-of-range value (e.g. an unvalidated private scalar) would otherwise get a
     *     JWK encoding a different, wrong value with no error.
     */
    public static Base64URL toBase64Url(BigInteger coordinate) {
        if (coordinate.signum() < 0 || coordinate.bitLength() > MAX_COORDINATE_BITS) {
            throw new IllegalArgumentException(
                    "Coordinate is not a valid unsigned 256-bit P-256 field element");
        }
        byte[] raw = coordinate.toByteArray();
        byte[] fixed = new byte[COORDINATE_LENGTH_BYTES];
        int srcOffset = Math.max(0, raw.length - COORDINATE_LENGTH_BYTES);
        int destOffset = Math.max(0, COORDINATE_LENGTH_BYTES - raw.length);
        System.arraycopy(raw, srcOffset, fixed, destOffset, raw.length - srcOffset);
        return Base64URL.encode(fixed);
    }
}
