package net.eudistack.verifierclient.jwt;

import com.nimbusds.jose.util.Base64URL;
import java.math.BigInteger;

/** Encodes a P-256 field element as the fixed-width, unsigned Base64URL a JWK coordinate needs. */
public final class P256Coordinates {

    private static final int COORDINATE_LENGTH_BYTES = 32;

    private P256Coordinates() {}

    public static Base64URL toBase64Url(BigInteger coordinate) {
        byte[] raw = coordinate.toByteArray();
        byte[] fixed = new byte[COORDINATE_LENGTH_BYTES];
        int srcOffset = Math.max(0, raw.length - COORDINATE_LENGTH_BYTES);
        int destOffset = Math.max(0, COORDINATE_LENGTH_BYTES - raw.length);
        System.arraycopy(raw, srcOffset, fixed, destOffset, raw.length - srcOffset);
        return Base64URL.encode(fixed);
    }
}
