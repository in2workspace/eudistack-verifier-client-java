package net.eudistack.verifierclient.binding;

import net.eudistack.verifierclient.exception.InvalidConfigurationException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * Decodes a {@code did:key} identifier for a P-256 (secp256r1) EC public key.
 *
 * <p>A {@code did:key} for P-256 is: the literal prefix {@code did:key:z}, followed by the
 * Base58btc (multibase 'z') encoding of {@code <multicodec 0x1200><compressed EC point>}. See
 * <a href="https://w3c-ccg.github.io/did-method-key/#p-256">did:key P-256 method</a>.
 */
public final class DidKeyCodec {

    private static final String DID_KEY_PREFIX = "did:key:z";

    // Multicodec varint prefix for P-256 (secp256r1) public keys: 0x1200 -> varint bytes [0x80, 0x24].
    private static final byte[] P256_MULTICODEC_PREFIX = {(byte) 0x80, 0x24};

    private static final String BASE58_ALPHABET =
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    private DidKeyCodec() {}

    /** {@code true} if the given confirmation-key value is a {@code did:key} identifier. */
    public static boolean isDidKey(String cnfValue) {
        return cnfValue != null && cnfValue.startsWith(DID_KEY_PREFIX);
    }

    /** Decodes a P-256 {@code did:key:z...} identifier into its public {@link ECKey}. */
    public static ECKey decodeP256PublicKey(String didKey) {
        if (!isDidKey(didKey)) {
            throw new InvalidConfigurationException("Not a did:key identifier: " + didKey);
        }
        String multibaseBody = didKey.substring(DID_KEY_PREFIX.length());
        byte[] decoded = base58Decode(multibaseBody);

        if (decoded.length < P256_MULTICODEC_PREFIX.length
                || !Arrays.equals(
                        Arrays.copyOfRange(decoded, 0, P256_MULTICODEC_PREFIX.length),
                        P256_MULTICODEC_PREFIX)) {
            throw new InvalidConfigurationException(
                    "did:key does not carry the P-256 multicodec prefix (0x1200): " + didKey);
        }

        byte[] compressedPoint =
                Arrays.copyOfRange(decoded, P256_MULTICODEC_PREFIX.length, decoded.length);
        return decompressP256(compressedPoint);
    }

    private static ECKey decompressP256(byte[] compressedPoint) {
        if (compressedPoint.length != 33 || (compressedPoint[0] != 0x02 && compressedPoint[0] != 0x03)) {
            throw new InvalidConfigurationException(
                    "did:key public key is not a valid SEC1-compressed P-256 point");
        }
        boolean yIsEven = compressedPoint[0] == 0x02;
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(compressedPoint, 1, 33));

        // secp256r1: y^2 = x^3 - 3x + b (mod p)
        BigInteger p =
                new BigInteger(
                        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
        BigInteger a = p.subtract(BigInteger.valueOf(3));
        BigInteger b =
                new BigInteger(
                        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);

        BigInteger rhs = x.modPow(BigInteger.valueOf(3), p).add(a.multiply(x)).add(b).mod(p);
        BigInteger y = modSqrt(rhs, p);
        if (y.testBit(0) == yIsEven) {
            y = p.subtract(y);
        }

        return new ECKey.Builder(Curve.P_256, toUnsignedFixed(x), toUnsignedFixed(y)).build();
    }

    // p mod 4 == 3 for secp256r1's prime, so y = rhs^((p+1)/4) mod p.
    private static BigInteger modSqrt(BigInteger value, BigInteger p) {
        BigInteger exponent = p.add(BigInteger.ONE).shiftRight(2);
        return value.modPow(exponent, p);
    }

    private static com.nimbusds.jose.util.Base64URL toUnsignedFixed(BigInteger coordinate) {
        byte[] raw = coordinate.toByteArray();
        byte[] fixed = new byte[32];
        int srcOffset = Math.max(0, raw.length - 32);
        int destOffset = Math.max(0, 32 - raw.length);
        System.arraycopy(raw, srcOffset, fixed, destOffset, raw.length - srcOffset);
        return com.nimbusds.jose.util.Base64URL.encode(fixed);
    }

    private static byte[] base58Decode(String input) {
        BigInteger value = BigInteger.ZERO;
        BigInteger base = BigInteger.valueOf(58);
        for (int i = 0; i < input.length(); i++) {
            int digit = BASE58_ALPHABET.indexOf(input.charAt(i));
            if (digit < 0) {
                throw new InvalidConfigurationException(
                        "Invalid Base58 character in did:key: '" + input.charAt(i) + "'");
            }
            value = value.multiply(base).add(BigInteger.valueOf(digit));
        }

        byte[] valueBytes = value.toByteArray();
        // Strip a possible leading sign byte introduced by BigInteger's two's-complement form.
        int start = (valueBytes.length > 1 && valueBytes[0] == 0) ? 1 : 0;

        int leadingZeroChars = 0;
        while (leadingZeroChars < input.length() && input.charAt(leadingZeroChars) == '1') {
            leadingZeroChars++;
        }

        byte[] result = new byte[leadingZeroChars + (valueBytes.length - start)];
        System.arraycopy(valueBytes, start, result, leadingZeroChars, valueBytes.length - start);
        return result;
    }
}
