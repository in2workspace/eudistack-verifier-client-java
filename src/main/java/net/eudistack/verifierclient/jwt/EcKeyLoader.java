package net.eudistack.verifierclient.jwt;

import net.eudistack.verifierclient.exception.InvalidConfigurationException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import java.math.BigInteger;
import java.text.ParseException;

/**
 * Parses an EC (P-256) private key, accepting either a JWK JSON object (RFC 7517) or a raw
 * private scalar as hex — {@code 0xb8c0...} or {@code b8c0...} — since some credential
 * issuers hand out the mandatee's private key in that bare form rather than as a JWK. The
 * public {@code (x, y)} coordinates are derived from the scalar via {@code d·G} when needed
 * ({@link P256ScalarMultiplier}); a JWK input is used as given.
 */
public final class EcKeyLoader {

    private static final int P256_SCALAR_MAX_HEX_LENGTH = 64;

    private EcKeyLoader() {}

    /**
     * Loads a P-256 private key from either a JWK JSON string or a raw hex-encoded scalar,
     * and validates it carries a usable private component.
     */
    public static ECKey loadPrivateKey(String privateKey) {
        if (privateKey == null || privateKey.isBlank()) {
            throw new InvalidConfigurationException("privateKey must not be blank");
        }
        String trimmed = privateKey.trim();
        ECKey ecKey = trimmed.startsWith("{") ? parseJwk(trimmed) : parseHexScalar(trimmed);

        if (!Curve.P_256.equals(ecKey.getCurve())) {
            throw new InvalidConfigurationException(
                    "privateKey must use curve P-256, found: " + ecKey.getCurve());
        }
        if (!ecKey.isPrivate()) {
            throw new InvalidConfigurationException(
                    "privateKey must contain the private component ('d')");
        }
        return ecKey;
    }

    private static ECKey parseJwk(String json) {
        try {
            return ECKey.parse(json);
        } catch (ParseException e) {
            throw new InvalidConfigurationException("privateKey is not a valid JWK", e);
        }
    }

    private static ECKey parseHexScalar(String hex) {
        String unprefixed = hex.startsWith("0x") || hex.startsWith("0X") ? hex.substring(2) : hex;
        // Zero-padding to the full 32-byte width is optional — a scalar whose leading bytes
        // are zero is often handed out a few hex digits short, and is still a valid P-256
        // private key (just represented as a smaller number).
        if (unprefixed.isEmpty()
                || unprefixed.length() > P256_SCALAR_MAX_HEX_LENGTH
                || !unprefixed.matches("(?i)[0-9a-f]+")) {
            // Never echo the candidate value here — it may be the private key itself, or a
            // file's raw content (e.g. a whitespace/BOM-mangled key), and this message is
            // exactly the kind of text applications log at ERROR by default.
            throw new InvalidConfigurationException(
                    "privateKey is neither a JWK JSON object nor a P-256 private scalar "
                            + "(expected up to "
                            + P256_SCALAR_MAX_HEX_LENGTH
                            + " hex digits, got "
                            + unprefixed.length()
                            + " characters)");
        }

        BigInteger d = new BigInteger(unprefixed, 16);
        BigInteger[] point;
        try {
            point = P256ScalarMultiplier.derivePublicPoint(d);
        } catch (ArithmeticException e) {
            throw new InvalidConfigurationException(
                    "privateKey scalar does not produce a valid P-256 key point", e);
        }

        return new ECKey.Builder(
                        Curve.P_256,
                        P256Coordinates.toBase64Url(point[0]),
                        P256Coordinates.toBase64Url(point[1]))
                .d(P256Coordinates.toBase64Url(d))
                .build();
    }
}
