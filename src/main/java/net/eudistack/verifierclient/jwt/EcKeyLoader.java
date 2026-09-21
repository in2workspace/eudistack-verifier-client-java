package net.eudistack.verifierclient.jwt;

import net.eudistack.verifierclient.exception.InvalidConfigurationException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import java.text.ParseException;

/** Parses an EC (P-256) private key supplied as a JWK JSON string. */
public final class EcKeyLoader {

    private EcKeyLoader() {}

    /**
     * Parses a private-key JWK and validates it is a P-256 EC key carrying the private
     * component ({@code d}) — the shape required to sign the VP-JWT / client_assertion.
     */
    public static ECKey loadPrivateKey(String privateKeyJwkJson) {
        if (privateKeyJwkJson == null || privateKeyJwkJson.isBlank()) {
            throw new InvalidConfigurationException("privateKeyJwk must not be blank");
        }
        ECKey ecKey;
        try {
            ecKey = ECKey.parse(privateKeyJwkJson);
        } catch (ParseException e) {
            throw new InvalidConfigurationException("privateKeyJwk is not a valid JWK", e);
        }
        if (!Curve.P_256.equals(ecKey.getCurve())) {
            throw new InvalidConfigurationException(
                    "privateKeyJwk must use curve P-256, found: " + ecKey.getCurve());
        }
        if (!ecKey.isPrivate()) {
            throw new InvalidConfigurationException(
                    "privateKeyJwk must contain the private component ('d')");
        }
        return ecKey;
    }

    /** Derives the public JWK (kty, crv, x, y — no private material) from a private EC key. */
    public static ECKey toPublicJwk(ECKey privateKey) {
        return privateKey.toPublicJWK();
    }
}
