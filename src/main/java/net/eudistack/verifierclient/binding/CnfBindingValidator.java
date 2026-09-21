package net.eudistack.verifierclient.binding;

import net.eudistack.verifierclient.credential.MachineCredential;
import net.eudistack.verifierclient.exception.CredentialKeyMismatchException;
import com.nimbusds.jose.jwk.ECKey;

/**
 * Validates, before any network call, that a configured private key's public counterpart
 * matches the machine credential's declared confirmation key ({@code cnf}).
 *
 * <p>This check is independent of (and stricter than) what the Verifier validates
 * server-side for the M2M grant: the Verifier's proof-of-possession check is against the
 * VP-JWT's own embedded {@code jwk} header, not against {@code cnf}. This validator exists
 * purely to catch a misconfigured key/credential pair on the client side, as early as
 * possible.
 */
public final class CnfBindingValidator {

    private CnfBindingValidator() {}

    /**
     * @throws CredentialKeyMismatchException if the derived public key does not match the
     *     credential's {@code cnf}, in either its JWK-object or {@code did:key} form.
     */
    public static void validate(ECKey privateKey, MachineCredential credential) {
        ECKey publicKey = privateKey.toPublicJWK();
        String cnf = credential.confirmationKey();

        ECKey cnfPublicKey =
                DidKeyCodec.isDidKey(cnf)
                        ? DidKeyCodec.decodeP256PublicKey(cnf)
                        : parseCnfJwk(cnf);

        boolean matches =
                publicKey.getCurve().equals(cnfPublicKey.getCurve())
                        && publicKey.getX().equals(cnfPublicKey.getX())
                        && publicKey.getY().equals(cnfPublicKey.getY());

        if (!matches) {
            throw new CredentialKeyMismatchException(
                    "The configured private key does not match the credential's cnf key. "
                            + "Verify you are using the private key belonging to the mandatee "
                            + "identified in this credential.");
        }
    }

    private static ECKey parseCnfJwk(String cnfJwkJson) {
        try {
            return ECKey.parse(cnfJwkJson);
        } catch (java.text.ParseException e) {
            throw new CredentialKeyMismatchException(
                    "The credential's cnf value is neither a valid JWK nor a did:key: " + e.getMessage());
        }
    }
}
