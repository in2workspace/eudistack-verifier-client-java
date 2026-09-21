package net.eudistack.verifierclient.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import net.eudistack.verifierclient.exception.InvalidConfigurationException;
import java.util.Map;
import org.junit.jupiter.api.Test;

class MachineCredentialTest {

    @Test
    void extractsClientIdTenantAndCnfFromAJwkCnf() {
        Map<String, Object> cnf =
                Map.of("jwk", Map.of("kty", "EC", "crv", "P-256", "x", "xValue", "y", "yValue"));
        String jwt = CredentialFixtures.machineCredentialJwt(cnf);

        MachineCredential credential = MachineCredential.parse(jwt);

        assertThat(credential.clientId()).isEqualTo(CredentialFixtures.CLIENT_ID);
        assertThat(credential.tenant()).isEqualTo(CredentialFixtures.TENANT);
        assertThat(credential.confirmationKey()).contains("xValue").contains("yValue");
        assertThat(credential.compactJwt()).isEqualTo(jwt);
    }

    @Test
    void extractsDidKeyCnfAsIs() {
        String didKey = "did:key:zDnaekTestConfirmationKey";
        String jwt = CredentialFixtures.machineCredentialJwt(didKey);

        MachineCredential credential = MachineCredential.parse(jwt);

        assertThat(credential.confirmationKey()).isEqualTo(didKey);
    }

    @Test
    void rejectsBlankInput() {
        assertThatThrownBy(() -> MachineCredential.parse(" "))
                .isInstanceOf(InvalidConfigurationException.class);
    }

    @Test
    void rejectsAMalformedJwt() {
        assertThatThrownBy(() -> MachineCredential.parse("not-a-jwt"))
                .isInstanceOf(InvalidConfigurationException.class);
    }
}
