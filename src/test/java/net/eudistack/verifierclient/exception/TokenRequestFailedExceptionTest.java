package net.eudistack.verifierclient.exception;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class TokenRequestFailedExceptionTest {

    @Test
    void statusAndBodyConstructorExposesBothViaAccessorsAndKeepsTheBodyOutOfGetMessage() {
        var exception = new TokenRequestFailedException(401, "{\"error\":\"invalid_client\"}");

        assertThat(exception.httpStatus()).isEqualTo(401);
        assertThat(exception.responseBody()).isEqualTo("{\"error\":\"invalid_client\"}");
        assertThat(exception.getMessage()).doesNotContain("invalid_client");
    }

    @Test
    void causeConstructorHasNoHttpStatusOrResponseBody() {
        var cause = new RuntimeException("network down");

        var exception = new TokenRequestFailedException("Failed to reach the Verifier", cause);

        assertThat(exception.httpStatus()).isEqualTo(-1);
        assertThat(exception.responseBody()).isNull();
        assertThat(exception.getCause()).isSameAs(cause);
    }
}
