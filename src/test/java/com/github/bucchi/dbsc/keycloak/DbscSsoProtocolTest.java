package com.github.bucchi.dbsc.keycloak;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DbscSsoProtocolTest {

    @Test
    void buildsGenerateKeyHeaderWithOriginChallengeAndSession() {
        assertEquals("(ES256 RS256); target_origin=\"https://rp.example\"; challenge=\"abc_123\""
                        + "; provider_session_id=\"session-1\"",
                DbscSsoProtocol.generateKeyHeader("https://rp.example", "abc_123", "session-1"));
    }

    @Test
    void buildsAikRegistrationHeaderWithChallengeAndRequiredAik() {
        assertEquals("(ES256 RS256); path=\"https://idp.example/realms/demo/dbsc/StartSession\""
                        + "; challenge=\"abc_123\"; aik_required=?1",
                DbscSsoProtocol.registrationHeader(
                        "https://idp.example/realms/demo/dbsc/StartSession", "abc_123"));
    }

    @Test
    void derivesOriginFromValidatedRedirectUri() {
        assertEquals("https://rp.example:8443",
                DbscSsoProtocol.origin("https://rp.example:8443/callback?code=ignored"));
        assertEquals("http://localhost:8080", DbscSsoProtocol.origin("http://localhost:8080/callback"));
    }

    @Test
    void rejectsInsecureOrAmbiguousRedirectOrigins() {
        assertThrows(IllegalArgumentException.class,
                () -> DbscSsoProtocol.origin("http://rp.example/callback"));
        assertThrows(IllegalArgumentException.class,
                () -> DbscSsoProtocol.origin("https://user@rp.example/callback"));
    }

    @Test
    void enablesOnlyExplicitlyConfiguredClients() {
        assertEquals(true, DbscSsoProtocol.isEnabledForClient("true"));
        assertEquals(false, DbscSsoProtocol.isEnabledForClient(null));
        assertEquals(false, DbscSsoProtocol.isEnabledForClient("false"));
    }

        @Test
        void requestFingerprintIsStableAndChangesWithPkceOrState() {
        Map<String, String> request = Map.of(
            "state", "state-1",
            "nonce", "nonce-1",
            "code_challenge", "pkce-1",
            "code_challenge_method", "S256");

        String fingerprint = DbscSsoProtocol.requestFingerprint(
            "client-id", "https://rp.example/callback", request);

        assertEquals(fingerprint, DbscSsoProtocol.requestFingerprint(
            "client-id", "https://rp.example/callback", request));
        assertNotEquals(fingerprint, DbscSsoProtocol.requestFingerprint(
            "client-id", "https://rp.example/callback", Map.of(
                "state", "state-1",
                "nonce", "nonce-1",
                "code_challenge", "pkce-2",
                "code_challenge_method", "S256")));
        }
}