package com.github.bucchi.dbsc.verification;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import org.keycloak.common.crypto.CryptoIntegration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DbscFakeUserAgentRoundTripTest {

        @BeforeAll
        static void initializeKeycloakCrypto() {
                CryptoIntegration.init(Thread.currentThread().getContextClassLoader());
        }

    @Test
    void registersIdpAikThenCreatesAnAttestedRpBinding() throws Exception {
        FakeDbscUserAgent userAgent = new FakeDbscUserAgent();
        DBSCRegistrationVerifier registrationVerifier = new DBSCRegistrationVerifier();
        DBSCBindingVerifier bindingVerifier = new DBSCBindingVerifier();
        String registrationChallenge = "registration-challenge";
        String registrationAudience = "https://idp.example/dbsc/StartSession";
        String registrationJws = userAgent.createRegistrationResponse(
                registrationChallenge, registrationAudience);

        DBSCRegistrationVerifier.VerifiedRegistration registration = registrationVerifier.verify(
                registrationJws, registrationChallenge, registrationAudience);

        assertEquals("TPM", registration.attestationFormat());
        assertEquals("ES256", registration.attestationAlgorithm());

        String bindingChallenge = "rp-binding-challenge";
        String bindingAudience = "https://idp.example/login-actions/authenticate?code=test";
        String bindingStatement = userAgent.createBindingStatement(bindingChallenge, bindingAudience);
        DBSCBindingVerifier.VerifiedBinding binding = bindingVerifier.verify(
                bindingStatement,
                bindingChallenge,
                bindingAudience,
                registration.attestationKey(),
                registration.attestationAlgorithm(),
                registration.attestationFormat());

        assertEquals("SHA-256", binding.digestAlgorithm());
        assertTrue(binding.thumbprint().matches("[A-Za-z0-9_-]{43}"));
    }

    @Test
    void rejectsBindingWhenTheChallengeDoesNotMatchTheAttestation() throws Exception {
        FakeDbscUserAgent userAgent = new FakeDbscUserAgent();
        String registrationAudience = "https://idp.example/dbsc/StartSession";
        DBSCRegistrationVerifier.VerifiedRegistration registration = new DBSCRegistrationVerifier().verify(
                userAgent.createRegistrationResponse("registration-challenge", registrationAudience),
                "registration-challenge",
                registrationAudience);
        String bindingAudience = "https://idp.example/login-actions/authenticate?code=test";
        String binding = userAgent.createBindingStatement("actual-challenge", bindingAudience);

        assertThrows(SecurityException.class, () -> new DBSCBindingVerifier().verify(
                binding,
                "different-challenge",
                bindingAudience,
                registration.attestationKey(),
                registration.attestationAlgorithm(),
                registration.attestationFormat()));
    }
}