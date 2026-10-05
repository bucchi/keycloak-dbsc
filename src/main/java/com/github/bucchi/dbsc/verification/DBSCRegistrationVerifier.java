package com.github.bucchi.dbsc.verification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.data.attestation.statement.TPMSAttest;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSInput;

public class DBSCRegistrationVerifier {

    private final ObjectMapper mapper = new ObjectMapper();
    private final DbscProofVerifier proofVerifier = new DbscProofVerifier(mapper);
    private final TpmAttestationVerifier tpmVerifier = new TpmAttestationVerifier();

    /**
     * Verify a first IdP DBSC registration. The caller must authenticate the existing IdP
     * session, issue expectedChallenge for that session, enforce its expiry/single use, and
     * persist the returned attestation key only after this method succeeds.
     */
    public VerifiedRegistration verify(
            String outerJwsString,
            String expectedChallenge,
            String expectedAudience) throws Exception {
        if (isBlank(expectedChallenge) || isBlank(expectedAudience)) {
            throw new IllegalArgumentException("期待challengeと期待audienceは必須です。");
        }

        JWSInput registrationJws = proofVerifier.parseJws(outerJwsString, "外側の登録JWS");
        if (!"dbsc+aik".equals(registrationJws.getHeader().getType())
                || !"jwt".equals(registrationJws.getHeader().getContentType())) {
            throw new SecurityException("外側JWSのtyp/ctyがDBSC AIK形式ではありません。");
        }

        JWK attestationKey = proofVerifier.readHeaderJwk(
                registrationJws, "外側JWSにattestation JWKがありません。");
        JsonNode registration = proofVerifier.readJson(registrationJws.getContent(), "外側JWS payload");
        proofVerifier.requireAudience(registration.path("aud"), expectedAudience, "外側JWS");

        JsonNode attestation = proofVerifier.readJson(
                proofVerifier.decodeBase64Url(proofVerifier.requiredText(registration, "att"), "att"),
                "attestation claim");
        if (!"TPM".equals(proofVerifier.requiredText(attestation, "fmt"))) {
            throw new SecurityException("TPM形式のattestation claimではありません。");
        }

        String attestationAlgorithm = proofVerifier.requiredText(attestation, "alg");
        proofVerifier.requireSupportedAlgorithm(attestationAlgorithm);
        if (!attestationAlgorithm.equals(registrationJws.getHeader().getRawAlgorithm())) {
            throw new SecurityException("外側JWSのalgとattestation claimのalgが一致しません。");
        }
        proofVerifier.requireJwkAlgorithm(attestationKey, attestationAlgorithm, "attestation key");
        proofVerifier.verifyJwsSignature(registrationJws, attestationKey);

        String encodedProof = proofVerifier.requiredText(registration, "jti");
        DbscProofVerifier.VerifiedProof proof = proofVerifier.verify(
                encodedProof, expectedChallenge, expectedAudience);

        TPMSAttest tpmAttestation = tpmVerifier.verify(
                attestation,
                expectedChallenge,
                proof.signingKey(),
                proof.algorithm(),
                attestationKey,
                attestationAlgorithm);

        return new VerifiedRegistration(
                tpmAttestation, proof.signingKey(), attestationKey, expectedAudience);
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    public record VerifiedRegistration(
            TPMSAttest attestation,
            JWK signingKey,
            JWK attestationKey,
            String audience) {
    }
}