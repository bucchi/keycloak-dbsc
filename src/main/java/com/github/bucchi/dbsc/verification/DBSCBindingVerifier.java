package com.github.bucchi.dbsc.verification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.common.util.Base64Url;
import org.keycloak.jose.jwk.ECPublicJWK;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.RSAPublicJWK;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

public final class DBSCBindingVerifier {

    private final ObjectMapper mapper = new ObjectMapper();
    private final DbscProofVerifier proofVerifier = new DbscProofVerifier(mapper);
    private final TpmAttestationVerifier tpmVerifier = new TpmAttestationVerifier();

    public VerifiedBinding verify(
            String encodedBindingStatement,
            String expectedChallenge,
            String expectedAudience,
            JWK storedAttestationKey,
            String storedAttestationAlgorithm,
            String storedAttestationFormat) throws Exception {
        if (isBlank(expectedChallenge) || isBlank(expectedAudience)
                || isBlank(storedAttestationAlgorithm) || isBlank(storedAttestationFormat)) {
            throw new IllegalArgumentException("Binding challenge, audience, fmt, and alg are required.");
        }

        JsonNode statement = parseBindingStatement(encodedBindingStatement);
        if (statement.has("aud")) {
            proofVerifier.requireAudience(statement.path("aud"), expectedAudience, "Binding statement");
        }
        String encodedProof = proofVerifier.requiredText(statement, "jti");
        DbscProofVerifier.VerifiedProof proof = proofVerifier.verify(
                encodedProof, expectedChallenge, expectedAudience);

        JsonNode attestation = proofVerifier.readJson(
            proofVerifier.decodeBase64Url(proofVerifier.requiredText(statement, "att"), "att"),
                "binding attestation claim");
        tpmVerifier.verifyBinding(
                attestation,
                expectedChallenge,
                proof.signingKey(),
                proof.algorithm(),
                storedAttestationKey,
                storedAttestationAlgorithm,
                storedAttestationFormat);

        return new VerifiedBinding(
                proof.signingKey(),
                jwkThumbprint(proof.signingKey()),
                digestAlgorithm(storedAttestationAlgorithm));
    }

    public String extractChallenge(String encodedBindingStatement) {
        JsonNode statement = parseBindingStatement(encodedBindingStatement);
        return proofVerifier.extractChallenge(proofVerifier.requiredText(statement, "jti"));
    }

    private JsonNode parseBindingStatement(String encodedBindingStatement) {
        if (encodedBindingStatement == null || encodedBindingStatement.isBlank()
                || encodedBindingStatement.length() > 32_768) {
            throw new SecurityException("Secure-Session-KeyBinding is missing or too large.");
        }
        try {
            byte[] json = Base64Url.decode(encodedBindingStatement);
            JsonNode statement = mapper.readTree(json);
            if (statement == null || !statement.isObject()) {
                throw new SecurityException("Binding statement must be a JSON object.");
            }
            return statement;
        } catch (Exception e) {
            throw new SecurityException("Secure-Session-KeyBinding is not a Base64URL JSON object.", e);
        }
    }

    public static JWK readStoredAttestationKey(String serializedJwk) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jwk = mapper.readTree(serializedJwk);
        return switch (jwk.path("kty").asText()) {
            case "EC" -> mapper.treeToValue(jwk, ECPublicJWK.class);
            case "RSA" -> mapper.treeToValue(jwk, RSAPublicJWK.class);
            default -> throw new SecurityException("Unsupported stored attestation key type.");
        };
    }

    static String jwkThumbprint(JWK jwk) throws Exception {
        String canonical;
        if (jwk instanceof ECPublicJWK ec) {
            if (!"P-256".equals(ec.getCrv())) {
                throw new SecurityException("Only P-256 RP keys are supported.");
            }
            canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":"
                    + jsonString(ec.getX()) + ",\"y\":" + jsonString(ec.getY()) + "}";
        } else if (jwk instanceof RSAPublicJWK rsa) {
            canonical = "{\"e\":" + jsonString(rsa.getPublicExponent())
                    + ",\"kty\":\"RSA\",\"n\":" + jsonString(rsa.getModulus()) + "}";
        } else {
            throw new SecurityException("Unsupported RP public key type.");
        }
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(canonical.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private static String jsonString(String value) {
        if (value == null || value.isEmpty()) {
            throw new SecurityException("JWK public key member is missing.");
        }
        return '"' + value + '"';
    }

    private static String digestAlgorithm(String algorithm) {
        return switch (algorithm) {
            case "ES256", "RS256" -> "SHA-256";
            default -> throw new SecurityException("Unsupported stored AIK algorithm.");
        };
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    public record VerifiedBinding(JWK signingKey, String thumbprint, String digestAlgorithm) {
    }
}