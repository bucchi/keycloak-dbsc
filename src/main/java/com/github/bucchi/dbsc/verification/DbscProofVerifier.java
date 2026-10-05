package com.github.bucchi.dbsc.verification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.ECPublicJWK;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.RSAPublicJWK;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.util.JWKSUtils;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Map;

final class DbscProofVerifier {

    private final ObjectMapper mapper;

    DbscProofVerifier(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    VerifiedProof verify(String encodedProof, String expectedChallenge, String expectedAudience) throws Exception {
        byte[] proofBytes = decodeBase64Url(encodedProof, "jti");
        JWSInput proof = parseJws(new String(proofBytes, StandardCharsets.UTF_8), "DBSC proof JWS");
        if (!"dbsc+jwt".equals(proof.getHeader().getType())) {
            throw new SecurityException("内側JWSのtypがdbsc+jwtではありません。");
        }

        JWK signingKey = readHeaderJwk(proof, "DBSC proof JWSにsigning JWKがありません。");
        verifyJwsSignature(proof, signingKey);
        JsonNode payload = readJson(proof.getContent(), "DBSC proof payload");
        if (!expectedChallenge.equals(requiredText(payload, "jti"))) {
            throw new SecurityException("DBSC proofのchallengeがサーバー発行値と一致しません。");
        }
        requireAudience(payload.path("aud"), expectedAudience, "DBSC proof");

        return new VerifiedProof(signingKey, proof.getHeader().getRawAlgorithm());
    }

    void verifyJwsSignature(JWSInput jws, JWK jwk) throws Exception {
        String algorithm = jws.getHeader().getRawAlgorithm();
        requireSupportedAlgorithm(algorithm);
        requireJwkAlgorithm(jwk, algorithm, "JWS signing key");

        KeyWrapper keyWrapper = JWKSUtils.getKeyWrapper(jwk);
        Key key = keyWrapper.getPublicKey();
        if (!(key instanceof PublicKey publicKey)) {
            throw new SecurityException("JWKから公開鍵を復元できません。");
        }

        Signature verifier = Signature.getInstance(signatureName(algorithm));
        verifier.initVerify(publicKey);
        verifier.update(jws.getEncodedSignatureInput().getBytes(StandardCharsets.US_ASCII));
        byte[] signature = jws.getSignature();
        if ("ES256".equals(algorithm)) {
            signature = EcdsaSignatureEncoding.joseToDer(signature);
        }
        if (!verifier.verify(signature)) {
            throw new SecurityException("JWS署名が不正です。");
        }
    }

    JWK readHeaderJwk(JWSInput jws, String error) throws Exception {
        if (jws.getHeader().getKey() != null) {
            return jws.getHeader().getKey();
        }
        Object value = jws.getHeader().getOtherClaims().get("jwk");
        if (!(value instanceof Map<?, ?> jwkMap)) {
            throw new SecurityException(error);
        }
        return mapper.readValue(mapper.writeValueAsBytes(jwkMap), JWK.class);
    }

    JWSInput parseJws(String value, String description) {
        if (value == null || value.isBlank()) {
            throw new SecurityException(description + "がありません。");
        }
        try {
            return new JWSInput(value);
        } catch (Exception e) {
            throw new SecurityException(description + "を解析できません。", e);
        }
    }

    JsonNode readJson(byte[] json, String description) {
        try {
            JsonNode node = mapper.readTree(json);
            if (node == null || !node.isObject()) {
                throw new SecurityException(description + "はJSON objectではありません。");
            }
            return node;
        } catch (Exception e) {
            throw new SecurityException(description + "をJSONとして解析できません。", e);
        }
    }

    String requiredText(JsonNode node, String name) {
        JsonNode value = node.get(name);
        if (value == null || !value.isTextual() || value.asText().isEmpty()) {
            throw new SecurityException("必須の文字列フィールド '" + name + "' がありません。");
        }
        return value.asText();
    }

    byte[] decodeBase64Url(String value, String field) {
        try {
            return Base64Url.decode(value);
        } catch (Exception e) {
            throw new SecurityException("'" + field + "' のBase64URLデコードに失敗しました。", e);
        }
    }

    void requireAudience(JsonNode audience, String expectedAudience, String description) {
        if (!audience.isTextual() || !expectedAudience.equals(audience.asText())) {
            throw new SecurityException(description + "のaudienceが期待値と一致しません。");
        }
    }

    void requireJwkAlgorithm(JWK jwk, String algorithm, String description) {
        if (("ES256".equals(algorithm) && !(jwk instanceof ECPublicJWK))
                || ("RS256".equals(algorithm) && !(jwk instanceof RSAPublicJWK))) {
            throw new SecurityException(description + "の鍵種別がalgと一致しません。");
        }
        if (jwk.getAlgorithm() != null && !algorithm.equals(jwk.getAlgorithm())) {
            throw new SecurityException(description + "のJWK algが一致しません。");
        }
    }

    void requireSupportedAlgorithm(String algorithm) {
        if (!"ES256".equals(algorithm) && !"RS256".equals(algorithm)) {
            throw new SecurityException("未対応の署名アルゴリズムです: " + algorithm);
        }
    }

    private String signatureName(String algorithm) {
        return switch (algorithm) {
            case "ES256" -> "SHA256withECDSA";
            case "RS256" -> "SHA256withRSA";
            default -> throw new SecurityException("未対応の署名アルゴリズムです: " + algorithm);
        };
    }

    record VerifiedProof(JWK signingKey, String algorithm) {
    }
}