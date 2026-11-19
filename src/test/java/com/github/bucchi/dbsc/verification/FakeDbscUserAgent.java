package com.github.bucchi.dbsc.verification;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

final class FakeDbscUserAgent {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Encoder BASE64_URL = Base64.getUrlEncoder().withoutPadding();

    private final KeyPair attestationKey = createKeyPair();
    private final KeyPair idpSessionKey = createKeyPair();

    String createRegistrationResponse(String challenge, String audience) throws Exception {
        String proof = createProof(idpSessionKey, challenge, audience);
        Map<String, Object> attestation = createAttestation(
            challenge, idpSessionKey, "ES256", true);
        Map<String, Object> payload = Map.of(
                "aud", audience,
                "jti", encode(proof.getBytes(StandardCharsets.UTF_8)),
                "att", encode(MAPPER.writeValueAsBytes(attestation)));
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "ES256");
        header.put("typ", "dbsc+aik");
        header.put("cty", "jwt");
        header.put("jwk", publicJwk(attestationKey));
        return signJws(header, payload, attestationKey);
    }

    String createBindingStatement(String challenge, String audience) throws Exception {
        KeyPair rpKey = createKeyPair();
        String proof = createProof(rpKey, challenge, audience);
        Map<String, Object> attestation = createAttestation(challenge, rpKey, "ES256", false);
        Map<String, Object> statement = Map.of(
                "jti", encode(proof.getBytes(StandardCharsets.UTF_8)),
                "att", encode(MAPPER.writeValueAsBytes(attestation)));
        return encode(MAPPER.writeValueAsBytes(statement));
    }

    private Map<String, Object> createAttestation(
            String challenge,
            KeyPair subjectKey,
            String algorithm,
            boolean includeFormat) throws Exception {
        byte[] publicArea = tpmPublicArea(subjectKey);
        byte[] attestation = tpmAttestation(challenge, publicArea);
        byte[] signature = sign(attestationKey, attestation);

        Map<String, Object> claim = new LinkedHashMap<>();
        if (includeFormat) {
            claim.put("fmt", "TPM");
            claim.put("alg", algorithm);
        }
        claim.put("stmt", encode(attestation));
        claim.put("sig", encode(tpmSignature(signature)));
        claim.put("sub_key", encode(publicArea));
        return claim;
    }

    private String createProof(KeyPair keyPair, String challenge, String audience) throws Exception {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "ES256");
        header.put("typ", "dbsc+jwt");
        header.put("jwk", publicJwk(keyPair));
        return signJws(header, Map.of("aud", audience, "jti", challenge), keyPair);
    }

    private String signJws(Map<String, Object> header, Map<String, Object> payload, KeyPair keyPair)
            throws Exception {
        String encodedHeader = encode(MAPPER.writeValueAsBytes(header));
        String encodedPayload = encode(MAPPER.writeValueAsBytes(payload));
        String signingInput = encodedHeader + "." + encodedPayload;
        return signingInput + "." + encode(derToJose(sign(keyPair, signingInput.getBytes(StandardCharsets.US_ASCII))));
    }

    private Map<String, String> publicJwk(KeyPair keyPair) {
        java.security.interfaces.ECPublicKey publicKey =
                (java.security.interfaces.ECPublicKey) keyPair.getPublic();
        Map<String, String> jwk = new LinkedHashMap<>();
        jwk.put("kty", "EC");
        jwk.put("crv", "P-256");
        jwk.put("x", encode(unsignedFixed(publicKey.getW().getAffineX(), 32)));
        jwk.put("y", encode(unsignedFixed(publicKey.getW().getAffineY(), 32)));
        return jwk;
    }

    private byte[] tpmPublicArea(KeyPair keyPair) throws Exception {
        java.security.interfaces.ECPublicKey publicKey =
                (java.security.interfaces.ECPublicKey) keyPair.getPublic();
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(bytes)) {
            output.writeShort(0x0023); // TPM_ALG_ECC
            output.writeShort(0x000b); // TPM_ALG_SHA256
            output.writeInt(0x00040072);
            writeSized(output, new byte[0]);
            output.writeShort(0x0010); // TPM_ALG_NULL symmetric
            output.writeShort(0x0010); // TPM_ALG_NULL scheme
            output.writeShort(0x0003); // TPM_ECC_NIST_P256
            output.writeShort(0x0010); // TPM_ALG_NULL KDF
            writeSized(output, unsignedFixed(publicKey.getW().getAffineX(), 32));
            writeSized(output, unsignedFixed(publicKey.getW().getAffineY(), 32));
        }
        return bytes.toByteArray();
    }

    private byte[] tpmAttestation(String challenge, byte[] publicArea) throws Exception {
        byte[] subjectName = concat(
                new byte[]{0x00, 0x0b},
                MessageDigest.getInstance("SHA-256").digest(publicArea));
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(bytes)) {
            output.writeInt(0xff544347); // TPM_GENERATED_VALUE
            output.writeShort(0x8017); // TPM_ST_ATTEST_CERTIFY
            writeSized(output, new byte[0]); // qualifiedSigner
            writeSized(output, MessageDigest.getInstance("SHA-256")
                    .digest(challenge.getBytes(StandardCharsets.UTF_8)));
            output.writeLong(0);
            output.writeInt(0);
            output.writeInt(0);
            output.writeByte(1);
            output.writeLong(0);
            writeSized(output, subjectName);
            writeSized(output, new byte[]{0x00, 0x10}); // qualifiedName with an empty TPM_ALG_NULL digest
        }
        return bytes.toByteArray();
    }

    private byte[] tpmSignature(byte[] derSignature) {
        byte[][] components = derToComponents(derSignature);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(bytes)) {
            output.writeShort(0x0018); // TPM_ALG_ECDSA
            output.writeShort(0x000b); // TPM_ALG_SHA256
            writeSized(output, components[0]);
            writeSized(output, components[1]);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return bytes.toByteArray();
    }

    private KeyPair createKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to create test key pair.", e);
        }
    }

    private byte[] sign(KeyPair keyPair, byte[] data) throws Exception {
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(keyPair.getPrivate());
        signer.update(data);
        return signer.sign();
    }

    private byte[] derToJose(byte[] der) {
        byte[][] components = derToComponents(der);
        return concat(unsignedFixed(new BigInteger(1, components[0]), 32),
                unsignedFixed(new BigInteger(1, components[1]), 32));
    }

    private byte[][] derToComponents(byte[] der) {
        int offset = 2;
        int rLength = Byte.toUnsignedInt(der[offset + 1]);
        byte[] r = java.util.Arrays.copyOfRange(der, offset + 2, offset + 2 + rLength);
        offset += 2 + rLength;
        int sLength = Byte.toUnsignedInt(der[offset + 1]);
        byte[] s = java.util.Arrays.copyOfRange(der, offset + 2, offset + 2 + sLength);
        return new byte[][]{unsignedInteger(r), unsignedInteger(s)};
    }

    private byte[] unsignedInteger(byte[] value) {
        int offset = value.length > 1 && value[0] == 0 ? 1 : 0;
        return java.util.Arrays.copyOfRange(value, offset, value.length);
    }

    private byte[] unsignedFixed(BigInteger value, int length) {
        byte[] encoded = value.toByteArray();
        int offset = encoded.length > 1 && encoded[0] == 0 ? 1 : 0;
        byte[] result = new byte[length];
        System.arraycopy(encoded, offset, result, length - (encoded.length - offset), encoded.length - offset);
        return result;
    }

    private byte[] concat(byte[] first, byte[] second) {
        byte[] result = java.util.Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    private void writeSized(DataOutputStream output, byte[] value) throws IOException {
        output.writeShort(value.length);
        output.write(value);
    }

    private String encode(byte[] bytes) {
        return BASE64_URL.encodeToString(bytes);
    }
}