package com.github.bucchi.dbsc.verification;

import com.fasterxml.jackson.databind.JsonNode;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.statement.ECCUnique;
import com.webauthn4j.data.attestation.statement.RSAUnique;
import com.webauthn4j.data.attestation.statement.TPMSAttest;
import com.webauthn4j.data.attestation.statement.TPMSCertifyInfo;
import com.webauthn4j.data.attestation.statement.TPMGenerated;
import com.webauthn4j.data.attestation.statement.TPMIAlgPublic;
import com.webauthn4j.data.attestation.statement.TPMISTAttest;
import com.webauthn4j.data.attestation.statement.TPMSECCParms;
import com.webauthn4j.data.attestation.statement.TPMTPublic;
import com.webauthn4j.data.attestation.statement.TPMSRSAParms;
import org.keycloak.common.util.Base64Url;
import org.keycloak.jose.jwk.ECPublicJWK;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.RSAPublicJWK;
import org.keycloak.util.JWKSUtils;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;

final class TpmAttestationVerifier {

    private static final int TPM_ALG_RSASSA = 0x0014;
    private static final int TPM_ALG_ECDSA = 0x0018;
    private static final int TPM_ALG_SHA256 = 0x000B;

    private final ObjectConverter objectConverter = new ObjectConverter();

    TpmAttestationVerifier() {
    }

    TPMSAttest verify(
            JsonNode claim,
            String challenge,
            JWK signingKey,
            String proofAlgorithm,
            JWK attestationKey,
            String attestationAlgorithm) throws Exception {
        requireSupportedAlgorithm(proofAlgorithm);
        requireSupportedAlgorithm(attestationAlgorithm);
        TPMSAttest attestation = decodeTpm(
                decodeBase64Url(requiredText(claim, "stmt"), "stmt"), TPMSAttest.class, "TPMS_ATTEST");
        if (attestation.getMagic() != TPMGenerated.TPM_GENERATED_VALUE
                || attestation.getType() != TPMISTAttest.TPM_ST_ATTEST_CERTIFY) {
            throw new SecurityException("TPMS_ATTESTが有効なTPM certify構造ではありません。");
        }

        byte[] expectedExtraData = MessageDigest.getInstance(hashName(attestationAlgorithm))
                .digest(challenge.getBytes(StandardCharsets.UTF_8));
        if (!MessageDigest.isEqual(expectedExtraData, attestation.getExtraData())) {
            throw new SecurityException("TPMS_ATTEST.extraDataがchallengeのハッシュと一致しません。");
        }

        TPMTPublic subjectKey = decodeTpm(
                decodeBase64Url(requiredText(claim, "sub_key"), "sub_key"),
                TPMTPublic.class,
                "TPMT_PUBLIC");
        verifySubjectKeyMatchesProof(subjectKey, signingKey, proofAlgorithm);
        verifyCertifiedName(attestation, subjectKey);
        verifyTpmSignature(
                decodeBase64Url(requiredText(claim, "sig"), "sig"),
                attestation.getBytes(),
                attestationKey,
                attestationAlgorithm);
        return attestation;
    }

    private void verifySubjectKeyMatchesProof(TPMTPublic subjectKey, JWK signingKey, String proofAlgorithm) {
        if ("ES256".equals(proofAlgorithm)) {
            if (subjectKey.getType() != TPMIAlgPublic.TPM_ALG_ECC
                    || !(subjectKey.getParameters() instanceof TPMSECCParms parameters)
                    || parameters.getCurveId().getValue() != 0x0003
                    || !(subjectKey.getUnique() instanceof ECCUnique unique)
                    || !(signingKey instanceof ECPublicJWK ecJwk)
                    || !"P-256".equals(ecJwk.getCrv())) {
                throw new SecurityException("TPM sub_keyとES256 proof keyの形式が一致しません。");
            }
            if (!MessageDigest.isEqual(unique.getX(), decodeBase64Url(ecJwk.getX(), "JWK x"))
                    || !MessageDigest.isEqual(unique.getY(), decodeBase64Url(ecJwk.getY(), "JWK y"))) {
                throw new SecurityException("TPM sub_keyとDBSC proof JWKのEC公開鍵が一致しません。");
            }
            return;
        }

        if (subjectKey.getType() != TPMIAlgPublic.TPM_ALG_RSA
                || !(subjectKey.getParameters() instanceof TPMSRSAParms parameters)
                || !(subjectKey.getUnique() instanceof RSAUnique unique)
                || !(signingKey instanceof RSAPublicJWK rsaJwk)) {
            throw new SecurityException("TPM sub_keyとRS256 proof keyの形式が一致しません。");
        }
        BigInteger tpmExponent = new BigInteger(1, parameters.getExponent());
        if (tpmExponent.signum() == 0) {
            tpmExponent = BigInteger.valueOf(65537);
        }
        if (!new BigInteger(1, unique.getN()).equals(new BigInteger(1, decodeBase64Url(rsaJwk.getModulus(), "JWK n")))
                || !tpmExponent.equals(new BigInteger(1, decodeBase64Url(rsaJwk.getPublicExponent(), "JWK e")))) {
            throw new SecurityException("TPM sub_keyとDBSC proof JWKのRSA公開鍵が一致しません。");
        }
    }

    private void verifyCertifiedName(TPMSAttest attestation, TPMTPublic subjectKey) throws Exception {
        if (!(attestation.getAttested() instanceof TPMSCertifyInfo certifyInfo)) {
            throw new SecurityException("TPMS_ATTESTにTPMS_CERTIFY_INFOがありません。");
        }
        if (certifyInfo.getName().getHashAlg() != subjectKey.getNameAlg()) {
            throw new SecurityException("certifyInfo.nameのhash algorithmがsub_key.nameAlgと一致しません。");
        }
        byte[] expectedName = MessageDigest.getInstance(hashName(subjectKey.getNameAlg().name()))
                .digest(subjectKey.getBytes());
        if (!MessageDigest.isEqual(expectedName, certifyInfo.getName().getDigest())) {
            throw new SecurityException("certifyInfo.nameがTPMT_PUBLIC sub_keyを指していません。");
        }
    }

    private void verifyTpmSignature(
            byte[] encodedSignature,
            byte[] signedData,
            JWK attestationKey,
            String algorithm) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(encodedSignature);
        int scheme = readUnsignedShort(buffer);
        int hashAlgorithm = readUnsignedShort(buffer);
        if (hashAlgorithm != TPM_ALG_SHA256 || !"SHA-256".equals(hashName(algorithm))) {
            throw new SecurityException("TPMT_SIGNATUREのhash algorithmがサポート対象外です。");
        }

        byte[] signature;
        if (scheme == TPM_ALG_ECDSA && "ES256".equals(algorithm) && attestationKey instanceof ECPublicJWK) {
            signature = EcdsaSignatureEncoding.tpmToDer(readSizedBytes(buffer), readSizedBytes(buffer));
        } else if (scheme == TPM_ALG_RSASSA && "RS256".equals(algorithm)
                && attestationKey instanceof RSAPublicJWK) {
            signature = readSizedBytes(buffer);
        } else {
            throw new SecurityException("TPMT_SIGNATUREのschemeがattestation key/algと一致しません。");
        }
        if (buffer.hasRemaining()) {
            throw new SecurityException("TPMT_SIGNATUREに余分なデータがあります。");
        }

        Key key = JWKSUtils.getKeyWrapper(attestationKey).getPublicKey();
        if (!(key instanceof PublicKey publicKey)) {
            throw new SecurityException("attestation JWKから公開鍵を復元できません。");
        }
        Signature verifier = Signature.getInstance(signatureName(algorithm));
        verifier.initVerify(publicKey);
        verifier.update(signedData);
        if (!verifier.verify(signature)) {
            throw new SecurityException("TPMS_ATTESTに対するTPMT_SIGNATUREが不正です。");
        }
    }

    private <T> T decodeTpm(byte[] raw, Class<T> type, String description) {
        try {
            byte[] cborByteString = objectConverter.getCborConverter().writeValueAsBytes(raw);
            return objectConverter.getCborConverter().readValue(cborByteString, type);
        } catch (Exception e) {
            throw new SecurityException(description + "のTPMバイナリをパースできません。", e);
        }
    }

    private String requiredText(JsonNode node, String name) {
        JsonNode value = node.get(name);
        if (value == null || !value.isTextual() || value.asText().isEmpty()) {
            throw new SecurityException("必須の文字列フィールド '" + name + "' がありません。");
        }
        return value.asText();
    }

    private byte[] decodeBase64Url(String value, String field) {
        try {
            return Base64Url.decode(value);
        } catch (Exception e) {
            throw new SecurityException("'" + field + "' のBase64URLデコードに失敗しました。", e);
        }
    }

    private int readUnsignedShort(ByteBuffer buffer) {
        if (buffer.remaining() < Short.BYTES) {
            throw new SecurityException("TPMT_SIGNATUREが途中で終わっています。");
        }
        return Short.toUnsignedInt(buffer.getShort());
    }

    private byte[] readSizedBytes(ByteBuffer buffer) {
        int length = readUnsignedShort(buffer);
        if (length > buffer.remaining()) {
            throw new SecurityException("TPMT_SIGNATUREのサイズ情報が不正です。");
        }
        byte[] result = new byte[length];
        buffer.get(result);
        return result;
    }

    private String hashName(String algorithm) {
        return switch (algorithm) {
            case "ES256", "RS256", "TPM_ALG_SHA256" -> "SHA-256";
            case "TPM_ALG_SHA384" -> "SHA-384";
            case "TPM_ALG_SHA512" -> "SHA-512";
            default -> throw new SecurityException("未対応のハッシュアルゴリズムです: " + algorithm);
        };
    }

    private String signatureName(String algorithm) {
        return switch (algorithm) {
            case "ES256" -> "SHA256withECDSA";
            case "RS256" -> "SHA256withRSA";
            default -> throw new SecurityException("未対応の署名アルゴリズムです: " + algorithm);
        };
    }

    private void requireSupportedAlgorithm(String algorithm) {
        if (!"ES256".equals(algorithm) && !"RS256".equals(algorithm)) {
            throw new SecurityException("未対応の署名アルゴリズムです: " + algorithm);
        }
    }
}