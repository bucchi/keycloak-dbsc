package com.github.bucchi.dbsc.verification;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.keycloak.jose.jwk.ECPublicJWK;
import org.keycloak.jose.jwk.JWK;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DBSCBindingVerifierTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void thumbprintUsesOnlyCanonicalPublicEcMembers() throws Exception {
        ECPublicJWK first = mapper.readValue("""
                {"kty":"EC","crv":"P-256","x":"AQ","y":"Ag","kid":"first"}
                """, ECPublicJWK.class);
        ECPublicJWK samePublicKey = mapper.readValue("""
                {"kty":"EC","crv":"P-256","x":"AQ","y":"Ag","kid":"second","alg":"ES256"}
                """, ECPublicJWK.class);
        ECPublicJWK differentPublicKey = mapper.readValue("""
                {"kty":"EC","crv":"P-256","x":"Aw","y":"Ag"}
                """, ECPublicJWK.class);

        String thumbprint = DBSCBindingVerifier.jwkThumbprint(first);

        assertEquals(thumbprint, DBSCBindingVerifier.jwkThumbprint(samePublicKey));
        assertNotEquals(thumbprint, DBSCBindingVerifier.jwkThumbprint(differentPublicKey));
        assertTrue(thumbprint.matches("[A-Za-z0-9_-]{43}"));
    }

        @Test
        void restoresStoredAttestationKeyAsItsConcreteJwkType() throws Exception {
                JWK key = DBSCBindingVerifier.readStoredAttestationKey(
                                "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"AQ\",\"y\":\"Ag\"}");

                assertTrue(key instanceof ECPublicJWK);
        }

        @Test
        void extractsChallengeFromBase64UrlBindingStatementAndNestedDbscProof() throws Exception {
                String challenge = "server-challenge-123";
                String proofHeader = base64Url("{\"alg\":\"ES256\",\"typ\":\"dbsc+jwt\",\"jwk\":{"
                                + "\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"AQ\",\"y\":\"Ag\"}}");
                String proofPayload = base64Url("{\"aud\":\"https://idp.example/auth\",\"jti\":\""
                                + challenge + "\"}");
                String proof = proofHeader + "." + proofPayload + "." + base64Url("signature");
                String statement = base64Url("{\"aud\":\"https://idp.example/auth\",\"jti\":\""
                                + base64Url(proof) + "\",\"att\":\""
                                + base64Url("{\"stmt\":\"attestation\",\"sig\":\"signature\",\"sub_key\":\"key\"}")
                                + "\"}");

                assertEquals(challenge, new DBSCBindingVerifier().extractChallenge(statement));
        }

        @Test
        void rejectsBindingStatementWithoutDbscProofChallenge() {
                String statement = base64Url("{\"jti\":\"not-a-jws\",\"att\":\"e30\"}");

                assertThrows(SecurityException.class,
                                () -> new DBSCBindingVerifier().extractChallenge(statement));
        }

        private String base64Url(String value) {
                return java.util.Base64.getUrlEncoder().withoutPadding()
                                .encodeToString(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
}