package com.github.bucchi.dbsc.keycloak;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserSessionModel;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

public final class DbscRegistrationNotes {

    public static final String CHALLENGE_NOTE = "dbsc.registration.challenge";
    public static final String SESSION_ID_NOTE = "dbsc.session.id";
    public static final String SIGNING_KEY_NOTE = "dbsc.signing.jwk";
    public static final String ATTESTATION_KEY_NOTE = "dbsc.attestation.jwk";
    public static final String GRANT_HASH_NOTE = "dbsc.grant.sha256";

    private static final String CHALLENGE_KEY_PREFIX = "dbsc:registration:";
    private static final SecureRandom RANDOM = new SecureRandom();

    private DbscRegistrationNotes() {
    }

    public static String issueChallenge(
            KeycloakSession session,
            UserSessionModel userSession,
            long lifetimeSeconds) {
        if (lifetimeSeconds <= 0) {
            throw new IllegalArgumentException("Challenge lifetime must be positive.");
        }

        byte[] random = new byte[32];
        RANDOM.nextBytes(random);
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        userSession.setNote(CHALLENGE_NOTE, challenge);
        session.singleUseObjects().put(challengeKey(userSession.getId(), challenge), lifetimeSeconds, Map.of());
        return challenge;
    }

    public static boolean consumeChallenge(
            KeycloakSession session,
            UserSessionModel userSession,
            String challenge) {
        if (challenge == null || challenge.isBlank()
                || !challenge.equals(userSession.getNote(CHALLENGE_NOTE))) {
            return false;
        }

        Map<String, String> consumed = session.singleUseObjects()
                .remove(challengeKey(userSession.getId(), challenge));
        if (consumed == null) {
            return false;
        }
        userSession.removeNote(CHALLENGE_NOTE);
        return true;
    }

    static String challengeKey(String userSessionId, String challenge) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(challenge.getBytes(StandardCharsets.UTF_8));
            String challengeHash = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
            return CHALLENGE_KEY_PREFIX + userSessionId + ":" + challengeHash;
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 is unavailable.", e);
        }
    }
}