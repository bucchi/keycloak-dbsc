package com.github.bucchi.dbsc.keycloak;

import com.github.bucchi.dbsc.verification.DBSCBindingVerifier;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Details;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.UserSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import jakarta.ws.rs.core.UriBuilder;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

public final class DbscSsoAuthenticator implements Authenticator {

    private static final String CHALLENGE_NOTE = "dbsc.sso.binding.challenge";
    private static final String USER_SESSION_NOTE = "dbsc.sso.binding.user-session-id";
    private static final String PENDING_USER_SESSION = "user_session";
    private static final String PENDING_USER_ID = "user_id";
    private static final String PENDING_CLIENT_ID = "client_id";
    private static final String PENDING_REDIRECT_URI = "redirect_uri";
    private static final String PENDING_TARGET_ORIGIN = "target_origin";
    private static final String PENDING_REQUEST_FINGERPRINT = "request_fingerprint";
    private static final String CHALLENGE_KEY_PREFIX = "dbsc:sso:binding:";
    private static final int CHALLENGE_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();
    private final DBSCBindingVerifier bindingVerifier = new DBSCBindingVerifier();

    @Override
    public void close() {
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        if (!DbscSsoProtocol.isEnabledForClient(context.getAuthenticationSession().getClient()
                .getAttribute(DbscSsoProtocol.CLIENT_ENABLED_ATTRIBUTE))) {
            context.attempted();
            return;
        }

        String bindingHeader = context.getHttpRequest().getHttpHeaders()
                .getHeaderString(DbscSsoProtocol.KEY_BINDING_HEADER);
        UserSessionModel userSession = getOrCreateUserSession(context);
        if (userSession == null) {
            fail(context);
            return;
        }

        if (bindingHeader != null) {
            verifyBindingAndContinue(context, userSession, bindingHeader);
            return;
        }

        if (!hasAttestationState(userSession)) {
            issueIdpRegistrationWait(context, userSession);
            return;
        }

        issueGenerateKeyChallenge(context, userSession);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        authenticate(context);
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    private UserSessionModel getOrCreateUserSession(AuthenticationFlowContext context) {
        RealmModel realm = context.getRealm();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String rootSessionId = authSession.getParentSession().getId();
        UserModel user = context.getUser();

        UserSessionModel userSession = context.getSession().sessions().getUserSession(realm, rootSessionId);
        if (userSession != null) {
            if (user != null && !user.getId().equals(userSession.getUser().getId())) {
                return null;
            }
            if (user == null) {
                context.setUser(userSession.getUser());
            }
        } else {
            AuthenticationManager.AuthResult cookieAuth = AuthenticationManager
                    .authenticateIdentityCookie(context.getSession(), realm, true);
            if (cookieAuth != null && cookieAuth.session() != null
                    && AuthenticationManager.isSessionValid(realm, cookieAuth.session())
                    && (user == null || user.getId().equals(cookieAuth.session().getUser().getId()))) {
                userSession = cookieAuth.session();
                if (user == null) {
                    context.setUser(userSession.getUser());
                }
            }
        }

        if (userSession == null) {
            if (user == null) {
                return null;
            }
            String rememberMeNote = authSession.getAuthNote(Details.REMEMBER_ME);
            boolean rememberMe = "true".equalsIgnoreCase(rememberMeNote);
            UserSessionModel.SessionPersistenceState persistenceState =
                    UserSessionModel.SessionPersistenceState.fromString(
                            authSession.getClientNote(AuthenticationManager.USER_SESSION_PERSISTENT_STATE));
            userSession = new UserSessionManager(context.getSession()).createUserSession(
                    rootSessionId,
                    realm,
                    user,
                    user.getUsername(),
                    context.getConnection().getRemoteHost(),
                    authSession.getProtocol(),
                    rememberMe,
                    null,
                    null,
                    persistenceState);
            userSession.setState(UserSessionModel.State.LOGGED_IN);
        }

        context.attachUserSession(userSession);
        context.getSession().getContext().setUserSession(userSession);
        return userSession;
    }

    private boolean hasAttestationState(UserSessionModel userSession) {
        return notBlank(userSession.getNote(DbscRegistrationNotes.SESSION_ID_NOTE))
                && notBlank(userSession.getNote(DbscRegistrationNotes.ATTESTATION_KEY_NOTE))
                && notBlank(userSession.getNote(DbscRegistrationNotes.ATTESTATION_FORMAT_NOTE))
                && notBlank(userSession.getNote(DbscRegistrationNotes.ATTESTATION_ALGORITHM_NOTE));
    }

            private void issueIdpRegistrationWait(
                AuthenticationFlowContext context,
                UserSessionModel userSession) {
            String challenge = userSession.getNote(DbscRegistrationNotes.CHALLENGE_NOTE);
            if (!DbscRegistrationNotes.isChallengeActive(context.getSession(), userSession, challenge)) {
                challenge = DbscRegistrationNotes.issueChallenge(
                    context.getSession(),
                    userSession,
                    DbscSsoProtocol.REGISTRATION_CHALLENGE_LIFETIME_SECONDS);
            }

            AuthenticationManager.createLoginCookie(
                context.getSession(),
                context.getRealm(),
                userSession.getUser(),
                userSession,
                context.getUriInfo(),
                context.getConnection());

            URI registrationEndpoint = realmResourceUri(context, RegistrationResource.START_SESSION_PATH);
            URI statusEndpoint = UriBuilder.fromUri(realmResourceUri(
                    context, RegistrationResource.REGISTRATION_STATUS_PATH))
                .queryParam("challenge", challenge)
                .build();
            URI scriptEndpoint = realmResourceUri(context, RegistrationResource.REGISTRATION_WAIT_SCRIPT_PATH);
            String code = context.generateAccessCode();
            URI actionUrl = context.getActionUrl(code);

            String html = registrationWaitPage(statusEndpoint, actionUrl, scriptEndpoint);

            Response response = Response.ok(html)
                .type("text/html; charset=UTF-8")
                .header("Secure-Session-Registration",
                    DbscSsoProtocol.registrationHeader(registrationEndpoint.toString(), challenge))
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .header("X-Content-Type-Options", "nosniff")
                .build();
            context.forceChallenge(response);
            }

            private String registrationWaitPage(URI statusEndpoint, URI actionUrl, URI scriptEndpoint) {
            try (InputStream template = getClass().getResourceAsStream("registration-wait.html")) {
                if (template == null) {
                    throw new IllegalStateException("Registration wait page resource is missing.");
                }
                String html = new String(template.readAllBytes(), StandardCharsets.UTF_8);
                return html.replace("{{STATUS_URL}}", escapeHtml(statusEndpoint.toString()))
                    .replace("{{ACTION_URL}}", escapeHtml(actionUrl.toString()))
                    .replace("{{SCRIPT_URL}}", escapeHtml(scriptEndpoint.toString()));
            } catch (IOException e) {
                throw new IllegalStateException("Unable to read registration wait page resource.", e);
            }
            }

            private URI realmResourceUri(AuthenticationFlowContext context, String endpoint) {
            return context.getUriInfo().getBaseUriBuilder()
                .path("realms")
                .path(context.getRealm().getName())
                .path(DbscRealmResourceProviderFactory.PROVIDER_ID)
                .path(endpoint)
                .build();
            }

            private String escapeHtml(String value) {
            return value.replace("&", "&amp;")
                .replace("\"", "&quot;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
            }

    private void issueGenerateKeyChallenge(AuthenticationFlowContext context, UserSessionModel userSession) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String challenge = authSession.getAuthNote(CHALLENGE_NOTE);
        boolean newChallenge = challenge == null;
        if (challenge == null) {
            challenge = randomChallenge();
            authSession.setAuthNote(CHALLENGE_NOTE, challenge);
            authSession.setAuthNote(USER_SESSION_NOTE, userSession.getId());
        } else if (!userSession.getId().equals(authSession.getAuthNote(USER_SESSION_NOTE))) {
            fail(context);
            return;
        }

        final String targetOrigin;
        try {
            targetOrigin = DbscSsoProtocol.origin(authSession.getRedirectUri());
        } catch (IllegalArgumentException e) {
            fail(context);
            return;
        }

        String clientId = authSession.getClient().getId();
        String redirectUri = authSession.getRedirectUri();
        String fingerprint = DbscSsoProtocol.requestFingerprint(
                clientId, redirectUri, authSession.getClientNotes());
        String challengeKey = challengeKey(context.getRealm().getId(), challenge);
        Map<String, String> pending = context.getSession().singleUseObjects().get(challengeKey);
        if (pending == null && newChallenge) {
            context.getSession().singleUseObjects().put(
                    challengeKey,
                    DbscSsoProtocol.CHALLENGE_LIFETIME_SECONDS,
                    pendingBinding(userSession, clientId, redirectUri, targetOrigin, fingerprint));
        } else if (!matchesPendingBinding(
            pending, userSession, clientId, redirectUri, targetOrigin, fingerprint)) {
            fail(context);
            return;
        }

        AuthenticationManager.createLoginCookie(
                context.getSession(),
                context.getRealm(),
                userSession.getUser(),
                userSession,
                context.getUriInfo(),
                context.getConnection());

        Response response = Response.status(Response.Status.UNAUTHORIZED)
                .header(DbscSsoProtocol.GENERATE_KEY_HEADER,
                        DbscSsoProtocol.generateKeyHeader(
                                targetOrigin,
                                challenge,
                                userSession.getNote(DbscRegistrationNotes.SESSION_ID_NOTE)))
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .build();
        context.forceChallenge(response);
    }

    private void verifyBindingAndContinue(
            AuthenticationFlowContext context,
            UserSessionModel userSession,
            String bindingHeader) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        if (!hasAttestationState(userSession)) {
            fail(context);
            return;
        }

        try {
            String challenge = bindingVerifier.extractChallenge(bindingHeader);
            String clientId = authSession.getClient().getId();
            String redirectUri = authSession.getRedirectUri();
            String targetOrigin = DbscSsoProtocol.origin(redirectUri);
            String fingerprint = DbscSsoProtocol.requestFingerprint(
                    clientId, redirectUri, authSession.getClientNotes());
            String pendingKey = challengeKey(context.getRealm().getId(), challenge);
            Map<String, String> pending = context.getSession().singleUseObjects().get(pendingKey);
            if (!matchesPendingBinding(
                    pending, userSession, clientId, redirectUri, targetOrigin, fingerprint)) {
                fail(context);
                return;
            }

            JWK attestationKey = DBSCBindingVerifier.readStoredAttestationKey(
                    userSession.getNote(DbscRegistrationNotes.ATTESTATION_KEY_NOTE));
            DBSCBindingVerifier.VerifiedBinding verified = bindingVerifier.verify(
                    bindingHeader,
                    challenge,
                    context.getUriInfo().getRequestUri().toString(),
                    attestationKey,
                    userSession.getNote(DbscRegistrationNotes.ATTESTATION_ALGORITHM_NOTE),
                    userSession.getNote(DbscRegistrationNotes.ATTESTATION_FORMAT_NOTE));
                Map<String, String> consumed = context.getSession().singleUseObjects().remove(pendingKey);
                if (!matchesPendingBinding(
                        consumed, userSession, clientId, redirectUri, targetOrigin, fingerprint)) {
                fail(context);
                return;
            }

            authSession.setClientNote(DbscSsoProtocol.RP_KEY_DIGEST_NOTE, verified.thumbprint());
            authSession.setClientNote(DbscSsoProtocol.RP_KEY_DIGEST_ALGORITHM_NOTE, verified.digestAlgorithm());
            authSession.removeAuthNote(CHALLENGE_NOTE);
            authSession.removeAuthNote(USER_SESSION_NOTE);
            context.attachUserSession(userSession);
            context.success();
        } catch (Exception e) {
            fail(context);
        }
    }

    private void fail(AuthenticationFlowContext context) {
        context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
    }

    private String randomChallenge() {
        byte[] bytes = new byte[CHALLENGE_BYTES];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

        private Map<String, String> pendingBinding(
            UserSessionModel userSession,
            String clientId,
            String redirectUri,
            String targetOrigin,
            String fingerprint) {
        return Map.of(
            PENDING_USER_SESSION, userSession.getId(),
            PENDING_USER_ID, userSession.getUser().getId(),
            PENDING_CLIENT_ID, clientId,
            PENDING_REDIRECT_URI, redirectUri,
            PENDING_TARGET_ORIGIN, targetOrigin,
            PENDING_REQUEST_FINGERPRINT, fingerprint);
        }

        private boolean matchesPendingBinding(
            Map<String, String> pending,
            UserSessionModel userSession,
            String clientId,
            String redirectUri,
            String targetOrigin,
            String fingerprint) {
        return pending != null
            && userSession.getUser() != null
            && userSession.getUser().getId().equals(pending.get(PENDING_USER_ID))
            && userSession.getId().equals(pending.get(PENDING_USER_SESSION))
            && clientId.equals(pending.get(PENDING_CLIENT_ID))
            && redirectUri.equals(pending.get(PENDING_REDIRECT_URI))
            && targetOrigin.equals(pending.get(PENDING_TARGET_ORIGIN))
            && fingerprint.equals(pending.get(PENDING_REQUEST_FINGERPRINT));
        }

        private String challengeKey(String realmId, String challenge) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(challenge.getBytes(StandardCharsets.US_ASCII));
            String hashedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
            return CHALLENGE_KEY_PREFIX + realmId + ":" + hashedChallenge;
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 is unavailable.", e);
        }
    }

    private boolean notBlank(String value) {
        return value != null && !value.isBlank();
    }
}