package com.github.bucchi.dbsc.keycloak;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.Provider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.managers.AuthenticationManager;
import com.github.bucchi.dbsc.verification.DBSCRegistrationVerifier;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

@Provider
@Path("/")
public final class RegistrationResource {

    static final String SECURE_SESSION_RESPONSE = "Secure-Session-Response";
    static final String DBSC_COOKIE_NAME = "KC_DBSC_AUTH";
    static final String START_SESSION_PATH = "StartSession";
    static final String REGISTRATION_STATUS_PATH = "RegistrationStatus";
    static final String REGISTRATION_WAIT_SCRIPT_PATH = "RegistrationWait.js";
    static final String REFRESH_PATH = "RefreshSession";
    static final int GRANT_LIFETIME_SECONDS = 600;

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();

    private final KeycloakSession session;
    private final DBSCRegistrationVerifier verifier;

    RegistrationResource(KeycloakSession session) {
        this.session = Objects.requireNonNull(session);
        this.verifier = new DBSCRegistrationVerifier();
    }

    @POST
    @Path("StartSession")
    @Consumes(MediaType.WILDCARD)
    @Produces(MediaType.APPLICATION_JSON)
    public Response register(@Context HttpHeaders headers, @Context UriInfo uriInfo) {
        RealmModel realm = session.getContext().getRealm();
        if (realm == null) {
            return unauthorized();
        }

        AuthenticationManager.AuthResult auth = AuthenticationManager.authenticateIdentityCookie(
                session, realm, true);
        if (auth == null || auth.session() == null || auth.session().isOffline()
                || !AuthenticationManager.isSessionValid(realm, auth.session())) {
            return unauthorized();
        }

        UserSessionModel userSession = auth.session();
        String expectedChallenge = userSession.getNote(DbscRegistrationNotes.CHALLENGE_NOTE);
        if (expectedChallenge == null) {
            return badRequest();
        }

        String outerJws;
        try {
            outerJws = parseStructuredFieldString(headers.getHeaderString(SECURE_SESSION_RESPONSE));
        } catch (IllegalArgumentException e) {
            return badRequest();
        }

        URI registrationUri = endpointUri("StartSession", uriInfo);
        DBSCRegistrationVerifier.VerifiedRegistration verified;
        try {
            verified = verifier.verify(outerJws, expectedChallenge, registrationUri.toString());
        } catch (Exception e) {
            return badRequest();
        }

        if (!DbscRegistrationNotes.consumeChallenge(session, userSession, expectedChallenge)) {
            return badRequest();
        }

        String dbscSessionId = randomToken(24);
        String grant = randomToken(32);
        try {
            userSession.setNote(DbscRegistrationNotes.SESSION_ID_NOTE, dbscSessionId);
            userSession.setNote(DbscRegistrationNotes.SIGNING_KEY_NOTE,
                    MAPPER.writeValueAsString(verified.signingKey()));
            userSession.setNote(DbscRegistrationNotes.ATTESTATION_KEY_NOTE,
                    MAPPER.writeValueAsString(verified.attestationKey()));
                userSession.setNote(DbscRegistrationNotes.ATTESTATION_FORMAT_NOTE, verified.attestationFormat());
                userSession.setNote(DbscRegistrationNotes.ATTESTATION_ALGORITHM_NOTE, verified.attestationAlgorithm());
            userSession.setNote(DbscRegistrationNotes.GRANT_HASH_NOTE, sha256(grant));
            userSession.setNote(DbscRegistrationNotes.COMPLETED_CHALLENGE_NOTE, expectedChallenge);
        } catch (Exception e) {
            return Response.serverError().header("Cache-Control", "no-store").build();
        }

        String cookiePath = AuthenticationManager.getRealmCookiePath(realm, uriInfo);
        String cookieAttributes = "Path=" + cookiePath + "; Secure; HttpOnly; SameSite=Lax";
        SessionInstructions instructions = new SessionInstructions(
                dbscSessionId,
                endpointUri(REFRESH_PATH, uriInfo).toString(),
                new ScopeInstructions(origin(uriInfo.getBaseUri()), false, List.of()),
                List.of(new CookieCredential(DBSC_COOKIE_NAME, cookieAttributes)));

        return Response.ok(instructions)
                .header("Set-Cookie", DBSC_COOKIE_NAME + "=" + grant
                        + "; Max-Age=" + GRANT_LIFETIME_SECONDS + "; " + cookieAttributes)
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .build();
    }

    @GET
    @Path(REGISTRATION_STATUS_PATH)
    @Produces(MediaType.APPLICATION_JSON)
    public Response registrationStatus(@QueryParam("challenge") String challenge) {
        RealmModel realm = session.getContext().getRealm();
        if (realm == null || challenge == null || challenge.isBlank()) {
            return badRequest();
        }

        AuthenticationManager.AuthResult auth = AuthenticationManager.authenticateIdentityCookie(
                session, realm, true);
        if (auth == null || auth.session() == null || auth.session().isOffline()
                || !AuthenticationManager.isSessionValid(realm, auth.session())) {
            return unauthorized();
        }

        UserSessionModel userSession = auth.session();
        if (challenge.equals(userSession.getNote(DbscRegistrationNotes.COMPLETED_CHALLENGE_NOTE))
                && userSession.getNote(DbscRegistrationNotes.ATTESTATION_KEY_NOTE) != null
                && userSession.getNote(DbscRegistrationNotes.ATTESTATION_FORMAT_NOTE) != null
                && userSession.getNote(DbscRegistrationNotes.ATTESTATION_ALGORITHM_NOTE) != null) {
            return statusResponse(true);
        }
        if (DbscRegistrationNotes.isChallengeActive(session, userSession, challenge)) {
            return statusResponse(false);
        }
        return Response.status(Response.Status.GONE).header("Cache-Control", "no-store").build();
    }

    @GET
    @Path(REGISTRATION_WAIT_SCRIPT_PATH)
    @Produces("application/javascript; charset=UTF-8")
    public Response registrationWaitScript() {
        return Response.ok(loadRegistrationWaitScript())
                .header("Cache-Control", "no-store")
                .header("X-Content-Type-Options", "nosniff")
                .build();
    }

    private String loadRegistrationWaitScript() {
        try (InputStream script = getClass().getResourceAsStream("registration-wait.js")) {
            if (script == null) {
                throw new IllegalStateException("Registration wait script resource is missing.");
            }
            return new String(script.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to read registration wait script resource.", e);
        }
    }

    private Response statusResponse(boolean registered) {
        return Response.ok(new RegistrationStatus(registered))
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .build();
    }

    static String parseStructuredFieldString(String value) {
        if (value == null || value.length() < 3 || value.length() > 16_384
                || value.charAt(0) != '"' || value.charAt(value.length() - 1) != '"') {
            throw new IllegalArgumentException("Secure-Session-Response must be an sf-string.");
        }
        String jws = value.substring(1, value.length() - 1);
        String[] segments = jws.split("\\.", -1);
        if (segments.length != 3) {
            throw new IllegalArgumentException("Secure-Session-Response is not a compact JWS.");
        }
        for (String segment : segments) {
            if (segment.isEmpty()) {
                throw new IllegalArgumentException("Secure-Session-Response is not a compact JWS.");
            }
            for (int i = 0; i < segment.length(); i++) {
                char c = segment.charAt(i);
                if (!(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
                        || c >= '0' && c <= '9' || c == '-' || c == '_')) {
                    throw new IllegalArgumentException("Secure-Session-Response contains invalid characters.");
                }
            }
        }
        return jws;
    }

    private URI endpointUri(String endpoint, UriInfo uriInfo) {
        return uriInfo.getBaseUriBuilder()
                .path("realms")
                .path(session.getContext().getRealm().getName())
                .path(DbscRealmResourceProviderFactory.PROVIDER_ID)
                .path(endpoint)
                .build();
    }

    private String origin(URI baseUri) {
        return UriBuilder.newInstance()
                .scheme(baseUri.getScheme())
                .host(baseUri.getHost())
                .port(baseUri.getPort())
                .build()
                .toString();
    }

    private String randomToken(int byteCount) {
        byte[] bytes = new byte[byteCount];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String sha256(String value) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private Response unauthorized() {
        return Response.status(Response.Status.UNAUTHORIZED)
                .header("Cache-Control", "no-store")
                .build();
    }

    private Response badRequest() {
        return Response.status(Response.Status.BAD_REQUEST)
                .header("Cache-Control", "no-store")
                .build();
    }

    public record SessionInstructions(
            @JsonProperty("session_identifier") String sessionIdentifier,
            @JsonProperty("refresh_url") String refreshUrl,
            @JsonProperty("scope") ScopeInstructions scope,
            @JsonProperty("credentials") List<CookieCredential> credentials) {
    }

    public record RegistrationStatus(@JsonProperty("registered") boolean registered) {
    }

    public record ScopeInstructions(
            @JsonProperty("origin") String origin,
            @JsonProperty("include_site") boolean includeSite,
            @JsonProperty("scope_specification") List<Object> scopeSpecification) {
    }

    public record CookieCredential(
            @JsonProperty("type") String type,
            @JsonProperty("name") String name,
            @JsonProperty("attributes") String attributes) {
        CookieCredential(String name, String attributes) {
            this("cookie", name, attributes);
        }
    }
}