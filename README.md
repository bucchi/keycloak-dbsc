# keycloak-dbsc

Keycloak 26.7.4 extension containing the DBSC TPM registration verifier and a
realm registration endpoint.

## Source layout

- `com.github.bucchi.dbsc.verification`: DBSC proof and TPM attestation verification.
- `com.github.bucchi.dbsc.keycloak`: Realm REST provider and UserSession integration.
- Test sources mirror these packages under `src/test/java`.

## Registration endpoint

The extension registers `POST /realms/{realm}/dbsc/StartSession`. It expects a
valid Keycloak SSO identity cookie and a `Secure-Session-Response` structured
field string containing the compact attested registration JWS.

Before returning a login response with the matching DBSC registration
challenge, the login integration must call `DbscRegistrationNotes.issueChallenge`
for the authenticated `UserSessionModel`. The registration endpoint verifies
that challenge, consumes it once, stores both verified public JWKs on that
session, and returns DBSC session instructions with a 10-minute `KC_DBSC_AUTH`
cookie.

The endpoint currently advertises `/realms/{realm}/dbsc/RefreshSession`, but
that refresh endpoint and the login-response integration that issues the
challenge and `Secure-Session-Registration` header are not included yet. Until
those pieces are implemented, this endpoint is the registration slice only and
does not provide a complete DBSC session lifecycle.

Deploy the built JAR to Keycloak's `providers/` directory and run
`bin/kc.sh build` before starting Keycloak.