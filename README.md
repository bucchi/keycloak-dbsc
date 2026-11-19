# keycloak-dbsc

Keycloak 26.7.4 extension containing the DBSC TPM registration verifier, a
realm registration endpoint, and an experimental DBSC-SSO authentication
execution.

## Source layout

- `com.github.bucchi.dbsc.verification`: DBSC proof and TPM attestation verification.
- `com.github.bucchi.dbsc.keycloak`: Realm REST provider, UserSession integration, and authentication execution.
- Test sources mirror these packages under `src/test/java`.

## Tests

See [TESTING.md](TESTING.md) for test commands, prerequisites, coverage, and
limitations. Run `mvn test` for unit tests or `mvn verify` to include the
Testcontainers-based Keycloak integration test.

## Registration endpoint

The extension registers `POST /realms/{realm}/dbsc/StartSession`. It expects a
valid Keycloak SSO identity cookie and a `Secure-Session-Response` structured
field string containing the compact attested registration JWS.

When the DBSC-SSO authenticator starts a first IdP session without an AIK, it
issues a registration challenge and returns `Secure-Session-Registration` with
`aik_required=?1`. Its waiting page polls the registration status endpoint and
continues the Keycloak flow after enrollment completes. The registration
endpoint authenticates the Keycloak SSO cookie, verifies and consumes the
challenge once, stores the verified public JWKs and AIK metadata on the
`UserSession`, and returns DBSC session instructions with a 10-minute
`KC_DBSC_AUTH` cookie.

The endpoint currently advertises `/realms/{realm}/dbsc/RefreshSession`, but
that refresh endpoint is not included yet, so the extension does not provide a
complete DBSC session lifecycle.

## Experimental DBSC-SSO authentication execution

The `DBSC-SSO binding (experimental)` execution is registered as
`dbsc-sso-binding`. Add it as a required execution after the browser flow has
identified the user. Enable it only for test RP clients by setting the client
attribute `dbsc.sso.enabled=true`.

For an enabled client with no registered AIK, the execution creates or reuses a
Keycloak `UserSession`, issues its normal identity/session cookies and an
`aik_required` registration header, then waits on a page while the browser
performs asynchronous TPM enrollment. After registration, the page resumes the
Keycloak authenticator through its standard action URL. The execution then
responds with HTTP 401 plus `Secure-Session-GenerateKey`. For clients with an
existing AIK, it goes directly to that 401 response. The RP origin is derived
from the OIDC redirect URI. The binding challenge is short-lived and single-use.
A hash-keyed pending record
stores the associated UserSession, client, redirect URI/origin, and OIDC request
fingerprint so a retry can be matched even when Keycloak creates a new child
Authentication Session. The Base64URL-encoded binding JSON carries a nested
DBSC proof; its challenge is matched to that pending record, the request
metadata is checked, and the binding is validated against the stored TPM AIK
before the execution succeeds and lets Keycloak finish its normal OIDC response.

This is an integration experiment, not a complete DBSC-SSO implementation. It
currently supports TPM attestations with ES256/RS256, does not implement the
refresh endpoint, and does not automatically add the support-hint claim to OIDC tokens.
The trusted key digest and algorithm are stored as client-session notes; expose
them with client-session protocol mappers before relying on them at an RP.
Verify in a real Keycloak deployment that the browser processes
`Secure-Session-Registration` from the waiting response, stores the cookies,
completes TPM enrollment, and resumes the OIDC transaction before using this
execution outside a test realm.

Deploy the built JAR to Keycloak's `providers/` directory and run
`bin/kc.sh build` before starting Keycloak.