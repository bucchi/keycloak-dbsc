# Testing

## Requirements

- JDK 21
- Maven 3.9 or newer
- Docker Engine or Docker Desktop, available to Testcontainers
- `keytool` on `PATH` (normally included with the JDK)
- Network access to pull `quay.io/keycloak/keycloak:26.7.4` on the first integration-test run

The Keycloak integration test creates a temporary PKCS#12 TLS keystore with `keytool`, starts Keycloak in a disposable container, and removes the container after the test. It does not use a fixed host port.

## Run Tests

Run the unit tests only:

```sh
mvn test
```

Run only the Keycloak integration test (Maven also runs the unit-test phase):

```sh
mvn -Dit.test=DbscSsoKeycloakIT verify
```

Run all unit and integration tests:

```sh
mvn verify
```

The integration test uses Testcontainers' `disabledWithoutDocker` option. If Docker is unavailable, the integration test is skipped; a successful Maven exit in that situation does not mean the integration flow ran. Check the Failsafe summary under `target/failsafe-reports/` for the executed or skipped test count.

## Test Coverage

### Unit Tests

The unit tests cover protocol header construction, origin validation, request fingerprints, DBSC proof and TPM attestation verification, JWK thumbprints, nested-proof challenge extraction, and signature-encoding conversions.

`DbscFakeUserAgentRoundTripTest` uses `FakeDbscUserAgent` to create P-256 keys and valid test-format DBSC proof JWS, TPM `TPMT_PUBLIC` / `TPMS_ATTEST` structures, and signatures. It passes the resulting IdP registration statement and RP binding statement through the production verification classes. It also checks that a mismatched binding challenge is rejected.

### Keycloak Integration Test

`DbscSsoKeycloakIT` installs the packaged provider JAR into Keycloak 26.7.4 and configures a temporary realm, client, user, and browser authentication flow through the Admin REST API. A Java HTTP client with a cookie jar plays the browser's HTTP role. The test drives the OIDC login flow, submits a fake AIK registration response, checks registration status before and after enrollment, resumes the Keycloak authenticator, receives `Secure-Session-GenerateKey`, and retries the original OIDC authorization request with `Secure-Session-KeyBinding`. It verifies that the final redirect returns to the RP with an authorization code.

The HTTP client trusts the test server's self-signed TLS certificate only inside this test. The certificate is generated for the temporary Keycloak container and is not used by the provider at runtime.

## Scope and Limitations

These tests verify the Keycloak SPI wiring, HTTP/session handoffs, protocol parsing, and server-side cryptographic verification. The fake User-Agent generates test data in Java; it does not run a browser, access a hardware key store, or use a physical TPM.

The current server verifier accepts TPM attestations only. This suite does not test a browser's `SECURE_ENCLAVE` attestation path, Local Key Helper integration, browser key isolation, or DBSC-SSO behavior in a released Chromium build. Those require a separately configured browser/device test environment and compatible server-side attestation support.

## Troubleshooting

- **Integration test skipped:** Start Docker Desktop / Docker Engine and verify that the current user can access its daemon, then rerun `mvn verify`.
- **Keycloak image pull fails:** Confirm network access to `quay.io` and rerun after access is restored.
- **Keystore generation fails:** Confirm that JDK 21 is installed and `keytool` is available on `PATH`.
- **Provider JAR is missing:** Run through Maven's `verify` lifecycle. Failsafe receives the JAR produced during the `package` phase.
- **Keycloak returns an unexpected error:** Inspect the Maven output; the integration test forwards Keycloak error and exception log lines to the test output. Full Surefire and Failsafe reports are under `target/surefire-reports/` and `target/failsafe-reports/`.
