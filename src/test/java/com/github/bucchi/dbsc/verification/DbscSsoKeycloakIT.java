package com.github.bucchi.dbsc.verification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;
import org.testcontainers.containers.wait.strategy.Wait;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Testcontainers(disabledWithoutDocker = true)
class DbscSsoKeycloakIT {

    private static final String REALM = "dbsc-sso-it";
    private static final String CLIENT_ID = "dbsc-rp";
    private static final String REDIRECT_URI = "https://rp.example.test/callback";
    private static final String AUTHENTICATOR_ID = "dbsc-sso-binding";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern FORM_PATTERN = Pattern.compile("(?is)<form\\b([^>]*)>(.*?)</form>");
    private static final Pattern ATTRIBUTE_PATTERN = Pattern.compile("([\\w-]+)\\s*=\\s*['\"]([^'\"]*)['\"]");
    private static final Pattern INPUT_PATTERN = Pattern.compile("(?is)<input\\b([^>]*)>");
    private static final Path KEYSTORE_PATH = createKeystore();

    @Container
    private static final GenericContainer<?> KEYCLOAK = new GenericContainer<>(
            DockerImageName.parse("quay.io/keycloak/keycloak:26.7.4"))
            .withExposedPorts(8443)
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
            .withCopyFileToContainer(
                        MountableFile.forHostPath(Path.of(System.getProperty("dbsc.provider.jar"))),
                    "/opt/keycloak/providers/keycloak-dbsc-test.jar")
                    .withCopyFileToContainer(MountableFile.forHostPath(KEYSTORE_PATH),
                        "/opt/keycloak/conf/dbsc-test-keystore.p12")
                    .withCommand("start-dev", "--http-enabled=false", "--https-port=8443",
                        "--https-key-store-file=/opt/keycloak/conf/dbsc-test-keystore.p12",
                        "--https-key-store-password=test-password", "--hostname-strict=false")
                    .withLogConsumer(frame -> {
                        String log = frame.getUtf8String();
                        if (log.contains("ERROR") || log.contains("Exception") || log.contains("Caused by")) {
                            System.err.print(log);
                        }
                    })
                        .waitingFor(Wait.forListeningPort()
                    .withStartupTimeout(Duration.ofMinutes(3)));

    @BeforeAll
    static void initializeKeycloakCrypto() {
        CryptoIntegration.init(Thread.currentThread().getContextClassLoader());
    }

    @Test
    void enrollsAikResumesAuthenticationAndBindsRpKey() throws Exception {
        HttpClient adminClient = newHttpClient();
        String adminToken = getAdminToken(adminClient);
        createRealmAndFlow(adminClient, adminToken);

        HttpClient browser = newHttpClient();
        URI authorizationUri = authorizationUri();
        HttpResponse<String> loginPage = getFollowingRedirects(browser, authorizationUri);
        assertEquals(200, loginPage.statusCode(), loginPage.body());
        Form loginForm = findForm(loginPage.body(), "kc-form-login");
        Map<String, String> loginFields = new LinkedHashMap<>(loginForm.hiddenFields());
        loginFields.put("username", "test-user");
        loginFields.put("password", "test-password");

        HttpResponse<String> waitingPage = postFormFollowingGet(browser, loginForm.action(), loginFields);
        assertEquals(200, waitingPage.statusCode(), waitingPage.body());
        String registrationHeader = waitingPage.headers()
                .firstValue("Secure-Session-Registration").orElseThrow();
        String registrationChallenge = structuredFieldValue(registrationHeader, "challenge");
        URI registrationUri = URI.create(structuredFieldValue(registrationHeader, "path"));
        URI actionUri = findForm(waitingPage.body(), "resume-authentication").action();

        HttpResponse<String> pendingStatus = get(browser,
                statusUri(registrationChallenge));
        assertEquals(200, pendingStatus.statusCode(), pendingStatus.body());
        assertEquals(false, MAPPER.readTree(pendingStatus.body()).path("registered").asBoolean());

        FakeDbscUserAgent userAgent = new FakeDbscUserAgent();
        String registrationJws = userAgent.createRegistrationResponse(
                registrationChallenge, registrationUri.toString());
        HttpResponse<String> registration = post(browser, registrationUri, Map.of(
                "Secure-Session-Response", '"' + registrationJws + '"'));
        assertEquals(200, registration.statusCode(), registration.body());
        assertNotNull(MAPPER.readTree(registration.body()).path("session_identifier").textValue());
        assertTrue(registration.headers().allValues("set-cookie").stream()
                .anyMatch(cookie -> cookie.startsWith("KC_DBSC_AUTH=")));

        HttpResponse<String> completedStatus = get(browser, statusUri(registrationChallenge));
        assertEquals(true, MAPPER.readTree(completedStatus.body()).path("registered").asBoolean());

        HttpResponse<String> generateKey = post(browser, actionUri, Map.of());
        assertEquals(401, generateKey.statusCode(), generateKey.body());
        String generateKeyHeader = generateKey.headers()
                .firstValue("Secure-Session-GenerateKey").orElseThrow();
        String bindingChallenge = structuredFieldValue(generateKeyHeader, "challenge");
        String bindingStatement = userAgent.createBindingStatement(bindingChallenge, authorizationUri.toString());

        HttpResponse<String> completedLogin = get(browser, authorizationUri,
            Map.of("Secure-Session-KeyBinding", bindingStatement));
        assertTrue(completedLogin.statusCode() >= 300 && completedLogin.statusCode() < 400,
                completedLogin.statusCode() + " " + completedLogin.body());
        String location = completedLogin.headers().firstValue("location").orElseThrow();
        assertTrue(location.startsWith(REDIRECT_URI), location);
        assertTrue(location.contains("code="), location);
    }

    private static void createRealmAndFlow(HttpClient client, String token) throws Exception {
        Map<String, Object> clientRepresentation = Map.of(
                "clientId", CLIENT_ID,
                "enabled", true,
                "publicClient", true,
                "redirectUris", List.of(REDIRECT_URI),
                "webOrigins", List.of("*"),
                "attributes", Map.of("dbsc.sso.enabled", "true"));
        HttpResponse<String> created = adminRequest(client, token, "POST", "/admin/realms",
                MAPPER.writeValueAsString(Map.of(
                        "realm", REALM,
                        "enabled", true,
                "clients", List.of(clientRepresentation))));
        assertEquals(201, created.statusCode(), created.body());

        HttpResponse<String> userCreated = adminRequest(client, token, "POST",
            "/admin/realms/" + REALM + "/users",
            MAPPER.writeValueAsString(Map.of(
                "username", "test-user",
                "firstName", "Test",
                "lastName", "User",
                "email", "test-user@example.test",
                "emailVerified", true,
                "requiredActions", List.of(),
                "enabled", true)));
        assertEquals(201, userCreated.statusCode(), userCreated.body());
        String userPath = userCreated.headers().firstValue("location").orElseThrow();
        HttpResponse<String> passwordSet = adminRequest(client, token, "PUT",
            userPath + "/reset-password",
            MAPPER.writeValueAsString(Map.of(
                "type", "password", "value", "test-password", "temporary", false)));
        assertEquals(204, passwordSet.statusCode(), passwordSet.body());
        JsonNode user = MAPPER.readTree(adminRequest(client, token, "GET", userPath, null).body());
        assertTrue(user.path("enabled").asBoolean(), user.toString());
        assertTrue(user.path("emailVerified").asBoolean(), user.toString());
        assertEquals(0, user.path("requiredActions").size(), user.toString());
        JsonNode credentials = MAPPER.readTree(adminRequest(client, token, "GET", userPath + "/credentials", null).body());
        assertTrue(credentials.toString().contains("password"), credentials.toString());

        HttpResponse<String> copied = adminRequest(client, token, "POST",
                "/admin/realms/" + REALM + "/authentication/flows/browser/copy",
                MAPPER.writeValueAsString(Map.of("newName", "DBSC Browser")));
        assertEquals(201, copied.statusCode(), copied.body());

        HttpResponse<String> added = adminRequest(client, token, "POST",
            "/admin/realms/" + REALM
                + "/authentication/flows/DBSC%20Browser%20forms/executions/execution",
                MAPPER.writeValueAsString(Map.of("provider", AUTHENTICATOR_ID, "priority", 1000)));
        assertEquals(201, added.statusCode(), added.body());

        JsonNode executions = MAPPER.readTree(adminRequest(client, token, "GET",
            "/admin/realms/" + REALM
                + "/authentication/flows/DBSC%20Browser%20forms/executions", null).body());
        JsonNode execution = null;
        for (JsonNode candidate : executions) {
            if (AUTHENTICATOR_ID.equals(candidate.path("providerId").asText())) {
                execution = candidate;
                break;
            }
        }
        assertNotNull(execution, executions.toString());
        HttpResponse<String> required = adminRequest(client, token, "PUT",
            "/admin/realms/" + REALM
                + "/authentication/flows/DBSC%20Browser%20forms/executions",
                MAPPER.writeValueAsString(Map.of(
                        "id", execution.path("id").asText(),
                        "priority", execution.path("priority").asInt(),
                        "requirement", "REQUIRED")));
        assertEquals(204, required.statusCode(), required.body());

        JsonNode realm = MAPPER.readTree(adminRequest(client, token, "GET",
                "/admin/realms/" + REALM, null).body());
        ((ObjectNode) realm).put("browserFlow", "DBSC Browser");
        HttpResponse<String> updated = adminRequest(client, token, "PUT",
                "/admin/realms/" + REALM, MAPPER.writeValueAsString(realm));
        assertEquals(204, updated.statusCode(), updated.body());
    }

    private static URI authorizationUri() {
        return URI.create(baseUrl() + "/realms/" + REALM
                + "/protocol/openid-connect/auth?client_id=" + CLIENT_ID
                + "&redirect_uri=" + encode(REDIRECT_URI)
                + "&response_type=code&scope=openid&state=state-123&nonce=nonce-123");
    }

    private static URI statusUri(String challenge) {
        return URI.create(baseUrl() + "/realms/" + REALM + "/dbsc/RegistrationStatus?challenge="
                + encode(challenge));
    }

    private static String getAdminToken(HttpClient client) throws Exception {
        HttpResponse<String> response = post(client,
                URI.create(baseUrl() + "/realms/master/protocol/openid-connect/token"),
                Map.of("Content-Type", "application/x-www-form-urlencoded"),
                formBody(Map.of(
                        "grant_type", "password",
                        "client_id", "admin-cli",
                        "username", "admin",
                        "password", "admin")));
        assertEquals(200, response.statusCode(), response.body());
        return MAPPER.readTree(response.body()).path("access_token").asText();
    }

    private static HttpResponse<String> adminRequest(
            HttpClient client, String token, String method, String path, String body) throws Exception {
        URI uri = path.startsWith("https://") ? URI.create(path) : URI.create(baseUrl() + path);
        HttpRequest.Builder request = HttpRequest.newBuilder(uri)
                .header("Authorization", "Bearer " + token)
                .header("Accept", "application/json");
        if (body != null) {
            request.header("Content-Type", "application/json")
                    .method(method, HttpRequest.BodyPublishers.ofString(body));
        } else {
            request.method(method, HttpRequest.BodyPublishers.noBody());
        }
        return client.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> getFollowingRedirects(HttpClient client, URI uri) throws Exception {
        HttpResponse<String> response = get(client, uri);
        for (int redirects = 0; redirects < 10 && response.statusCode() >= 300 && response.statusCode() < 400;
                redirects++) {
            response = get(client, uri.resolve(response.headers().firstValue("location").orElseThrow()));
        }
        return response;
    }

    private static HttpResponse<String> postFormFollowingGet(
            HttpClient client, URI uri, Map<String, String> fields) throws Exception {
        HttpResponse<String> response = post(client, uri, Map.of("Content-Type", "application/x-www-form-urlencoded"),
                formBody(fields));
        for (int redirects = 0; redirects < 10 && response.statusCode() >= 300 && response.statusCode() < 400;
                redirects++) {
            response = get(client, uri.resolve(response.headers().firstValue("location").orElseThrow()));
        }
        return response;
    }

    private static HttpResponse<String> get(HttpClient client, URI uri) throws Exception {
        return client.send(HttpRequest.newBuilder(uri).GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> get(HttpClient client, URI uri, Map<String, String> headers)
            throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri).GET();
        headers.forEach(request::header);
        return client.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> post(HttpClient client, URI uri, Map<String, String> headers)
            throws Exception {
        return post(client, uri, headers, "");
    }

    private static HttpResponse<String> post(HttpClient client, URI uri, Map<String, String> headers, String body)
            throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri).POST(HttpRequest.BodyPublishers.ofString(body));
        headers.forEach(request::header);
        return client.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static Form findForm(String html, String id) {
        Matcher forms = FORM_PATTERN.matcher(html);
        while (forms.find()) {
            Map<String, String> attributes = attributes(forms.group(1));
            if (!id.equals(attributes.get("id"))) {
                continue;
            }
            URI action = URI.create(baseUrl()).resolve(attributes.get("action"));
            Map<String, String> fields = new LinkedHashMap<>();
            Matcher inputs = INPUT_PATTERN.matcher(forms.group(2));
            while (inputs.find()) {
                Map<String, String> input = attributes(inputs.group(1));
                if (input.containsKey("name") && input.containsKey("value")) {
                    fields.put(input.get("name"), input.get("value"));
                }
            }
            return new Form(action, fields);
        }
        throw new AssertionError("Form not found: " + id);
    }

    private static Map<String, String> attributes(String source) {
        Map<String, String> attributes = new LinkedHashMap<>();
        Matcher matcher = ATTRIBUTE_PATTERN.matcher(source);
        while (matcher.find()) {
            attributes.put(matcher.group(1), matcher.group(2));
        }
        return attributes;
    }

    private static String structuredFieldValue(String header, String parameter) {
        Matcher matcher = Pattern.compile("(?:^|;\\s*)" + Pattern.quote(parameter) + "=\\\"([^\\\"]+)\\\"")
                .matcher(header);
        if (!matcher.find()) {
            throw new AssertionError("Missing " + parameter + " in structured header: " + header);
        }
        return matcher.group(1);
    }

    private static String formBody(Map<String, String> fields) {
        List<String> encoded = new ArrayList<>();
        fields.forEach((key, value) -> encoded.add(encode(key) + "=" + encode(value)));
        return String.join("&", encoded);
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static HttpClient newHttpClient() {
        CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }}, new SecureRandom());
            return HttpClient.newBuilder().cookieHandler(cookies).sslContext(sslContext).build();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to create test HTTP client.", e);
        }
    }

    private static String baseUrl() {
        return "https://" + KEYCLOAK.getHost() + ":" + KEYCLOAK.getMappedPort(8443);
    }

    private static Path createKeystore() {
        try {
            Path directory = Files.createTempDirectory("dbsc-keycloak-it-");
            Path keystore = directory.resolve("dbsc-test-keystore.p12");
            Process keytool = new ProcessBuilder(
                    "keytool", "-genkeypair", "-noprompt", "-alias", "keycloak",
                    "-keyalg", "RSA", "-keysize", "2048", "-validity", "2",
                    "-dname", "CN=localhost", "-storetype", "PKCS12",
                    "-keystore", keystore.toString(), "-storepass", "test-password",
                    "-keypass", "test-password")
                    .redirectErrorStream(true)
                    .start();
            if (!keytool.waitFor(30, java.util.concurrent.TimeUnit.SECONDS) || keytool.exitValue() != 0) {
                throw new IllegalStateException("Unable to generate test TLS keystore: "
                        + new String(keytool.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
            }
            return keystore;
        } catch (Exception e) {
            throw new IllegalStateException("Unable to prepare Keycloak test TLS keystore.", e);
        }
    }

    private record Form(URI action, Map<String, String> hiddenFields) {
    }
}
