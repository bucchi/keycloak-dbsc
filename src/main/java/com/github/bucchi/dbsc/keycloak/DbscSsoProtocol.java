package com.github.bucchi.dbsc.keycloak;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Locale;

final class DbscSsoProtocol {

    static final String GENERATE_KEY_HEADER = "Secure-Session-GenerateKey";
    static final String KEY_BINDING_HEADER = "Secure-Session-KeyBinding";
    static final String CLIENT_ENABLED_ATTRIBUTE = "dbsc.sso.enabled";
    static final String RP_KEY_DIGEST_NOTE = "dbsc.sso.rp-key-digest";
    static final String RP_KEY_DIGEST_ALGORITHM_NOTE = "dbsc.sso.rp-key-digest-alg";
    static final long CHALLENGE_LIFETIME_SECONDS = 120;
    static final long REGISTRATION_CHALLENGE_LIFETIME_SECONDS = 300;
        private static final List<String> REQUEST_FINGERPRINT_NOTES = List.of(
            "state", "nonce", "response_type", "response_mode", "scope", "code_challenge",
            "code_challenge_method", "prompt", "max_age", "acr_values", "claims", "resource", "request",
            "request_uri");

    private DbscSsoProtocol() {
    }

    static boolean isEnabledForClient(String enabledAttribute) {
        return "true".equalsIgnoreCase(enabledAttribute);
    }

    static String requestFingerprint(String clientId, String redirectUri, Map<String, String> clientNotes) {
        StringBuilder canonical = new StringBuilder();
        appendFingerprintField(canonical, "client_id", clientId);
        appendFingerprintField(canonical, "redirect_uri", redirectUri);
        for (String note : REQUEST_FINGERPRINT_NOTES) {
            appendFingerprintField(canonical, note, clientNotes.get(note));
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(canonical.toString().getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 is unavailable.", e);
        }
    }

    static String generateKeyHeader(String targetOrigin, String challenge, String providerSessionId) {
        return "(ES256 RS256); target_origin=" + quote(targetOrigin)
                + "; challenge=" + quote(challenge)
                + "; provider_session_id=" + quote(providerSessionId);
    }

    static String registrationHeader(String endpoint, String challenge) {
        return "(ES256 RS256); path=" + quote(endpoint)
                + "; challenge=" + quote(challenge)
                + "; aik_required=?1";
    }

    static String origin(String redirectUri) {
        URI uri;
        try {
            uri = new URI(redirectUri);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("RP redirect URI is invalid.", e);
        }
        if (!uri.isAbsolute() || uri.getHost() == null || uri.getUserInfo() != null
                || uri.getFragment() != null) {
            throw new IllegalArgumentException("RP redirect URI must have a valid secure origin.");
        }

        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        String host = uri.getHost().toLowerCase(Locale.ROOT);
        if (!"https".equals(scheme) && !("http".equals(scheme) && isLoopback(host))) {
            throw new IllegalArgumentException("RP redirect URI must use HTTPS.");
        }
        int port = uri.getPort();
        if (port == ("https".equals(scheme) ? 443 : 80)) {
            port = -1;
        }
        try {
            return new URI(scheme, null, host, port, null, null, null).toASCIIString();
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("RP origin is invalid.", e);
        }
    }

    private static String quote(String value) {
        if (value == null || value.isEmpty() || value.indexOf('"') >= 0 || value.indexOf('\\') >= 0) {
            throw new IllegalArgumentException("Structured Field string value is invalid.");
        }
        return '"' + value + '"';
    }

    private static boolean isLoopback(String host) {
        return "localhost".equals(host) || "127.0.0.1".equals(host) || "[::1]".equals(host)
                || "::1".equals(host);
    }

    private static void appendFingerprintField(StringBuilder target, String name, String value) {
        target.append(name.length()).append(':').append(name)
                .append(value == null ? -1 : value.length()).append(':');
        if (value != null) {
            target.append(value);
        }
        target.append('\n');
    }
}