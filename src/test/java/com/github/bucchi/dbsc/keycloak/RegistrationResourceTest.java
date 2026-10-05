package com.github.bucchi.dbsc.keycloak;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RegistrationResourceTest {

    @Test
    void parsesCompactJwsFromStructuredFieldString() {
        String jws = "eyJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL2lkcCJ9.c2lnbmF0dXJl";

        assertEquals(jws, RegistrationResource.parseStructuredFieldString('"' + jws + '"'));
    }

    @Test
    void rejectsUnquotedHeaderValue() {
        assertThrows(IllegalArgumentException.class,
                () -> RegistrationResource.parseStructuredFieldString("header.payload.signature"));
    }

    @Test
    void rejectsNonCompactOrUnsafeJwsValues() {
        assertThrows(IllegalArgumentException.class,
                () -> RegistrationResource.parseStructuredFieldString("\"header.payload\""));
        assertThrows(IllegalArgumentException.class,
                () -> RegistrationResource.parseStructuredFieldString("\"header.pa yload.signature\""));
    }
}