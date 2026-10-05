package com.github.bucchi.dbsc.keycloak;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public final class DbscRealmResourceProvider implements RealmResourceProvider {

    private final RegistrationResource resource;

    public DbscRealmResourceProvider(KeycloakSession session) {
        this.resource = new RegistrationResource(session);
    }

    @Override
    public Object getResource() {
        return resource;
    }

    @Override
    public void close() {
    }
}