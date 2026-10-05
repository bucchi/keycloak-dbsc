package com.github.bucchi.dbsc.keycloak;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public final class DbscRealmResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String PROVIDER_ID = "dbsc";

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new DbscRealmResourceProvider(session);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void close() {
    }
}