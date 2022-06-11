package org.example.auth.api_authorization.domain;

import org.example.auth.api_authorization.domain.test_fixtures.RequiresScopeContract;

import static org.example.auth.api_authorization.domain.AuthApi.requiresScopeLogic;

class RequiresScopeLogicTest extends RequiresScopeContract {
    public RequiresScopeLogicTest() {
        super(requiresScopeLogic.apply(new AuthApi.AuthConfig("trusted-issuer", "valid-audience")));
    }
}

