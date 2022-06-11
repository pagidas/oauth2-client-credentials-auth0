package org.example.auth.api_authorization.jwt;

import org.example.auth.api_authorization.domain.AuthApi.AuthConfig;
import org.example.auth.api_authorization.domain.test_fixtures.RequiresScopeContract;
import org.example.auth.api_authorization.jwt.JwtAuthAdapter.SigningSecret;

import static org.example.auth.api_authorization.jwt.JwtAdapterTestClient.jwtTestClient;

public class JwtRequiresScopeTest extends RequiresScopeContract {
    public JwtRequiresScopeTest() {
        super(jwtTestClient
                .apply(new AuthConfig("trusted-issuer", "valid-audience"))
                .apply(new SigningSecret("some-secret-key"))
        );
    }
}
