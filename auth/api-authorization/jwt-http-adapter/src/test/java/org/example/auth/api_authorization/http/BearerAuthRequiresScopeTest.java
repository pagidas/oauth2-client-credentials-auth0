package org.example.auth.api_authorization.http;

import kong.unirest.Unirest;
import org.example.auth.api_authorization.domain.AuthApi;
import org.example.auth.api_authorization.domain.test_fixtures.RequiresScopeContract;
import org.example.auth.api_authorization.jwt.JwtAuthAdapter.SigningSecret;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import spark.Service;

import static org.example.auth.api_authorization.domain.AuthApi.TokenScope.READ_WIKIS;
import static org.example.auth.api_authorization.domain.AuthApi.requiresScopeLogic;
import static org.example.auth.api_authorization.http.AuthFilter.bearerAuthRequiresScope;
import static org.example.auth.api_authorization.http.BearerAuthFilterTestClient.bearerAuthTestClient;
import static org.example.auth.api_authorization.jwt.JwtAuthAdapter.requiresScopeJwtAdapter;
import static spark.Service.ignite;

public class BearerAuthRequiresScopeTest extends RequiresScopeContract {

    public static final Service httpApp;

    static {

        var requiresScope = requiresScopeLogic.apply(
                new AuthApi.AuthConfig("trusted-issuer", "valid-audience"));
        var jwtRequiresScope = requiresScopeJwtAdapter
                .apply(requiresScope)
                .apply(new SigningSecret("some-secret-key"));
        var bearerRequiresScope = bearerAuthRequiresScope.apply(jwtRequiresScope);

        httpApp = ignite().port(8080);
        httpApp.path("/api", () -> {
            httpApp.before("/protected", bearerRequiresScope.apply(READ_WIKIS));
            httpApp.get("/protected", (req, resp) -> {
                resp.status(200);
                resp.body("Hello from private endpoint!");
                return resp.body();
            });
        });
    }

    public BearerAuthRequiresScopeTest() {
        super(bearerAuthTestClient
                .apply(Unirest.get("http://localhost:8080/api/protected"))
                .apply(new SigningSecret("some-secret-key")));
    }

    @BeforeAll
    static void setup() {
        httpApp.init();
    }

    @AfterAll
    static void teardown() {
        httpApp.stop();
    }
}
