package org.example.auth.api_authorization.http;

import org.example.auth.api_authorization.domain.AuthApi;
import org.example.auth.api_authorization.domain.AuthApi.Tokens;
import org.example.auth.api_authorization.jwt.JwtAuthAdapter.SigningSecret;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import spark.Service;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.stream.Stream;

import static org.eclipse.jetty.http.HttpHeader.AUTHORIZATION;
import static org.example.auth.api_authorization.domain.AuthApi.TokenScope.READ_WIKIS;
import static org.example.auth.api_authorization.domain.AuthApi.requiresScopeLogic;
import static org.example.auth.api_authorization.http.AuthFilter.bearerAuthRequiresScope;
import static org.example.auth.api_authorization.jwt.JwtAuthAdapter.requiresScopeJwtAdapter;
import static org.example.auth.api_authorization.jwt.test_fixtures.FromTokenToJwtMapper.fromTokenToRawJwt;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static spark.Service.ignite;

public class BearerAuthFilterInvalidSchemeTest {

    public static final Service httpApp;
    public static final HttpClient http = HttpClient.newHttpClient();

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

    @BeforeAll
    static void setup() {
        httpApp.init();
    }

    @AfterAll
    static void teardown() {
        httpApp.stop();
    }

    @ParameterizedTest()
    @MethodSource("provideInvalidBearerAuthHeader")
    void unauthorisedWhenInvalidBearerScheme(String headerValue) throws IOException, InterruptedException {
        var response = http.send(
                HttpRequest.newBuilder(URI.create("http://localhost:8080/api/protected"))
                        .GET()
                        .header(AUTHORIZATION.asString(), headerValue)
                        .build(),
                BodyHandlers.ofString()
        );

        assertEquals(401, response.statusCode());
    }

    private static Stream<Arguments> provideInvalidBearerAuthHeader() {
        var rawJwt = fromTokenToRawJwt.apply(new Tokens().with($ -> {
            $.issuer = "trusted-issuer";
            $.audience = "valid-audience";
            $.scope = "read_wikis";
        }).get()).apply(new SigningSecret("some-secret-key"));

        var missingAuthScheme = rawJwt.value();
        var unknownScheme = "invalid_scheme %s".formatted(rawJwt.value());
        var invalidBearerScheme = "bearer %s".formatted(rawJwt.value());

        return Stream.of(
                Arguments.of(missingAuthScheme),
                Arguments.of(unknownScheme),
                Arguments.of(invalidBearerScheme)
        );
    }

}
