package org.example.main.authentication_api;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.github.cdimascio.dotenv.Dotenv;
import kong.unirest.HttpRequest;
import kong.unirest.Unirest;
import org.example.main.authentication_api.AuthenticationAuth0Api.AccessToken;
import org.example.main.authentication_api.AuthenticationAuth0Api.Auth0GetToken;
import org.example.main.authentication_api.AuthenticationAuth0Api.GetTokenRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.URI;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.eclipse.jetty.http.HttpHeader.AUTHORIZATION;
import static org.example.main.Demo.startHttpServer;
import static org.example.main.authentication_api.AuthenticationAuth0Api.httpAuth0GetToken;
import static org.example.main.authentication_api.E2ETest.Helper.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class E2ETest {


    static final Dotenv dotenv = Dotenv.load();

    final Auth0GetToken auth0GetToken = httpAuth0GetToken.apply(URI.create(dotenv.get("TRUSTED_ISSUER")));

    static final URI baseUrl;

    static final Client READ_ACCESS_CLIENT = readAccessClient.apply(dotenv);

    static final Client WRITE_ACCESS_CLIENT = writeAccessClient.apply(dotenv);

    static {
        startHttpServer.apply(dotenv).apply(8080);
        baseUrl = URI.create("http://localhost:8080/api");
    }

    @Test
    void canRequestUnsecuredEndpoint() {
        assertEquals(200, Unirest.get(baseUrl + "/hello").asEmpty().getStatus());
    }

    @Test
    void canGetAllWikisWithValidBearerToken() {
        var token = auth0GetToken.apply(
                new GetTokenRequest(READ_ACCESS_CLIENT.id(), READ_ACCESS_CLIENT.secret())
        );

        var response = Unirest.get(baseUrl + "/wiki")
                .header(AUTHORIZATION.asString(), bearer.apply(token))
                .asEmpty();

        assertEquals(200, response.getStatus());
    }

    @Test
    void forbiddenToGetAllWikisWithInvalidBearerToken() {
        var token = auth0GetToken.apply(
                new GetTokenRequest(WRITE_ACCESS_CLIENT.id(), WRITE_ACCESS_CLIENT.secret())
        );

        var response = Unirest.get(baseUrl + "/wiki")
                .header(AUTHORIZATION.asString(), bearer.apply(token))
                .asEmpty();

        assertEquals(403, response.getStatus());
    }

    @Test
    void canCreateNewWikiWithValidBearerToken() {
        var token = auth0GetToken.apply(
                new GetTokenRequest(WRITE_ACCESS_CLIENT.id(), WRITE_ACCESS_CLIENT.secret())
        );

        var response = Unirest.post(baseUrl + "/wiki")
                .header(AUTHORIZATION.asString(), bearer.apply(token))
                .body("new_wiki")
                .asEmpty();

        assertEquals(201, response.getStatus());
    }

    @Test
    void forbiddenToCreateNewWikiWithInvalidBearerToken() {
        var token = auth0GetToken.apply(
                new GetTokenRequest(READ_ACCESS_CLIENT.id(), READ_ACCESS_CLIENT.secret())
        );

        var response = Unirest.post(baseUrl + "/wiki")
                .header(AUTHORIZATION.asString(), bearer.apply(token))
                .asEmpty();

        assertEquals(403, response.getStatus());
    }

    @ParameterizedTest
    @MethodSource("provideSecuredHttpRequestWithNoBearerToken")
    void unauthorizedToRequestSecuredEndpointsWithNoBearerToken(HttpRequest<?> httpRequest) {
        assertEquals(401, httpRequest.asEmpty().getStatus());
    }

    private static Stream<Arguments> provideSecuredHttpRequestWithNoBearerToken() {
        return Stream.of(
                Arguments.of(Unirest.get(baseUrl + "/wiki")),
                Arguments.of(Unirest.post(baseUrl + "/wiki"))
        );
    }

    @ParameterizedTest
    @MethodSource("provideSecuredHttpRequestWithUnverifiedBearerToken")
    void unauthorizedToRequestSecuredEndpointWithUnverifiedBearerToken(HttpRequest<?> httpRequest) {
        assertEquals(401, httpRequest.asEmpty().getStatus());
    }

    private static Stream<Arguments> provideSecuredHttpRequestWithUnverifiedBearerToken() {
        var unverifiedBearerToken =
                new AccessToken(JWT.create()
                        .withIssuer("some-issuer")
                        .withAudience("some-audience")
                        .sign(Algorithm.HMAC256("key")));

        return Stream.of(
                Arguments.of(Unirest.get(baseUrl + "/wiki")
                        .header(AUTHORIZATION.asString(), bearer.apply(unverifiedBearerToken))),
                Arguments.of(Unirest.post(baseUrl + "/wiki")
                        .header(AUTHORIZATION.asString(), bearer.apply(unverifiedBearerToken)))
        );
    }

    record Client(String id, String secret) {}

    static class Helper {

        static final Function<AccessToken, String> bearer =
                accessToken -> "Bearer %s".formatted(accessToken.value());

        static final Function<Dotenv, Client> readAccessClient =
                dotenv -> new Client(
                        dotenv.get("READ_ACCESS_CLIENT_ID"),
                        dotenv.get("READ_ACCESS_CLIENT_SECRET")
                );

        static final Function<Dotenv, Client> writeAccessClient =
                dotenv -> new Client(
                        dotenv.get("WRITE_ACCESS_CLIENT_ID"),
                        dotenv.get("WRITE_ACCESS_CLIENT_SECRET")
                );

    }
}
