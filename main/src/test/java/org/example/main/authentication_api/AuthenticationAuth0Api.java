package org.example.main.authentication_api;

import kong.unirest.Unirest;

import java.net.URI;
import java.util.function.Function;

import static org.example.main.authentication_api.AuthenticationAuth0Api.Helper.CLIENT_CREDENTIALS_GRANT_TYPE;
import static org.example.main.authentication_api.AuthenticationAuth0Api.Helper.WIKI_API_AUDIENCE;

public class AuthenticationAuth0Api {

    interface Auth0GetToken extends Function<GetTokenRequest, AccessToken> {}

    record GetTokenRequest(String clientId, String clientSecret) {}

    record AccessToken(String value) {}

    public static final Function<URI, Auth0GetToken> httpAuth0GetToken =
            baseUrl -> getTokenRequest -> {
                var tokenRaw = Unirest.post(baseUrl.resolve("/oauth/token").toString())
                        .header("content-type", "application/json")
                        .body(new GetTokenAuth0Request(
                                getTokenRequest.clientId(),
                                getTokenRequest.clientSecret(),
                                WIKI_API_AUDIENCE,
                                CLIENT_CREDENTIALS_GRANT_TYPE
                        ).toJsonSnakeCase())
                        .asJson()
                        .getBody()
                        .getObject()
                        .getString("access_token");

                return new AccessToken(tokenRaw);
            };

    private record GetTokenAuth0Request(String clientId, String clientSecret, String audience, String grantType) {
        String toJsonSnakeCase() {
            return """
                  {
                    "client_id": "%s",
                    "client_secret": "%s",
                    "audience": "%s",
                    "grant_type": "%s"
                  }
                  """.formatted(clientId, clientSecret, audience, grantType);
        }
    }

    static class Helper {
        static final String WIKI_API_AUDIENCE = "https://wiki/api";
        static final String CLIENT_CREDENTIALS_GRANT_TYPE = "client_credentials";
    }
}