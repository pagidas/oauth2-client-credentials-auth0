package org.example.auth.api_authorization.http;

import io.vavr.CheckedFunction0;
import io.vavr.control.Try;
import kong.unirest.HttpRequest;
import kong.unirest.HttpResponse;
import org.example.auth.api_authorization.domain.AuthApi.Authorization;
import org.example.auth.api_authorization.domain.AuthApi.RequiresScope;
import org.example.auth.api_authorization.jwt.JwtAuthAdapter.RawJwt;
import org.example.auth.api_authorization.jwt.JwtAuthAdapter.SigningSecret;

import java.util.function.Function;
import java.util.function.Supplier;

import static org.eclipse.jetty.http.HttpHeader.AUTHORIZATION;
import static org.example.auth.api_authorization.domain.AuthApi.Authorization.*;
import static org.example.auth.api_authorization.http.BearerAuthFilterTestClient.Helper.*;
import static org.example.auth.api_authorization.jwt.test_fixtures.FromTokenToJwtMapper.fromTokenToRawJwt;

public class BearerAuthFilterTestClient {

    public static final Function<HttpRequest<?>, Function<SigningSecret, RequiresScope>> bearerAuthTestClient =
            httpRequest -> secret -> scope -> token -> {
                var rawJwt = fromTokenToRawJwt.apply(token).apply(secret);
                var sendHttpRequest = CheckedFunction0.<HttpResponse<?>>of(() ->
                        httpRequest.header(AUTHORIZATION.asString(), bearer.apply(rawJwt)).asEmpty()
                );

                return Try.of(sendHttpRequest)
                        .map(httpResponseToAuthorization)
                        .getOrElseThrow(testHttpServerNotCorrectlyConfigured);
            };

    static class Helper {

        public static final Supplier<IllegalStateException> testHttpServerNotCorrectlyConfigured =
                () -> new IllegalStateException("Target test http server not correctly configured");

        public static final Function<HttpResponse<?>, Authorization> httpResponseToAuthorization = resp -> {
            var statusCode = resp.getStatus();
            if (statusCode >= 200 && statusCode < 300)
                return AUTHORIZED;
            else if (statusCode == 401)
                return UNAUTHORIZED;
            else if (statusCode == 403)
                return FORBIDDEN;
            else if (statusCode == 404)
                throw testHttpServerNotCorrectlyConfigured.get();
            else
                throw new IllegalArgumentException("status code %s is not expected to be handled here".formatted(statusCode));
        };

        public static final Function<RawJwt, String> bearer = rawJwt -> "Bearer %s".formatted(rawJwt.value());
    }
}
