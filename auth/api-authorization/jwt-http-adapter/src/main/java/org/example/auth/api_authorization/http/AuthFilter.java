package org.example.auth.api_authorization.http;

import org.example.auth.api_authorization.domain.AuthApi.TokenScope;
import org.example.auth.api_authorization.jwt.JwtAuthAdapter.JwtRequiresScope;
import org.example.auth.api_authorization.jwt.JwtAuthAdapter.RawJwt;
import spark.Filter;

import java.util.Optional;
import java.util.function.Function;
import java.util.function.Predicate;

import static org.eclipse.jetty.http.HttpHeader.AUTHORIZATION;
import static org.example.auth.api_authorization.domain.AuthApi.Authorization.FORBIDDEN;
import static org.example.auth.api_authorization.domain.AuthApi.Authorization.UNAUTHORIZED;
import static org.example.auth.api_authorization.http.AuthFilter.Helper.*;
import static spark.Spark.halt;

public class AuthFilter {
    public static final Function<JwtRequiresScope, Function<TokenScope, Filter>> bearerAuthRequiresScope =
            jwtRequiresScope -> scope -> (req, resp) -> {
                var result = Optional.ofNullable(req.headers(AUTHORIZATION.asString()))
                        .filter(validBearerScheme)
                        .map(readBearer)
                        .map(toRawJwt)
                        .map(jwtRequiresScope.apply(scope))
                        .orElse(UNAUTHORIZED);
                switch (result) {
                    case AUTHORIZED -> {}
                    case UNAUTHORIZED -> halt(UNAUTHORIZED.status(), UNAUTHORIZED.message());
                    case FORBIDDEN -> halt(FORBIDDEN.status(), FORBIDDEN.message());
                }
            };

    static class Helper {
        private static final String BEARER = "Bearer";

        static final Function<String, String[]> splitByBearer = authHeader -> authHeader.split(BEARER);

        static final Predicate<String> containsBearer = authHeader -> authHeader.contains(BEARER);

        static final Predicate<String> headerHasTypeAndToken = authHeader -> splitByBearer.apply(authHeader).length == 2;

        static final Predicate<String> validBearerScheme = containsBearer.and(headerHasTypeAndToken);

        static final Function<String, String> retrieveTokenFromHeader = authHeader -> splitByBearer.apply(authHeader)[1];

        static final Function<String, String> removeWhitespaces = jwt -> jwt.replaceAll("\\s", "");

        static final Function<String, String> readBearer = retrieveTokenFromHeader.andThen(removeWhitespaces);

        static final Function<String, RawJwt> toRawJwt = RawJwt::new;
    }
}
