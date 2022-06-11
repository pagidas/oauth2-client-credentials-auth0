package org.example.auth.api_authorization.http;

import org.example.auth.api_authorization.domain.AuthApi;
import org.example.auth.api_authorization.jwt.JwtAuthAdapter;
import spark.Route;

import static org.example.auth.api_authorization.domain.AuthApi.TokenScope.READ_WIKIS;
import static org.example.auth.api_authorization.domain.AuthApi.requiresScopeLogic;
import static org.example.auth.api_authorization.jwt.JwtAuthAdapter.requiresScopeJwtAdapter;
import static spark.Spark.*;

public class Main {

    public static void main(String[] args) {
        var requiresScope = requiresScopeLogic.apply(new AuthApi.AuthConfig("issuer", "audience"));
        var jwtAdapter = requiresScopeJwtAdapter.apply(requiresScope).apply(new JwtAuthAdapter.SigningSecret("key"));
        var bearerRequiresScope = AuthFilter.bearerAuthRequiresScope.apply(jwtAdapter);

        port(8080);
        path("/api", () -> {
            path("/hello", () -> {
                get("/", HelloApi.hello);
                get("/:name", HelloApi.helloName);
            });
            path("/private", () -> {
                before("/*", bearerRequiresScope.apply(READ_WIKIS));
                get("/hello", PrivateApi.hello);
            });
        });
    }

    public static class HelloApi {
        public static Route hello = (req, resp) -> {
            resp.status(200);
            resp.body("Hello world!");
            return resp.body();
        };
        public static Route helloName = (req, resp) -> {
            resp.status(200);
            resp.body("Hello, %s".formatted(req.params(":name")));
            return resp.body();
        };
    }

    public static class PrivateApi {
        public static Route hello = (req, resp) -> {
            resp.status(200);
            resp.body("Hello from private endpoint!");
            return resp.body();
        };
    }
}