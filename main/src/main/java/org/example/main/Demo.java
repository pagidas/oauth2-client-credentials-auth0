package org.example.main;

import io.github.cdimascio.dotenv.Dotenv;
import org.example.auth.api_authorization.domain.AuthApi.TokenScope;
import spark.Filter;
import spark.Route;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import static org.example.auth.api_authorization.domain.AuthApi.TokenScope.READ_WIKIS;
import static org.example.auth.api_authorization.domain.AuthApi.TokenScope.WRITE_WIKIS;
import static org.example.auth.api_authorization.main.BearerAuthFilter.bearerAuthFilter;
import static org.example.main.Demo.Helper.wikiAuthFilter;
import static spark.Service.ignite;

public class Demo {

    public static final Function<Dotenv, Function<Integer, Void>> startHttpServer =
            dotenv -> port -> {
                /*
                Save below environment variables in a .env at resources folder of the project.
                Values can be found at the api configured in the auth0 profile.
                 */
                var bearerRequiresScope = bearerAuthFilter
                        .withTrustedIssuer(dotenv.get("TRUSTED_ISSUER"))
                        .withValidAudience(dotenv.get("VALID_AUDIENCE"))
                        .withSigningSecret(dotenv.get("SIGNING_SECRET"))
                        .get();

                var httpApp = ignite();
                httpApp.port(8080);
                httpApp.path("/api", () -> {
                    httpApp.get("/hello", HelloApi.hello);
                    httpApp.path("/wiki", () -> {
                        httpApp.before("", wikiAuthFilter.apply(bearerRequiresScope));
                        httpApp.get("", WikiApi.allWikis);
                        httpApp.post("", WikiApi.newWiki);
                    });
                });
                httpApp.init();
                return null;
            };

    static class Helper {

        /*
        Unfortunately, spark does not provide adding a filter on a specific route bound on a http method.
        Thus, we have another filter on the api's route that on different request method applies different
        scoped authorization.
         */
        static final Function<Function<TokenScope, Filter>, Filter> wikiAuthFilter =
                bearerRequiresScope -> (req, resp) -> {
                    if ("GET".equals(req.requestMethod()))
                        bearerRequiresScope.apply(READ_WIKIS).handle(req, resp);
                    else if ("POST".equals(req.requestMethod()))
                        bearerRequiresScope.apply(WRITE_WIKIS).handle(req, resp);
                    else resp.status(404);
                };
    }

    static class HelloApi {
        static final Route hello = (req, resp) -> {
            resp.status(200);
            return "Hello World";
        };
    }

    static class WikiApi {
        static final List<String> wikis = new ArrayList<>(List.of(
                "a-wiki",
                "another-wiki",
                "a-perfect-wiki"
        ));

        static final Route allWikis = (req, resp) -> {
            resp.status(200);
            return wikis;
        };

        static final Route newWiki = (req, resp) -> {
            String newWiki = req.body();
            wikis.add(newWiki);
            resp.status(201);
            return newWiki;
        };
    }
}