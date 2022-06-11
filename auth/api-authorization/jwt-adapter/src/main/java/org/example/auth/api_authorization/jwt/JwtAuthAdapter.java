package org.example.auth.api_authorization.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.vavr.control.Try;
import org.example.auth.api_authorization.domain.AuthApi;
import org.example.auth.api_authorization.domain.AuthApi.Authorization;
import org.example.auth.api_authorization.domain.AuthApi.RequiresScope;
import org.example.auth.api_authorization.domain.AuthApi.Token;
import org.example.auth.api_authorization.domain.AuthApi.TokenScope;

import java.util.function.Function;

import static org.example.auth.api_authorization.domain.AuthApi.Authorization.UNAUTHORIZED;
import static org.example.auth.api_authorization.jwt.JwtAuthAdapter.Helper.fromDecodedJwtToToken;
import static org.example.auth.api_authorization.jwt.JwtAuthAdapter.Helper.tryDecodeJwt;

public class JwtAuthAdapter {
    public interface JwtRequiresScope extends Function<TokenScope, AuthoriseJwt> {}
    public interface AuthoriseJwt extends Function<RawJwt, Authorization> {}

    public static final Function<RequiresScope, Function<SigningSecret, JwtRequiresScope>> requiresScopeJwtAdapter =
            requiresScopeLogic -> secret -> scope -> rawJwt -> {
                var authoriseToken = requiresScopeLogic.apply(scope);
                var algo = Algorithm.HMAC256(secret.value());
                return tryDecodeJwt.apply(algo).apply(rawJwt)
                        .map(fromDecodedJwtToToken)
                        .map(authoriseToken)
                        .getOrElse(UNAUTHORIZED);
            };

    public record RawJwt(String value) {}
    public record SigningSecret(String value) {}

    static class Helper {

        static final Function<Algorithm, Function<RawJwt, Try<DecodedJWT>>> tryDecodeJwt =
                algo -> rawJwt -> {
                    var verifier = JWT.require(algo).build();
                    return Try.of(() -> verifier.verify(rawJwt.value()));
                };
        static final Function<DecodedJWT, Token> fromDecodedJwtToToken =
                decodedJWT -> new AuthApi.Tokens().with($ -> {
                    $.issuer = decodedJWT.getIssuer();
                    $.audience = decodedJWT.getAudience().get(0);
                    $.scope = decodedJWT.getClaim("scope").asString();
                }).get();
    }
}
