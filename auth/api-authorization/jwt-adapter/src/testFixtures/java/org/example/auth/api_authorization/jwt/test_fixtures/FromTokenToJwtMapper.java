package org.example.auth.api_authorization.jwt.test_fixtures;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.example.auth.api_authorization.domain.AuthApi.Claim.Audience;
import org.example.auth.api_authorization.domain.AuthApi.Claim.Issuer;
import org.example.auth.api_authorization.domain.AuthApi.Claim.Scope;
import org.example.auth.api_authorization.domain.AuthApi.Token;
import org.example.auth.api_authorization.jwt.JwtAuthAdapter.RawJwt;
import org.example.auth.api_authorization.jwt.JwtAuthAdapter.SigningSecret;

import java.util.function.Function;

public class FromTokenToJwtMapper {
    public static final Function<Token, Function<SigningSecret, RawJwt>> fromTokenToRawJwt =
            token -> secret -> {
                var jwtBuilder =  JWT.create();
                token.claims().forEach(claim -> {
                    switch (claim) {
                        case Issuer issuer -> jwtBuilder.withIssuer(issuer.value());
                        case Audience audience -> jwtBuilder.withAudience(audience.value());
                        case Scope scope -> jwtBuilder.withClaim("scope", scope.value());
                    }
                });
                return new RawJwt(jwtBuilder.sign(Algorithm.HMAC256(secret.value())));
            };
}
