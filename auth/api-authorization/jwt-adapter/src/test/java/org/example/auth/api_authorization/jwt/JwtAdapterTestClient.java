package org.example.auth.api_authorization.jwt;

import org.example.auth.api_authorization.domain.AuthApi.AuthConfig;
import org.example.auth.api_authorization.domain.AuthApi.RequiresScope;
import org.example.auth.api_authorization.jwt.JwtAuthAdapter.RawJwt;
import org.example.auth.api_authorization.jwt.JwtAuthAdapter.SigningSecret;

import java.util.function.Function;

import static org.example.auth.api_authorization.domain.AuthApi.requiresScopeLogic;
import static org.example.auth.api_authorization.jwt.JwtAuthAdapter.requiresScopeJwtAdapter;
import static org.example.auth.api_authorization.jwt.test_fixtures.FromTokenToJwtMapper.fromTokenToRawJwt;

public class JwtAdapterTestClient {

    public static final Function<AuthConfig, Function<SigningSecret, RequiresScope>> jwtTestClient =
            authConfig -> secret -> scope -> token -> {
                var requiresScope = requiresScopeLogic.apply(authConfig);
                var jwtAdapter = requiresScopeJwtAdapter.apply(requiresScope).apply(secret);

                RawJwt rawJwt = fromTokenToRawJwt.apply(token).apply(secret);
                return jwtAdapter.apply(scope).apply(rawJwt);
            };
}
