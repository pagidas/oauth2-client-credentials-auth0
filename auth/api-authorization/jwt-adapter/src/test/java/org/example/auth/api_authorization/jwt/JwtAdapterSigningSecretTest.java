package org.example.auth.api_authorization.jwt;

import org.example.auth.api_authorization.domain.AuthApi.AuthConfig;
import org.example.auth.api_authorization.domain.AuthApi.Tokens;
import org.example.auth.api_authorization.jwt.JwtAuthAdapter.JwtRequiresScope;
import org.example.auth.api_authorization.jwt.JwtAuthAdapter.SigningSecret;
import org.junit.jupiter.api.Test;

import java.util.function.Function;

import static org.example.auth.api_authorization.domain.AuthApi.Authorization.UNAUTHORIZED;
import static org.example.auth.api_authorization.domain.AuthApi.TokenScope.READ_WIKIS;
import static org.example.auth.api_authorization.domain.AuthApi.requiresScopeLogic;
import static org.example.auth.api_authorization.jwt.JwtAuthAdapter.requiresScopeJwtAdapter;
import static org.example.auth.api_authorization.jwt.test_fixtures.FromTokenToJwtMapper.fromTokenToRawJwt;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class JwtAdapterSigningSecretTest {

    Function<SigningSecret, JwtRequiresScope> authoriseJwt = requiresScopeJwtAdapter.apply(
            requiresScopeLogic.apply(
                    new AuthConfig("trusted-issuer", "valid-audience")));

    @Test
    void unauthorizedWhenTokenHasBeenSignedWithDifferentSecret() {
        var secret = new SigningSecret("the-secret");
        var authorise = authoriseJwt.apply(secret);

        var rawJwt = fromTokenToRawJwt.apply(new Tokens().with($ -> {
            $.issuer = "trusted-issuer";
            $.audience = "valid-audience";
            $.scope = "read_wikis";
        }).get()).apply(new SigningSecret("some-other-secret"));

        var result = authorise.apply(READ_WIKIS).apply(rawJwt);

        assertEquals(UNAUTHORIZED, result);
    }
}
