package org.example.auth.api_authorization.domain.test_fixtures;

import org.example.auth.api_authorization.domain.AuthApi.Authorization;
import org.example.auth.api_authorization.domain.AuthApi.RequiresScope;
import org.example.auth.api_authorization.domain.AuthApi.Token;
import org.example.auth.api_authorization.domain.AuthApi.Tokens;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.example.auth.api_authorization.domain.AuthApi.Authorization.*;
import static org.example.auth.api_authorization.domain.AuthApi.TokenScope.READ_WIKIS;
import static org.junit.jupiter.api.Assertions.assertEquals;

public abstract class RequiresScopeContract {

    RequiresScope requiresScope;

    public RequiresScopeContract(RequiresScope requiresScope) {
        this.requiresScope = requiresScope;
    }

    @ParameterizedTest
    @MethodSource("provideAuthorisedToken")
    void canAuthoriseVerifiedTokenWithCorrectScope(Token token) {
        Authorization result = requiresScope.apply(READ_WIKIS).apply(token);
        assertEquals(AUTHORIZED, result);
    }

    private static Stream<Arguments> provideAuthorisedToken() {
        var exactCorrectScope = new Tokens().with($ -> {
            $.issuer = "trusted-issuer";
            $.audience = "valid-audience";
            $.scope = "read_wikis";
        }).get();
        var containsCorrectScope = new Tokens().with($ -> {
            $.issuer = "trusted-issuer";
            $.audience = "valid-audience";
            $.scope = "read_wikis, some_other_scope";
        }).get();

        return Stream.of(
                Arguments.of(exactCorrectScope),
                Arguments.of(containsCorrectScope)
        );
    }

    @Test
    void forbiddenWhenVerifiedTokenButIncorrectScope() {
        var token = new Tokens().with($ -> {
            $.issuer = "trusted-issuer";
            $.audience = "valid-audience";
            $.scope = "incorrect-permissions";
        }).get();
        Authorization result = requiresScope.apply(READ_WIKIS).apply(token);
        assertEquals(FORBIDDEN, result);
    }

    @ParameterizedTest
    @MethodSource("provideUnverifiedToken")
    void unauthorizedWhenUnverifiedToken(Token token) {
        assertEquals(UNAUTHORIZED, requiresScope.apply(READ_WIKIS).apply(token));
    }

    private static Stream<Arguments> provideUnverifiedToken() {
        var untrustedIssuerToken = new Tokens().with($ -> {
            $.issuer = "untrusted-issuer";
            $.audience = "valid-audience";
            $.scope = "read_wikis";
        }).get();
        var invalidAudienceToken = new Tokens().with($ -> {
            $.issuer = "trusted-issuer";
            $.audience = "invalid-audience";
            $.scope = "read_wikis";
        }).get();
        var emptyScope = new Tokens().with($ -> {
            $.issuer = "untrusted-issuer";
            $.audience = "invalid-audience";
            $.scope = "";
        }).get();
        var blankScope = new Tokens().with($ -> {
            $.issuer = "untrusted-issuer";
            $.audience = "invalid-audience";
            $.scope = "   ";
        }).get();

        return Stream.of(
                Arguments.of(untrustedIssuerToken),
                Arguments.of(invalidAudienceToken),
                Arguments.of(emptyScope),
                Arguments.of(blankScope)
        );
    }
}

