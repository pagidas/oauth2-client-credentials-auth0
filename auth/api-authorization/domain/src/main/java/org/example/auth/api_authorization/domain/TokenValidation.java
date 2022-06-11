package org.example.auth.api_authorization.domain;

import org.example.auth.api_authorization.domain.AuthApi.Claim;
import org.example.auth.api_authorization.domain.AuthApi.Claim.Audience;
import org.example.auth.api_authorization.domain.AuthApi.Claim.Issuer;
import org.example.auth.api_authorization.domain.AuthApi.Claim.Scope;
import org.example.auth.api_authorization.domain.AuthApi.Token;
import org.example.auth.api_authorization.domain.AuthApi.TokenScope;

import java.util.function.Function;
import java.util.function.Predicate;

import static org.example.auth.api_authorization.domain.ClaimVerification.Helper.*;
import static org.example.auth.api_authorization.domain.ClaimVerification.*;
import static org.example.auth.api_authorization.domain.TokenValidation.PermissionsVerification.ACCESS_ALLOWED;
import static org.example.auth.api_authorization.domain.TokenValidation.PermissionsVerification.ACCESS_DENIED;
import static org.example.auth.api_authorization.domain.TokenValidation.TokenVerification.UNVERIFIED;
import static org.example.auth.api_authorization.domain.TokenValidation.TokenVerification.VERIFIED;

class TokenValidation {
    interface VerifyToken extends Function<Token, TokenVerification> {}

    interface VerifyPermissions extends Function<Token, PermissionsVerification> {}

    enum TokenVerification {
        VERIFIED,
        UNVERIFIED
    }

    enum PermissionsVerification {
        ACCESS_ALLOWED,
        ACCESS_DENIED
    }

    record VerificationCriteria(String validIssuer, String validAudience) {}

    static final Function<VerificationCriteria, VerifyToken> verifyTokenWithRequiredCriteria =
            criteria -> token -> {
                var validClaim = validClaimWithCriteria.apply(criteria);
                return token.claims().stream()
                        .allMatch(validClaim) ? VERIFIED : UNVERIFIED;
            };

    static final Function<TokenScope, VerifyPermissions> verifyTokenScope =
            apiScope -> token ->
                    token.claims()
                            .stream()
                            .filter(permissionsClaim)
                            .anyMatch(validScope.apply(apiScope)) ? ACCESS_ALLOWED : ACCESS_DENIED;
}

class ClaimVerification {

    static final Predicate<Claim> permissionsClaim = claim -> claim instanceof Scope;

    static final Function<TokenValidation.VerificationCriteria, Predicate<Claim>> validClaimWithCriteria =
            criteria -> claim -> {
                var validIssuer = hasIssuer.apply(criteria.validIssuer());
                var validAudience = hasAudience.apply(criteria.validAudience());
                return switch (claim) {
                    case Issuer issuer -> validIssuer.apply(issuer);
                    case Audience audience -> validAudience.apply(audience);
                    case Scope scope -> hasNonBlankOrEmptyScope.apply(scope);
                };
            };

    static final Function<TokenScope, Predicate<Claim>> validScope =
            apiScope -> claim -> {
                var validScope = hasScope.apply(apiScope.name().toLowerCase());
                if (claim instanceof Scope scope) return validScope.apply(scope);
                else throw new IllegalArgumentException("No other claim than scope allowed here");
            };

    static class Helper {

        static final Function<String, Function<Issuer, Boolean>> hasIssuer =
                required -> issuer -> issuer.value().equals(required);

        static final Function<String, Function<Audience, Boolean>> hasAudience =
                required -> audience -> audience.value().equals(required);

        static final Function<String, Function<Scope, Boolean>> hasScope =
                required -> scope -> scope.value().contains(required);

        private static final Predicate<Scope> scopeIsEmpty = scope -> scope.value().isEmpty();

        private static final Predicate<Scope> scopeIsBlank = scope -> scope.value().isBlank();

        private static final Predicate<Scope> scopeIsBlankOrEmpty = scopeIsBlank.or(scopeIsEmpty);

        private static final Predicate<Scope> scopeIsNotBlankOrEmpty = scopeIsBlankOrEmpty.negate();

        static final Function<Scope, Boolean> hasNonBlankOrEmptyScope = scopeIsNotBlankOrEmpty::test;

    }
}

