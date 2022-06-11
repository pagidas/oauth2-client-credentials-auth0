package org.example.auth.api_authorization.domain;

import org.example.auth.api_authorization.domain.AuthApi.Claim.Audience;
import org.example.auth.api_authorization.domain.AuthApi.Claim.Issuer;
import org.example.auth.api_authorization.domain.AuthApi.Claim.Scope;
import org.example.auth.api_authorization.domain.TokenValidation.VerificationCriteria;

import java.util.Collection;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;

import static org.example.auth.api_authorization.domain.AuthApi.Authorization.*;
import static org.example.auth.api_authorization.domain.TokenValidation.PermissionsVerification.ACCESS_DENIED;
import static org.example.auth.api_authorization.domain.TokenValidation.verifyTokenScope;
import static org.example.auth.api_authorization.domain.TokenValidation.verifyTokenWithRequiredCriteria;

public class AuthApi {
    public interface RequiresScope extends Function<TokenScope, AuthoriseToken> {}
    public interface AuthoriseToken extends Function<Token, Authorization> {}

    public static final Function<AuthConfig, RequiresScope> requiresScopeLogic =
            config -> apiScope -> token -> {
                var criteria = new VerificationCriteria(config.issuer(), config.audience());
                var verifyToken = verifyTokenWithRequiredCriteria.apply(criteria);
                var verifyScope = verifyTokenScope.apply(apiScope);
                return switch (verifyToken.apply(token)) {
                    case UNVERIFIED -> UNAUTHORIZED;
                    case VERIFIED -> verifyScope.apply(token) == ACCESS_DENIED ? FORBIDDEN : AUTHORIZED;
                };
            };

    public enum TokenScope { READ_WIKIS, WRITE_WIKIS }

    public record Token(Collection<Claim> claims) {}

    public sealed interface Claim permits Issuer, Audience, Scope {
        record Issuer(String value) implements Claim {}
        record Audience(String value) implements Claim {}
        record Scope(String value) implements Claim {}
    }

    public enum Authorization {
        AUTHORIZED(200, "Ok"),
        UNAUTHORIZED(401, "Unauthorized"),
        FORBIDDEN(403, "Forbidden");

        private final int status;
        private final String message;

        Authorization(int status, String message) {
            this.status = status;
            this.message = message;
        }

        public int status() {
            return status;
        }

        public String message() {
            return message;
        }

        @Override
        public String toString() {
            return "Authorization{status=%s, message='%s'}".formatted(this.status, this.message);
        }
    }

    public record AuthConfig(String issuer, String audience) {}

    public static class Tokens {
        public String issuer;
        public String audience;
        public String scope;

        public Tokens with(Consumer<Tokens> consumer) {
            consumer.accept(this);
            return this;
        }

        public Token get() {
            return new Token(List.of(
                    new Issuer(issuer),
                    new Audience(audience),
                    new Scope(scope)
            ));
        }
    }
}

