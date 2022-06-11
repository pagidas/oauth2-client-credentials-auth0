package org.example.auth.api_authorization.main;

import org.example.auth.api_authorization.domain.AuthApi.AuthConfig;
import org.example.auth.api_authorization.domain.AuthApi.TokenScope;
import org.example.auth.api_authorization.jwt.JwtAuthAdapter.SigningSecret;
import spark.Filter;

import java.util.function.Function;
import java.util.function.Supplier;

import static org.example.auth.api_authorization.domain.AuthApi.requiresScopeLogic;
import static org.example.auth.api_authorization.http.AuthFilter.bearerAuthRequiresScope;
import static org.example.auth.api_authorization.jwt.JwtAuthAdapter.requiresScopeJwtAdapter;

public class BearerAuthFilterBuilder {
    private String issuer;
    private String audience;
    private String secret;

    BearerAuthFilterBuilder() {}

    public BearerAuthFilterBuilder withTrustedIssuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    public BearerAuthFilterBuilder withValidAudience(String audience) {
        this.audience = audience;
        return this;
    }

    public BearerAuthFilterBuilder withSigningSecret(String secret) {
        this.secret = secret;
        return this;
    }

    public Function<TokenScope, Filter> get() {
        validate();
        var authConfig = new AuthConfig(issuer, audience);
        var secret = new SigningSecret(this.secret);
        return bearerAuthRequiresScope.apply(
                requiresScopeJwtAdapter
                        .apply(requiresScopeLogic.apply(authConfig))
                        .apply(secret));
    }

    private void validate() {
        if (issuer == null || issuer.isBlank() || issuer.isEmpty())
            illegalStateException.apply("issuer").get();
        else if (audience == null || audience.isBlank() || audience.isEmpty())
            illegalStateException.apply("audience").get();
        else if (secret == null || secret.isBlank() || secret.isEmpty())
            illegalStateException.apply("secret").get();
    }

    private static final String builderErrorMsg =
            "%s cannot be empty, blank or null when building the bearer auth filter";

    private static final Function<String, Supplier<IllegalStateException>> illegalStateException =
            state -> () -> { throw new IllegalStateException(builderErrorMsg.formatted(state)); };
}
