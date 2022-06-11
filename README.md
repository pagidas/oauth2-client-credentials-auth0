# Oauth2 -- Client Credentials flow (grant)

This is a demo on how to secure an HTTP API, that its client is an
application and not a user. It is also known as machine-to-machine
authorization (M2M).

To implement the 
[oauth2 client credentials grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4)
we used [Auth0](https://auth0.com/) as our authentication server where we can configure
our API and its scopes, along with different clients (applications in our case). These
configured applications all have their own unique credentials, which when sent to the
authentication server they get back a bearer token to use when calling the secured API.

## Theme of demo

In this demo we worked in a bottom-up approach to further understand underlying concepts
of [claims-based identity](https://en.wikipedia.org/wiki/Claims-based_identity).

What we mean by bottom-up is that we attempted to model a security token
which merely is a group of claims of an identity stating what the subject
is or is not. After modeling a security token, we have also implemented
a function which given a specified scope, it determines whether the given
token is **_authorized_**, **_unauthorized_** or **_forbidden_**.

Whether a security token follows the [JWT standard](https://en.wikipedia.org/wiki/JSON_Web_Token)
or if it's signed/encrypted, or even complies with the [Bearer](https://datatracker.ietf.org/doc/html/rfc6750) 
HTTP authentication scheme; these are all implementation details of 
different interfaces that can adapt to the core idea of a security 
token.

To make things more interesting we attempted to do all this with just functions :relieved:.
Thus we used `Java17` that brought in record types, sealed types, which can be used as algebraic data 
types. Also, pattern-matching (still feature on preview) is now less verbose and the switch construct
can be used as an expression.

### Requirements

To run this demo project, we would need:
- java version `17`, 
the specific version is also specified in the `.sdkmanrc` located at the root of the project.
- A free account in Auth0 (or any alternative) in order to comply with the following
environment variables configured in the demo: 
  - `TRUSTED_ISSUER` 
  - `VALID_AUDIENCE` 
  - `SIGNING_SECRET`
- The demo api has one unsecured endpoint, and two secured endpoints which can be used two different clients.
  - Client with scope claim `read_wikis`, which has id and secret exported in environment as 
`READ_ACCESS_CLIENT_ID` and `READ_ACCESS_CLIENT_SECRET`.
  - Client with scope claim `write_wikis`, which has id and secret exported in environment as
`WRITE_ACCESS_CLIENT_ID`, `WRITE_ACCESS_CLIENT_SECRET`

Once everything is set up, we have to add those values in a `.env` file placed in a test resources folder, and run
the `.main/test/E2ETest` to verify everything is correctly wired up.

### Testing strategy

We tried to code to the interface, thus our tests should reflect that. We see a function as an interface
as, really, it is an abstraction. It's a thing that defines what is the input and what is the output.
Its definition/implementation can be whatever as long as it complies with the interface. Moreover,
we also created extra types for some functions to indicate that they have a particular domain meaning.

e.g.
```java
interface AuthoriseToken extends Function<Token, Authorization> {} 
```

We have a contract (a base test) that its system under test is that function that defines our api.
The api is, given a required scope, whether a security token is authorized, unauthorized or forbidden.
This contract defines the behaviour of the api.

We have tests against:
- the core functionality of token authorization.
- the token authorization adapted to the JWT standard.
- the token authorization adapted to the Bearer HTTP auth type as an HTTP filter.
- plus that end-to-end test, that spins up an HTTP secured api, 
and a client is able to receive an access token from the auth server
and request the protected resource of the api.

### Technology

We used little but also some extras to have fun:
- Java17.
- [Auth0 JWT](https://github.com/auth0/java-jwt).
- [Vavr](https://github.com/vavr-io/vavr) - a functional toolkit.
- [Spark](https://github.com/perwendel/spark) - a tiny web framework.
- [Unirest](https://github.com/Kong/unirest-java) - a lightweight HTTP client library (for testing).
- [Dotenv](https://github.com/cdimascio/dotenv-java) - a module that loads environment variables from a .env file.
- [JUnit5](https://github.com/junit-team/junit5).

