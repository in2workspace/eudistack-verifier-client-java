# EUDIStack Verifier Client (Java)

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_eudistack-verifier-client-java&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=in2workspace_eudistack-verifier-client-java)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_eudistack-verifier-client-java&metric=coverage)](https://sonarcloud.io/summary/new_code?id=in2workspace_eudistack-verifier-client-java)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_eudistack-verifier-client-java&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=in2workspace_eudistack-verifier-client-java)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_eudistack-verifier-client-java&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=in2workspace_eudistack-verifier-client-java)

A small, dependency-light Java SDK for machine-to-machine (M2M) authentication against
OID4VP-style Verifiers, using the `client_credentials` grant with `private_key_jwt`
(RFC 7523) and a self-signed Verifiable Presentation JWT as proof of possession.

It is **not tied to any single Verifier implementation** — any Verifier that accepts this
wire protocol (self-signed VP-JWT + `client_assertion` carrying `vp_token`, `X-Tenant`
header, standard OAuth2 token response) can be used as the target.

No Spring, no reactive stack, no DI framework. Just [Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt)
for JWS/JWK handling and the JDK's own `java.net.http.HttpClient`.

## Who this is for

Any service that holds:

1. An **EC (P-256) private key**, and
2. A **machine credential** (e.g. a `LEARCredentialMachine`) that binds that key as its
   confirmation key (`cnf`),

and needs to obtain an OAuth2 access token from a Verifier that trusts that credential.

## Installation

**Gradle**

```groovy
dependencies {
    implementation 'net.eudistack:eudistack-verifier-client-java:<version>'
}
```

**Maven**

```xml
<dependency>
    <groupId>net.eudistack</groupId>
    <artifactId>eudistack-verifier-client-java</artifactId>
    <version>&lt;version&gt;</version>
</dependency>
```

## Quick start

You configure **3 values** — your private key, your machine credential, and the Verifier's
base URL. The tenant and `client_id` are derived automatically from the credential, so
there's nothing else to keep in sync.

### Programmatic

```java
VerifierM2MClient client = VerifierM2MClient.builder()
    .verifierUrl("https://verifier.example.org")
    .privateKeyJwk(privateKeyJwkJson)      // or .privateKeyJwkFile(Path.of("key.jwk.json"))
    .credentialJwt(machineCredentialJwt)   // or .credentialJwtFile(Path.of("credential.jwt"))
    .build();

AccessToken token = client.authenticate();
System.out.println(token.accessToken());
```

`build()` validates that your private key matches the credential's `cnf` **immediately**,
so a misconfigured key/credential pair fails at startup — not on the first request that
happens to need a token.

### From a config file

```java
VerifierM2MClient client = VerifierM2MClient.fromConfig("verifier-client.yaml");
AccessToken token = client.authenticate();
```

## Configuration reference

| Key | Required | Meaning |
|---|---|---|
| `verifier.url` | yes | The Verifier's base URL, e.g. `https://verifier.example.org` |
| `verifier.private-key-jwk` | one of these two | Private key, inline JWK JSON (P-256) |
| `verifier.private-key-jwk-path` | | Path to a file containing the JWK JSON (relative to the config file) |
| `verifier.credential-jwt` | one of these two | Machine credential, inline compact JWT |
| `verifier.credential-jwt-path` | | Path to a file containing the credential JWT (relative to the config file) |

Set exactly one of the inline/path variants for the key, and exactly one for the credential.

### `.properties`

```properties
verifier.url=https://verifier.example.org
verifier.private-key-jwk-path=key.jwk.json
verifier.credential-jwt-path=credential.jwt
```

### `.yaml`

```yaml
verifier:
  url: https://verifier.example.org
  private-key-jwk-path: key.jwk.json
  credential-jwt-path: credential.jwt
```

> YAML support requires `org.yaml:snakeyaml` on your classpath — it's an **optional**
> dependency of this SDK, only needed if you load a `.yaml`/`.yml` file. If you only use
> `.properties` files or the programmatic builder, you don't need it.

## Where do the inputs come from?

- The **private key** is generated when you (or your identity provider) create the key
  pair the mandate is bound to. It must be a P-256 EC key.
- The **machine credential** is issued to you by an EUDIStack-compatible Issuer (or any
  compliant OID4VCI issuer) as a `LEARCredentialMachine`-shaped Verifiable Credential, with
  a `cnf` claim binding your public key.

This SDK does not issue credentials or generate keys — it only consumes them to
authenticate.

## The `cnf` binding check

Before making any network call, `VerifierM2MClient` verifies that the public counterpart of
your configured private key matches the credential's confirmation key. Two `cnf` encodings
are supported:

```json
"cnf": { "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." } }
```

```json
"cnf": "did:key:zDnaek9hf761hzFqLFZvTntvhEKfYKiCPaQbV4uXifYV8eHw6"
```

If they don't match, construction throws `CredentialKeyMismatchException` — this is a
client-side safety check, independent of whatever the Verifier itself validates
server-side, meant to catch a misconfigured deployment immediately instead of via an opaque
rejection on first use.

## Error handling

| Exception | Thrown when |
|---|---|
| `InvalidConfigurationException` | A required value is missing/blank, a JWK/JWT is malformed, or a config file is invalid |
| `CredentialKeyMismatchException` | The private key does not match the credential's `cnf` |
| `TokenRequestFailedException` | The Verifier returned a non-2xx response, or was unreachable — carries `httpStatus()` and `responseBody()` |

All extend `VerifierClientException`.

## Troubleshooting

- **"Verifier response is missing the 'access_token' field" / tenant mismatch errors** —
  the Verifier resolves the tenant from the credential's `mandate.power[].domain` and
  compares it against the `X-Tenant` header this SDK sends automatically. If your
  credential's mandate doesn't declare the domain you expect, the grant is rejected.
- **`CredentialKeyMismatchException` on startup** — you're pointing at the wrong private
  key file, or the wrong credential. Confirm the key pair used to request the credential is
  the one configured here.
- **Encoding gotchas this SDK handles for you** — the `vp_token` claim inside
  `client_assertion` must be **standard** Base64 (not URL-safe), and all `iat`/`exp`/`nbf`
  claims must be seconds since epoch, not milliseconds. If you're implementing your own
  client against the same Verifier from another language, these are the two most common
  interop mistakes.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
