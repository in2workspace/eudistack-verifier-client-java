# Contributing

Thanks for considering a contribution to this SDK.

## Development

```bash
git clone https://github.com/in2workspace/eudistack-verifier-client-java.git
cd eudistack-verifier-client-java
./gradlew check
```

`check` runs the full build: compile, format check (Spotless), Checkstyle,
tests, and the JaCoCo coverage gate (minimum 80% instruction coverage).

Formatting is auto-fixable with:

```bash
./gradlew spotlessApply
```

## Design constraints

This SDK is intentionally dependency-light: no Spring, no reactive stack, no
DI framework. It uses [Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt)
for JWS/JWK handling and the JDK's own `java.net.http.HttpClient`. Please
keep new dependencies to a minimum, and prefer the JDK standard library where
reasonable — that constraint is part of the value this library offers to
consumers who don't want to pull in a framework just to authenticate.

## Pull requests

- Keep PRs focused on one change.
- Add or update tests for any behavior change — the coverage gate will fail
  the build otherwise.
- This repo squash-merges to `main`; write a commit message that stands on
  its own as the final history entry.

## Reporting a vulnerability

Do not open a public issue for security vulnerabilities — see
[SECURITY.md](SECURITY.md).
