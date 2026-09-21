# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - 2026-09-22

### Added

- Accept a raw hex-encoded P-256 private scalar (`0xb8c0...`, with or without leading-zero
  padding) as an alternative to JWK JSON, since some credential issuers hand out keys this
  way. The public key is derived automatically.

### Changed

- Config keys renamed: `verifier.private-key-jwk[-path]` → `verifier.client.private-key[-path]`,
  `verifier.credential-jwt[-path]` → `verifier.client.credential-jwt[-path]` — the private
  key and credential belong to the caller, not the Verifier. Builder method
  `privateKeyJwk`/`privateKeyJwkFile` renamed to `privateKey`/`privateKeyFile` to reflect
  that it now accepts either format.
- The `cnf` confirmation key for a `did:key` credential must now be wrapped in `cnf.kid`
  (RFC 7800 §3.4) rather than passed as a bare string, per the actual normative
  representation — `cnf` is always a JSON object.

### Fixed

- `verifierUrl` now requires `https` by default (opt-out via `allowInsecureHttp()` for
  local testing) — the `client_assertion` is a replayable, bearer-equivalent credential.
- Config `*-path` values can no longer escape the config file's own directory.
- `did:key` decoding now explicitly verifies the derived point is on the P-256 curve.
- Exception messages no longer echo private key material or the Verifier's raw response
  body.
- `VerifierM2MClientConfig.toString()` redacts the private key and credential.

## [0.1.0] - 2026-09-21

### Added

- Initial SDK: `VerifierM2MClient` for M2M `client_credentials` authentication against
  OID4VP-style Verifiers, using `private_key_jwt` (RFC 7523) with a self-signed VP-JWT as
  proof of possession.
- `.yaml`/`.yml` and `.properties` config file support.
- Client-side `cnf` binding validation (JWK and `did:key` forms), performed eagerly at
  client construction.
