# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Initial SDK: `VerifierM2MClient` for M2M `client_credentials` authentication against
  OID4VP-style Verifiers, using `private_key_jwt` (RFC 7523) with a self-signed VP-JWT as
  proof of possession.
- `.yaml`/`.yml` and `.properties` config file support.
- Client-side `cnf` binding validation (JWK and `did:key` forms), performed eagerly at
  client construction.
