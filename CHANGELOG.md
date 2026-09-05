# Changelog

All notable changes to the Open Evidence Verification Protocol (OEVP) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- Initial pre-application MVP for the Open Evidence Verification Protocol.
- JSON schemas: `verification-profile.schema.json`, `verification-receipt.schema.json`, `reverification-report.schema.json` (Draft 2020-12).
- Deterministic RFC 8785 (JCS) canonicalization with integer range boundary enforcement `[-(2^53 - 1), 2^53 - 1]`.
- Granular `CheckResult` model with 6 exact states: `PASS`, `FAIL`, `NOT_RUN`, `NOT_APPLICABLE`, `UNVERIFIED`, `UNSUPPORTED`.
- Deterministic overall result aggregation with 5 exact states: `TECHNICAL_CHECKS_PASSED`, `TECHNICAL_CHECKS_FAILED`, `TECHNICAL_CHECKS_PARTIAL`, `EXECUTION_INCOMPLETE`, `PROFILE_UNSATISFIED`.
- Canonical receipt digest with strict self-digest recursion avoidance rule.
- DSSE v1 specification envelope implementation with PAE and Ed25519 signing.
- Caller-supplied verifier trust roots preventing self-trust and key-hint impersonation.
- Pluggable `PackageAdapter` protocol with optional reference `OEPTAdapter`.
- Receipt inspection engine decoupled from package bytes.
- Package re-verification engine comparing fresh evaluations against historical receipts.
- Minimal CLI (`oev verify`, `oev inspect-receipt`, `oev reverify`, `oev receipt verify`).
- Five primary MVP conformance fixtures.
