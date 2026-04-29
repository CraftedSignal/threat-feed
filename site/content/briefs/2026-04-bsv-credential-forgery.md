---
title: bsv-sdk and bsv-wallet Credential Forgery Vulnerability
slug: 2026-04-bsv-credential-forgery
description: The bsv-sdk and bsv-wallet packages are vulnerable to credential forgery because the `acquire_certificate` function persists certificate records to storage without verifying the certifier's signature, allowing attackers to forge identity certificates.
date: "2026-04-09T20:28:10Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - credential-forgery
  - ruby
  - bsv-sdk
  - bsv-wallet
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-hc36-c89j-5f4j
  - https://brc.dev/52
  - https://github.com/sgbett/bsv-ruby-sdk
rules:
  - title: Detect Direct Certificate Acquisition with Arbitrary Signature
    description: 'Detects calls to `acquire_certificate` with `acquisition_protocol: ''direct''` which could indicate an attempt to inject a forged certificate.'
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - process_creation
      - linux
  - title: Detect Issuance Certificate Acquisition from Untrusted Certifier
    description: 'Detects calls to `acquire_certificate` with `acquisition_protocol: ''issuance''` targeting suspicious or untrusted certifier URLs.'
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - credential_access
    techniques:
      - T1071.001
      - T1555
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

The `bsv-sdk` and `bsv-wallet` Ruby gems are vulnerable to credential forgery due to a signature verification bypass in the `acquire_certificate` function. This function, present in both gems, persists certificate records to storage without properly verifying the certifier's signature. An attacker can exploit this vulnerability through two acquisition paths: by directly supplying certificate fields (direct path) or by controlling a certifier endpoint (issuance path). This allows the attacker to forge identity certificates that are then treated as authentic by other functions like `list_certificates` and `prove_certificate`. The vulnerability affects `bsv-sdk` versions >= 0.3.1 and < 0.8.2, and `bsv-wallet` versions >= 0.1.2 and < 0.3.4. This vulnerability was identified during a cross-SDK compliance review conducted on 2026-04-08.

## Attack Chain

1.  Attacker gains access to a system that uses either the `bsv-sdk` or `bsv-wallet` Ruby gem.
2.  The attacker invokes the `acquire_certificate` function with `acquisition_protocol: 'direct'`.
3.  The attacker supplies arbitrary certificate fields, including a forged `signature`, a `certifier`, `serial_number`, and `revocation_outpoint`.
4.  Alternatively, the attacker invokes the `acquire_certificate` function with `acquisition_protocol: 'issuance'` and specifies a malicious certifier URL they control.
5.  The vulnerable `acquire_certificate` function persists the attacker-supplied certificate data to storage without verifying the certifier's signature.
6.  The attacker or a downstream process invokes `list_certificates` or `prove_certificate` to retrieve the forged certificate.
7.  The application trusts the forged certificate as authentic, leading to credential forgery and potential unauthorized access or privilege escalation.

## Impact

Successful exploitation of this vulnerability allows an attacker to forge identity certificates attributed to arbitrary certifier identities. This can lead to credential forgery, where the attacker can assert false attributes about a subject. Applications relying on the wallet's certificate store for identity attributes, such as KYC assertions or role claims, become vulnerable to credential forgery. This is a credential-forgery primitive, not merely a spec divergence from BRC-52.

## Recommendation

*   Upgrade to `bsv-sdk >= 0.8.2` or `bsv-wallet >= 0.3.4` to patch the vulnerability. These versions implement signature verification using `BSV::Wallet::CertificateSignature` and raise `BSV::Wallet::CertificateSignature::InvalidError` for invalid certificates.
*   If upgrading is not immediately possible, do not expose `acquire_certificate` (either acquisition protocol) to untrusted callers, as described in the Workarounds section of this brief.
*   If upgrading is not immediately possible, treat any record returned by `list_certificates` / `prove_certificate` as unverified and perform an out-of-band BRC-52 verification against the certifier's public key before acting on it.
