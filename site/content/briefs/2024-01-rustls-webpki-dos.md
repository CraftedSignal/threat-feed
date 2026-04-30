---
title: rustls-webpki Denial-of-Service Vulnerability via Malformed CRL BIT STRING
slug: 2024-01-rustls-webpki-dos
description: A denial-of-service vulnerability exists in rustls-webpki versions prior to 0.103.13 and between 0.104.0-alpha.1 and 0.104.0-alpha.7 due to a panic in `bit_string_flags()` when processing a malformed CRL BIT STRING, triggered when CRL checking is enabled and an attacker provides a crafted CRL.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - rustls-webpki
  - crl
vendors:
  - rust
products:
  - rustls-webpki
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://github.com/advisories/GHSA-82j2-j2ch-gfr8
rules:
  - title: Detect Malformed CRL Bit String
    description: Detects malformed CRLs with a BIT STRING containing only 0x00 in the issuingDistributionPoint extension, which triggers a panic in rustls-webpki.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - windows
  - title: Detect Panic in rustls-webpki via Sysmon
    description: Detects process termination events indicative of a panic in rustls-webpki due to the malformed CRL processing vulnerability.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A denial-of-service vulnerability has been identified in the rustls-webpki crate, specifically affecting versions prior to 0.103.13 and versions between 0.104.0-alpha.1 and 0.104.0-alpha.7. The vulnerability stems from a panic within the `bit_string_flags()` function located in `src/der.rs`. This panic occurs when the function processes a malformed Certificate Revocation List (CRL) containing a BIT STRING with a content of exactly `[0x00]`. The issue is triggered via the `issuingDistributionPoint` CRL extension when CRL revocation checking is explicitly enabled through `RevocationOptions` and the application loads CRL data from a source controlled by an attacker. This vulnerability allows a remote attacker to cause a denial of service in applications that rely on rustls-webpki for certificate validation.

## Attack Chain

1.  Attacker obtains a certificate from a Certificate Authority (CA) that permits custom Certificate Distribution Point (CDP) URLs.
2.  Attacker sets the CDP of the certificate to point to a server they control (e.g., `cdp`).
3.  The attacker crafts a malicious CRL with a BIT STRING in the `issuingDistributionPoint` extension containing the byte sequence `0x00`, triggering the vulnerability in `bit_string_flags()`. The CRL must be DER encoded and contain the following ASN.1 structure: `a0 10 30 0e 30 0c 06 03 55 1d 1c 04 05 30 03 83 01 00`
4.  The attacker hosts the crafted CRL on the server specified in the CDP.
5.  A vulnerable mTLS server configured to use CRL checking receives a connection request from a client presenting the attacker's certificate.
6.  The mTLS server fetches the CRL from the attacker-controlled CDP server during the TLS handshake.
7.  The `BorrowedCertRevocationList::from_der()` function parses the CRL, leading to the execution of `bit_string_flags()` on the malformed BIT STRING.
8.  The `bit_string_flags()` function panics due to an index-out-of-bounds error, resulting in a denial-of-service condition on the mTLS server.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service condition. Affected applications that perform mTLS, particularly servers, become unavailable when processing connections from clients presenting certificates with malicious CRL distribution points. This can disrupt services and impact availability. The severity is high because an attacker can trigger the vulnerability remotely without authentication.

## Recommendation

*   Upgrade to rustls-webpki version 0.103.13 or 0.104.0-alpha.7 or later to patch the vulnerability.
*   Deploy the Sigma rule `Detect-Malformed-CRL-Bit-String` to identify attempts to exploit this vulnerability by monitoring for specific byte sequences in CRL data.
*   Implement strict validation and sanitization of CRL data before processing it with `rustls-webpki`, especially when fetching CRLs from untrusted sources.
