---
title: Oxia TLS Certificate Chain Validation Failure
slug: 2024-01-30-oxia-tls-failure
description: Oxia's `trustedCertPool()` function fails to parse multi-certificate PEM bundles, leading to certificate chain validation failure and rejection of legitimate clients in mTLS deployments.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - tls
  - mtls
  - certificate-validation
  - oxia
  - vulnerability
vendors:
  - Oxia
products:
  - Oxia
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1588
    technique_name: Obtain Capabilities
references:
  - https://github.com/advisories/GHSA-7jrq-q4pq-rhm6
rules:
  - title: Oxia TLS Authentication Failure - Unknown Authority
    description: 'Detects ''x509: certificate signed by unknown authority'' errors in Oxia server logs, indicating a potential TLS certificate chain validation failure.'
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1588.004
    data_sources:
      - webserver
      - linux
  - title: Oxia TLS Configuration - Multiple Certificates in CA File
    description: Detects Oxia using a trusted CA file with multiple certificate entries which may indicate the vulnerability.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1588.004
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The Oxia database platform, specifically versions 0.16.1 and earlier, contains a vulnerability in its TLS configuration parsing. The `trustedCertPool()` function within the `common/security/tls.go` file is designed to load trusted Certificate Authority (CA) certificates for mTLS authentication. However, the function only processes the first PEM-encoded certificate block within a specified CA file. This means that if a CA file contains a bundle of certificates, such as an intermediate CA and a root CA, only the first certificate is loaded and the rest are silently discarded. This issue was reported on GitHub as GHSA-7jrq-q4pq-rhm6 and can lead to a significant degradation of security posture.

## Attack Chain

1. An administrator configures Oxia to use mTLS for client authentication, specifying a CA bundle file containing both intermediate and root CA certificates via the `trustedCaFile` setting.
2. Oxia's `trustedCertPool()` function attempts to load the CA certificates from the specified file.
3. The `pem.Decode()` function is called, but it only parses the first PEM block (e.g., the intermediate CA certificate).
4. Subsequent certificates within the CA bundle (e.g., the root CA certificate) are silently ignored because the code doesn't iterate over all PEM blocks.
5. A legitimate client attempts to connect to Oxia using a certificate chain that is correctly signed by the intermediate CA, which is in turn signed by the root CA.
6. Oxia only trusts the intermediate CA certificate that was loaded.
7. Certificate chain validation fails because the root CA is not trusted, resulting in the error "x509: certificate signed by unknown authority".
8. The legitimate client connection is rejected, effectively breaking mTLS authentication.

## Impact

The vulnerability results in the failure of certificate chain validation in mTLS deployments of Oxia. This means that legitimate clients with properly chained certificates are rejected, leading to a denial of service. Operators might be forced to disable client certificate verification, which severely weakens the security posture of Oxia deployments. All Oxia versions up to and including 0.16.1 are vulnerable if TLS with the `trustedCaFile` configuration is used.

## Recommendation

*   Apply the patch provided by Oxia that iterates over all PEM blocks in the CA file (reference: GHSA-7jrq-q4pq-rhm6).
*   As a temporary workaround, use CA files containing only a single certificate (the direct issuer of client certificates) for the `trustedCaFile` configuration (reference: GHSA-7jrq-q4pq-rhm6).
*   Monitor Oxia server logs for "x509: certificate signed by unknown authority" errors after configuring mTLS, which may indicate this vulnerability is being triggered.
