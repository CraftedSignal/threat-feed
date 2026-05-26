---
title: 'CVE-2026-42013: gnutls Certificate Validation Bypass via Oversized SAN'
slug: 2026-05-gnutls-cert-bypass
description: A vulnerability in gnutls (CVE-2026-42013) allows a remote attacker to bypass certificate validation by providing an oversized Subject Alternative Name (SAN), causing the validation process to fall back to the Common Name (CN) field, potentially leading to spoofing or man-in-the-middle attacks.
date: "2026-05-26T22:18:53Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - certificate validation
  - spoofing
  - man-in-the-middle
  - gnutls
  - CVE-2026-42013
vendors:
  - Red Hat
products:
  - gnutls
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1588
    technique_name: Obtain Capabilities
cves:
  - id: CVE-2026-42013
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42013
  - https://access.redhat.com/security/cve/CVE-2026-42013
  - https://bugzilla.redhat.com/show_bug.cgi?id=2467448
rules:
  - title: Detect GnuTLS Certificate Validation Bypass - Large SAN
    description: Detects CVE-2026-42013 exploitation — monitors network traffic for TLS connections using certificates with unusually large Subject Alternative Name (SAN) fields, which could indicate an attempt to bypass certificate validation.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - cve-2026-42013
    techniques:
      - T1588.004
    data_sources:
      - network_connection
      - windows
  - title: Detect GnuTLS Certificate Validation Bypass - Fallback to CN
    description: Detects CVE-2026-42013 exploitation — This rule detects potential exploitation of CVE-2026-42013 by monitoring for certificate validation events where a fallback to the Common Name (CN) field occurs after encountering an issue with the Subject Alternative Name (SAN).
    platform: sigma
    severity: low
    tactics:
      - credential_access
      - cve-2026-42013
    techniques:
      - T1588.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-42013 describes a certificate validation bypass vulnerability within the gnutls library. The vulnerability occurs when gnutls encounters an oversized Subject Alternative Name (SAN) during certificate validation. Instead of properly rejecting the certificate, the validation process incorrectly falls back to checking the Common Name (CN) field. This fallback behavior allows a remote attacker to potentially bypass certificate validation. An attacker could exploit this flaw to perform spoofing or man-in-the-middle attacks by presenting a certificate with a valid CN but a manipulated SAN. This vulnerability was published on 2026-05-26.

## Attack Chain

1.  Attacker crafts a malicious certificate with an oversized Subject Alternative Name (SAN) field.
2.  The attacker sets the Common Name (CN) field in the certificate to a value they wish to impersonate (e.g., a legitimate domain).
3.  The attacker initiates a TLS connection to a target server or client using the crafted certificate.
4.  The gnutls library on the target attempts to validate the presented certificate.
5.  Due to the oversized SAN, the gnutls library fails to properly process the SAN field.
6.  The gnutls library incorrectly falls back to validating the CN field.
7.  The CN field matches the expected value, and the gnutls library incorrectly considers the certificate valid.
8.  The attacker successfully bypasses certificate validation, enabling potential spoofing or man-in-the-middle attacks.

## Impact

Successful exploitation of CVE-2026-42013 allows a remote attacker to bypass certificate validation, potentially leading to spoofing or man-in-the-middle attacks. This could allow the attacker to intercept sensitive data, inject malicious content, or compromise the confidentiality and integrity of communications. The CVSS v3.1 base score is 8.2, indicating a high severity.

## Recommendation

*   Apply the necessary patches or updates provided by Red Hat to address CVE-2026-42013 on systems using the affected gnutls library.
*   Monitor network traffic for TLS connections using certificates with unusually large SAN fields, as these could indicate exploitation attempts. Consider implementing a network connection rule targeting connections utilizing certificates with large SAN sizes.
*   Deploy the Sigma rule `Detect GnuTLS Certificate Validation Bypass - Large SAN` to identify potential exploitation attempts based on process execution patterns and network connections.
