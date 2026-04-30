---
title: Distribution Toolkit Authentication Redirection Vulnerability (CVE-2026-33540)
slug: 2026-04-distribution-auth-redirect
description: A vulnerability in the distribution toolkit prior to 3.1.0 allows a malicious upstream registry or man-in-the-middle attacker to redirect authentication requests, potentially exposing upstream credentials.
date: "2026-04-06T15:17:10Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - CVE-2026-33540
  - authentication
  - redirection
  - container
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-33540
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33540
rules:
  - title: Detect Basic Authentication to Non-Standard Ports
    description: Detects basic authentication attempts to non-standard ports, which may indicate credential theft or redirection attempts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555.004
    data_sources:
      - network_connection
      - linux
  - title: Detect Authentication Redirection
    description: Detects requests to unusual or suspicious realm URLs from container registries, potentially indicating an authentication redirection attack.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The distribution toolkit, used for managing container content, is vulnerable to an authentication redirection attack in versions prior to 3.1.0 when operating in pull-through cache mode. The vulnerability, identified as CVE-2026-33540, stems from the toolkit's method of discovering token authentication endpoints. It parses WWW-Authenticate challenges from upstream registries without properly validating the realm URL against the upstream registry host. This allows an attacker controlling the upstream registry or positioned as a Man-in-the-Middle to redirect authentication requests to an attacker-controlled realm URL. This results in distribution sending the configured upstream credentials via basic authentication to the malicious URL. Organizations using affected versions of the distribution toolkit are vulnerable to credential compromise if the toolkit interacts with a malicious or compromised upstream registry. Upgrading to version 3.1.0 or later resolves this vulnerability.

## Attack Chain

1.  Attacker gains control of or MitM position to an upstream registry server used by the distribution toolkit.
2.  Distribution toolkit attempts to pull an image from the upstream registry.
3.  Attacker's registry responds with a WWW-Authenticate header, specifying a Bearer authentication scheme and an attacker-controlled realm URL.
4.  The distribution toolkit, vulnerable to CVE-2026-33540, parses the WWW-Authenticate header but fails to validate the realm URL against the legitimate upstream registry.
5.  The distribution toolkit initiates a basic authentication request to the attacker-controlled realm URL, sending the configured upstream credentials (username and password).
6.  The attacker captures the credentials sent via basic authentication.
7.  Attacker uses the compromised credentials to gain unauthorized access to the legitimate upstream registry.

## Impact

Successful exploitation of CVE-2026-33540 allows an attacker to steal credentials used by the distribution toolkit to authenticate to an upstream registry. This can lead to unauthorized access to container images stored in the upstream registry, potentially resulting in supply chain attacks, data breaches, or the deployment of malicious container images. The severity of the impact depends on the permissions associated with the compromised credentials and the sensitivity of the data stored in the upstream registry.

## Recommendation

*   Upgrade the distribution toolkit to version 3.1.0 or later to remediate CVE-2026-33540.
*   Implement network monitoring to detect basic authentication attempts originating from the distribution toolkit to unusual or unexpected destinations (see rule: "Detect Basic Authentication to Non-Standard Ports").
*   Monitor network traffic for connections to unusual or suspicious realm URLs returned in WWW-Authenticate headers from container registries (see rule: "Detect Authentication Redirection").
