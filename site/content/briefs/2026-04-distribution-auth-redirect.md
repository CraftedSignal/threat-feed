---
title: Distribution Toolkit Authentication Redirection Vulnerability (CVE-2026-33540)
slug: 2026-04-distribution-auth-redirect
description: A vulnerability in the distribution toolkit prior to 3.1.0 allows a malicious upstream registry or man-in-the-middle attacker to redirect authentication requests, potentially exposing upstream credentials.
date: "2026-04-06T15:17:10Z"
severities:
  - high
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

The distribution toolkit, used for managing container content, is vulnerable to an authentication redirection attack in versions prior to 3.1.0 when operating in pull-through cache mode. The vulnerability, identified as CVE-2026-33540, stems from the toolkit's method of discovering token authentication endpoints. It parses WWW-Authenticate challenges from upstream registries without properly validating the realm URL against the upstream registry host. This allows an attacker controlling the…
