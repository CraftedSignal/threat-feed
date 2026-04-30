---
title: Vault Token Leak via Authorization Header Forwarding
slug: 2026-04-vault-token-leak
description: Vault instances configured to pass through the 'Authorization' header may forward Vault tokens to auth plugin backends when the header is used for authentication, potentially leading to token compromise; this vulnerability is tracked as CVE-2026-4525 and patched in versions 2.0.0, 1.21.5, 1.20.10, and 1.19.16.
date: "2026-04-17T04:16:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vault
  - token-leak
  - authorization
  - cve-2026-4525
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
cves:
  - id: CVE-2026-4525
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4525
  - https://discuss.hashicorp.com/t/hcsec-2026-07-vault-may-expose-tokens-to-auth-plugins-due-to-incorrect-header-sanitization/77344
iocs:
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
rules:
  - title: Detect Unauthorized Vault Authentication via Auth Path
    description: Detects attempts to authenticate to Vault using a specific auth path after a potential token compromise.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.001
    data_sources:
      - webserver
      - linux
  - title: Detect Vault Authentication with Authorization Header
    description: Detects authentication attempts to Vault using the Authorization header, which may indicate exploitation of CVE-2026-4525 prior to patching.
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1552.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-4525 describes a vulnerability in HashiCorp Vault where an improperly sanitized "Authorization" header can lead to token exposure. Specifically, if a Vault auth mount is configured to pass through the "Authorization" header, and that header is used to authenticate with Vault, the Vault token itself is inadvertently forwarded to the auth plugin backend. This unintended token forwarding could allow malicious actors to gain unauthorized access if they can intercept or control the auth plugin backend. This issue affects Vault versions prior to 2.0.0, 1.21.5, 1.20.10, and 1.19.16 and was reported by HashiCorp. The vulnerability was patched in the aforementioned versions. Exploitation would require specific Vault configuration and the ability to influence the authentication process via the Authorization header.

## Attack Chain

1.  An attacker identifies a Vault instance with an auth mount configured to pass through the "Authorization" header.
2.  The attacker crafts a malicious request to Vault, including a valid "Authorization" header for authentication purposes.
3.  Vault processes the request and, due to the vulnerability, forwards the Vault token contained in the "Authorization" header to the configured auth plugin backend.
4.  The attacker intercepts the forwarded Vault token, either by compromising the auth plugin backend or through network monitoring.
5.  The attacker uses the stolen Vault token to authenticate directly to Vault, bypassing normal authentication procedures.
6.  The attacker gains unauthorized access to sensitive data and secrets stored within Vault.
7.  The attacker escalates privileges within the Vault environment by leveraging the compromised token's permissions.

## Impact

Successful exploitation of CVE-2026-4525 allows an attacker to steal Vault tokens, potentially granting them complete control over the Vault instance and access to all stored secrets. The severity is high due to the potential for complete compromise of sensitive data. The impact depends on the scope of secrets managed by the compromised Vault instance; in some cases, this could lead to a complete breach of the affected organization's infrastructure. The vulnerability affects all organizations using vulnerable versions of Vault with auth mounts configured to pass through the "Authorization" header.

## Recommendation

*   Upgrade Vault instances to versions 2.0.0, 1.21.5, 1.20.10, or 1.19.16 or later to remediate CVE-2026-4525.
*   Review Vault auth mount configurations to ensure that the "Authorization" header is not being passed through unnecessarily.
*   Monitor network traffic for unauthorized access attempts using stolen Vault tokens after applying the patch.
*   Implement the provided Sigma rule targeting the usage of specific auth paths after a potential compromise.
