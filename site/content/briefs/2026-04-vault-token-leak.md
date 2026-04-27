---
title: Vault Token Leak via Authorization Header Forwarding
slug: 2026-04-vault-token-leak
description: Vault instances configured to pass through the 'Authorization' header may forward Vault tokens to auth plugin backends when the header is used for authentication, potentially leading to token compromise; this vulnerability is tracked as CVE-2026-4525 and patched in versions 2.0.0, 1.21.5, 1.20.10, and 1.19.16.
date: "2026-04-17T04:16:09Z"
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

CVE-2026-4525 describes a vulnerability in HashiCorp Vault where an improperly sanitized "Authorization" header can lead to token exposure. Specifically, if a Vault auth mount is configured to pass through the "Authorization" header, and that header is used to authenticate with Vault, the Vault token itself is inadvertently forwarded to the auth plugin backend. This unintended token forwarding could allow malicious actors to gain unauthorized access if they can intercept or control the auth…
