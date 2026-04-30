---
title: HashiCorp Vault Denial-of-Service Vulnerability (CVE-2026-5807)
slug: 2026-04-vault-dos
description: HashiCorp Vault is vulnerable to a denial-of-service (DoS) condition, identified as CVE-2026-5807, where an unauthenticated attacker can repeatedly initiate or cancel root token generation or rekey operations, preventing legitimate operators from completing these workflows.
date: "2026-04-17T05:16:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vault
  - cve-2026-5807
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-5807
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5807
  - https://discuss.hashicorp.com/t/hcsec-2026-08-vault-vulnerable-to-denial-of-service-via-unauthenticated-root-token-generation-rekey-operations/77345
rules:
  - title: Detect Vault Root Token Generation/Rekey DoS Attempts
    description: Detects repeated attempts to initiate or cancel root token generation or rekey operations in HashiCorp Vault, indicative of CVE-2026-5807 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.002
    data_sources:
      - webserver
      - linux
  - title: Vault Unauthenticated Root Token Generation Attempt
    description: Detects attempts to generate a root token without authentication in HashiCorp Vault, indicating a potential exploit attempt of CVE-2026-5807.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

HashiCorp Vault, a secrets management tool, is susceptible to a denial-of-service attack due to a flaw in its root token generation and rekey operation handling. The vulnerability, CVE-2026-5807, allows an unauthenticated attacker to repeatedly initiate or cancel these operations, effectively locking the single in-progress operation slot. This prevents legitimate administrators from performing necessary security functions. The vulnerability affects all versions prior to 2.0.0 of both Vault Community Edition and Vault Enterprise. The issue was reported publicly in April 2026 and patched in Vault version 2.0.0. Organizations using affected versions of Vault are urged to upgrade immediately to mitigate the risk of DoS attacks.

## Attack Chain

1.  Unauthenticated attacker sends a request to initiate a root token generation process to the Vault server's API endpoint.
2.  The Vault server accepts the request, placing the operation in the single available slot.
3.  The attacker sends a request to cancel the root token generation process.
4.  The Vault server cancels the operation, freeing the slot.
5.  The attacker repeats steps 1-4 in rapid succession, continuously occupying and freeing the operation slot.
6.  A legitimate Vault administrator attempts to initiate a root token generation or rekey operation.
7.  The administrator's request is blocked because the operation slot is perpetually occupied by the attacker's requests.
8.  The Vault server becomes effectively unresponsive for legitimate root token generation or rekey tasks, resulting in a denial of service.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition, preventing legitimate Vault administrators from performing critical operations such as root token generation or rekeying. This can disrupt normal operations, hinder security incident response, and potentially lead to extended outages if root access is required for recovery. While the exact number of affected organizations is not available, any organization using Vault versions prior to 2.0.0 is potentially vulnerable. The impact severity is heightened in environments where Vault is a critical component of the infrastructure.

## Recommendation

*   Upgrade Vault to version 2.0.0 or later immediately to patch CVE-2026-5807.
*   Monitor Vault access logs for suspicious patterns of root token generation or rekey initiation/cancellation requests, and create alerts based on those patterns using `webserver` log source.
*   Implement rate limiting on Vault's API endpoints to mitigate the impact of rapid request flooding.
*   Deploy the provided Sigma rule to detect attempts to repeatedly initiate or cancel root token generation or rekey operations.
