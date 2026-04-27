---
title: HashiCorp Vault Denial-of-Service Vulnerability (CVE-2026-5807)
slug: 2026-04-vault-dos
description: HashiCorp Vault is vulnerable to a denial-of-service (DoS) condition, identified as CVE-2026-5807, where an unauthenticated attacker can repeatedly initiate or cancel root token generation or rekey operations, preventing legitimate operators from completing these workflows.
date: "2026-04-17T05:16:19Z"
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

HashiCorp Vault, a secrets management tool, is susceptible to a denial-of-service attack due to a flaw in its root token generation and rekey operation handling. The vulnerability, CVE-2026-5807, allows an unauthenticated attacker to repeatedly initiate or cancel these operations, effectively locking the single in-progress operation slot. This prevents legitimate administrators from performing necessary security functions. The vulnerability affects all versions prior to 2.0.0 of both Vault…
