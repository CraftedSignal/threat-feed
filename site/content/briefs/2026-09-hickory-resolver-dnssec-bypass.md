---
title: DNSSEC Validation Bypass in hickory-resolver
slug: 2026-09-hickory-resolver-dnssec-bypass
description: A vulnerability in hickory-resolver versions prior to 0.26.2 causes the library to ignore bogus DNSSEC proof states, allowing attackers to inject forged DNS records as validated data.
date: "2026-09-18T16:08:55Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:hickory:hickory-resolver:*:*:*:*:*:*:*:*
tags:
  - dnssec
  - vulnerability
  - network-security
vendors:
  - Hickory
products:
  - hickory-resolver (< 0.26.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1565.002
    technique_name: Data Manipulation
    evidence: Attackers controlling the answering zone or positioned on the network path can have forged DNS records accepted as validated, bypassing DNSSEC authentication checks.
    confidence_band: high
cves:
  - id: CVE-2026-93657
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93657
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Upgrade hickory-resolver to version 0.26.2 or later
      owner: Development
      due: 72h
      evidence: CVE-2026-93657 fix version identified in source
  mitigation_plan:
    - priority: immediate
      action: Update dependency version in project build files (Cargo.toml)
      owner: Development
      addresses: CVE-2026-93657
      evidence: NVD advisory
---

The hickory-resolver library (versions prior to 0.26.2) contains a security flaw affecting its DNSSEC validation logic. Specifically, the Resolver::lookup() and Resolver::lookup_ip() APIs fail to correctly propagate the 'bogus' state of a DNSSEC validation result. When a DNS response fails validation, the library does not communicate this status to the calling application, leading it to treat potentially malicious or forged DNS records as cryptographically verified. This issue is particularly dangerous for applications that rely on hickory-resolver to establish secure connections, such as TLS or SSH, as it allows attackers who can intercept network traffic or control an authoritative DNS zone to redirect users to malicious endpoints without triggering validation errors.

## Impact

Successful exploitation allows for the subversion of DNS integrity, enabling man-in-the-middle attacks where traffic is redirected to attacker-controlled infrastructure. This bypasses the security guarantees provided by DNSSEC, potentially leading to unauthorized data interception, phishing, or malware delivery for any application utilizing the affected library for name resolution in a security-sensitive context.

## Recommendation

Prioritize the update of the hickory-resolver library across all development environments and production services.
- Upgrade any application dependencies utilizing hickory-resolver to version 0.26.2 or later to address CVE-2026-93657.
- Audit applications that utilize the Resolver::lookup() or Resolver::lookup_ip() APIs to verify they do not rely solely on implicit validation when hickory-resolver is in use.
- Monitor for unusual network traffic patterns originating from internal servers to unexpected IP addresses, as this may indicate DNS redirection following a successful bypass.
