---
title: Authentication Bypass in passport-saml-encrypted via Unsigned SAML Assertions
slug: 2026-09-passport-saml-bypass
description: The passport-saml-encrypted library versions up to 0.1.13 contain a critical vulnerability where SAML signature verification is skipped if a specific configuration is omitted, allowing attackers to forge and inject arbitrary authentication assertions.
date: "2026-09-10T19:07:39Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:passport-saml-encrypted:passport-saml-encrypted:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - saml
  - supply-chain
products:
  - passport-saml-encrypted (<= 0.1.13)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550.002
    technique_name: Use Alternate Authentication Material
    evidence: The library allows attackers to post forged SAML responses with arbitrary NameID and attributes to the assertion consumer service endpoint to receive authenticated profiles without valid signatures.
    confidence_band: high
cves:
  - id: CVE-2026-89042
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89042
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Application Security
  immediate_actions:
    - action: Upgrade passport-saml-encrypted to the latest version and verify configuration.
      owner: Application Security
      due: 24h
      evidence: CVE-2026-89042
  mitigation_plan:
    - priority: immediate
      action: Upgrade passport-saml-encrypted dependency to version > 0.1.13
      owner: IT Operations
      addresses: CVE-2026-89042
      evidence: NVD vulnerability disclosure
---

CVE-2026-89042 affects the passport-saml-encrypted library through version 0.1.13. The vulnerability stems from an insecure implementation of SAML signature verification logic, where the library makes the verification process conditional based on an optional 'cert' configuration parameter. When this parameter is absent or misconfigured, the library fails to validate the signature of the SAML response. This design flaw allows a remote, unauthenticated attacker to inject forged SAML responses directly into the application's Assertion Consumer Service (ACS) endpoint. By providing an unsigned assertion containing arbitrary 'NameID' fields and malicious user attributes, the attacker can successfully impersonate any user within the target system, bypassing primary authentication mechanisms. The severity is elevated due to the ease of exploitation and the direct impact on system-wide access control.

## Impact

Successful exploitation allows for full authentication bypass, leading to unauthorized account access and potential privilege escalation within applications utilizing this library. The vulnerability affects any service relying on passport-saml-encrypted for SAML-based identity federation. Given the nature of SAML assertions, an attacker can craft assertions to match any existing user ID, posing a severe risk to multi-tenant or enterprise environments.

## Recommendation

1. Patch immediately by upgrading the passport-saml-encrypted dependency to a version higher than 0.1.13.
2. Audit all application configurations utilizing this library to ensure that the optional 'cert' validation parameter is explicitly enabled and properly configured.
3. Review application authentication logs for anomalous SAML response submissions that lack corresponding signature metadata or originate from unexpected sources.
