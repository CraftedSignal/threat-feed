---
title: OpenBao Recovery Mode Timing Attack
slug: 2026-09-openbao-token-leak
description: OpenBao recovery mode is vulnerable to a timing attack (CVE-2026-63132) that allows an unauthenticated attacker to exfiltrate the recovery token and gain administrative control.
date: "2026-09-23T01:54:27Z"
lastmod: "2026-09-23T01:55:34Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:openbao:openbao:*:*:*:*:*:*:*:*
tags:
  - credential-access
  - vulnerability
  - openbao
  - privilege-escalation
  - secrets-management
  - cve-2026-71543
vendors:
  - OpenBao
products:
  - OpenBao (0.1.0 to 1.1.5, < 0.0.0-20260713141742-763625a20721)
  - OpenBao (< 0.0.0-20260710001938-2d4ebafec5c5, 0.1.0-1.1.5)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: This allowed an attacker to extract the recovery token and use it to perform operations against the OpenBao instance.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: If the data used in the template can be controlled by an attacker and globbing characters are considered valid they will be able to escalate their privileges.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-34fc-gh42-pj53
  - https://github.com/advisories/GHSA-59w7-v8rr-pr4p
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-71543
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade OpenBao to version 2.6.0
      owner: IT Operations
      due: 24h
      evidence: This has been patched in OpenBao v2.6.0.
  mitigation_plan:
    - priority: immediate
      action: Rotate all credentials stored in OpenBao instances
      owner: Security Engineering
      addresses: CVE-2026-63132
      evidence: Successful exploitation grants full administrative control.
updates:
  - at: "2026-09-23T01:55:34Z"
    level: L2
    summary: added coverage for OpenBao (< 0.0.0-20260710001938-2d4ebafec5c5, 0.1.0-1.1.5)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-59w7-v8rr-pr4p
---

OpenBao, an open-source secret management tool, contains a critical vulnerability (CVE-2026-63132) in its recovery mode mechanism. The vulnerability originates from a timing discrepancy in how recovery tokens are verified, allowing an attacker to reconstruct the token via repeated requests. Because the recovery mode is designed for administrative maintenance and bypasses standard access controls, successful extraction of this single recovery token grants an attacker full administrative privileges. This enables unauthorized actors to read or modify any data managed by the OpenBao instance, effectively compromising the entire secrets infrastructure. The vulnerability affects OpenBao versions ranging from 0.1.0 to 1.1.5, as well as specific development builds prior to July 2026. Defenders should prioritize patching to version 2.6.0 immediately.

## Impact

Successful exploitation of CVE-2026-63132 results in full administrative access to an organization's OpenBao instance. This leads to the complete compromise of stored secrets, credentials, and API keys. The impact is critical, as it bypasses standard authorization and auditing mechanisms, potentially leading to widespread lateral movement and privilege escalation across the infrastructure.

## Recommendation

- Upgrade all OpenBao instances to version 2.6.0 or later to mitigate CVE-2026-63132.
- Audit OpenBao access logs for abnormal request patterns targeting the recovery endpoint.
- Rotate all secrets and credentials managed by any OpenBao instance that was exposed to network access during the vulnerable period.
