---
title: SpringBlade Privilege Escalation via Hardcoded JWT Key and Unprotected Endpoint
slug: 2026-08-springblade-priv-esc
description: SpringBlade versions 2.7.3 through 3.5.0 allow authenticated attackers to forge administrative tokens using a hardcoded JWT signing key and escalate privileges via an unprotected internal endpoint.
date: "2026-08-28T21:37:22Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:springblade:springblade:2.7.3:*:*:*:*:*:*:*
  - cpe:2.3:a:springblade:springblade:3.5.0:*:*:*:*:*:*:*
tags:
  - vulnerability
  - privilege-escalation
  - authentication-bypass
vendors:
  - SpringBlade
products:
  - SpringBlade (2.7.3 - 3.5.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: SpringBlade versions 2.7.3 through 3.5.0 contain a privilege escalation vulnerability that allows authenticated attackers to create system administrator accounts.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
    evidence: The gateway's authentication filter... only validates JWT parsing without verifying user roles or caller identity.
    confidence_band: high
cves:
  - id: CVE-2026-56100
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56100
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Inventory all SpringBlade deployments and verify version numbers against 2.7.3-3.5.0 range.
      owner: IT Operations
      due: 24h
      evidence: Affected products list.
  mitigation_plan:
    - priority: immediate
      action: Upgrade SpringBlade to a patched version post 3.5.0 and rotate all JWT signing keys.
      owner: IT Operations
      addresses: CVE-2026-56100
      evidence: Vulnerability analysis in brief.
---

SpringBlade versions 2.7.3 through 3.5.0 contain a critical privilege escalation vulnerability, tracked as CVE-2026-56100. The vulnerability stems from an improperly secured internal Feign user-creation endpoint exposed via a REST controller that lacks sufficient authorization checks. An attacker with low-privilege authenticated access can leverage a hardcoded JWT signing key, which is embedded within publicly available distributed JAR files, to forge arbitrary administrative tokens. The gateway's authentication filter is insufficient, as it only validates the structural integrity of the JWT without verifying the user's roles, identity, or the caller's origin. By exploiting this flaw, attackers can escalate their access level to system administrator, resulting in full unauthorized access, cross-tenant data pollution, and the establishment of persistent backdoors.

## Impact

Successful exploitation of this vulnerability allows unauthorized users to elevate their privileges to administrator status. This grants them full control over the SpringBlade environment, leading to the compromise of sensitive cross-tenant data and the installation of persistent administrative backdoors. The vulnerability affects all deployments using SpringBlade versions 2.7.3 through 3.5.0.

## Recommendation

Prioritize the identification and remediation of SpringBlade instances within the environment.

- Upgrade all SpringBlade instances to a version beyond 3.5.0 that addresses the hardcoded JWT secret and enforces authorization on the Feign user-creation endpoint.
- Audit access logs for anomalous POST requests directed at internal user-creation endpoints that are exposed via @RestController patterns.
- Rotate the JWT signing keys for all production SpringBlade environments immediately, as the embedded keys in existing versions are considered public knowledge.
