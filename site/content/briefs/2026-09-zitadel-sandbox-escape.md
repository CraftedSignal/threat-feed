---
title: ZITADEL Actions V1 Sandbox Escape via File System Access
slug: 2026-09-zitadel-sandbox-escape
description: An insecure configuration of the goja JavaScript runtime in ZITADEL Actions V1 allows authenticated organization owners to perform a sandbox escape and read arbitrary host files via the require() module loader, leading to potential privilege escalation to instance administrator.
date: "2026-09-24T20:08:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:zitadel:zitadel:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - sandbox-escape
  - zitadel
  - cve-2026-85057
vendors:
  - ZITADEL
products:
  - ZITADEL (3.0.0 through 3.4.12)
  - ZITADEL (4.0.0 through 4.16.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An organization Action author to read files from the ZITADEL host filesystem through the JavaScript require() module loader... and escalate from a single-tenant organization owner to instance administrator.
    confidence_band: high
cves:
  - id: CVE-2026-85057
    cvss: 8.7
references:
  - https://github.com/advisories/GHSA-fgmf-7rf8-m6vf
  - https://github.com/zitadel/zitadel/releases/tag/v4.16.1
  - https://github.com/zitadel/zitadel/releases/tag/v3.4.13
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade ZITADEL to 4.16.1 or 3.4.13
      owner: IT Operations
      due: 24h
      evidence: Vendor patch availability in GHSA
  mitigation_plan:
    - priority: immediate
      action: Revoke org.action.write and org.flow.write permissions for non-trusted users
      owner: Security Engineering
      addresses: CVE-2026-85057
      evidence: Workaround suggested in GHSA
---

ZITADEL versions 3.x (< 3.4.13) and 4.x (< 4.16.1) contain a high-severity vulnerability (CVE-2026-85057) that enables a sandbox escape from the ZITADEL Actions V1 environment. Actions in ZITADEL are triggered during OIDC, SAML, and login flows, executing custom JavaScript within the server process using the goja Node-compatible engine. 

The vulnerability stems from the engine's `require()` module loader, which was improperly configured to allow loading files from the host filesystem rather than restricting imports to authorized `zitadel/*` modules. Because the ZITADEL process must have read access to certain configuration files and secrets to function, an attacker with `org.action.write` or `org.flow.write` permissions (typically held by an ORG_OWNER) can craft malicious scripts to read these files. This is particularly critical in deployments where bootstrap credentials like the Login Client PAT or machine keys are stored in locations reachable by the API process, allowing attackers to escalate privileges from an organization-level administrator to an instance-wide administrator.

## Impact

Successful exploitation collapses multi-tenant isolation, granting an organization administrator unauthorized access to host-level secrets and sensitive credentials. In self-hosted environments that follow documented bootstrap patterns, this leads to full instance control (IAM_OWNER). The vulnerability impacts all ZITADEL deployments utilizing Actions V1 on affected versions.

## Recommendation

* Upgrade ZITADEL 4.x deployments to version 4.16.1 or later immediately.
* Upgrade ZITADEL 3.x deployments to version 3.4.13 or later immediately.
* In multi-tenant environments, strictly limit the assignment of `org.action.write` and `org.flow.write` permissions to trusted administrators only.
* Audit existing Action scripts for the presence of `require()` calls referencing filesystem paths.
* Remove or relocate bootstrap credentials (e.g., `login-client.pat`, machine keys) to volumes or locations not accessible by the ZITADEL API process user.
