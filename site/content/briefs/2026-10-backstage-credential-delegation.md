---
title: Improper Access Restriction Enforcement in Backstage Service Delegation
slug: 2026-10-backstage-credential-delegation
description: A vulnerability in Backstage's backend-defaults package allows restricted service credentials to bypass defined access restrictions when routing requests through plugin delegation paths, potentially leading to unauthorized privilege escalation.
date: "2026-10-07T22:55:32Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:backstage:backend-defaults:*:*:*:*:*:*:*:*
vendors:
  - Backstage
products:
  - backend-defaults (< 0.17.8)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This could allow a restricted service to perform operations beyond its intended scope, including write operations on plugins it was restricted to read-only access for.
    confidence_band: high
cves:
  - id: CVE-2026-106492
    cvss: 7.6
references:
  - https://github.com/advisories/GHSA-cq7v-rfgc-5c7v
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade @backstage/backend-defaults to version 0.17.8 or later
      owner: IT Operations
      due: 48h
      evidence: Patched in @backstage/backend-defaults version 0.17.8
  mitigation_plan:
    - priority: immediate
      action: Restrict network-level access to Backstage backend API endpoints to known trusted callers
      owner: Network Security
      addresses: CVE-2026-106492
      evidence: Restrict network-level access to Backstage backend API endpoints to trusted callers only.
---

Backstage, an open platform for building developer portals, contains a security vulnerability in the `@backstage/backend-defaults` package (versions prior to 0.17.8). The issue arises from the improper preservation of access restrictions during service credential delegation. When an external service credential is configured with limited access, such as read-only permissions, the Backstage backend may fail to enforce these constraints when requests are routed through specific plugin delegation paths.

This flaw allows an attacker or a compromised service to perform actions beyond its intended scope, including executing write operations on plugins that were explicitly restricted to read-only access. Because this bypass occurs within the internal delegation logic, the risk is higher in environments where service-to-service authentication relies heavily on delegated credentials. Defenders must prioritize upgrading the vulnerable package or implementing network-level access controls to restrict access to the backend API.

## Impact

The vulnerability poses a significant risk to the integrity of systems integrated with Backstage. If exploited, an attacker could gain unauthorized write access to resources managed by plugins, potentially modifying sensitive configurations or data. This bypass affects organizations using Backstage for service-to-service interactions where granular access control is enforced via credential delegation. The scope of impact is contingent upon the number of plugins relying on these specific delegation paths and the privilege level of the credentials involved.

## Recommendation

* Upgrade the `@backstage/backend-defaults` package to version 0.17.8 or later immediately to address CVE-2026-106492.
* If an immediate upgrade is not possible, rotate restricted credentials and replace them with purpose-specific, unrestricted credentials scoped strictly to trusted consumers.
* Restrict network-level access to all Backstage backend API endpoints, ensuring only authorized callers and internal services can communicate with the API.
