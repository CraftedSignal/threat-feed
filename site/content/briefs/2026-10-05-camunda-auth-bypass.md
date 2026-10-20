---
brief_id: brief-2026-10-05-camunda-auth-bypass
event_id: brief-2026-10-05-camunda-auth-bypass
revision: 2
activity_at: "2026-10-06T00:51:58Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:fac37c53d4b46a2cf2ca61a5f4537a2d57b8ab4c705cb275515079865ca6b7b4
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: Authorization Bypass in Camunda Platform Admin Setup
slug: 2026-10-05-camunda-auth-bypass
description: An incorrect authorization vulnerability in Camunda Platform 7.24.x allows unauthenticated remote attackers to create new administrator accounts by exploiting logic flaws in the first-run setup endpoint.
date: "2026-10-06T00:51:58Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cves:
  - id: CVE-2026-77226
    cvss: 8.1
    kev_status: unknown
---

Camunda Platform version 7.24.0 through 7.24.14 contains an incorrect authorization vulnerability in the Admin web application's first-run setup endpoint, tracked as CVE-2026-77226. The vulnerability exists within the SetupResource component, which incorrectly validates setup availability by only checking the membership of the 'camunda-admin' group.

If the 'camunda-admin' group is empty, even if the system is already configured with other administrators, the application logic incorrectly identifies the system as being in its initial setup phase. This allows an unauthenticated remote attacker to access the user-create endpoint and register a new administrator account. Successful exploitation grants the attacker full administrative access to the platform, enabling capabilities such as process deployment and arbitrary script execution under the context of the engine's service user, leading to potential full system compromise.

## Impact

Successful exploitation allows unauthenticated attackers to achieve full administrator-level access to the Camunda Platform. This results in the ability to deploy malicious processes, execute arbitrary scripts via the engine, and potentially pivot into the underlying server environment. This vulnerability affects enterprise deployments utilizing Camunda Platform 7.24.0 through 7.24.14.

## Recommendation

* Upgrade Camunda Platform to version 7.24.15 or later immediately to address CVE-2026-77226.
* Restrict network access to the Camunda Admin web application endpoints, specifically the setup and user-create paths, using a Web Application Firewall (WAF) or ingress filtering for untrusted networks.
* Audit existing user accounts and group memberships within the 'camunda-admin' group for unauthorized changes.
* Monitor web server logs for suspicious POST requests to setup
