---
brief_id: brief-2026-10-25-dokploy-auth-bypass
event_id: brief-2026-10-25-dokploy-auth-bypass
revision: 2
activity_at: "2026-10-25T14:44:13Z"
revision_history:
  - revision: 2
    at: "2026-10-25T14:44:13Z"
    checksum: sha256:51d9a76c092371a0b2b27f951e87cd05cbc0ed68d2a0fe3c2414c8793e5cdf24
    summary: poc_available
    changed_fields:
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-116068&utm_source=rss&utm_medium=rss
title: 'Dokploy: Authorization bypass and tenant application manipulation (CVE-2026-116068)'
slug: 2026-10-dokploy-auth-bypass
description: Dokploy versions through 0.30.10 contain an authorization bypass vulnerability allowing authenticated owners or admins to manipulate and disrupt other tenants' applications via malformed applicationId requests.
date: "2026-10-25T12:28:21Z"
lastmod: "2026-10-25T14:43:42Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified; no IOCs provided; manual review of application logs required by operators.
cpes:
  - cpe:2.3:a:dokploy:dokploy:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-116068&utm_source=rss&utm_medium=rss
tags:
  - authorization-bypass
  - cloud-security
  - web-application
vendors:
  - Dokploy
products:
  - Dokploy (<= 0.30.10)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1565.002
    technique_name: Transmitted Data Manipulation
    evidence: Attackers can call procedures like saveEnvironment, updateTraefikConfig, deploy, or stop to overwrite environment variables and build secrets, repoint sources, and disrupt other tenants applications.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Attackers can call procedures like ... stop to ... disrupt other tenants applications.
    confidence_band: high
cves:
  - id: CVE-2026-116068
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116068
  - https://sploitus.com/exploit?id=CVE-2026-116068&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Dokploy to a version exceeding 0.30.10
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-116068 affects versions <= 0.30.10
  hunt_leads:
    - lead: Identify cross-tenant administrative API calls
      technique_id: T1565.002
      data_needed:
        - Application audit logs or web server access logs for API endpoints saveEnvironment, updateTraefikConfig, deploy, and stop
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers can call procedures like saveEnvironment, updateTraefikConfig, deploy, or stop to overwrite environment variables
  mitigation_plan:
    - priority: immediate
      action: Upgrade Dokploy to fixed version
      owner: IT Operations
      addresses: CVE-2026-116068
      evidence: NVD disclosure states vulnerability exists through 0.30.10
updates:
  - at: "2026-10-25T14:43:42Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-116068&utm_source=rss&utm_medium=rss
---

Dokploy versions up to and including 0.30.10 contain an authorization bypass vulnerability. The flaw resides in the application's handling of `applicationId` values during API requests. An authenticated user (owner or admin) of one organization can provide a foreign `applicationId` belonging to a different tenant to invoke administrative procedures. 

## Impact

Confirmed impact includes the ability for an attacker to overwrite environment variables and build secrets, modify source repository mappings, and perform disruptive actions such as deploying or stopping unauthorized applications across different tenant boundaries.

## Recommendation

- Upgrade Dokploy to a patched version beyond 0.30.10 immediately.
- Audit logs for administrative API calls (specifically saveEnvironment, updateTraefikConfig, deploy, and stop) to identify suspicious cross-tenant application interactions.
- Temporarily restrict administrative access to the Dokploy interface until the patch is applied.
