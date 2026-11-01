---
brief_id: brief-2026-11-01-beta9-volume-traversal
event_id: brief-2026-11-01-beta9-volume-traversal
revision: 1
activity_at: "2026-11-01T14:53:59Z"
title: 'Beta9: Sandbox escape via volume mount path traversal (CVE-2026-120308)'
slug: 2026-11-beta9-volume-traversal
description: A path traversal vulnerability in the Beta9 gateway fails to validate volume ownership and paths, allowing tenants to access arbitrary worker files and other tenants data.
date: "2026-11-01T14:53:59Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:beta9:gateway:*:*:*:*:*:*:*:*
  - cpe:2.3:a:beta9:worker:*:*:*:*:*:*:*:*
tags:
  - path-traversal
  - sandbox-escape
  - cloud
vendors:
  - Beta9
products:
  - Gateway (< 0.1.776)
  - Worker (< 0.1.756)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A tenant with a workspace token can therefore read and write the workers files, including other tenants volumes stored on that machine.
    confidence_band: high
cves:
  - id: CVE-2026-120308
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120308
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Beta9 gateway to 0.1.776 and worker to 0.1.756
      owner: IT Operations
      due: 24h
      evidence: 'Fixed in gateway 0.1.776 and worker 0.1.756: volume identifiers and mount paths are validated'
  hunt_leads:
    - lead: Monitor Beta9 audit logs for deployment requests containing parent-directory segments in volume identifiers
      technique_id: T1068
      data_needed:
        - Gateway access or audit logs
        - Stub configuration audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Parent-directory segments in the identifier collapse the joined path to the workers filesystem root
  mitigation_plan:
    - priority: immediate
      action: Upgrade to specified patched versions
      owner: IT Operations
      addresses: CVE-2026-120308
      evidence: Fixed in gateway 0.1.776 and worker 0.1.756
---

A path traversal vulnerability exists in Beta9 gateway and worker components where volume identifiers are not validated for ownership or path constraints. By providing a volume identifier containing parent-directory traversal sequences, an authenticated tenant can cause the worker to bind-mount directories from the host filesystem into their sandbox. This grants read/write access to worker files and data belonging to other tenants. This vulnerability is confirmed in gateway version 0.1.769 and worker version 0.1.745.

## Impact
A tenant with a workspace token can perform unauthorized read and write operations on the underlying worker filesystem, potentially resulting in cross-tenant data exposure and host system compromise.

## Recommendation
Patch all Beta9 deployments by upgrading the gateway component to version 0.1.776 or later and the worker component to version 0.1.756 or later. These versions implement strict validation of volume identifiers and ownership checks.
